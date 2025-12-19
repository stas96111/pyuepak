import hashlib
from collections import defaultdict

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from .entry import Entry
from .file_io import Reader, Writer
from .utils import fnv64, fnv64_path, split_path_child, COMPRESSION
from .version import PakVersion
from .footer import Footer

from logging import getLogger

logger = getLogger("pyuepak.index")


def hash_sh1(data: bytes) -> bytes:
    hasher = hashlib.sha1()
    hasher.update(data)
    return hasher.digest()  # 20 bytes


def decrypt(key: bytes, data: bytes):
    if key is None or key == bytes(32):
        raise ValueError("Encryption key is required")

    if len(data) % 16 != 0:
        raise ValueError("Data length must be a multiple of 16 bytes")

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()

    return decryptor.update(data) + decryptor.finalize()


class Index:
    def __init__(self):
        self.entry_count = 0

        self.entrys: dict[str, Entry] = {}

    def read(self, reader: Reader, footer: Footer, key: bytes):
        """Read the index of the pak file."""

        version = footer.version
        index_offset = footer.index_offset
        index_size = footer.index_size
        is_encrypted = footer.is_encrypted
        compressions = footer.compresion

        logger.debug("Reading index...")
        index_reader = reader.buffer(index_offset, index_size)

        if is_encrypted:
            index_reader = Reader(decrypt(key, index_reader.read(index_size)))

        self.mount_point = index_reader.string()
        self.entry_count = index_reader.uint32()
        path_hash_index = []
        directories = {}

        if version >= PakVersion.V10:
            path_hash_seed = index_reader.uint64()

            has_path_index = index_reader.uint32()
            if has_path_index != 0:
                path_hash_index_offset = index_reader.uint64()
                path_hash_index_size = index_reader.uint64()
                path_hash_index_hash = index_reader.sha1()

                path_hash_index_reader = reader.buffer(
                    path_hash_index_offset, path_hash_index_size
                )

                if is_encrypted:
                    path_hash_index_reader = Reader(
                        decrypt(key, path_hash_index_reader.read(path_hash_index_size))
                    )

                count = path_hash_index_reader.uint32()
                for _ in range(count):
                    path_hash_index.append(
                        (
                            path_hash_index_reader.uint64(),  # Hash
                            path_hash_index_reader.uint32(),  # encoded offset
                        )
                    )

            has_full_directory_index = index_reader.uint32()
            if has_full_directory_index != 0:
                full_directory_index_offset = index_reader.uint64()
                full_directory_index_size = index_reader.uint64()
                full_directory_index_hash = index_reader.sha1()

                full_directory_index_reader = reader.buffer(
                    full_directory_index_offset, full_directory_index_size
                )

                if is_encrypted:
                    full_directory_index_reader = Reader(
                        decrypt(
                            key,
                            full_directory_index_reader.read(full_directory_index_size),
                        )
                    )

                dir_count = full_directory_index_reader.uint32()
                for _ in range(dir_count):
                    dir_name = full_directory_index_reader.string()
                    file_count = full_directory_index_reader.uint32()
                    files = {}
                    for _ in range(file_count):
                        file_name = full_directory_index_reader.string()
                        files[file_name] = full_directory_index_reader.int32()
                    directories[dir_name] = files

            size = index_reader.int32()
            encoded_entries = index_reader.read(size)

            not_encoded_entry_count = index_reader.uint32()
            not_encoded_entries = []
            for _ in range(not_encoded_entry_count):
                entry = Entry()
                entry.read(index_reader, version)
                self.entrys.append(entry)

            entrys_by_path = {}
            if has_full_directory_index:
                encoded_offset_reader = Reader(encoded_entries)
                for dir_name, files in directories.items():
                    for file_name, encoded_offset in files.items():
                        entry = None
                        if encoded_offset >= 0:
                            encoded_offset_reader.set_pos(encoded_offset)
                            entry = Entry()
                            logger.debug(f"Reading {dir_name}/{file_name}")
                            entry.read_encoded(
                                encoded_offset_reader, version, compressions
                            )
                        else:
                            index = -encoded_offset - 1
                            entry = not_encoded_entries[index].copy()

                        path = dir_name.lstrip("/") + file_name
                        entrys_by_path[path] = entry

            self.entrys = entrys_by_path

        else:
            self.entrys = {}
            for _ in range(self.entry_count):
                entry = Entry()
                path = index_reader.string()
                entry.read(index_reader, version)
                self.entrys[path] = entry

        logger.debug(f"Read {len(self.entrys)} entries from index.")

    def write(
        self,
        writer: Writer,
        version: PakVersion,
        mount_point: str = "../../../",
        path_hash_seed: int = 0,
    ):
        self.offset = writer.get_pos()

        index_buf = Writer()

        fdi_buf, phi_buf = None, None

        index_buf.string(mount_point)  # mount point
        index_buf.uint32(len(self.entrys))  # entry count

        if version >= PakVersion.V10:
            index_buf.uint64(path_hash_seed)  # path_hash_seed

            encoded_entries = Writer()
            entrys_offsets = []
            for path, entry in self.entrys.items():
                entrys_offsets.append((path, encoded_entries.get_pos()))
                entry.write_encoded(encoded_entries, version)

            bytes_before_phi = (
                105 + len(mount_point) + len(encoded_entries.file.getvalue())
            )

            phi_offset = self.offset + bytes_before_phi
            phi_buf = Writer()

            generate_phi(phi_buf, entrys_offsets, path_hash_seed)

            fdi_offset = phi_offset + len(phi_buf.file.getvalue())
            fdi_buf = Writer()

            generate_fdi(fdi_buf, entrys_offsets)

            index_buf.uint32(1)
            index_buf.uint64(phi_offset)
            index_buf.uint64(len(phi_buf.file.getvalue()))
            index_buf.write(hash_sh1(phi_buf.file.getvalue()))

            index_buf.uint32(1)
            index_buf.uint64(fdi_offset)
            index_buf.uint64(len(fdi_buf.file.getvalue()))
            index_buf.write(hash_sh1(fdi_buf.file.getvalue()))

            index_buf.uint32(len(encoded_entries.file.getvalue()))
            index_buf.write(encoded_entries.file.getvalue())
            index_buf.uint32(0)
        else:
            for path, entry in self.entrys.items():
                index_buf.string(path)
                entry.write(index_buf, version)

        self.hash = hash_sh1(index_buf.file.getvalue())
        self.size = len(index_buf.file.getvalue())

        writer.write(index_buf.file.getvalue())

        if phi_buf:
            writer.write(phi_buf.file.getvalue())

        if fdi_buf:
            writer.write(fdi_buf.file.getvalue())


def generate_phi(writer: Writer, entries: list[tuple[str, int]], path_hash_seed=0):
    writer.uint32(len(entries))
    for path, offset in entries:
        path_hash = fnv64_path(path, path_hash_seed)
        writer.uint64(path_hash)
        writer.uint32(offset)

    writer.uint32(0)


def generate_fdi(writer: Writer, entries: list[tuple[str, int]]):
    fdi = defaultdict(dict)

    for path, offset in entries:
        p = path
        while True:
            result = split_path_child(p)
            if result is None:
                break
            parent, _ = result
            p = parent
            fdi.setdefault(parent, {})

        result = split_path_child(path)
        if result is None:
            raise ValueError("Path is root — invalid in this context")
        dir, filename = result
        fdi[dir][filename] = offset

    writer.uint32(len(fdi))
    for dir, files in fdi.items():
        writer.string(dir)
        writer.uint32(len(files))
        for filename, offset in files.items():
            writer.string(filename)
            writer.uint32(offset)
