import hashlib
from math import ceil

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .file_io import Reader, Writer
from .utils import hybrid_method, COMPRESSION
from .version import PakVersion
from .oodle import oodle

import logging
import zlib

logger = logging.getLogger("pyuepak.entry")

UINT32_MAX = 0xFFFFFFFF

oodle_comp = oodle()


def align(offset: int) -> int:
    return (offset + 15) & ~15


class Block:
    """Represents a block in the entry."""

    def __init__(self, start=None, end=None):
        self.start = start
        self.end = end

    def read(self, reader: Reader):
        """Read the block from the reader."""
        self.start = reader.uint64()
        self.end = reader.uint64()

        return self


class Entry:
    def __init__(self):
        self.offset = 0
        self.is_encrypted = False
        self.data = None
        self.blocks: list[Block] = []
        self.compressio_name = None
        self.compression_block_size = 0
        self.compression_block_count = 0
        self.size = 0
        self.compressed_size = 0

    def __repr__(self):
        return f"Entry(offset={self.offset}, size={self.size})"

    @staticmethod
    def get_serialized_size(
        version: PakVersion, compresion: COMPRESSION, compression_block_count: int
    ) -> int:
        out = 24
        if version == PakVersion.V8A:
            out += 1
        else:
            out += 4

        if version == PakVersion.V1:
            out += 8

        out += 20

        if compresion != COMPRESSION.NONE:
            out += 4 + 16 * compression_block_count

        out += 1

        if version >= PakVersion.V3:
            out += 4

        return out

    @hybrid_method
    def read(self, reader: Reader, version: PakVersion) -> "Entry":
        """Read the entry from the reader."""
        self.offset = reader.uint64()
        self.compressed_size = reader.uint64()
        self.size = reader.uint64()

        if version == PakVersion.V8A:
            self.compression = reader.uint()
        else:
            self.compression = reader.uint32()

        if version == PakVersion.V1:
            self.timestamp = reader.uint64()

        self.hash = reader.sha1()

        if version >= PakVersion.V3:
            if self.compression != 0:
                self.blocks = reader.list(Block().read)
            self.is_encrypted = bool(reader.uint())
            self.compression_block_size = reader.uint32()

        logger.debug(
            f"Read Entry: offset={self.offset}, size={self.size}, compressed_size={self.compressed_size},"
            f" is_encrypted={self.is_encrypted}, compression_name={self.compression}"
        )

        return self

    @hybrid_method
    def read_encoded(
        self, reader: Reader, version: PakVersion, compressions: list[COMPRESSION]
    ):
        """Read the entry from the encoded reader."""

        data = reader.uint32()

        compressio_name = (data >> 23) & 0x3F

        self.compression = compressions[compressio_name]

        self.is_encrypted = bool(data & (1 << 22))
        self.compression_block_count = (data >> 6) & 0xFFFF
        compression_block_size = data & 0x3F

        if compression_block_size == 0x3F:
            compression_block_size = reader.uint32()
        else:
            compression_block_size <<= 11

        self.compression_block_size = compression_block_size

        def read_varint(bit):
            if data & (1 << bit) != 0:
                return reader.uint32()
            else:
                return reader.uint64()

        self.offset = read_varint(31)
        self.size = read_varint(30)

        if self.compression == COMPRESSION.NONE:
            self.compressed_size = self.size
        else:
            self.compressed_size = read_varint(29)

        offset_base = Entry.get_serialized_size(
            version, self.compression, self.compression_block_count
        )

        if self.compression_block_count == 1 and not self.is_encrypted:
            self.blocks = [Block(offset_base, offset_base + self.compressed_size)]
        elif self.compression_block_count > 0:
            index = offset_base
            self.blocks = []
            for _ in range(self.compression_block_count):
                block_size = reader.uint32()
                block = Block(index, index + block_size)
                if self.is_encrypted:
                    block_size = align(block_size)

                index += block_size
                self.blocks.append(block)

        logger.debug(
            f"Read Encoded Entry:\n"
            f" offset={self.offset}\n"
            f" size={self.size}\n"
            f" compressed_size={self.compressed_size}\n"
            f" is_encrypted={self.is_encrypted}\n"
            f" compression={self.compression}\n"
            f" compression_block_count={self.compression_block_count}\n"
            f" compression_block_size={self.compression_block_size}\n"
            f" blocks={[(str(b.start) + '-' + str(b.end)) for b in self.blocks]}"
        )

        return self

    @hybrid_method
    def read_file(self, reader: Reader, version: PakVersion, key: bytes):
        """Read the entry from the file."""
        reader.set_pos(self.offset)

        # Read and discard the entry header from the file - we already have the metadata from the index
        _discard_entry = Entry.read(reader, version)
        data_offset = reader.get_pos()
        data = None
        if self.is_encrypted:
            data = reader.read(align(self.compressed_size))
        else:
            data = reader.read(self.compressed_size)

        if self.is_encrypted:
            cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
            decryptor = cipher.decryptor()

            decrypted_data = bytearray()
            for i in range(0, len(data), 16):
                block = data[i : i + 16]
                if len(block) == 16:  # Only decrypt full blocks
                    decrypted_block = decryptor.update(block)
                    decrypted_data.extend(decrypted_block)
                else:
                    decrypted_data.extend(block)

            # Truncate to original compressed size
            data = decrypted_data[: self.compressed_size]

        ranges = []
        if self.blocks:

            def offset(index: int) -> int:
                if version >= PakVersion.V5:
                    return index - (data_offset - self.offset)
                else:
                    return index - data_offset

            ranges = [range(offset(b.start), offset(b.end)) for b in self.blocks]
        else:
            ranges = [range(0, len(data))]

        decompressed_data = Writer()

        chunk_size = 0
        if len(ranges) == 1:
            chunk_size = self.size
        else:
            chunk_size = self.compression_block_size

        if self.compression == COMPRESSION.NONE:
            return bytes(data)

        elif self.compression == COMPRESSION.Zlib:
            for r in ranges:
                decompressed_data.write(zlib.decompress(data[r.start : r.stop]))
            return decompressed_data.file.getvalue()

        elif self.compression == COMPRESSION.Oodle:
            total_uncompressed = self.size

            offset = 0
            for r in ranges:
                expected = min(chunk_size, total_uncompressed - offset)
                comp_block = data[r.start : r.stop]
                decompressed_data.write(oodle_comp.decompress(comp_block, expected))
                offset += expected

            return decompressed_data.file.getvalue()

        else:
            raise NotImplementedError(f"{self.compression} not implemented.")

    def write_data(self, writer: Writer, version: PakVersion):
        self.offset = writer.get_pos()
        self.size = len(self.data)
        self.compressed_size = self.size

        writer.uint64(self.offset)  # offset
        writer.uint64(self.size)  # size
        writer.uint64(self.compressed_size)  # uncomp size

        # TODO: Compression

        if version == PakVersion.V8A:
            writer.uint(0)
        else:
            writer.uint32(0)

        if version == PakVersion.V1:
            writer.uint64(0)

        hash = hashlib.sha1()
        hash.update(self.data)
        self.hash = hash.digest()
        writer.sha1(self.hash)

        if version >= PakVersion.V3:
            if self.compressio_name is not None:
                pass  # TODO: COMPRESSION
            self.flags = writer.uint(0)  # TODO
            self.compressio_block_size = writer.uint32(0)  # 0 if not compressed

        writer.write(self.data)

    def write(self, writer: Writer, version: PakVersion):
        writer.uint64(self.offset)  # offset
        writer.uint64(self.size)  # size
        writer.uint64(self.compressed_size)  # uncomp size
        # TODO: COMP SUP

        # COMP NAME
        # TODO: COMP
        if version == PakVersion.V8A:
            writer.uint(0)
        else:
            writer.uint32(0)

        if version == PakVersion.V1:
            writer.uint64(0)

        writer.sha1(self.hash)

        if version >= PakVersion.V3:
            if self.compressio_name is not None:
                pass  # TODO: Compression
            self.flags = writer.uint(0)  # TODO
            self.compressio_block_size = writer.uint32(0)  # 0 if not compressed

    def write_encoded(self, writer: Writer, version: PakVersion):
        compression_block_size = (self.compression_block_size >> 11) & 0x3F
        if (compression_block_size << 11) != self.compression_block_size:
            self.compression_block_size = 0x3F

        is_size_32_bit_safe = self.compressed_size <= UINT32_MAX
        is_uncompressed_size_32_bit_safe = self.size <= UINT32_MAX
        is_offset_32_bit_safe = self.offset <= UINT32_MAX

        flags = (
            compression_block_size
            | (self.compression_block_count << 6)
            | (int(self.is_encrypted) << 22)
            | (
                (self.compressio_name + 1 if self.compressio_name is not None else 0)
                << 23
            )
            | (int(is_size_32_bit_safe) << 29)
            | (int(is_uncompressed_size_32_bit_safe) << 30)
            | (int(is_offset_32_bit_safe) << 31)
        )

        writer.uint32(flags)

        if self.compression_block_size == 0x3F:
            writer.uint32(self.compression_block_size)

        if is_offset_32_bit_safe:
            writer.uint32(self.offset)
        else:
            writer.uint64(self.offset)

        if is_uncompressed_size_32_bit_safe:
            writer.uint32(self.size)
        else:
            writer.uint64(self.size)
