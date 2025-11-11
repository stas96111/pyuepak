from .file_io import Reader, Writer
from .version import PakVersion

import logging

logger = logging.getLogger("pyuepak.footer")

PAK_MAGIC = 0x5A6F12E1


def check_pak_version(reader: Reader) -> PakVersion:
    """Check the version of the pak file."""

    size = reader.get_size()

    reader.set_pos(size - 44)  # Version from 1 to 7
    magic = reader.uint32()
    if magic == PAK_MAGIC:
        return PakVersion(reader.uint32())

    reader.set_pos(size - 172)  # Version 8A
    magic = reader.uint32()
    if magic == PAK_MAGIC:
        return PakVersion.V8A

    reader.set_pos(size - 204)  # Version 8B, 10, 11
    magic = reader.uint32()
    if magic == PAK_MAGIC:
        return PakVersion(reader.uint32() + 1)

    reader.set_pos(size - 205)  # Version 9
    magic = reader.uint32()
    if magic == PAK_MAGIC:
        return PakVersion.V9

    raise ValueError("Invalid pak file or unsupported version.")


class Footer:
    def __init__(self):
        self.encryption_key = None
        self.is_encrypted = False
        self.version = None
        self.index_offset = 0
        self.index_size = 0
        self.hash = None
        self.is_frozen = False
        self.compresion = None

    def read(self, reader: Reader):
        """Read the footer of the pak file."""

        self.version = check_pak_version(reader)
        if self.version < PakVersion.V4:
            reader.set_pos(44, end=True)
        elif self.version < PakVersion.V7:
            reader.set_pos(45, end=True)
        elif self.version == PakVersion.V7:
            reader.set_pos(65, end=True)
        elif self.version == PakVersion.V8A:
            reader.set_pos(193, end=True)
        elif self.version == PakVersion.V9:
            reader.set_pos(226, end=True)
        else:
            reader.set_pos(225, end=True)

        if self.version >= PakVersion.V7:
            self.encryption_key = reader.sha1()
        if self.version >= PakVersion.V4:
            self.is_encrypted = reader.uint() == 1

        magic = reader.uint32()

        if magic != PAK_MAGIC:
            logger.error("Invalid pak file magic: %X", magic)
            raise ValueError("Invalid pak file magic.")

        version = reader.uint32()

        self.index_offset = reader.uint64()
        self.index_size = reader.uint64()

        self.hash = reader.sha1()
        self.is_frozen = reader.uint()
        self.compresion = reader.string(5)

        logger.debug(
            "Footer:"
            f"\n  Version: {self.version.name}"
            f"\n  Index Offset: {self.index_offset}"
            f"\n  Index Size: {self.index_size}"
            f"\n  Is Encrypted: {self.is_encrypted}"
            f"\n  Compression: {self.compresion}"
        )

    def write(self, writer: Writer, version: PakVersion, offset, size, hash):
        if version >= PakVersion.V7:
            writer.uint128(0)
        if version >= PakVersion.V4:
            writer.uint(0)  # is encrypted TODO

        writer.uint32(PAK_MAGIC)

        if version >= 9:
            writer.uint32(version - 1)
        else:
            writer.uint32(version)

        writer.uint64(offset)
        writer.uint64(size)
        writer.write(hash)

        if version == PakVersion.V9:
            writer.uint(0)  # is frozen

        algo_size = 0
        if version == PakVersion.V8A:
            algo_size = 4
        elif version > PakVersion.V8A:
            algo_size = 5

        writer.write(b"\x00" * 32 * algo_size)
