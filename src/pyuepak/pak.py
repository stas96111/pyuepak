import logging
import os
import shutil
import base64

from pathlib import Path
from .entry import Entry
from .file_io import Reader, Writer
from .footer import Footer
from .index import Index
from .version import PakVersion

logger = logging.getLogger("pyuepak")

handler = logging.StreamHandler()
fh = logging.FileHandler("spam.log")

formatter = logging.Formatter("[%(name)s]:[%(levelname)s]: %(message)s")

handler.setFormatter(formatter)
fh.setFormatter(formatter)

logger.addHandler(handler)
logger.addHandler(fh)

logger.propagate = False


class PakFile:
    def __init__(self):
        """Initialize a new PakFile instance."""
        self.version = PakVersion.V11
        self.key = bytes(32)
        self.mount_point = "../../../"
        self.path_hash_seed = 0

        self.reader = Reader()

        self._index = Index()
        self._footer = Footer()

    @property
    def count(self) -> int:
        """Get the number of entries in the pak file."""
        return len(self._index.entrys)

    def set_key(self, key: bytes | str) -> None:
        if isinstance(key, str):
            key_str = key.strip()
            try:
                # Try hex first
                byte_key = bytes.fromhex(key_str)
            except ValueError:
                try:
                    # Try base64
                    byte_key = base64.b64decode(key_str)
                except Exception:
                    raise ValueError(
                        "Invalid key format: must be hex, base64, or bytes"
                    )
        elif isinstance(key, bytes):
            byte_key = key
        else:
            raise TypeError("Key must be str or bytes")

        if len(byte_key) != 32:
            raise ValueError(f"Invalid key length: {len(byte_key)} bytes (expected 32)")

        self.key = byte_key

    def set_mount_point(self, mount_point: str) -> None:
        """Set the mount point for the pak file."""
        self.mount_point = mount_point

    def set_path_hash_seed(self, seed: int):
        """Set the path hash seed for the pak file."""
        if not isinstance(seed, int):
            raise ValueError("Seed must be an integer.")

        self.path_hash_seed = seed

    def set_version(self, version: PakVersion) -> None:
        """Set the version of the pak file."""
        if not isinstance(version, PakVersion):
            raise ValueError("Version must be an instance of PakVersion.")

        self.version = version

    def read(self, file: str | Path | bytes) -> None:
        """Read the pak file."""

        if isinstance(file, Path):
            file = str(file)

        self.reader = Reader(file)

        self._footer = Footer()
        self._footer.read(self.reader)

        self.version = self._footer.version

        self._index = Index()
        self._index.read(
            self.reader,
            self._footer.version,
            self._footer.index_offset,
            self._footer.index_size,
            self._footer.compresion,
        )

    def write(self, file: str | Path) -> None:
        """Write the pak file."""

        if isinstance(file, Path):
            file = str(file)

        self.reader.reopen()
        writer = Writer(f"{file}.tmp")

        for _, entry in self._index.entrys.items():
            if entry.data:
                entry.write_data(writer, self.version)
            else:
                entry.data = entry.read_file(self.reader, self.version, self.key)
                entry.write_data(writer, self.version)

            entry.data = None

        self.reader.close()

        self._index.write(writer, self.version)
        self._footer.write(
            writer, self.version, self._index.offset, self._index.size, self._index.hash
        )
        writer.close()

        shutil.move(f"{file}.tmp", file)

    def add_file(self, path: str | Path, data: bytes) -> None:
        """Add a file to the pak file."""

        if isinstance(path, Path):
            path = str(path.as_posix())

        entry = Entry()
        self._index.entrys[path] = entry
        entry.data = data

    def remove_file(self, path: str | Path) -> None:
        """Remove a file from the pak file."""

        if isinstance(path, Path):
            path = str(path.as_posix())

        if path in self._index.entrys:
            del self._index.entrys[path]
        else:
            raise KeyError(f"Path '{path}' not found in pak file.")

    def read_file(self, path: str | Path) -> bytes:
        """Read a file from the pak file."""

        if isinstance(path, Path):
            path = str(path.as_posix())

        entry = self._index.entrys.get(path)
        if not entry:
            logger.debug(f"Entry for path '{path}' not found.")
            raise KeyError(f"Path '{path}' not found in pak file.")
        return entry.read_file(self.reader, self._footer.version, self.key)

    def list_files(self) -> list[str]:
        """List all files in the pak file."""
        return list(self._index.entrys.keys())
