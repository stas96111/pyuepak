import logging
import os, io
import shutil
import base64

from pathlib import Path
from .entry import Entry
from .file_io import Reader, Writer
from .footer import Footer
from .index import Index
from .version import PakVersion

from concurrent.futures import ThreadPoolExecutor
import threading
import tempfile

logger = logging.getLogger("pyuepak")

handler = logging.StreamHandler()
fh = logging.FileHandler("spam.log")

formatter = logging.Formatter("[%(name)s]:[%(levelname)s]: %(message)s")

handler.setFormatter(formatter)
fh.setFormatter(formatter)

logger.addHandler(handler)
logger.addHandler(fh)

logger.propagate = False


_thread_local = threading.local()


def get_reader(pak_path):
    if not hasattr(_thread_local, "reader"):
        _thread_local.reader = Reader(pak_path)
    return _thread_local.reader


def _unpack_one(args):
    (
        pak_file,
        path,
        version,
        key,
        offset,
        size,
        compressed_size,
        compression,
        is_encrypted,
    ) = args

    entry = Entry()
    entry.offset = offset
    entry.size = size
    entry.compressed_size = compressed_size
    entry.compression = compression
    entry.is_encrypted = is_encrypted

    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)

    reader = get_reader(str(pak_file))
    with open(path, "wb", buffering=256 * 1024) as f:
        entry.extract_file(reader, version, key, f)


def _unpack_batch(args_list):
    """Process multiple small files in a single thread to reduce overhead."""
    for args in args_list:
        _unpack_one(args)


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
        if isinstance(key, int):
            try:
                byte_key = key.to_bytes(32, byteorder="big")
            except OverflowError:
                raise ValueError("Integer key is too large to fit in 32 bytes.")

        elif isinstance(key, bytes):
            byte_key = key

        elif isinstance(key, str):
            key_str = key.strip()
            try:
                # Try hex first
                if key_str.startswith("0x"):
                    key_str = key_str[2:]
                byte_key = bytes.fromhex(key_str)
                if len(byte_key) != 32:
                    raise ValueError
            except ValueError:
                try:
                    # Try base64
                    byte_key = base64.b64decode(key_str)
                    if len(byte_key) != 32:
                        raise ValueError
                except Exception:
                    raise ValueError(
                        "Invalid key format: must be hex, base64, or bytes"
                    )
        else:
            raise TypeError("Key must be str, bytes or int.")

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
        self._index.read(self.reader, self._footer, self.key)

    def write(self, file: str | Path) -> None:
        """Write the pak file."""

        if isinstance(file, Path):
            file = str(file)

        self.reader.reopen()

        with tempfile.NamedTemporaryFile(
            delete=False,
            dir=os.path.dirname(file),
            prefix=file + ".",
            suffix=".tmp",
        ) as tmp:
            tmp_path = tmp.name
        writer = Writer(tmp_path)

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

        os.replace(tmp_path, file)

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
        buf = io.BytesIO()
        entry.extract_file(self.reader, self.version, self.key, buf)
        return buf.getvalue()

    @classmethod
    def unpack(
        cls,
        input_pak: str | Path,
        output_dir: str | Path = "./out",
        key: str | bytes = None,
        progress=False,
    ):
        """
        Unpack a pak file to a directory.

        Args:
            input_pak: Path to the pak file
            output_dir: Output directory path
            key: Encryption key if needed
            progress: Print progress information (default: False)
        """
        pak = cls()
        if key is not None:
            pak.set_key(key)
        pak.read(input_pak)

        if isinstance(output_dir, str):
            output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        # Build jobs list with sizes for batching strategy
        SMALL_FILE_THRESHOLD = 256 * 1024  # 256KB threshold

        jobs_data = [
            (
                pak.reader.path,
                output_dir / path.lstrip("/\\"),
                pak.version,
                pak.key,
                entry.offset,
                entry.size,
                entry.compressed_size,
                entry.compression,
                entry.is_encrypted,
                entry.size,  # For sorting
            )
            for path, entry in pak._index.entrys.items()
        ]

        # Separate large and small files
        large_jobs = []
        small_jobs = []

        for job_data in jobs_data:
            job = job_data[:-1]  # Remove sort key
            size = job_data[9]
            if size >= SMALL_FILE_THRESHOLD:
                large_jobs.append(job)
            else:
                small_jobs.append(job)

        # Sort large files by size (largest first) for better load balancing
        large_jobs.sort(key=lambda x: x[5], reverse=True)

        # Create batches of small files for each thread
        num_workers = min(os.cpu_count() * 2, max(1, len(large_jobs) + 1))

        if small_jobs and num_workers > 1:
            # Batch small files - one batch per thread
            batch_size = max(1, len(small_jobs) // num_workers)
            small_batches = [
                small_jobs[i : i + batch_size]
                for i in range(0, len(small_jobs), batch_size)
            ]
            # Convert single-item batches back to regular jobs for efficiency
            batched_jobs = []
            regular_jobs = []
            for batch in small_batches:
                if len(batch) > 1:
                    batched_jobs.append(batch)
                else:
                    regular_jobs.extend(batch)

            # Combine: large jobs + batches + regular small jobs
            all_tasks = large_jobs + regular_jobs
        else:
            all_tasks = large_jobs + small_jobs
            batched_jobs = []

        # Use ThreadPoolExecutor with optimal worker count
        with ThreadPoolExecutor(max_workers=num_workers) as pool:
            if progress:
                from tqdm import tqdm

                total_items = len(all_tasks) + len(batched_jobs)

                # Process large jobs and small jobs
                futures = []
                for task in all_tasks:
                    futures.append(pool.submit(_unpack_one, task))

                # Process batches
                for batch in batched_jobs:
                    futures.append(pool.submit(_unpack_batch, batch))

                for _ in tqdm(futures, total=total_items):
                    _
            else:
                # Process large jobs and small jobs
                for task in all_tasks:
                    pool.submit(_unpack_one, task).result()

                # Process batches
                for batch in batched_jobs:
                    pool.submit(_unpack_batch, batch).result()
        # Cleanup thread-local reader
        if hasattr(_thread_local, "reader"):
            _thread_local.reader.close()
            delattr(_thread_local, "reader")

    def list_files(self) -> list[str]:
        """List all files in the pak file."""
        return list(self._index.entrys.keys())
