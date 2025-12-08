import ctypes
import hashlib
import os
import sys
import urllib.request
from pathlib import Path
from dataclasses import dataclass

OODLE_VERSION = "2.9.10"
OODLE_BASE_URL = (
    "https://github.com/WorkingRobot/OodleUE/raw/refs/heads/main/"
    "Engine/Source/Programs/Shared/EpicGames.Oodle/Sdk/"
)


class OodleError(Exception):
    pass


class HashMismatch(OodleError):
    pass


class CompressionFailed(OodleError):
    pass


class InitializationFailed(OodleError):
    pass


@dataclass(frozen=True)
class OodlePlatform:
    path: str
    name: str
    sha256: str


if sys.platform == "linux" and sys.maxsize > 2**32:
    OODLE_PLATFORM = OodlePlatform(
        "linux/lib",
        "liboo2corelinux64.so.9",
        "ed7e98f70be1254a80644efd3ae442ff61f854a2fe9debb0b978b95289884e9c",
    )
elif os.name == "nt":
    OODLE_PLATFORM = OodlePlatform(
        "win/redist",
        "oo2core_9_win64.dll",
        "6f5d41a7892ea6b2db420f2458dad2f84a63901c9a93ce9497337b16c195f457",
    )
else:
    raise InitializationFailed("Unsupported platform")


def oodle_url():
    return (
        f"{OODLE_BASE_URL}/{OODLE_VERSION}/{OODLE_PLATFORM.path}/{OODLE_PLATFORM.name}"
    )


def check_hash(data: bytes):
    sha = hashlib.sha256(data).hexdigest()
    if sha != OODLE_PLATFORM.sha256:
        raise HashMismatch(f"expected {OODLE_PLATFORM.sha256}, got {sha}")


def fetch_oodle():
    script_dir = Path(__file__).resolve().parent
    dest = script_dir / OODLE_PLATFORM.name

    if not dest.exists():
        print(f"Downloading {OODLE_PLATFORM.name}...", flush=True)
        data = urllib.request.urlopen(oodle_url()).read()
        check_hash(data)
        dest.write_bytes(data)

    return dest


class Oodle:
    def __init__(self):
        path = fetch_oodle()

        try:
            self.lib = ctypes.CDLL(str(path))
        except OSError as e:
            raise InitializationFailed(e)

        self.compress_fn = self.lib.OodleLZ_Compress
        self.compress_fn.restype = ctypes.c_longlong

        self.decompress_fn = self.lib.OodleLZ_Decompress
        self.decompress_fn.restype = ctypes.c_longlong

        self.get_size_fn = self.lib.OodleLZ_GetCompressedBufferSizeNeeded
        self.get_size_fn.restype = ctypes.c_size_t

        # Disable Oodle's stdout logging
        self.set_printf = self.lib.OodleCore_Plugins_SetPrintf
        self.set_printf(ctypes.c_void_p(0))

    def compress(self, data: bytes, compressor: int, level: int) -> bytes:
        raw = ctypes.c_char_p(data)
        raw_len = len(data)

        out_size = self.get_size_fn(compressor, raw_len)
        out_buffer = (ctypes.c_ubyte * out_size)()

        written = self.compress_fn(
            compressor,
            raw,
            raw_len,
            out_buffer,
            level,
            None,
            None,
            None,
            None,
            0,
        )

        if written == -1:
            raise CompressionFailed()

        return bytes(out_buffer[:written])

    def decompress(self, data: bytes, output_size: int) -> bytes:
        out_buffer = (ctypes.c_ubyte * output_size)()
        written = self.decompress_fn(
            data,
            len(data),
            out_buffer,
            output_size,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            None,
            0,
            3,
        )
        if written == 0:
            raise CompressionFailed("Oodle decompression failed")

        return bytes(out_buffer[:written])


_oodle_singleton = None


def oodle():
    global _oodle_singleton
    if _oodle_singleton is None:
        _oodle_singleton = Oodle()
    return _oodle_singleton
