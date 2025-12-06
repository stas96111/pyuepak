from enum import Enum, auto


class COMPRESSION(Enum):
    NONE = auto()
    Zlib = auto()
    Glib = auto()
    Oodle = auto()


class hybrid_method:
    def __init__(self, func):
        self.func = func

    def __get__(self, obj, cls=None):
        def wrapper(*args, **kwargs):
            instance = obj if obj is not None else cls()
            return self.func(instance, *args, **kwargs)

        return wrapper


def fnv64(data_bytes: bytes, offset: int) -> int:
    OFFSET = 0xCBF29CE484222325
    PRIME = 0x00000100000001B3
    hash_ = (OFFSET + offset) & 0xFFFFFFFFFFFFFFFF

    for b in data_bytes:
        hash_ ^= b
        hash_ = (hash_ * PRIME) & 0xFFFFFFFFFFFFFFFF  # simulate u64 wrapping

    return hash_


def fnv64_path(path: str, offset: int) -> int:
    lower = path.lower()
    utf16le = lower.encode("utf-16le")  # match encode_utf16 + to_le_bytes
    return fnv64(utf16le, offset)


def split_path_child(path: str) -> tuple[str, str] | None:
    if path == "/" or not path:
        return None

    # Remove trailing slash if present
    path = path.rstrip("/")

    idx = path.rfind("/")
    if idx != -1:
        return (path[: idx + 1], path[idx + 1 :])
    else:
        return ("/", path)
