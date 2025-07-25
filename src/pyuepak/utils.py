


def hybrid_method(func):
    def wrapper(instance_or_cls, *args, **kwargs):
        if isinstance(instance_or_cls, type):
            # Called on class: create a temporary instance
            temp_instance = instance_or_cls()
            return func(temp_instance, *args, **kwargs)
        else:
            # Called on instance
            return func(instance_or_cls, *args, **kwargs)

    return classmethod(wrapper)

        
        
def fnv64(data_bytes: bytes, offset: int) -> int:
    OFFSET = 0xcbf29ce484222325
    PRIME = 0x00000100000001b3
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
        return (path[:idx + 1], path[idx + 1:])
    else:
        return ("/", path)