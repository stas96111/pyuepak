from io import BytesIO
from uuid import UUID

def _is_ascii(s):
    return all(ord(c) < 128 for c in s)


class IOBase:
    def __init__(self, file: str | BytesIO):
        self.file = file
    
    def get_pos(self):
        return self.file.tell()
    
    def set_pos(self, position: int, end=False):
        self.file.seek(-position if end else position, 2 if end else 0)
        
    def get_size(self):
        current_pos = self.file.tell()
        self.file.seek(0, 2)
        size = self.file.tell()
        self.file.seek(current_pos)
        return size
    
    def close(self):
        self.file.close()

class Reader(IOBase):
    def __init__(self, file=None):
        self.path = file
        if isinstance(file, str):
            self.file = open(file, 'rb')
        elif isinstance(file, bytes):
            self.file = BytesIO(file)
        else:
            self.file = BytesIO()
            
    def reopen(self):
        self.__init__(self.path)
    
    def read(self, size: int):
        return self.file.read(size)
        
    def uint(self):
        return int.from_bytes(self.file.read(1), byteorder='little')
    
    def uint32(self):
        return int.from_bytes(self.file.read(4), byteorder='little')
    
    def uint64(self):
        return int.from_bytes(self.file.read(8), byteorder='little')
    
    def int(self):
        return int.from_bytes(self.file.read(1), byteorder='little', signed=True)
    
    def int32(self):
        return int.from_bytes(self.file.read(4), byteorder='little', signed=True)
    
    def int64(self):
        return int.from_bytes(self.file.read(8), byteorder='little', signed=True)
    
    def sha1(self):
        return self.file.read(20)  
    
    def string(self, length=None):
        if length is None:
            length = self.int32()
        string = ""
        
        if length > 0:
            string = self.file.read(length).decode('ascii', errors='replace')
        elif length < 0:
            string = self.file.read(length * -2).decode('utf-16le', errors='replace')
        elif length == 0:
            string = ""
            
        return string.rstrip('\0')
    
    def strings_list(self, length=None):
        return self.list(self.string, length=length)
    
    def list(self, func, length=None):
        if not length:
            length = self.uint32()
        out_list = [func() for i in range(length)]
        return out_list
        
    def buffer(self, offset: int = None, size: int = None):
        if offset is None:
            offset = self.get_pos()
        
        current_pos = self.get_pos()
        self.set_pos(offset)
        buffer = Reader(self.read(size) if size else self.read())
        self.set_pos(current_pos)
        return buffer
        
class Writer(IOBase):
    def __init__(self, path = None):
        if path:
            self.file = open(path, "wb")
        else:
            self.file = BytesIO()
        
    def write(self, data):
        self.file.write(data)
        
    def uint(self, value: int):
        self.file.write(value.to_bytes(1, 'little'))
        
    def uint32(self, value: int):
        self.file.write(value.to_bytes(4, 'little'))
        
    def uint64(self, value: int):
        self.file.write(value.to_bytes(8, 'little'))
        
    def uint128(self, value: int):
        self.file.write(value.to_bytes(16, 'little'))
        
    def int(self, value: int):
        self.file.write(value.to_bytes(1, 'little', signed=True))

    def int32(self, value: int):
        self.file.write(value.to_bytes(4, 'little', signed=True))
        
    def int64(self, value: int):
        self.file.write(value.to_bytes(8, 'little', signed=True))
        
    def int128(self, value: int):
        self.file.write(value.to_bytes(16, 'little', signed=True))
        
        
    def sha1(self, value: bytes):
        self.file.write(value)  # Write 20 bytes for SHA1

    def string(self, value: str, use_unicode=False):
        value += '\x00'
        if (not use_unicode) and _is_ascii(value):
            self.uint32(len(value))
            self.write(value.encode("ascii"))
        else:
            length = int(len(value.encode("utf-16le")) / 2 * -1)
            self.int32(length)
            self.write(value.encode("utf-16le"))
            
    def list(self, list_items, use_length=False):
        if use_length:
            self.uint32(len(list_items))
        for item in list_items:
            self.write(item)
            
    def strings_list(self, list_items, use_length=False):
        if use_length:
            print("Length: ", len(list_items))
            self.uint32(len(list_items))
        for item in list_items:
            self.string(item)