from .file_io import Reader
from .version import LocresVersion


PAK_MAGIC = 0x5A6F12E1


def check_pak_version(reader: Reader) -> LocresVersion:
    """Check the version of the pak file."""
    
    size = reader.get_size()
    
    reader.set_pos(size - 44) # Version from 1 to 7
    magic = reader.uint32()
    if magic == PAK_MAGIC:
        return LocresVersion(reader.uint32())
    
    reader.set_pos(size - 172) # Version 8A
    magic = reader.uint32()
    if magic == PAK_MAGIC:
        return LocresVersion.V8A
    
    reader.set_pos(size - 204) # Version 8B, 10, 11
    magic = reader.uint32()
    if magic == PAK_MAGIC:
        return LocresVersion(reader.uint32() + 1)   
    
    reader.set_pos(size - 205) # Version 9
    magic = reader.uint32()
    if magic == PAK_MAGIC:
        return LocresVersion.V9
    
    raise ValueError("Invalid pak file or unsupported version.")


class Footer():
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
        if self.version < LocresVersion.V4:
            reader.set_pos(44, end=True)
        elif self.version < LocresVersion.V7:
            reader.set_pos(45, end=True)
        elif self.version == LocresVersion.V7:
            reader.set_pos(65, end=True)
        elif self.version == LocresVersion.V8A:
            reader.set_pos(193, end=True)
        elif self.version == LocresVersion.V9:
            reader.set_pos(226, end=True)
        else:
            reader.set_pos(225, end=True)
        
        if self.version >= LocresVersion.V7:
            self.encryption_key = reader.uuid4() 
        if self.version >= LocresVersion.V4:
            self.is_encrypted = reader.uint() == 1
        
        magic = reader.uint32()
        version = reader.uint32()
        
        self.index_offset = reader.uint64()
        self.index_size = reader.uint64()
        self.hash = reader.uuid4()
        self.is_frozen = reader.uint() == 1 if self.version >= LocresVersion.V9 else False
            
        # TODO: COMPRESSION