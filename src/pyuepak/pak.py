from .version import LocresVersion
from .file_io import Reader
from .footer import Footer


class PakFile:
    def __init__(self):
        self.version = LocresVersion.V11
        
    
    def read(self, file: str | bytes):
        """Read the pak file."""
        
        self.reader = Reader(file)
        
        self._footer = Footer()
        self._footer.read(self.reader)
        
        print(f"Pak version: {self._footer.version.name}")
        print(f"Pak is encrypted: {self._footer.is_encrypted}")
        print(f"Pak index offset: {self._footer.index_offset}")
        print(f"Pak index size: {self._footer.index_size}")
        print(f"Pak compression: {self._footer.compresion}")
        print(f"Pak encryption key: {self._footer.encryption_key}")
        print(f"Pak hash: {self._footer.hash}")
        print(f"Pak is frozen: {self._footer.is_frozen}")
        
        
        