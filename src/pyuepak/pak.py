from .version import PakVersion
from .file_io import Reader, Writer
from .footer import Footer
from .index import Index
from .entry import Entry

import shutil, os
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
    def count(self):
        """Get the number of entries in the pak file."""
        return len(self._index.entrys)
    
    
    def set_key(self, key: bytes | str):
        """Set the encryption key for the pak file."""
        byte_key = bytes.fromhex(key) if isinstance(key, str) else key

        if len(byte_key) != 32:
            raise ValueError("Key must be 32 bytes long.")
        
        self.key = byte_key
        
    def set_mount_point(self, mount_point: str):
        """Set the mount point for the pak file."""
        self.mount_point = mount_point
        
    def set_path_hash_seed(self, seed: int):
        """Set the path hash seed for the pak file."""
        if not isinstance(seed, int):
            raise ValueError("Seed must be an integer.")
        
        self.path_hash_seed = seed
        
    def set_version(self, version: PakVersion):
        """Set the version of the pak file."""
        if not isinstance(version, PakVersion):
            raise ValueError("Version must be an instance of PakVersion.")
        
        self.version = version


    def read(self, file: str | bytes):
        """Read the pak file."""
        
        self.reader = Reader(file)
        
        self._footer = Footer()
        self._footer.read(self.reader)
        
        self.version = self._footer.version
        
        self._index = Index()
        self._index.read(self.reader, 
            self._footer.version,
            self._footer.index_offset,
            self._footer.index_size)
        
        
    def write(self, file: str):
        """Write the pak file."""
        
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
        self._footer.write(writer, self.version, self._index.offset, self._index.size, self._index.hash)
        writer.close()
        
        shutil.move(f"{file}.tmp", file)


    def add_file(self, path: str, data: bytes):
        """Add a file to the pak file."""
        entry = Entry()
        self._index.entrys[path] = entry
        entry.data = data
        
        
    def remove_file(self, path: str):
        """Remove a file from the pak file."""

        if path in self._index.entrys:
            del self._index.entrys[path]
        else:
            raise KeyError(f"Path '{path}' not found in pak file.")
                
        
    def read_file(self, path: str) -> bytes:
        """Read a file from the pak file."""
        
        entry = self._index.entrys.get(path)
        return entry.read_file(self.reader, self._footer.version, self.key) 
    
    
    def list_files(self) -> list[str]:
        """List all files in the pak file."""
        return list(self._index.entrys.keys())
    
    
    def unpack(self, output_dir: str):
        """Unpack the pak file to the specified directory."""

        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        entries_list = self.list_files()

        for path in entries_list:
            entry = self._index.entrys.get(path)
            file_path = os.path.join(output_dir, path)
            os.makedirs(os.path.dirname(file_path), exist_ok=True)

            data = entry.read_file(self.reader, self._footer.version, self.key)
            with open(file_path, 'wb') as f:
                f.write(data)
