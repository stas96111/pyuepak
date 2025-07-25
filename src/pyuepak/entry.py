from .file_io import Reader, Writer
from .version import PakVersion
from .utils import hybrid_method

import hashlib
from math import ceil

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


UINT32_MAX = 0xFFFFFFFF


def align(offset: int) -> int:
    return (offset + 15) & ~15


class Block:
    """Represents a block in the entry."""
    
    def __init__(self, start, end):
        self.start = start
        self.end = end
        
    def read(self, reader: Reader):
        """Read the block from the reader."""
        self.start = reader.uint64()
        self.end = reader.uint64()
        
        return self


class Entry:
    def __init__(self):
        self.offset = 0
        self.is_encrypted = False
        self.data = None
        self.blocks: list[Block] = []
        self.compressio_name = None
        self.compression_block_size = 0
        self.compression_block_count = 0
        self.size = 0
        self.compressed_size = 0
        
    def __repr__(self):
        return f"Entry(offset={self.offset}, size={self.size})"


    @staticmethod
    def get_serialized_size(version: PakVersion, size: int, compression_block_count: int) -> int:
        out = 24
        if version == PakVersion.V8A:
            out += 1
        else:
            out += 4
        
        if version == PakVersion.V1:
            out += 8
        
        out += 20
        
        if size:
            out += 4 + 16 * compression_block_count
            
        size += 1
        
        if version >= PakVersion.V3:
            out += 4
        
        return out


    @hybrid_method
    def read(self, reader:Reader, version: PakVersion) -> 'Entry':
        """Read the entry from the reader."""
        self.offset = reader.uint64()
        self.compressed_size = reader.uint64()
        self.size = reader.uint64()
        
        if version == PakVersion.V8A:
            self.compressio_name = reader.uint()
        else:
            self.compressio_name = reader.uint32()
        self.compressio_name = None if self.compressio_name == 0 else self.compressio_name - 1
            
        if version == PakVersion.V1:
            self.timestamp = reader.uint64()
            
        self.hash = reader.sha1()
            
        if version >= PakVersion.V3:
            if self.compressio_name is not None:
                self.blocks = reader.list(Block().read)
            self.is_encrypted = reader.uint()
            self.compressio_block_size = reader.uint32()
            
        return self
            
    @hybrid_method
    def read_encoded(self, reader: Reader, version: PakVersion):
        """Read the entry from the encoded reader."""
        
        data = reader.uint32()
        self.compressio_name = (data >> 23) & 0x3F
        self.compressio_name = None if self.compressio_name == 0 else self.compressio_name - 1
        
        self.is_encrypted = bool(data & (1 << 22))
        compression_block_count = (data >> 6) & 0xffff
        compression_block_size = data & 0x3f
        
        if compression_block_size == 0x3F:
            compression_block_size = reader.uint32()
        else:
            compression_block_size <<= 11
            
            
        def read_varint(bit):
            if data & (1 << bit) != 0 :
                return reader.uint32()
            else:
                return reader.uint64()
            
        self.offset = read_varint(31)
        self.size = read_varint(30)

        if self.compressio_name is not None:
            self.compressed_size = read_varint(29)
        else:
            self.compressed_size = self.size
            
        offset_base = Entry.get_serialized_size(version, self.size, compression_block_count)
        
        if compression_block_count == 1 and not self.is_encrypted:
            self.blocks = [Block(offset_base, offset_base + self.size)]
        elif compression_block_count > 0:
            index = offset_base
            self.blocks = []
            for _ in range(compression_block_count):
                block_size = reader.uint32()
                block = Block(index, index + block_size)
                if self.is_encrypted:
                    block_size = align(block_size)
            
                index += block_size
                self.blocks.append(block)
            
        return self
    
    @hybrid_method
    def read_file(self, reader: Reader, version: PakVersion, key: bytes):
        """Read the entry from the file."""
        reader.set_pos(self.offset)

        test = Entry.read(reader, version)
        
        data = None
        if self.is_encrypted:
            data = reader.read(align(self.compressed_size))
        else:
            data = reader.read(self.size)
            
        if self.is_encrypted:
            cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
            decryptor = cipher.decryptor()
            
            decrypted_data = bytearray()
            for i in range(0, len(data), 16):
                block = data[i:i+16]
                if len(block) == 16:  # Only decrypt full blocks
                    decrypted_block = decryptor.update(block)
                    decrypted_data.extend(decrypted_block)
                else:
                    decrypted_data.extend(block)
            
            # Truncate to original compressed size
            data = decrypted_data[:self.compressed_size]
    
        return bytes(data)
    
    def write_data(self, writer: Writer, version: PakVersion):
        self.offset = writer.get_pos()
        self.size = len(self.data)
        self.compressed_size = self.size
        
        writer.uint64(self.offset) # offset
        writer.uint64(self.size) # size
        writer.uint64(self.compressed_size) # uncomp size 
        
        # TODO: Compression
        
        if version == PakVersion.V8A:
            writer.uint(0)
        else:
            writer.uint32(0)
            
        if version == PakVersion.V1:
            writer.uint64(0)
                
        hash = hashlib.sha1()
        hash.update(self.data)
        self.hash = hash.digest()
        writer.sha1(self.hash)
        
        if version >= PakVersion.V3:
            if self.compressio_name is not None:
                pass # TODO: COMPRESSION
            self.flags = writer.uint(0) # TODO
            self.compressio_block_size = writer.uint32(0) # 0 if not compressed
        
        writer.write(self.data)

    
    def write(self, writer: Writer, version: PakVersion):
        writer.uint64(self.offset) # offset
        writer.uint64(self.size) # size
        writer.uint64(self.compressed_size) # uncomp size
        # TODO: COMP SUP
        
        # COMP NAME 
        # TODO: COMP
        if version == PakVersion.V8A:
            writer.uint(0)
        else:
            writer.uint32(0)
            
        if version == PakVersion.V1:
            writer.uint64(0)
                
        writer.sha1(self.hash)
        
        if version >= PakVersion.V3:
            if self.compressio_name is not None:
                pass # TODO: Compression
            self.flags = writer.uint(0) # TODO
            self.compressio_block_size = writer.uint32(0) # 0 if not compressed
    
    
    def write_encoded(self, writer: Writer, version: PakVersion):
        compression_block_size = (self.compression_block_size >> 11) & 0x3F
        if (compression_block_size << 11) != self.compression_block_size:
            self.compression_block_size = 0x3F
        
        is_size_32_bit_safe = self.compressed_size <= UINT32_MAX
        is_uncompressed_size_32_bit_safe = self.size <= UINT32_MAX
        is_offset_32_bit_safe = self.offset <= UINT32_MAX
        
        flags = (
            compression_block_size
            | (self.compression_block_count << 6)
            | (int(self.is_encrypted) << 22)
            | ((self.compressio_name + 1 if self.compressio_name is not None else 0) << 23)
            | (int(is_size_32_bit_safe) << 29)
            | (int(is_uncompressed_size_32_bit_safe) << 30)
            | (int(is_offset_32_bit_safe) << 31)
        )
        
        writer.uint32(flags)
        
        if self.compression_block_size == 0x3F:
            writer.uint32(self.compression_block_size)
            
        if is_offset_32_bit_safe:
            writer.uint32(self.offset)
        else:
            writer.uint64(self.offset)
            
        if is_uncompressed_size_32_bit_safe:
            writer.uint32(self.size)
        else:
            writer.uint64(self.size)