# pyuepak

**pyuepak** is a Python library for working with Unreal Engine `.pak` files.

## Features

- Can read and write `.pak` versions 1–11
- Can read encrypted paks
- Can read Zlib compressed paks

## Installation

```bash
pip install pyuepak
```

Or install directly from the repository:

```bash
git clone https://github.com/stas96111/pyuepak.git
cd pyuepak
pip install -r requirements.txt
pip install .
```

## Usage

```python
from pyuepak import PakFile, PakVersion

pak = PakFile()
pak.read(r"path/to/pak.pak")

print(pak.list_files()) # ["/Game/asset.uasset", ...]
print(pak.mout_point) # "../../../" (default)
print(pak.key) # b'0000000...' AES key (default)
print(pak.path_hash_seed) # 0 (default)
print(pak.count) # prints file count

data = pak.read_file(r"/Game/asset.uasset") # return binary data
pak.remove_file(r"/Game/asset.uasset")

new_pak = PakFile()
new_pak.add_file("/Game/asset.uasset", data)
new_pak.set_version(PakVersion.V11)
new_pak.set_mount_point("../../..")

new_pak.write(r"path/to/pak.pak")

```

## Contributing

Contributions are welcome! Please open issues or submit pull requests.

## Credits
This project is based on information and ideas from two great open-source tools: 
 - [repak](https://github.com/trumank/repak)
 - [rust-u4pak](https://github.com/panzi/rust-u4pak).

## License

This project is licensed under the MIT License.
