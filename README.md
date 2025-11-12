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

## CLT

```bash
pyuepak [OPTIONS] COMMAND [ARGS]...
```

Global option:
`--aes <key>` — AES key for encrypted `.pak` files.

---

## Commands

| Command   | Description                     |
| --------- | ------------------------------- |
| `info`    | Show info about a `.pak` file   |
| `list`    | List all files in the archive   |
| `extract` | Extract one file                |
| `unpack`  | Unpack all files                |
| `pack`    | Pack a folder into `.pak`       |
| `read`    | Read a file and print to stdout |

---

## Examples

```bash
pyuepak info -p game.pak
pyuepak unpack -p game.pak -o out/
pyuepak extract -p game.pak -f "Game/Content/file.txt"
pyuepak pack -i folder -o new.pak
```

Encrypted file:

```bash
pyuepak --aes 1234567890ABCDEF info -p encrypted.pak
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
