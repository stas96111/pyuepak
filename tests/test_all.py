from pyuepak import PakFile, PakVersion

from pathlib import Path
import pytest
import tempfile
import os

paks = {
    "./tests/pack_v5": PakVersion.V5,
    "./tests/pack_v7": PakVersion.V7,
    "./tests/pack_v8a": PakVersion.V8A,
    "./tests/pack_v8b": PakVersion.V8B,
    "./tests/pack_v9": PakVersion.V9,
    "./tests/pack_v11": PakVersion.V11,
}

PAK_VARIANTS = [
    ".pak",
    "_compress.pak",
    "_encrypt.pak",
    "_encryptindex.pak",
    "_encrypt_encryptindex.pak",
    "_compress_encrypt.pak",
    "_compress_encryptindex.pak",
    "_compress_encrypt_encryptindex.pak",
]

TEST_FILES = {
    "./tests/test_files/test.png": {"pak_path": "test.png", "data": None},
    "./tests/test_files/test.txt": {"pak_path": "test.txt", "data": None},
    "./tests/test_files/zeros.bin": {"pak_path": "zeros.bin", "data": None},
    "./tests/test_files/directory/nested.txt": {
        "pak_path": "directory/nested.txt",
        "data": None,
    },
}

PAKS_BY_PATH = {}

AES_KEY = "lNJbw660IOC+kU7cnVQ1oeqrXyhk4J6UAZrCBbcnp94="


@pytest.fixture(scope="session", autouse=True)
def init():
    global PAKS_BY_PATH

    # preload test file bytes
    for file_path, pak_data in TEST_FILES.items():
        with open(file_path, "rb") as f:
            pak_data["data"] = f.read()

    # build pak path → version map
    for base_path, version in paks.items():
        for variant in PAK_VARIANTS:
            pak_path = f"{base_path}{variant}"
            PAKS_BY_PATH[pak_path] = version


def test_read():
    for path, version in PAKS_BY_PATH.items():
        pak = PakFile()
        pak.set_key(AES_KEY)
        pak.read(path)

        assert pak.version == version

        for file_info in TEST_FILES.values():
            data = pak.read_file(file_info["pak_path"])
            assert data == file_info["data"]


def test_write_and_read():
    for version in PakVersion:

        pak = PakFile()
        pak.set_version(version)
        pak.set_key(AES_KEY)

        for file_info in TEST_FILES.values():
            pak.add_file(
                file_info["pak_path"],
                file_info["data"],
            )

        pak.write("temp.pak")

        pak2 = PakFile()
        pak2.set_key(AES_KEY)
        pak2.read("temp.pak")

        assert pak2.version == version

        for file_info in TEST_FILES.values():
            data = pak2.read_file(file_info["pak_path"])
            assert data == file_info["data"]

        os.remove("temp.pak")
