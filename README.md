# Nothyr EterPack Unpacker

Unpacker for Nothyr Metin2 client encrypted pack files (`.idx` / `.dat`).

## Encryption Details

Determined via reverse engineering of `NothyrClient.exe`:

- **Cipher:** AES-128-CTR (Rijndael, CryptoPP library)
- **Compression:** Zstandard (zstd) — not LZO as in standard Metin2
- **MCOZ format:** Each `.idx` and each file within `.dat` is wrapped in an MCOZ envelope:
  `MCOZ(4) + data_size(4) + compressed_size(4) + raw_size(4) + AES-CTR-encrypted(data_size)`
- **After decryption:** Inner `MCOZ(4)` magic + zstd-compressed payload
- **Key material:** Located at VA `0x9F6620` in the binary — 4 key types, 32 bytes each (Key\[16\] + IV\[16\]), XOR-transformed with constants `[0x5A7F3C9D, 0xE2B9146A, 0x8D1F6B3C, 0xC7A4F925]`
- **Shared-buffer quirk:** `GetKey()` and `GetIV()` both write to the same global at `0xAC5D60`, so the AES key and IV end up identical (= the IV bytes after XOR)
- **Key types:** Index files (`.idx`) use key type 1; data files (`.dat`) use key type 2
- **EPKD v2 index:** 192-byte entries with 164-byte filename field; file offsets are absolute positions in the `.dat`

## Requirements

```
pip install pycryptodome zstandard
```

Optional (fallback for standard Metin2 packs):
```
pip install lzallright
```

## Usage

### Dump keys from running client

Start `NothyrClient.exe`, then:

```
python unpacker.py dump-keys
```

Saves runtime keys to `dumped_keys.json`. Only needed once (keys can also be extracted statically from the binary).

### List files in a pack

```
python unpacker.py list root
python unpacker.py list bgm
```

### Extract a pack

```
python unpacker.py extract root
python unpacker.py extract bgm
python unpacker.py extract --all
```

Extracted files are written to `extracted/<pack_name>_extracted/`.

### Inspect a file header

```
python unpacker.py dump-header root.idx
```

## Configuration

Paths are configured at the top of `unpacker.py`:

```python
PACKS_DIR = Path(r"C:\MT2\Nothyr\client\data\packs")
CLIENT_EXE = Path(r"C:\MT2\Nothyr\client\NothyrClient.exe")
OUTPUT_BASE = Path(r"C:\MT2\Nothyr\client\eterpack_unpacker\extracted")
DUMPED_KEYS_PATH = Path(r"C:\MT2\Nothyr\client\eterpack_unpacker\dumped_keys.json")
```

Adjust these to match your Nothyr client installation.

## How It Works

1. **Index decryption:** Read `.idx` → parse MCOZ header → AES-128-CTR decrypt (key type 1) → zstd decompress → parse EPKD v2 entries
2. **File extraction:** For each entry, seek to the absolute offset in `.dat` → read the per-file MCOZ block → AES-128-CTR decrypt (key type 2) → zstd decompress → write to disk
