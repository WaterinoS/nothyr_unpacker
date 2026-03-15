#!/usr/bin/env python3
"""
EterPack MCOZ Unpacker for Metin2 (Nothyr Client)

Handles:
- MCOZ format: AES-128-CTR encrypted + Zstandard compressed pack index/data
- EPKD format: Standard EterPack with per-file XTEA/LZO compression
- Key extraction from NothyrClient.exe binary or running process

Encryption details (from reverse engineering NothyrClient.exe):
- Cipher: AES-128-CTR (Rijndael, CryptoPP)
- Key layout at VA 0x9F6620: 4 types x 32 bytes (Key[16] + IV[16])
- GetKey/GetIV both write to shared buffer 0xAC5D60 with XOR transform
- Due to shared buffer, AES key = AES IV = second_16_bytes XOR'd
- Compression: Zstandard (zstd), NOT LZO as in standard Metin2

Usage:
    python unpacker.py dump-keys                # Dump runtime keys from running NothyrClient.exe
    python unpacker.py extract <pack_name>      # Extract specific pack (uses dumped_keys.json)
    python unpacker.py extract --all            # Extract all packs
    python unpacker.py list <pack_name>         # List files in pack
    python unpacker.py dump-header <file>       # Dump header info
"""

import struct
import sys
import os
import json
from pathlib import Path

# Try to import crypto libraries
try:
    from Crypto.Cipher import AES
    from Crypto.Util import Counter
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

try:
    import zstandard
    HAS_ZSTD = True
except ImportError:
    HAS_ZSTD = False

try:
    import lzallright
    HAS_LZO = True
except ImportError:
    HAS_LZO = False

# ===== Configuration =====
PACKS_DIR = Path(r"C:\MT2\Nothyr\client\data\packs")
CLIENT_EXE = Path(r"C:\MT2\Nothyr\client\NothyrClient.exe")
OUTPUT_BASE = Path(r"C:\MT2\Nothyr\client\eterpack_unpacker\extracted")
DUMPED_KEYS_PATH = Path(r"C:\MT2\Nothyr\client\eterpack_unpacker\dumped_keys.json")

# MCOZ format constants
MCOZ_MAGIC = b'MCOZ'
EPKD_MAGIC = b'EPKD'
ZSTD_MAGIC = b'\x28\xb5\x2f\xfd'
MCOZ_HEADER_SIZE = 16  # magic(4) + data_size(4) + compressed_size(4) + raw_size(4)

# EterPack encryption types (per-file within .dat)
ENCRYPT_NONE = 0
ENCRYPT_XTEA = 1
ENCRYPT_LZO = 2
ENCRYPT_XTEA_LZO = 3

# XTEA constants
XTEA_DELTA = 0x9E3779B9
XTEA_ROUNDS = 32
MASK32 = 0xFFFFFFFF

# XOR constants used in key derivation (from NothyrClient.exe GetKey/GetIV at 0x437FAF)
KEY_XOR_CONSTANTS = [0x5A7F3C9D, 0xE2B9146A, 0x8D1F6B3C, 0xC7A4F925]

# Raw key material file offset in NothyrClient.exe
# Layout: 4 types x 32 bytes = Key[16 bytes] + IV[16 bytes] per type
RAW_KEY_MATERIAL_OFFSET = 0x5F4220

# ===== dump-keys constants (runtime memory addresses) =====
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
KEY_DATA_VA = 0x9F6620       # 4 key types, 32 bytes each (Key[16] + IV[16])
KEY_DATA_SIZE = 4 * 32       # 4 types * 32 bytes
LZ_MANAGER_VA = 0xAC5E50
DEFAULT_BASE = 0x400000


def read_u8(data, offset):
    return struct.unpack_from('<B', data, offset)[0]

def read_u16(data, offset):
    return struct.unpack_from('<H', data, offset)[0]

def read_u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


# ===== XTEA Implementation =====
def xtea_decrypt_block(v0, v1, key):
    """Decrypt a single 8-byte XTEA block (32 rounds)."""
    delta = XTEA_DELTA
    sum_val = (delta * XTEA_ROUNDS) & MASK32
    for _ in range(XTEA_ROUNDS):
        v1 = (v1 - (((v0 << 4 ^ v0 >> 5) + v0) ^ (sum_val + key[(sum_val >> 11) & 3]))) & MASK32
        sum_val = (sum_val - delta) & MASK32
        v0 = (v0 - (((v1 << 4 ^ v1 >> 5) + v1) ^ (sum_val + key[sum_val & 3]))) & MASK32
    return v0, v1

def xtea_decrypt(data, key):
    """Decrypt data with XTEA in ECB mode."""
    result = bytearray()
    for i in range(0, len(data) - 7, 8):
        v0, v1 = struct.unpack_from('<II', data, i)
        d0, d1 = xtea_decrypt_block(v0, v1, key)
        result.extend(struct.pack('<II', d0, d1))
    remainder = len(data) % 8
    if remainder:
        result.extend(data[len(data) - remainder:])
    return bytes(result)


# ===== Decompression =====
def zstd_decompress(data, max_output_size=0):
    """Decompress Zstandard data."""
    if not HAS_ZSTD:
        raise RuntimeError("zstandard not available. Install: pip install zstandard")
    dctx = zstandard.ZstdDecompressor()
    return dctx.decompress(data, max_output_size=max(max_output_size, 16 * 1024 * 1024))

def lzo_decompress(data, output_size):
    """Decompress LZO1X data."""
    if HAS_LZO:
        comp = lzallright.LZOCompressor()
        return comp.decompress(data, output_size)
    else:
        raise RuntimeError("LZO decompression not available. Install: pip install lzallright")


# ===== Key Management =====
def _xor_key_material(raw_dwords):
    """Apply XOR transform to 4 raw DWORDs, return as bytes."""
    xored = [(raw_dwords[i] ^ KEY_XOR_CONSTANTS[i]) & MASK32 for i in range(4)]
    return struct.pack('<IIII', *xored), xored

def load_dumped_keys(path=None):
    """Load keys from dumped_keys.json."""
    path = path or DUMPED_KEYS_PATH
    if not os.path.exists(path):
        return None

    with open(path, 'r') as f:
        data = json.load(f)

    keys_raw = data.get('keys', {})
    keys = {}
    for type_str, kinfo in keys_raw.items():
        type_num = int(type_str)
        # Binary layout: Key[16] at offset 0, IV[16] at offset 16
        # Due to shared buffer bug in GetKey/GetIV, AES uses IV data for both key and IV
        # 'iv_raw'/'iv_xored'/'iv_bytes' in the JSON = first 16 bytes = actual KEY material
        # 'key_raw'/'key_xored'/'key_bytes' in the JSON = second 16 bytes = actual IV material
        # But due to shared buffer: AES key = AES IV = the IV material (second 16 bytes, XOR'd)
        aes_key_iv = bytes.fromhex(kinfo['key_bytes'])  # second 16 bytes after XOR

        keys[type_num] = {
            'aes_key': aes_key_iv,
            'aes_iv': aes_key_iv,
            # Keep XTEA keys for per-file decryption (first 16 bytes XOR'd as 4 DWORDs)
            'xtea_key': kinfo['iv_xored'],  # first 16 bytes XOR'd = 4 u32 values
        }

    return keys

def extract_keys_from_binary(exe_path):
    """Extract encryption keys from NothyrClient.exe."""
    with open(exe_path, 'rb') as f:
        data = f.read()

    keys = {}
    for type_num in range(1, 5):
        base = RAW_KEY_MATERIAL_OFFSET + (type_num - 1) * 0x20
        # First 16 bytes = Key material, Second 16 bytes = IV material
        key_raw = struct.unpack_from('<IIII', data, base)
        iv_raw = struct.unpack_from('<IIII', data, base + 16)

        key_bytes, key_u32 = _xor_key_material(key_raw)
        iv_bytes, iv_u32 = _xor_key_material(iv_raw)

        # Due to shared buffer in GetKey/GetIV: AES key = AES IV = iv_bytes
        keys[type_num] = {
            'aes_key': iv_bytes,
            'aes_iv': iv_bytes,
            'xtea_key': key_u32,
        }

    return keys

def get_keys():
    """Get decryption keys, preferring dumped_keys.json over static binary extraction."""
    dumped = load_dumped_keys()
    if dumped is not None:
        print("  Using runtime keys from dumped_keys.json")
        return dumped

    if CLIENT_EXE.exists():
        print("  No dumped_keys.json found, falling back to static binary extraction")
        return extract_keys_from_binary(CLIENT_EXE)

    return None


# ===== MCOZ Format =====
def parse_mcoz_header(data):
    """Parse MCOZ header. Returns (data_size, compressed_size, raw_size)."""
    if data[:4] != MCOZ_MAGIC:
        raise ValueError(f"Not MCOZ format: {data[:4]}")
    data_size, compressed_size, raw_size = struct.unpack_from('<III', data, 4)
    return data_size, compressed_size, raw_size


def decrypt_mcoz(data, keys, key_type=1):
    """
    Decrypt and decompress an MCOZ block.

    Format: MCOZ(4) + data_size(4) + compressed_size(4) + raw_size(4) + encrypted_data(data_size)
    After AES-128-CTR decryption: MCOZ(4) + zstd_compressed(data_size - 4)
    After zstd decompression: raw EPKD index data (raw_size bytes)
    """
    data_size, compressed_size, raw_size = parse_mcoz_header(data)
    encrypted = data[MCOZ_HEADER_SIZE:MCOZ_HEADER_SIZE + data_size]

    if not HAS_CRYPTO:
        raise RuntimeError("PyCryptodome not available. Install: pip install pycryptodome")

    key_info = keys.get(key_type)
    if key_info is None:
        raise ValueError(f"Key type {key_type} not found")

    aes_key = key_info['aes_key']
    aes_iv = key_info['aes_iv']

    # AES-128-CTR decryption (Crypto++ convention: big-endian counter, initial value = IV)
    iv_int = int.from_bytes(aes_iv, 'big')
    ctr = Counter.new(128, initial_value=iv_int)
    cipher = AES.new(aes_key, AES.MODE_CTR, counter=ctr)
    decrypted = cipher.decrypt(encrypted)

    if decrypted[:4] != MCOZ_MAGIC:
        raise RuntimeError(f"Decryption failed: expected MCOZ magic, got {decrypted[:4].hex()}")

    # After inner MCOZ magic: compressed data
    compressed_data = decrypted[4:]

    # Detect compression format
    if compressed_data[:4] == ZSTD_MAGIC:
        result = zstd_decompress(compressed_data, raw_size * 2)
    else:
        # Fallback to LZO
        result = lzo_decompress(compressed_data, raw_size)

    if len(result) != raw_size:
        print(f"  Warning: decompressed size {len(result)} != expected {raw_size}")

    return result


def try_decrypt_mcoz(data, exe_path=None):
    """
    Try to decrypt MCOZ data. Returns decrypted/decompressed data or None.
    """
    data_size, compressed_size, raw_size = parse_mcoz_header(data)
    encrypted = data[MCOZ_HEADER_SIZE:MCOZ_HEADER_SIZE + data_size]

    # Method 1: Direct decompression (no encryption)
    if encrypted[4:8] == ZSTD_MAGIC:
        try:
            result = zstd_decompress(encrypted[4:], raw_size * 2)
            if len(result) == raw_size:
                print("  No encryption! Direct zstd decompression")
                return result
        except:
            pass

    # Method 2: AES-128-CTR with dumped/extracted keys
    keys = get_keys()
    if keys:
        for key_type in range(1, 5):
            try:
                result = decrypt_mcoz(data, keys, key_type)
                print(f"  Decrypted with AES-128-CTR key type {key_type}")
                return result
            except:
                pass

    return None


# ===== EPKD Format =====
def parse_epkd_index(data):
    """
    Parse EPKD index data (decrypted/decompressed .idx content).

    Nothyr EPKD v2 format (192 bytes per entry):
    - Header: EPKD(4) + version(4) + count(4) = 12 bytes
    - Per entry (192 bytes):
        - 4 bytes: id
        - 164 bytes: filename (null-terminated, padded to 4-byte alignment)
        - 4 bytes: filename CRC32
        - 4 bytes: offset in .dat file (absolute)
        - 4 bytes: compressed size in .dat
        - 4 bytes: data CRC32
        - 4 bytes: raw (decompressed) size (0 = same as compressed)
        - 1 byte: encryption type (0=none, 1=XTEA, 2=zstd/LZO, 3=XTEA+zstd/LZO)
        - 3 bytes: padding
    """
    if len(data) < 12:
        raise ValueError(f"Index data too small: {len(data)} bytes")

    magic = data[:4]
    if magic == EPKD_MAGIC:
        version = read_u32(data, 4)
        count = read_u32(data, 8)
        header_size = 12
    else:
        version = read_u32(data, 0)
        count = read_u32(data, 4)
        header_size = 8

    entries = []

    # Detect entry size from data
    if count > 0:
        entry_data_size = len(data) - header_size
        entry_size = entry_data_size // count
    else:
        entry_size = 192

    # Determine filename length based on entry size
    # Fields after filename: fname_crc(4) + offset(4) + comp_size(4) + data_crc(4) + raw_size(4) + encrypt(4) = 24
    fname_len = entry_size - 4 - 24  # id(4) + fields(24)
    if fname_len < 100 or fname_len > 300:
        fname_len = 164  # default for v2

    print(f"  EPKD version={version}, entries={count}, entry_size={entry_size}, fname_len={fname_len}")

    for i in range(count):
        entry_offset = header_size + i * entry_size
        if entry_offset + entry_size > len(data):
            print(f"  Warning: entry {i} extends beyond data (offset {entry_offset}, data size {len(data)})")
            break

        entry_id = read_u32(data, entry_offset)

        # Extract filename (null-terminated)
        fname_bytes = data[entry_offset + 4:entry_offset + 4 + fname_len]
        null_pos = fname_bytes.find(b'\x00')
        if null_pos >= 0:
            fname = fname_bytes[:null_pos].decode('ascii', errors='replace')
        else:
            fname = fname_bytes.decode('ascii', errors='replace')

        # Read fields after filename
        # Layout: fname_crc(4) + field1(4) + field2(4) + data_crc(4) + dat_offset(4) + encrypt_type(1) + pad(3)
        fields_offset = entry_offset + 4 + fname_len
        fname_crc = read_u32(data, fields_offset)
        field1 = read_u32(data, fields_offset + 4)      # size-related
        field2 = read_u32(data, fields_offset + 8)      # size-related
        data_crc = read_u32(data, fields_offset + 12)
        dat_offset = read_u32(data, fields_offset + 16)  # absolute offset in .dat
        encrypt_type = read_u8(data, fields_offset + 20)

        entries.append({
            'id': entry_id,
            'filename': fname,
            'filename_crc': fname_crc,
            'offset': dat_offset,
            'compressed_size': field2,
            'raw_size': field1,
            'crc': data_crc,
            'encrypt_type': encrypt_type,
        })

    return version, entries


def decrypt_mcoz_dat_file(dat_data, keys, key_type=1):
    """Decrypt a single file from .dat that has MCOZ wrapper."""
    if dat_data[:4] != MCOZ_MAGIC:
        return dat_data

    data_size, compressed_size, raw_size = parse_mcoz_header(dat_data)
    encrypted = dat_data[MCOZ_HEADER_SIZE:MCOZ_HEADER_SIZE + data_size]

    key_info = keys.get(key_type)
    if key_info is None:
        return dat_data

    aes_key = key_info['aes_key']
    aes_iv = key_info['aes_iv']

    iv_int = int.from_bytes(aes_iv, 'big')
    ctr = Counter.new(128, initial_value=iv_int)
    cipher = AES.new(aes_key, AES.MODE_CTR, counter=ctr)
    decrypted = cipher.decrypt(encrypted)

    if decrypted[:4] == MCOZ_MAGIC:
        compressed_data = decrypted[4:]
        if compressed_data[:4] == ZSTD_MAGIC:
            return zstd_decompress(compressed_data, raw_size * 2)
        else:
            return lzo_decompress(compressed_data, raw_size)

    return decrypted


def extract_file_from_dat(dat_path, entry, keys=None, dat_header_size=0):
    """Extract a single file from a .dat pack file.

    Each file in the .dat is stored as its own MCOZ block at an absolute offset.
    The MCOZ block is AES-128-CTR encrypted (key type 2) and zstd compressed.
    """
    offset = entry['offset']

    with open(dat_path, 'rb') as f:
        f.seek(offset)
        header = f.read(16)

        if header[:4] == MCOZ_MAGIC:
            # File is wrapped in its own MCOZ envelope
            fds, fcs, frs = struct.unpack_from('<III', header, 4)
            encrypted = f.read(fds)

            if keys:
                # Dat files use key type 2
                key_info = keys.get(2)
                if key_info:
                    aes_key = key_info['aes_key']
                    aes_iv = key_info['aes_iv']
                    iv_int = int.from_bytes(aes_iv, 'big')
                    ctr = Counter.new(128, initial_value=iv_int)
                    cipher = AES.new(aes_key, AES.MODE_CTR, counter=ctr)
                    decrypted = cipher.decrypt(encrypted)

                    if decrypted[:4] == MCOZ_MAGIC:
                        compressed = decrypted[4:]
                        if compressed[:4] == ZSTD_MAGIC:
                            return zstd_decompress(compressed, frs * 2)
                        elif HAS_LZO:
                            comp = lzallright.LZOCompressor()
                            return comp.decompress(compressed, frs)
                        else:
                            raise RuntimeError("No decompressor available")
                    else:
                        # Maybe not encrypted, try direct decompression
                        if encrypted[4:8] == ZSTD_MAGIC:
                            return zstd_decompress(encrypted[4:], frs * 2)

            raise RuntimeError(f"Could not decrypt MCOZ file block at offset {offset}")

        else:
            # Not MCOZ - read raw data
            f.seek(offset)
            comp_size = entry['compressed_size']
            raw_size = entry['raw_size']
            file_data = f.read(comp_size if comp_size > 0 else raw_size)

            enc_type = entry['encrypt_type']
            if enc_type == ENCRYPT_NONE:
                return file_data[:raw_size] if raw_size > 0 else file_data
            elif enc_type == ENCRYPT_LZO:
                if file_data[:4] == ZSTD_MAGIC:
                    return zstd_decompress(file_data, raw_size * 2)
                elif HAS_LZO:
                    return lzo_decompress(file_data, raw_size)
            elif enc_type == ENCRYPT_XTEA and keys:
                xtea_key = keys.get(1, {}).get('xtea_key')
                if xtea_key:
                    return xtea_decrypt(file_data, xtea_key)[:raw_size]
            elif enc_type == ENCRYPT_XTEA_LZO and keys:
                xtea_key = keys.get(1, {}).get('xtea_key')
                if xtea_key:
                    decrypted = xtea_decrypt(file_data, xtea_key)
                    if decrypted[:4] == ZSTD_MAGIC:
                        return zstd_decompress(decrypted, raw_size * 2)
                    elif HAS_LZO:
                        return lzo_decompress(decrypted, raw_size)

            return file_data


# ===== dump-keys: Read keys from running process =====
def _find_process(name):
    """Find a process by name, return its PID."""
    import subprocess
    result = subprocess.run(['tasklist', '/FI', f'IMAGENAME eq {name}', '/FO', 'CSV', '/NH'],
                          capture_output=True, text=True)
    for line in result.stdout.strip().split('\n'):
        if name.lower() in line.lower():
            parts = line.strip('"').split('","')
            if len(parts) >= 2:
                return int(parts[1])
    return None

def _read_process_memory(pid, address, size):
    """Read memory from a process."""
    import ctypes

    kernel32 = ctypes.windll.kernel32
    handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        raise RuntimeError(f"Cannot open process {pid}: error {ctypes.GetLastError()}")

    try:
        buffer = (ctypes.c_char * size)()
        bytes_read = ctypes.c_size_t(0)
        success = kernel32.ReadProcessMemory(
            handle, ctypes.c_void_p(address), buffer, size, ctypes.byref(bytes_read))
        if not success:
            raise RuntimeError(f"Cannot read memory at 0x{address:X}: error {ctypes.GetLastError()}")
        return bytes(buffer[:bytes_read.value])
    finally:
        kernel32.CloseHandle(handle)

def cmd_dump_keys():
    """Dump encryption keys from running NothyrClient.exe to dumped_keys.json."""
    pid = _find_process("NothyrClient.exe")
    if pid is None:
        print("NothyrClient.exe is not running!")
        print("Start the game client first, then run this script.")
        return None

    print(f"Found NothyrClient.exe (PID: {pid})")

    print(f"Reading key data from VA 0x{KEY_DATA_VA:X}...")
    key_data = _read_process_memory(pid, KEY_DATA_VA, KEY_DATA_SIZE)
    print(f"  Read {len(key_data)} bytes")

    print(f"Reading LZ manager from VA 0x{LZ_MANAGER_VA:X}...")
    try:
        mgr_data = _read_process_memory(pid, LZ_MANAGER_VA, 4)
        mgr_ptr = struct.unpack('<I', mgr_data)[0]
        print(f"  LZ manager pointer: 0x{mgr_ptr:08X}")
    except:
        mgr_ptr = 0

    keys = {}
    for type_num in range(1, 5):
        base = (type_num - 1) * 32
        # Layout: Key[16 bytes] + IV[16 bytes]
        key_raw = struct.unpack_from('<IIII', key_data, base)
        iv_raw = struct.unpack_from('<IIII', key_data, base + 16)

        key_xored = [(key_raw[i] ^ KEY_XOR_CONSTANTS[i]) & MASK32 for i in range(4)]
        iv_xored = [(iv_raw[i] ^ KEY_XOR_CONSTANTS[i]) & MASK32 for i in range(4)]

        keys[type_num] = {
            'key_raw': list(key_raw),
            'iv_raw': list(iv_raw),
            'key_xored': key_xored,
            'iv_xored': iv_xored,
            'key_bytes': struct.pack('<IIII', *key_xored).hex(),
            'iv_bytes': struct.pack('<IIII', *iv_xored).hex(),
        }

        print(f"\n  Type {type_num}:")
        print(f"    Key (raw):   [{', '.join(f'0x{v:08X}' for v in key_raw)}]")
        print(f"    IV  (raw):   [{', '.join(f'0x{v:08X}' for v in iv_raw)}]")
        print(f"    Key (XORed): [{', '.join(f'0x{v:08X}' for v in key_xored)}]")
        print(f"    IV  (XORed): [{', '.join(f'0x{v:08X}' for v in iv_xored)}]")
        print(f"    AES key/IV (=IV XOR'd): {struct.pack('<IIII', *iv_xored).hex()}")

    result = {
        'pid': pid,
        'lz_manager': mgr_ptr,
        'keys': {str(k): v for k, v in keys.items()},
    }

    with open(DUMPED_KEYS_PATH, 'w') as f:
        json.dump(result, f, indent=2)
    print(f"\nKeys saved to: {DUMPED_KEYS_PATH}")
    return result


# ===== Pack listing and extraction =====
def list_pack(pack_name):
    """List files in a pack."""
    idx_path = PACKS_DIR / f"{pack_name}.idx"
    if not idx_path.exists():
        print(f"Index file not found: {idx_path}")
        return

    with open(idx_path, 'rb') as f:
        idx_data = f.read()

    print(f"Pack: {pack_name}")
    print(f"Index file: {idx_path} ({len(idx_data)} bytes)")

    if idx_data[:4] == MCOZ_MAGIC:
        data_size, compressed_size, raw_size = parse_mcoz_header(idx_data)
        print(f"  MCOZ: data_size={data_size}, compressed_size={compressed_size}, raw_size={raw_size}")

        index_data = try_decrypt_mcoz(idx_data, CLIENT_EXE)
        if index_data is None:
            print("  ERROR: Could not decrypt index. Run 'dump-keys' first.")
            return
    else:
        index_data = idx_data

    try:
        version, entries = parse_epkd_index(index_data)
        print(f"\n  Version: {version}")
        print(f"  Files: {len(entries)}")
        print()
        print(f"  {'#':<6} {'Encrypt':<10} {'Raw Size':<12} {'Comp Size':<12} {'Filename'}")
        print(f"  {'-'*6} {'-'*10} {'-'*12} {'-'*12} {'-'*40}")
        for i, e in enumerate(entries):
            enc_names = {0: 'none', 1: 'XTEA', 2: 'LZO/zstd', 3: 'XTEA+LZO/zstd'}
            enc = enc_names.get(e['encrypt_type'], f'?{e["encrypt_type"]}')
            print(f"  {i:<6} {enc:<10} {e['raw_size']:<12} {e['compressed_size']:<12} {e['filename']}")
    except Exception as ex:
        print(f"  ERROR parsing index: {ex}")
        print(f"  First 64 bytes: {index_data[:64].hex()}")


def extract_pack(pack_name, output_dir=None):
    """Extract all files from a pack."""
    idx_path = PACKS_DIR / f"{pack_name}.idx"
    dat_path = PACKS_DIR / f"{pack_name}.dat"

    if not idx_path.exists():
        print(f"Index file not found: {idx_path}")
        return False
    if not dat_path.exists():
        print(f"Data file not found: {dat_path}")
        return False

    if output_dir is None:
        output_dir = OUTPUT_BASE / f"{pack_name}_extracted"

    print(f"Extracting pack: {pack_name}")
    print(f"  Index: {idx_path}")
    print(f"  Data:  {dat_path}")
    print(f"  Output: {output_dir}")

    # Read and decrypt index
    with open(idx_path, 'rb') as f:
        idx_data = f.read()

    if idx_data[:4] == MCOZ_MAGIC:
        index_data = try_decrypt_mcoz(idx_data, CLIENT_EXE)
        if index_data is None:
            print("  ERROR: Could not decrypt index. Run 'dump-keys' first.")
            return False
    else:
        index_data = idx_data

    # Parse index
    try:
        version, entries = parse_epkd_index(index_data)
    except Exception as ex:
        print(f"  ERROR parsing index: {ex}")
        return False

    # Get keys
    keys = get_keys()

    print(f"  Found {len(entries)} files")
    if keys:
        print(f"  Keys loaded for file extraction")
    else:
        print(f"  WARNING: No keys available, encrypted files will fail")

    # Extract files
    os.makedirs(output_dir, exist_ok=True)
    extracted = 0
    failed = 0

    for i, entry in enumerate(entries):
        if not entry['filename']:
            continue

        out_path = output_dir / entry['filename'].replace('\\', '/')
        os.makedirs(out_path.parent, exist_ok=True)

        try:
            file_data = extract_file_from_dat(dat_path, entry, keys=keys)
            with open(out_path, 'wb') as f:
                f.write(file_data)
            extracted += 1
        except Exception as ex:
            print(f"  ERROR extracting {entry['filename']}: {ex}")
            failed += 1

        if (i + 1) % 100 == 0:
            print(f"  Progress: {i + 1}/{len(entries)} ({extracted} ok, {failed} failed)")

    print(f"  Done: {extracted} extracted, {failed} failed")
    return True


# ===== CLI =====
def main():
    if len(sys.argv) < 2:
        print(__doc__)
        print("\nAvailable packs:")
        if PACKS_DIR.exists():
            packs = set()
            for f in PACKS_DIR.iterdir():
                if f.suffix == '.idx':
                    packs.add(f.stem)
            for p in sorted(packs):
                idx_size = (PACKS_DIR / f"{p}.idx").stat().st_size
                dat_size = (PACKS_DIR / f"{p}.dat").stat().st_size if (PACKS_DIR / f"{p}.dat").exists() else 0
                print(f"  {p:<30} idx={idx_size:>10}  dat={dat_size:>12}")
        return

    cmd = sys.argv[1]

    if cmd == 'dump-keys':
        cmd_dump_keys()

    elif cmd == 'extract':
        if len(sys.argv) < 3:
            print("Usage: unpacker.py extract <pack_name>")
            print("       unpacker.py extract --all")
            return
        if sys.argv[2] == '--all':
            if PACKS_DIR.exists():
                packs = set()
                for f in PACKS_DIR.iterdir():
                    if f.suffix == '.idx':
                        packs.add(f.stem)
                for p in sorted(packs):
                    extract_pack(p)
        else:
            extract_pack(sys.argv[2])

    elif cmd == 'list':
        if len(sys.argv) < 3:
            print("Usage: unpacker.py list <pack_name>")
            return
        list_pack(sys.argv[2])

    elif cmd == 'dump-header':
        if len(sys.argv) < 3:
            print("Usage: unpacker.py dump-header <file>")
            return
        path = Path(sys.argv[2])
        if not path.exists():
            path = PACKS_DIR / sys.argv[2]
        with open(path, 'rb') as f:
            data = f.read(256)
        if data[:4] == MCOZ_MAGIC:
            ds, cs, rs = parse_mcoz_header(data)
            print(f"MCOZ: data_size={ds}, compressed_size={cs}, raw_size={rs}")
            print(f"Header (16 bytes): {data[:16].hex()}")
            print(f"Encrypted data starts at offset 16:")
            print(f"  First 32 bytes: {data[16:48].hex()}")
        elif data[:4] == EPKD_MAGIC:
            ver = read_u32(data, 4)
            cnt = read_u32(data, 8)
            print(f"EPKD: version={ver}, count={cnt}")
        else:
            print(f"Unknown format: {data[:4].hex()}")
            print(f"First 64 bytes: {data[:64].hex()}")

    else:
        extract_pack(cmd)


if __name__ == '__main__':
    main()
