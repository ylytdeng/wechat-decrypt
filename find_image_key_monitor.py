"""持续监控微信进程内存，捕获图片 AES 密钥

运行此脚本后，在微信中打开查看几张图片。
脚本会自动检测到 key 并保存到 config.json。

按 Ctrl+C 退出。
"""
import os
import sys
import re
import struct
import glob
import json
import time
import ctypes
from ctypes import wintypes
from Crypto.Cipher import AES
from Crypto.Util import Padding

# Windows API constants
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]

kernel32 = ctypes.windll.kernel32

# Regex for key patterns
RE_KEY32 = re.compile(rb'(?<![a-zA-Z0-9])[a-zA-Z0-9]{32}(?![a-zA-Z0-9])')
RE_KEY16 = re.compile(rb'(?<![a-zA-Z0-9])[a-zA-Z0-9]{16}(?![a-zA-Z0-9])')


def get_wechat_pids():
    import subprocess
    result = subprocess.run(
        ['tasklist.exe', '/FI', 'IMAGENAME eq Weixin.exe', '/FO', 'CSV', '/NH'],
        capture_output=True, text=True
    )
    pids = []
    for line in result.stdout.strip().split('\n'):
        if 'Weixin.exe' in line:
            parts = line.strip('"').split('","')
            if len(parts) >= 2:
                pids.append(int(parts[1]))
    return pids


def find_v2_ciphertext(attach_dir):
    v2_magic = b'\x07\x08V2\x08\x07'
    pattern = os.path.join(attach_dir, "*", "*", "Img", "*_t.dat")
    dat_files = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)
    for f in dat_files[:100]:
        try:
            with open(f, 'rb') as fp:
                header = fp.read(31)
            if header[:6] == v2_magic and len(header) >= 31:
                return header[15:31], os.path.basename(f)
        except:
            continue
    return None, None


def find_xor_key(attach_dir):
    v2_magic = b'\x07\x08V2\x08\x07'
    pattern = os.path.join(attach_dir, "*", "*", "Img", "*_t.dat")
    dat_files = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)
    tail_counts = {}
    for f in dat_files[:32]:
        try:
            sz = os.path.getsize(f)
            with open(f, 'rb') as fp:
                head = fp.read(6)
                fp.seek(sz - 2)
                tail = fp.read(2)
            if head == v2_magic and len(tail) == 2:
                key = (tail[0], tail[1])
                tail_counts[key] = tail_counts.get(key, 0) + 1
        except:
            continue
    if not tail_counts:
        return None
    most_common = max(tail_counts, key=tail_counts.get)
    return most_common[0] ^ 0xFF


def try_key(key_bytes, ciphertext):
    try:
        cipher = AES.new(key_bytes, AES.MODE_ECB)
        dec = cipher.decrypt(ciphertext)
        if dec[:3] == b'\xFF\xD8\xFF': return 'JPEG'
        if dec[:4] == bytes([0x89, 0x50, 0x4E, 0x47]): return 'PNG'
        if dec[:4] == b'RIFF': return 'WEBP'
        if dec[:4] == b'wxgf': return 'WXGF'
        if dec[:3] == b'GIF': return 'GIF'
    except:
        pass
    return None


def is_rw_protect(protect):
    rw_flags = (PAGE_READWRITE | PAGE_WRITECOPY |
                PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
    return (protect & rw_flags) != 0


def get_rw_regions(h_process):
    """Get RW committed memory regions"""
    address = 0
    mbi = MEMORY_BASIC_INFORMATION()
    regions = []
    while address < 0x7FFFFFFFFFFF:
        result = kernel32.VirtualQueryEx(
            h_process, ctypes.c_void_p(address),
            ctypes.byref(mbi), ctypes.sizeof(mbi)
        )
        if result == 0:
            break
        if (mbi.State == MEM_COMMIT and
            mbi.Protect != PAGE_NOACCESS and
            (mbi.Protect & PAGE_GUARD) == 0 and
            mbi.RegionSize <= 50 * 1024 * 1024 and
            is_rw_protect(mbi.Protect)):
            regions.append((mbi.BaseAddress, mbi.RegionSize))
        next_addr = address + mbi.RegionSize
        if next_addr <= address:
            break
        address = next_addr
    return regions


def quick_scan(h_process, regions, ciphertext):
    """Fast scan of RW regions, return key or None"""
    for base_addr, region_size in regions:
        buffer = ctypes.create_string_buffer(region_size)
        bytes_read = ctypes.c_size_t(0)
        ok = kernel32.ReadProcessMemory(
            h_process, ctypes.c_void_p(base_addr),
            buffer, region_size, ctypes.byref(bytes_read)
        )
        if not ok or bytes_read.value < 32:
            continue

        data = buffer.raw[:bytes_read.value]

        # 32-char keys (first 16 as AES-128)
        for m in RE_KEY32.finditer(data):
            key_bytes = m.group()
            fmt = try_key(key_bytes[:16], ciphertext)
            if fmt:
                return key_bytes.decode('ascii')[:16], fmt
            fmt = try_key(key_bytes, ciphertext)
            if fmt:
                return key_bytes.decode('ascii'), fmt

        # Standalone 16-char keys
        for m in RE_KEY16.finditer(data):
            key_bytes = m.group()
            fmt = try_key(key_bytes, ciphertext)
            if fmt:
                return key_bytes.decode('ascii'), fmt

    return None, None


def verify_and_decrypt(attach_dir, aes_key_str, xor_key):
    """Decrypt one V2 file as verification"""
    v2_magic = b'\x07\x08V2\x08\x07'
    key = aes_key_str.encode('ascii')[:16]
    pattern = os.path.join(attach_dir, "*", "*", "Img", "*_t.dat")
    dat_files = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)

    for f in dat_files[:10]:
        try:
            with open(f, 'rb') as fp:
                data = fp.read()
            if data[:6] != v2_magic:
                continue
            sig, aes_size, xor_size = struct.unpack_from('<6sLL', data)
            aligned_aes_size = aes_size
            aligned_aes_size -= ~(~aligned_aes_size % 16)
            offset = 15
            aes_data = data[offset:offset + aligned_aes_size]
            cipher = AES.new(key, AES.MODE_ECB)
            dec_aes = Padding.unpad(cipher.decrypt(aes_data), AES.block_size)
            offset += aligned_aes_size
            raw_data = data[offset:len(data) - xor_size]
            offset += len(raw_data)
            xor_data = data[offset:]
            dec_xor = bytes(b ^ xor_key for b in xor_data) if xor_key is not None else xor_data
            result = dec_aes + raw_data + dec_xor

            fmt, ext = "unknown", ".bin"
            if result[:3] == b'\xFF\xD8\xFF': fmt, ext = "JPEG", ".jpg"
            elif result[:4] == bytes([0x89, 0x50, 0x4E, 0x47]): fmt, ext = "PNG", ".png"
            elif result[:4] == b'RIFF': fmt, ext = "WEBP", ".webp"
            elif result[:4] == b'wxgf': fmt, ext = "WXGF", ".hevc"

            if fmt != "unknown":
                out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "decoded_images")
                os.makedirs(out_dir, exist_ok=True)
                out_path = os.path.join(out_dir, os.path.splitext(os.path.basename(f))[0] + ext)
                with open(out_path, 'wb') as fp:
                    fp.write(result)
                print(f"  Verified: {os.path.basename(f)} -> {fmt} ({len(result):,}B)", flush=True)
                print(f"  Saved: {out_path}", flush=True)
                return True
        except:
            continue
    return False


def main():
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
    with open(config_path, "r", encoding="utf-8") as f:
        config = json.load(f)

    db_dir = config['db_dir']
    base_dir = os.path.dirname(db_dir)
    attach_dir = os.path.join(base_dir, 'msg', 'attach')

    xor_key = find_xor_key(attach_dir)
    print(f"XOR key: 0x{xor_key:02x}" if xor_key else "XOR key: unknown", flush=True)

    ciphertext, ct_file = find_v2_ciphertext(attach_dir)
    if ciphertext is None:
        print("No V2 .dat files found")
        return
    print(f"V2 cipher: {ciphertext.hex()} ({ct_file})", flush=True)

    # Check existing key
    if config.get('image_aes_key'):
        fmt = try_key(config['image_aes_key'].encode('ascii')[:16], ciphertext)
        if fmt:
            print(f"Existing key valid: {config['image_aes_key']} -> {fmt}", flush=True)
            return

    pids = get_wechat_pids()
    if not pids:
        print("WeChat not running!")
        return

    # Find the main PID (largest memory footprint)
    main_pid = pids[0]
    print(f"\nMonitoring PID {main_pid} (main WeChat process)", flush=True)
    print("=" * 60, flush=True)
    print("NOW: Open WeChat and tap to view 2-3 images (full size)", flush=True)
    print("The script will automatically detect the key...", flush=True)
    print("=" * 60, flush=True)

    access = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
    h_process = kernel32.OpenProcess(access, False, main_pid)
    if not h_process:
        print(f"Cannot open process {main_pid} (run as admin?)", flush=True)
        return

    try:
        # Get regions once (they don't change much)
        regions = get_rw_regions(h_process)
        total_mb = sum(r[1] for r in regions) / 1024 / 1024
        print(f"RW regions: {len(regions)} ({total_mb:.0f} MB)", flush=True)

        scan_count = 0
        while True:
            scan_count += 1
            t0 = time.time()
            aes_key, fmt = quick_scan(h_process, regions, ciphertext)
            elapsed = time.time() - t0

            if aes_key:
                print(f"\n{'='*60}", flush=True)
                print(f"*** FOUND AES key! -> {fmt} ***", flush=True)
                print(f"AES key: {aes_key}", flush=True)
                print(f"XOR key: 0x{xor_key:02x}" if xor_key else "XOR key: unknown", flush=True)
                print(f"{'='*60}", flush=True)

                config['image_aes_key'] = aes_key
                if xor_key is not None:
                    config['image_xor_key'] = xor_key
                with open(config_path, "w", encoding="utf-8") as f:
                    json.dump(config, f, indent=2, ensure_ascii=False)
                print(f"Saved to {config_path}", flush=True)

                verify_and_decrypt(attach_dir, aes_key, xor_key)
                return

            print(f"  Scan #{scan_count}: no key found ({elapsed:.1f}s)", end='\r', flush=True)

            # Wait 5 seconds before next scan
            time.sleep(5)

            # Refresh regions periodically (every 5 scans)
            if scan_count % 5 == 0:
                regions = get_rw_regions(h_process)

    except KeyboardInterrupt:
        print("\nStopped by user", flush=True)
    finally:
        kernel32.CloseHandle(h_process)


if __name__ == '__main__':
    main()
