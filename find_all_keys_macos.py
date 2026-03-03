#!/usr/bin/env python3
"""
macOS WeChat memory scanner using Mach VM APIs.
Scans WeChat process memory for SQLCipher encryption keys.
Must run as root (sudo).
"""
import ctypes
import ctypes.util
import struct
import json
import os
import sys
import time
import hashlib
import hmac

# ============ Mach VM API bindings ============

libc = ctypes.CDLL(ctypes.util.find_library('c'))

# Types
mach_port_t = ctypes.c_uint32
kern_return_t = ctypes.c_int32
vm_address_t = ctypes.c_uint64
vm_size_t = ctypes.c_uint64
vm_offset_t = ctypes.c_uint64
natural_t = ctypes.c_uint32
vm_prot_t = ctypes.c_int32
vm_inherit_t = ctypes.c_uint32
boolean_t = ctypes.c_int32
memory_object_name_t = mach_port_t
vm_behavior_t = ctypes.c_int32

# Function signatures (ctypes defaults are unsafe for 64-bit Mach VM APIs)
libc.task_for_pid.argtypes = [mach_port_t, ctypes.c_int, ctypes.POINTER(mach_port_t)]
libc.task_for_pid.restype = kern_return_t
libc.mach_vm_region.argtypes = [
    mach_port_t,
    ctypes.POINTER(vm_address_t),
    ctypes.POINTER(vm_size_t),
    ctypes.c_int,
    ctypes.c_void_p,
    ctypes.POINTER(natural_t),
    ctypes.POINTER(mach_port_t),
]
libc.mach_vm_region.restype = kern_return_t
libc.mach_vm_read.argtypes = [
    mach_port_t,
    vm_address_t,
    vm_size_t,
    ctypes.POINTER(vm_offset_t),
    ctypes.POINTER(natural_t),
]
libc.mach_vm_read.restype = kern_return_t
libc.mach_vm_deallocate.argtypes = [mach_port_t, vm_address_t, vm_size_t]
libc.mach_vm_deallocate.restype = kern_return_t
libc.mach_port_deallocate.argtypes = [mach_port_t, mach_port_t]
libc.mach_port_deallocate.restype = kern_return_t

MACH_TASK_SELF = mach_port_t.in_dll(libc, 'mach_task_self_')

# vm_region_basic_info_64
class vm_region_basic_info_64(ctypes.Structure):
    _fields_ = [
        ("protection", vm_prot_t),
        ("max_protection", vm_prot_t),
        ("inheritance", vm_inherit_t),
        ("shared", boolean_t),
        ("reserved", boolean_t),
        ("offset", ctypes.c_uint64),
        ("behavior", vm_behavior_t),
        ("user_wired_count", ctypes.c_uint16),
    ]

VM_REGION_BASIC_INFO_64 = 9
VM_REGION_BASIC_INFO_COUNT_64 = ctypes.sizeof(vm_region_basic_info_64) // 4

VM_PROT_READ = 1
VM_PROT_WRITE = 2

def get_task(pid):
    """Get mach task port for a process"""
    task = mach_port_t(0)
    ret = libc.task_for_pid(MACH_TASK_SELF, pid, ctypes.byref(task))
    if ret != 0:
        print(f"task_for_pid failed: {ret}")
        sys.exit(1)
    return task

def get_regions(task):
    """Enumerate readable memory regions"""
    regions = []
    address = vm_address_t(0)
    size = vm_size_t(0)
    info = vm_region_basic_info_64()
    info_count = natural_t(VM_REGION_BASIC_INFO_COUNT_64)
    object_name = mach_port_t(0)
    
    while True:
        ret = libc.mach_vm_region(
            task,
            ctypes.byref(address),
            ctypes.byref(size),
            VM_REGION_BASIC_INFO_64,
            ctypes.byref(info),
            ctypes.byref(info_count),
            ctypes.byref(object_name)
        )
        if ret != 0:
            break
        
        # Only readable + writable regions (heap, where keys live)
        if (info.protection & VM_PROT_READ) and (info.protection & VM_PROT_WRITE):
            if size.value > 0 and size.value < 200 * 1024 * 1024:
                regions.append((address.value, size.value))

        if object_name.value:
            libc.mach_port_deallocate(MACH_TASK_SELF, object_name)
            object_name = mach_port_t(0)

        address.value += size.value
        info_count.value = VM_REGION_BASIC_INFO_COUNT_64
    
    return regions

def read_memory(task, address, size):
    """Read memory from a task"""
    data_ptr = vm_offset_t(0)
    data_cnt = natural_t(0)
    ret = libc.mach_vm_read(
        task,
        vm_address_t(address),
        vm_size_t(size),
        ctypes.byref(data_ptr),
        ctypes.byref(data_cnt)
    )
    if ret != 0:
        return None

    if data_ptr.value == 0 or data_cnt.value == 0:
        return None

    # string_at copies bytes into Python-managed memory, so deallocating
    # the Mach VM buffer immediately after this call is safe.
    buf = ctypes.string_at(data_ptr.value, data_cnt.value)
    # Deallocate
    libc.mach_vm_deallocate(
        MACH_TASK_SELF,
        vm_address_t(data_ptr.value),
        vm_size_t(data_cnt.value)
    )
    return buf

def find_wechat_pid():
    """Find WeChat main process PID"""
    import subprocess
    try:
        proc = subprocess.run(["ps", "aux"], capture_output=True, text=True, check=False)
    except OSError:
        return None
    if proc.returncode != 0 or not proc.stdout:
        return None

    candidates = []
    for line in proc.stdout.splitlines():
        if '/WeChat.app/Contents/MacOS/WeChat' in line and 'WeChatAppEx' not in line and 'wxplayer' not in line and 'wxutility' not in line:
            parts = line.split()
            if len(parts) < 2:
                continue
            try:
                candidates.append(int(parts[1]))
            except ValueError:
                continue
    if candidates:
        return max(candidates)
    return None

# ============ Main ============

if __name__ == '__main__':
    print("=" * 60)
    print("  macOS WeChat Memory Key Scanner")
    print("=" * 60)
    
    pid = find_wechat_pid()
    if not pid:
        print("WeChat not running!")
        sys.exit(1)
    print(f"WeChat PID: {pid}")
    
    t0 = time.time()
    task = get_task(pid)
    print(f"Got task port: {task.value}")
    
    regions = get_regions(task)
    total_mb = sum(s for _, s in regions) / (1024*1024)
    print(f"Found {len(regions)} R/W regions, {total_mb:.1f}MB total")
    progress_step = max(1, len(regions) // 10) if regions else 1
    
    # Scan for x'<64hex_key><32hex_salt>' pattern
    pattern = b"x'"
    found_keys = {}
    scanned = 0
    
    CHUNK = 8 * 1024 * 1024  # Read 8MB at a time
    OVERLAP = 98             # Pattern length (99) - 1, avoid boundary misses
    
    for i, (base, size) in enumerate(regions):
        offset = 0
        while offset < size:
            chunk_size = min(CHUNK, size - offset)
            data = read_memory(task, base + offset, chunk_size)
            if not data:
                step = (chunk_size - OVERLAP) if chunk_size > OVERLAP else chunk_size
                offset += step
                continue
            
            scanned += len(data)
            
            pos = 0
            while True:
                idx = data.find(pattern, pos)
                if idx == -1:
                    break
                
                remaining = data[idx+2:idx+2+97]
                if len(remaining) >= 97 and remaining[96:97] == b"'":
                    hex_str = remaining[:96]
                    try:
                        hex_decoded = hex_str.decode('ascii')
                        if all(c in '0123456789abcdefABCDEF' for c in hex_decoded):
                            enc_key = hex_decoded[:64].lower()
                            salt = hex_decoded[64:].lower()
                            addr_found = base + offset + idx
                            if salt not in found_keys:
                                found_keys[salt] = (enc_key, addr_found)
                                print(f"  [FOUND] salt={salt}")
                                print(f"    key={enc_key}")
                                print(f"    addr=0x{addr_found:016x}")
                    except UnicodeDecodeError:
                        pass
                pos = idx + 1

            step = (chunk_size - OVERLAP) if chunk_size > OVERLAP else chunk_size
            offset += step
        
        pct = (i+1) / len(regions) * 100
        if ((i+1) % progress_step == 0) or (i + 1 == len(regions)):
            print(f"  [{pct:.1f}%] {len(found_keys)} keys found, {scanned/(1024*1024):.0f}MB scanned", flush=True)

    libc.mach_port_deallocate(MACH_TASK_SELF, task)

    elapsed = time.time() - t0
    print(f"\nScan complete: {elapsed:.1f}s, {scanned/(1024*1024):.0f}MB scanned, {len(found_keys)} unique keys")
    
    # Save raw results
    out = {}
    for salt, (key, addr) in found_keys.items():
        out[salt] = {"enc_key": key, "addr": hex(addr)}
    
    out_path = os.path.expanduser("~/wechat_keys_raw.json")
    with open(out_path, 'w') as f:
        json.dump(out, f, indent=2)
    print(f"Saved to {out_path}")
