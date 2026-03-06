"""
Linux 版微信数据库密钥提取

原理: 与 Windows/macOS 相同 — 扫描微信进程内存，查找
WCDB 缓存的 x'<64hex_enc_key><32hex_salt>' 模式，
通过匹配数据库 salt + HMAC 校验确认密钥。

读取方式: /proc/<pid>/maps + /proc/<pid>/mem
权限要求: root 或 CAP_SYS_PTRACE
"""
import functools
import os
import re
import sys
import time

from key_scan_common import (
    collect_db_files, scan_memory_for_keys, cross_verify_keys, save_results,
)

print = functools.partial(print, flush=True)


def _safe_readlink(path):
    try:
        return os.path.realpath(os.readlink(path))
    except OSError:
        return ""


_INTERPRETER_PREFIXES = ("python", "bash", "sh", "zsh", "node", "perl", "ruby")


def _is_wechat_process(pid):
    """检查 pid 是否为微信进程。

    使用子串匹配以覆盖 wechat 主进程和 WeChatAppEx 子进程，
    同时排除自身和解释器进程（如 python3 find_all_keys.py）。
    """
    if pid == os.getpid():
        return False
    try:
        with open(f"/proc/{pid}/comm") as f:
            comm = f.read().strip()
        exe_path = _safe_readlink(f"/proc/{pid}/exe")
        exe_name = os.path.basename(exe_path)
        # 排除脚本解释器进程（避免匹配 python3.11 wechat-decrypt 等）
        if any(exe_name.lower().startswith(p) for p in _INTERPRETER_PREFIXES):
            return False
        haystack = f"{comm} {exe_name}".lower()
        return "wechat" in haystack or "weixin" in haystack
    except (PermissionError, FileNotFoundError, ProcessLookupError):
        return False


def get_pids():
    """返回所有疑似微信主进程的 (pid, rss_kb) 列表，按内存降序。"""
    pids = []
    for pid_str in os.listdir("/proc"):
        if not pid_str.isdigit():
            continue
        pid = int(pid_str)
        try:
            if not _is_wechat_process(pid):
                continue
            with open(f"/proc/{pid}/statm") as f:
                rss_pages = int(f.read().split()[1])
            rss_kb = rss_pages * 4
            pids.append((pid, rss_kb))
        except (PermissionError, FileNotFoundError, ProcessLookupError):
            continue

    if not pids:
        raise RuntimeError("未检测到 Linux 微信进程")

    pids.sort(key=lambda item: item[1], reverse=True)
    for pid, rss_kb in pids:
        exe_path = _safe_readlink(f"/proc/{pid}/exe")
        print(f"[+] WeChat PID={pid} ({rss_kb // 1024}MB) {exe_path}")
    return pids


_SKIP_MAPPINGS = {"[vdso]", "[vsyscall]", "[vvar]"}
_SKIP_PATH_PREFIXES = ("/usr/lib/", "/lib/", "/usr/share/")


def _get_readable_regions(pid):
    """解析 /proc/<pid>/maps，返回可读内存区域列表。

    跳过 [vdso]、[vsyscall] 等特殊映射和系统库映射，
    聚焦匿名映射和堆区（WCDB 密钥缓存所在位置）。
    """
    regions = []
    with open(f"/proc/{pid}/maps") as f:
        for line in f:
            parts = line.split()
            if len(parts) < 2:
                continue
            if "r" not in parts[1]:
                continue
            # 跳过特殊映射和无关系统库，但保留 wcdb/wechat 相关库
            if len(parts) >= 6:
                mapping_name = parts[5]
                if mapping_name in _SKIP_MAPPINGS:
                    continue
                mapping_lower = mapping_name.lower()
                if (any(mapping_name.startswith(p) for p in _SKIP_PATH_PREFIXES)
                        and "wcdb" not in mapping_lower
                        and "wechat" not in mapping_lower
                        and "weixin" not in mapping_lower):
                    continue
            start_s, end_s = parts[0].split("-")
            start = int(start_s, 16)
            size = int(end_s, 16) - start
            if 0 < size < 500 * 1024 * 1024:
                regions.append((start, size))
    return regions


def _check_permissions():
    """检查是否有读取进程内存的权限（root 或 CAP_SYS_PTRACE）。"""
    if os.geteuid() == 0:
        return
    # 检查 CAP_SYS_PTRACE: 读取 /proc/self/status 中的 CapEff
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("CapEff:"):
                    cap_eff = int(line.split(":")[1].strip(), 16)
                    CAP_SYS_PTRACE = 1 << 19
                    if cap_eff & CAP_SYS_PTRACE:
                        return
                    break
    except (OSError, ValueError):
        pass
    print("[!] 需要 root 权限或 CAP_SYS_PTRACE 才能读取进程内存")
    print("    请使用: sudo python3 find_all_keys.py")
    print("    或授予 capability: sudo setcap cap_sys_ptrace=ep $(which python3)")
    sys.exit(1)


def main():
    from config import load_config
    _cfg = load_config()
    db_dir = _cfg["db_dir"]
    out_file = _cfg["keys_file"]

    _check_permissions()

    print("=" * 60)
    print("  提取 Linux 微信数据库密钥（内存扫描）")
    print("=" * 60)

    # 1. 收集 DB 文件和 salt
    db_files, salt_to_dbs = collect_db_files(db_dir)
    if not db_files:
        raise RuntimeError(f"在 {db_dir} 未找到可解密的 .db 文件")

    print(f"\n找到 {len(db_files)} 个数据库, {len(salt_to_dbs)} 个不同的 salt")
    for salt_hex, dbs in sorted(salt_to_dbs.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"  salt {salt_hex}: {', '.join(dbs)}")

    # 2. 找到微信进程
    pids = get_pids()

    hex_re = re.compile(rb"x'([0-9a-fA-F]{64,192})'")
    key_map = {}  # salt_hex -> enc_key_hex
    remaining_salts = set(salt_to_dbs.keys())
    all_hex_matches = 0
    t0 = time.time()

    for pid, rss_kb in pids:
        try:
            regions = _get_readable_regions(pid)
        except PermissionError:
            print(f"[WARN] 无法读取 /proc/{pid}/maps，权限不足，跳过")
            continue
        except (FileNotFoundError, ProcessLookupError):
            print(f"[WARN] PID {pid} 已退出，跳过")
            continue

        total_bytes = sum(s for _, s in regions)
        total_mb = total_bytes / 1024 / 1024
        print(f"\n[*] 扫描 PID={pid} ({total_mb:.0f}MB, {len(regions)} 区域)")

        scanned_bytes = 0
        try:
            mem = open(f"/proc/{pid}/mem", "rb")
        except PermissionError:
            print(f"[WARN] 无法打开 /proc/{pid}/mem，权限不足，跳过")
            continue
        except (FileNotFoundError, ProcessLookupError):
            print(f"[WARN] PID {pid} 已退出，跳过")
            continue

        # 防御 TOCTOU: 打开 mem 后再次确认仍为微信进程
        if not _is_wechat_process(pid):
            print(f"[WARN] PID {pid} 已不是微信进程，跳过")
            mem.close()
            continue

        try:
            for reg_idx, (base, size) in enumerate(regions):
                try:
                    mem.seek(base)
                    data = mem.read(size)
                except (OSError, ValueError):
                    continue
                scanned_bytes += len(data)

                all_hex_matches += scan_memory_for_keys(
                    data, hex_re, db_files, salt_to_dbs,
                    key_map, remaining_salts, base, pid, print,
                )

                if (reg_idx + 1) % 200 == 0:
                    elapsed = time.time() - t0
                    progress = scanned_bytes / total_bytes * 100 if total_bytes else 100
                    print(
                        f"  [{progress:.1f}%] {len(key_map)}/{len(salt_to_dbs)} salts matched, "
                        f"{all_hex_matches} hex patterns, {elapsed:.1f}s"
                    )
        finally:
            mem.close()

        if not remaining_salts:
            print(f"\n[+] 所有密钥已找到，跳过剩余进程")
            break

    elapsed = time.time() - t0
    print(f"\n扫描完成: {elapsed:.1f}s, {len(pids)} 个进程, {all_hex_matches} hex 模式")

    cross_verify_keys(db_files, salt_to_dbs, key_map, print)
    save_results(db_files, salt_to_dbs, key_map, db_dir, out_file, print)


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as exc:
        print(f"\n[ERROR] {exc}")
        sys.exit(1)
