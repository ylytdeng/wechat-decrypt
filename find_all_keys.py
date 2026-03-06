import platform
import sys


def _load_impl():
    system = platform.system().lower()
    if system == "windows":
        import find_all_keys_windows as impl
        return impl
    if system == "linux":
        import find_all_keys_linux as impl
        return impl
    raise RuntimeError(f"当前平台暂不支持通过 find_all_keys.py 提取密钥: {platform.system()}")


def get_pids():
    return _load_impl().get_pids()


def main():
    return _load_impl().main()


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as exc:
        print(f"\n[ERROR] {exc}")
        sys.exit(1)
