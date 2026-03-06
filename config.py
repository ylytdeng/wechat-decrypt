"""
配置加载器 - 从 config.json 读取路径配置
首次运行时自动检测微信数据目录，检测失败则提示手动配置
"""
import glob
import json
import os
import platform
import sys

CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

_SYSTEM = platform.system().lower()

if _SYSTEM == "linux":
    _DEFAULT_TEMPLATE_DIR = os.path.expanduser("~/Documents/xwechat_files/your_wxid/db_storage")
    _DEFAULT_PROCESS = "wechat"
elif _SYSTEM == "darwin":
    # macOS 使用独立的 C 扫描器 (find_all_keys_macos.c)，此处仅提供 config 默认值
    _DEFAULT_TEMPLATE_DIR = os.path.expanduser("~/Documents/xwechat_files/your_wxid/db_storage")
    _DEFAULT_PROCESS = "WeChat"
else:
    _DEFAULT_TEMPLATE_DIR = r"D:\xwechat_files\your_wxid\db_storage"
    _DEFAULT_PROCESS = "Weixin.exe"

_DEFAULT = {
    "db_dir": _DEFAULT_TEMPLATE_DIR,
    "keys_file": "all_keys.json",
    "decrypted_dir": "decrypted",
    "decoded_image_dir": "decoded_images",
    "wechat_process": _DEFAULT_PROCESS,
}


def _choose_candidate(candidates):
    """在多个候选目录中选择一个。"""
    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1:
        if not sys.stdin.isatty():
            return candidates[0]
        print("[!] 检测到多个微信数据目录（请选择当前正在运行的微信账号）:")
        for i, c in enumerate(candidates, 1):
            print(f"    {i}. {c}")
        print("    0. 跳过，稍后手动配置")
        try:
            while True:
                choice = input("请选择 [0-{}]: ".format(len(candidates))).strip()
                if choice == "0":
                    return None
                if choice.isdigit() and 1 <= int(choice) <= len(candidates):
                    return candidates[int(choice) - 1]
                print("    无效输入，请重新选择")
        except (EOFError, KeyboardInterrupt):
            print()
            return None
    return None


def _auto_detect_db_dir_windows():
    """从微信本地配置自动检测 Windows db_storage 路径。

    读取 %APPDATA%\\Tencent\\xwechat\\config\\*.ini，
    找到数据存储根目录，然后匹配 xwechat_files\\*\\db_storage。
    """
    appdata = os.environ.get("APPDATA", "")
    config_dir = os.path.join(appdata, "Tencent", "xwechat", "config")
    if not os.path.isdir(config_dir):
        return None

    # 从 ini 文件中找到有效的目录路径
    data_roots = []
    for ini_file in glob.glob(os.path.join(config_dir, "*.ini")):
        try:
            # 微信 ini 可能是 utf-8 或 gbk 编码（中文路径）
            content = None
            for enc in ("utf-8", "gbk"):
                try:
                    with open(ini_file, "r", encoding=enc) as f:
                        content = f.read(1024).strip()
                    break
                except UnicodeDecodeError:
                    continue
            if not content or any(c in content for c in "\n\r\x00"):
                continue
            if os.path.isdir(content):
                data_roots.append(content)
        except OSError:
            continue

    # 在每个根目录下搜索 xwechat_files\*\db_storage
    seen = set()
    candidates = []
    for root in data_roots:
        pattern = os.path.join(root, "xwechat_files", "*", "db_storage")
        for match in glob.glob(pattern):
            normalized = os.path.normcase(os.path.normpath(match))
            if os.path.isdir(match) and normalized not in seen:
                seen.add(normalized)
                candidates.append(match)

    return _choose_candidate(candidates)


def _auto_detect_db_dir_linux():
    """自动检测 Linux 微信 db_storage 路径。

    优先搜索当前用户的 home 目录。以 sudo 运行时通过 SUDO_USER 回退到
    实际用户的 home，避免只搜索 /root 而遗漏真实数据目录。
    """
    seen = set()
    candidates = []
    search_roots = [
        os.path.expanduser("~/Documents/xwechat_files"),
    ]
    # sudo 运行时，~ 展开为 /root；回退到实际用户的 home
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        # 验证 SUDO_USER 是合法系统用户，防止路径注入
        import pwd
        try:
            pw = pwd.getpwnam(sudo_user)
            sudo_home = pw.pw_dir
        except KeyError:
            sudo_home = None
        if not sudo_home:
            sudo_home = os.path.expanduser(f"~{sudo_user}")
        fallback = os.path.join(sudo_home, "Documents", "xwechat_files")
        if fallback not in search_roots:
            search_roots.append(fallback)

    for root in search_roots:
        if not os.path.isdir(root):
            continue
        pattern = os.path.join(root, "*", "db_storage")
        for match in glob.glob(pattern):
            normalized = os.path.normcase(os.path.normpath(match))
            if os.path.isdir(match) and normalized not in seen:
                seen.add(normalized)
                candidates.append(match)

    # 早期 Linux 微信版本（wine/容器方案）使用的数据路径
    old_path = os.path.expanduser("~/.local/share/weixin/data/db_storage")
    if os.path.isdir(old_path):
        normalized = os.path.normcase(os.path.normpath(old_path))
        if normalized not in seen:
            candidates.append(old_path)

    # 优先使用最近活跃账号：按 message 目录 mtime 降序（近似排序，best-effort）
    def _mtime(path):
        msg_dir = os.path.join(path, "message")
        target = msg_dir if os.path.isdir(msg_dir) else path
        try:
            return os.path.getmtime(target)
        except OSError:
            return 0

    candidates.sort(key=_mtime, reverse=True)
    return _choose_candidate(candidates)


def auto_detect_db_dir():
    if _SYSTEM == "windows":
        return _auto_detect_db_dir_windows()
    if _SYSTEM == "linux":
        return _auto_detect_db_dir_linux()
    return None


def load_config():
    cfg = {}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE) as f:
                cfg = json.load(f)
        except json.JSONDecodeError:
            print(f"[!] {CONFIG_FILE} 格式损坏，将使用默认配置")
            cfg = {}
    cfg = {**_DEFAULT, **cfg}

    # db_dir 缺失或仍为模板值时，尝试自动检测
    db_dir = cfg.get("db_dir", "")
    if not db_dir or db_dir == _DEFAULT_TEMPLATE_DIR or "your_wxid" in db_dir:
        detected = auto_detect_db_dir()
        if detected:
            print(f"[+] 自动检测到微信数据目录: {detected}")
            # 合并默认值并保存
            cfg = {**_DEFAULT, **cfg, "db_dir": detected}
            with open(CONFIG_FILE, "w") as f:
                json.dump(cfg, f, indent=4, ensure_ascii=False)
            print(f"[+] 已保存到: {CONFIG_FILE}")
        else:
            if not os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, "w") as f:
                    json.dump(_DEFAULT, f, indent=4, ensure_ascii=False)
            print(f"[!] 未能自动检测微信数据目录")
            print(f"    请手动编辑 {CONFIG_FILE} 中的 db_dir 字段")
            if _SYSTEM == "linux":
                print("    Linux 默认路径类似: ~/Documents/xwechat_files/<wxid>/db_storage")
            else:
                print(f"    路径可在 微信设置 → 文件管理 中找到")
            sys.exit(1)

    # 将相对路径转为绝对路径
    base = os.path.dirname(os.path.abspath(__file__))
    for key in ("keys_file", "decrypted_dir", "decoded_image_dir"):
        if key in cfg and not os.path.isabs(cfg[key]):
            cfg[key] = os.path.join(base, cfg[key])

    # 自动推导微信数据根目录（db_dir 的上级目录）
    # db_dir 格式: D:\xwechat_files\<wxid>\db_storage
    # base_dir 格式: D:\xwechat_files\<wxid>
    db_dir = cfg.get("db_dir", "")
    if db_dir and os.path.basename(db_dir) == "db_storage":
        cfg["wechat_base_dir"] = os.path.dirname(db_dir)
    else:
        cfg["wechat_base_dir"] = db_dir

    # decoded_image_dir 默认值
    if "decoded_image_dir" not in cfg:
        cfg["decoded_image_dir"] = os.path.join(base, "decoded_images")

    return cfg
