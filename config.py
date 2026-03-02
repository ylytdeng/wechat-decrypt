"""
配置加载器 - 从 config.json 读取路径配置
首次运行时自动生成 config.json 模板
"""
import json
import os
import sys

CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

_DEFAULT = {
    "db_dir": r"D:\xwechat_files\your_wxid\db_storage",
    "keys_file": "all_keys.json",
    "decrypted_dir": "decrypted",
    "wechat_process": "Weixin.exe",
    "image_key": "",
    "decrypted_images_dir": "decrypted_images",
}


def load_config():
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "w") as f:
            json.dump(_DEFAULT, f, indent=4)
        print(f"[!] 已生成配置文件: {CONFIG_FILE}")
        print("    请修改 config.json 中的路径后重新运行")
        sys.exit(1)

    with open(CONFIG_FILE) as f:
        cfg = json.load(f)

    # 将相对路径转为绝对路径
    base = os.path.dirname(os.path.abspath(__file__))
    for key in ("keys_file", "decrypted_dir"):
        if key in cfg and not os.path.isabs(cfg[key]):
            cfg[key] = os.path.join(base, cfg[key])

    # Image decryption defaults
    cfg.setdefault("image_key", "")
    cfg.setdefault("decrypted_images_dir", "decrypted_images")
    if "decrypted_images_dir" in cfg and not os.path.isabs(cfg["decrypted_images_dir"]):
        cfg["decrypted_images_dir"] = os.path.join(base, cfg["decrypted_images_dir"])
    # Auto-derive image cache dir from db_dir
    if "db_dir" in cfg:
        parent = os.path.dirname(cfg["db_dir"])
        cfg["image_dir"] = os.path.join(parent, "msg")

    return cfg
