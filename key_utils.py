import os


def strip_key_metadata(keys):
    """移除 all_keys.json 中以下划线开头的元数据字段。"""
    return {k: v for k, v in keys.items() if not k.startswith("_")}


def key_path_variants(rel_path):
    """生成同一路径的多种分隔符表示，兼容 Windows/Linux JSON key。"""
    normalized = rel_path.replace("\\", "/")
    variants = []
    for candidate in (
        rel_path,
        normalized,
        normalized.replace("/", "\\"),
        normalized.replace("/", os.sep),
    ):
        if candidate not in variants:
            variants.append(candidate)
    return variants


def get_key_info(keys, rel_path):
    """按相对路径查找数据库密钥，自动兼容不同平台分隔符。"""
    for candidate in key_path_variants(rel_path):
        if candidate in keys and not candidate.startswith("_"):
            return keys[candidate]
    return None
