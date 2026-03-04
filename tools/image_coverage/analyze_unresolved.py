from collections import Counter
from pathlib import Path


_TYPE_KEYS = ("orig", "thumb", "hd")


def _detect_type(file_name: str) -> str:
    if file_name.endswith("_t.bin"):
        return "thumb"
    if file_name.endswith("_h.bin"):
        return "hd"
    return "orig"


def summarize_unresolved(decrypted_images_dir: Path | str) -> dict[str, object]:
    base_dir = Path(decrypted_images_dir)
    attach_dir = base_dir / "attach"

    by_hash: Counter[str] = Counter()
    by_month: Counter[str] = Counter()
    by_type: Counter[str] = Counter({key: 0 for key in _TYPE_KEYS})
    total_unresolved = 0

    if attach_dir.exists():
        for image_file in attach_dir.glob("*/*/Img/*.bin"):
            month = image_file.parent.parent.name
            hash_value = image_file.parent.parent.parent.name
            file_type = _detect_type(image_file.name)

            total_unresolved += 1
            by_hash[hash_value] += 1
            by_month[month] += 1
            by_type[file_type] += 1

    return {
        "total_unresolved": total_unresolved,
        "by_hash": dict(sorted(by_hash.items())),
        "by_month": dict(sorted(by_month.items())),
        "by_type": {key: by_type[key] for key in _TYPE_KEYS},
    }
