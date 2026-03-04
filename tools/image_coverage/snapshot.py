from collections.abc import Mapping
from typing import Any


def diff_keys(
    old_map: Mapping[str, Any], new_map: Mapping[str, Any]
) -> dict[str, dict[str, Any]]:
    """Return only added/changed keys; keys deleted from new_map are ignored."""
    added = {key: value for key, value in new_map.items() if key not in old_map}
    changed = {
        key: value
        for key, value in new_map.items()
        if key in old_map and old_map[key] != value
    }
    return {"added": added, "changed": changed}
