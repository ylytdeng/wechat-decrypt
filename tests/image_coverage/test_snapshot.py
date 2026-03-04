from tools.image_coverage.snapshot import diff_keys


def test_diff_keys_reports_added_entries() -> None:
    old_map = {"existing": "same", "updated": "old-value"}
    new_map = {"existing": "same", "updated": "new-value", "added": "new-entry"}

    diff = diff_keys(old_map, new_map)

    assert diff == {
        "added": {"added": "new-entry"},
        "changed": {"updated": "new-value"},
    }


def test_diff_keys_returns_empty_for_identical_maps() -> None:
    old_map = {"existing": "same", "unchanged": "value"}
    new_map = {"existing": "same", "unchanged": "value"}

    diff = diff_keys(old_map, new_map)

    assert diff == {"added": {}, "changed": {}}


def test_diff_keys_ignores_deleted_entries() -> None:
    old_map = {"kept": "same", "removed": "old-value"}
    new_map = {"kept": "same"}

    diff = diff_keys(old_map, new_map)

    assert diff == {"added": {}, "changed": {}}
