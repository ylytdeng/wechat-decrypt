from tools.image_coverage.resolve_chat import hash_usernames


def test_hash_usernames_md5_mapping() -> None:
    assert hash_usernames(["alice", "bob"]) == {
        "6384e2b2184bcbf58eccf10ca7a6563c": "alice",
        "9f9d51bc70ef21ca5c14f307980a29d8": "bob",
    }


def test_hash_usernames_empty_input_returns_empty_dict() -> None:
    assert hash_usernames([]) == {}


def test_hash_usernames_non_ascii_username() -> None:
    assert hash_usernames(["中文"]) == {"a7bac2239fcdcb3a067903d8077c4a07": "中文"}


def test_hash_usernames_duplicate_usernames_keep_single_mapping() -> None:
    assert hash_usernames(["alice", "alice"]) == {
        "6384e2b2184bcbf58eccf10ca7a6563c": "alice"
    }
