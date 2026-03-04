import hashlib


def hash_usernames(usernames: list[str]) -> dict[str, str]:
    return {
        hashlib.md5(username.encode("utf-8")).hexdigest(): username
        for username in usernames
    }
