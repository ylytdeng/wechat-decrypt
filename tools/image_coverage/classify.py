def classify_magic(head: bytes) -> str:
    if head.startswith(b"\xff\xd8\xff"):
        return "jpg"
    return "unknown"
