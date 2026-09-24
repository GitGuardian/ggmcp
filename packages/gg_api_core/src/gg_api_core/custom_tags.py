__all__ = ["parse_tag"]


def parse_tag(tag: str) -> tuple[str, str | None]:
    key, _, value = tag.partition(":")
    key = key.strip()
    if not key:
        raise ValueError(f"Custom tag key cannot be empty: {tag!r}")
    return key, value.strip() or None
