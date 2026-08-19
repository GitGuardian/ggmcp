"""Shared grammar for the custom-tag "key" / "key:value" format.

Both the global custom-tag library tool (write_custom_tags) and the
incident-scoped tool (manage_incident_custom_tags) rely on this single
parser so the tag format is defined in exactly one place.
"""

__all__ = ["parse_tag"]


def parse_tag(tag: str) -> tuple[str, str | None]:
    """Split "key" or "key:value" into a whitespace-stripped (key, value) pair.

    Args:
        tag: The raw tag string to parse.

    Returns:
        A (key, value) tuple; an empty value becomes None.

    Raises:
        ValueError: If the key is empty after stripping.
    """
    key, _, value = tag.partition(":")
    key = key.strip()
    if not key:
        raise ValueError(f"Custom tag key cannot be empty: {tag!r}")
    return key, value.strip() or None
