"""Lexical Windows metadata basename validation; no filesystem access or authority.

This deliberately accepts only a single component. It does not authorize any
root, resolve a file, check a junction, or replace handle-relative traversal.
"""

import re

_RESERVED = frozenset({"CON", "PRN", "AUX", "NUL"}
                      | {f"COM{i}" for i in range(1, 10)}
                      | {f"LPT{i}" for i in range(1, 10)})
_SUPERSCRIPT_DIGITS = str.maketrans({"¹": "1", "²": "2", "³": "3"})


def validate_windows_metadata_basename(value):
    """Return a single safe lexical component or raise ValueError.

    Caller-owned root authorization and native no-reparse open are separate
    mandatory gates. This function must never be used as containment evidence.
    """
    if not isinstance(value, str) or not value:
        raise ValueError("metadata basename must be a nonempty string")
    if len(value) > 255:
        raise ValueError("metadata basename too long")
    if value in (".", "..") or value[-1] in " .":
        raise ValueError("metadata basename has forbidden dot or trailing character")
    if re.search(r'[<>:"/\\|?*\x00-\x1f]', value):
        raise ValueError("metadata basename has forbidden Windows character")
    stem = value.split(".", 1)[0].upper().translate(_SUPERSCRIPT_DIGITS)
    if stem in _RESERVED:
        raise ValueError("metadata basename names a reserved Windows device")
    return value
