"""Shannon entropy helpers for generic high-entropy secret candidates.

Entropy alone never proves a string is a secret — it only helps rank weak,
generic matches (severity LOW). Strings that merely look random (hashes,
commit ids, UUIDs, build artifacts) are explicitly excluded.
"""

from __future__ import annotations

import math
import re
from collections import Counter

MIN_ENTROPY_DEFAULT = 4.5  # bits per character, for base64/hex-like strings

# Strings that look random but are routine development artifacts.
_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$|^7[0-9a-f]{38}$")
_MD5_RE = re.compile(r"^[0-9a-f]{32}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_BASE64_DATA_URI_RE = re.compile(r"^data:")
_LONG_DIGITS_RE = re.compile(r"^\d{20,}$")
_REPEATING_RE = re.compile(r"^(..)\1{8,}$")


def shannon_entropy(text: str) -> float:
    """Bits of entropy per character (Shannon formula)."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def looks_like_common_artifact(value: str) -> bool:
    """True for hashes, UUIDs and other non-secret random-looking strings."""
    v = value.strip()
    if _GIT_SHA_RE.match(v) or _MD5_RE.match(v) or _SHA256_RE.match(v):
        return True
    if _UUID_RE.match(v):
        return True
    if _BASE64_DATA_URI_RE.match(v):
        return True
    if _LONG_DIGITS_RE.match(v):
        return True
    if _REPEATING_RE.match(v):
        return True
    return False


def is_high_entropy_candidate(value: str, threshold: float = MIN_ENTROPY_DEFAULT) -> bool:
    """Whether a string qualifies as a generic high-entropy secret candidate."""
    v = value.strip()
    if len(v) < 24 or len(v) > 128:
        return False
    if looks_like_common_artifact(v):
        return False
    # Must have mixed character classes; pure-alpha "words" are usually prose.
    has_digit = any(ch.isdigit() for ch in v)
    has_upper = any(ch.isupper() for ch in v)
    has_lower = any(ch.islower() for ch in v)
    if not (has_digit and (has_upper or has_lower)):
        return False
    return shannon_entropy(v) >= threshold
