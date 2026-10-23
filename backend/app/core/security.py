"""Security helpers: HMAC fingerprints for deduplication.

SecretLeak never stores raw secret values. To detect "the same secret seen
twice" we store an HMAC-SHA256 keyed with a locally generated random key
(stored outside the database and outside source control). A plain hash would
be vulnerable to offline guessing of low-entropy secrets, so a keyed HMAC is
used instead.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from pathlib import Path

from .config import get_hmac_key_path

_KEY_CACHE: dict[str, bytes] = {}


def get_hmac_key() -> bytes:
    """Load the local HMAC key, generating it on first use.

    The key is random 32 bytes stored as hex in a file with restrictive
    permissions (best effort on Windows). It never leaves the machine and is
    excluded from version control via .gitignore.
    """
    path = get_hmac_key_path()
    cache_key = str(path)
    cached = _KEY_CACHE.get(cache_key)
    if cached is not None:
        return cached

    if path.exists():
        key = path.read_bytes().strip()
        if len(key) < 32:
            raise RuntimeError(
                "HMAC key file is invalid (too short). Delete it to regenerate: "
                f"{path}"
            )
    else:
        key = secrets.token_hex(32).encode("ascii")
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.with_suffix(path.suffix + ".tmp")
        tmp_path.write_bytes(key)
        try:  # best effort; Windows permission model differs from POSIX
            os.chmod(tmp_path, 0o600)
        except OSError:
            pass
        tmp_path.replace(path)

    _KEY_CACHE[cache_key] = key
    return key


def fingerprint(rule_id: str, value: str) -> str:
    """Keyed, stable fingerprint for a secret value. Reversible only with the key."""
    mac = hmac.new(get_hmac_key(), f"{rule_id}:{value}".encode("utf-8"), hashlib.sha256)
    return mac.hexdigest()[:32]


def clear_key_cache() -> None:
    """Testing helper: forget cached keys (used when tests change the key path)."""
    _KEY_CACHE.clear()
