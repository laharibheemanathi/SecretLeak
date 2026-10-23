"""Placeholder filtering and redaction (masking) helpers.

Central rules:

* Values that are obviously placeholders/dummy data are never reported.
* Everything surfaced to a human is masked first; the engine holds raw values
  in memory only long enough to compute a masked preview, a redacted context
  snippet and an HMAC fingerprint.
"""

from __future__ import annotations

import re

BULLET = "\u2022"

# Token prefixes we keep visible in masked previews (shape hints, not secrets).
KNOWN_TOKEN_PREFIXES: tuple[str, ...] = (
    "github_pat_",
    "ghp_", "gho_", "ghu_", "ghs_", "ghr_",
    "glpat-", "glptt-", "glrt-",
    "xoxb-", "xoxp-", "xoxa-", "xoxs-", "xoxe-",
    "sk_live_", "pk_live_", "rk_live_",
    "AKIA", "ASIA",
)

_PEM_HEADER_RE = re.compile(r"-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?)PRIVATE KEY-----")

# A full PEM block appearing inside a context snippet must be masked wholesale.
_PEM_IN_TEXT_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)

# Anything shaped like a provider token or JWT gets masked inside context snippets.
_TOKENISH_RE = re.compile(
    r"(?:github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}"
    r"|(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}"
    r"|glpat-[A-Za-z0-9_-]{20,}"
    r"|xox[baprse]-[A-Za-z0-9-]{10,}"
    r"|hooks\.slack\.com/services/\S+"
    r"|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"
    r"|\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b)"
)

# --- Placeholder detection -----------------------------------------------------

_PLACEHOLDER_SUBSTRINGS = (
    "your_", "your-", "you-", "example", "placeholder", "change_me", "changeme",
    "change-this", "changeit", "change_it", "redacted", "dummy", "fake", "sample",
    "insert_", "insert-", "replace_", "replace-", "xxxx", "aaaa",
    "password", "secret_value", "token_here", "key_here", "value_here", "not_a_",
    "notreal", "not-real", "secret123", "admin123", "qwerty", "todo", "fixme",
    "<your", "<<", "****",
)

_PLACEHOLDER_EXACT = {
    "", "-", "--", "*", "**", "********", "null", "none", "nil", "true", "false",
    "n/a", "na", "str", "string", "int", "var", "value", "undefined", "notset",
    "not set", "password", "secret", "token", "apikey", "api_key", "redacted",
    "example", "sample", "test", "testing", "dummy", "changeme", "hunter2",
}

_ENV_REFERENCE_RE = re.compile(
    r"^(?:"
    r"\$\{[^}]+\}"        # ${VAR}
    r"|\$[A-Za-z_][A-Za-z0-9_]*"   # $VAR
    r"|%[A-Za-z0-9_]+%"   # %VAR% (Windows)
    r"|\{\{[^}]+\}\}"     # {{var}}
    r"|<[^>]+>"           # <your-key-here>
    r"|\(\([^)]+\)\)"     # ((var))
    r"|process\.env\b.*"  # process.env.SOMETHING
    r"|os\.environ.*"     # os.environ.get(...)
    r"|env\(\)?[A-Za-z_]*"
    r"|[A-Z_][A-Z0-9_]*\.(?:get|fetch|read)\(.*"
    r")$"
)

_RUNTIME_CALL_RE = re.compile(r"^(?:input|getpass|read|prompt|new PasswordSpec)\(.*$")
_ALL_SAME_CHAR_RE = re.compile(r"^(.)\1*$")
_ALL_DIGITS_RE = re.compile(r"^\d+$")


def is_placeholder(value: str) -> bool:
    """True when the value is obviously a placeholder, dummy or runtime reference."""
    v = value.strip().strip("\"'`").strip()
    if len(v) < 6:
        return True
    if v.lower() in _PLACEHOLDER_EXACT:
        return True
    lowered = v.lower()
    if any(s in lowered for s in _PLACEHOLDER_SUBSTRINGS):
        return True
    if _ENV_REFERENCE_RE.match(v) or _ENV_REFERENCE_RE.match(lowered):
        return True
    if _RUNTIME_CALL_RE.match(v):
        return True
    if _ALL_SAME_CHAR_RE.match(v):
        return True
    if _ALL_DIGITS_RE.match(v) and len(v) < 16:
        return True
    # Dotted module paths / code expressions are not secrets.
    if re.fullmatch(r"[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)+", v):
        return True
    return False


# --- Masking -------------------------------------------------------------------


def mask_secret(value: str) -> str:
    """Return a safe masked preview. Never returns the raw value."""
    v = value.strip()
    if not v:
        return ""
    pem = _PEM_HEADER_RE.match(v)
    if pem:
        key_type = pem.group(1).strip()
        label = f"{key_type} " if key_type else ""
        return f"-----BEGIN {label}PRIVATE KEY-----{BULLET * 8}"
    for prefix in KNOWN_TOKEN_PREFIXES:
        if v.startswith(prefix) and len(v) > len(prefix):
            return prefix + BULLET * 16
    if len(v) <= 4:
        return BULLET * max(len(v), 1)
    return v[:4] + BULLET * 16


def mask_value_in_text(text: str, value: str) -> str:
    """Replace every occurrence of *value* in text with its masked form."""
    if not value:
        return text
    return text.replace(value, mask_secret(value))


def _mask_pem_lines(snippet: str) -> str:
    """Redact PEM block interiors line by line.

    A context window may contain a key block without both delimiters visible,
    so a regex across delimiters is not enough. Tracks BEGIN/END state and
    blanks every line inside a block (markers like '>> ' are preserved).
    """
    out: list[str] = []
    inside = False
    for line in snippet.splitlines():
        stripped = line.lstrip(" >*")
        prefix = line[: len(line) - len(stripped)]
        if stripped.startswith("-----BEGIN") and "PRIVATE KEY" in stripped:
            inside = True
            out.append(prefix + mask_secret(stripped) + " [key material redacted]")
        elif inside and stripped.startswith("-----END"):
            inside = False
            out.append(prefix + stripped)
        elif inside:
            out.append(prefix + "[key material redacted]")
        else:
            out.append(line)
    return "\n".join(out)


def redact_context_snippet(
    snippet: str,
    all_secret_values: list[str],
) -> str:
    """Redact known secret values and token-shaped strings inside a context snippet.

    Applied defensively: every raw value detected in the same scan is masked, plus
    anything that merely looks like a provider token or JWT.
    """
    result = _mask_pem_lines(snippet)
    # Longest values first so substrings do not leave fragments behind.
    for value in sorted({v for v in all_secret_values if len(v) >= 6}, key=len, reverse=True):
        result = result.replace(value, mask_secret(value))
    result = _TOKENISH_RE.sub(lambda m: mask_secret(m.group(0)), result)
    return result
