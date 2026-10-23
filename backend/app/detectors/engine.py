"""The detection engine: turns text into redacted, fingerprinted findings.

Pipeline:
1. Run every regex rule over the input.
2. Apply placeholder filtering (dummy values never surface).
3. Run the optional generic high-entropy heuristic.
4. Resolve overlapping matches by rule priority (private keys beat everything,
   provider formats beat generic assignments).
5. Deduplicate identical findings at identical locations.
6. Build masked previews, redacted context snippets and HMAC fingerprints —
   raw values never leave this module except transiently in memory.

A pattern match never proves a credential is valid.
"""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass

from ..core.security import fingerprint
from .entropy import MIN_ENTROPY_DEFAULT, is_high_entropy_candidate, shannon_entropy
from .redaction import is_placeholder, mask_secret, redact_context_snippet
from .rules import (
    ENTROPY_RULE_META,
    RULES,
    Rule,
)

MAX_INPUT_CHARS = 2_000_000  # defensive cap; the API enforces smaller limits
CONTEXT_LINES = 2
MAX_LINE_CHARS = 300

_TOKEN_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/=_\-]{32,128}")
_PEM_END_RE = re.compile(r"^-----END (?:[A-Z0-9 ]+)?PRIVATE KEY-----\s*$", re.MULTILINE)

_RULES_COMPILED: list[tuple[Rule, re.Pattern[str]]] = [
    (rule, re.compile(rule.pattern)) for rule in RULES if not rule.multiline
]


@dataclass
class RawMatch:
    rule: Rule
    start: int
    end: int
    value: str
    line: int  # 1-based
    column: int  # 1-based


@dataclass
class FindingDraft:
    rule_id: str
    rule_name: str
    category: str
    severity: str
    confidence: str
    label: str
    line: int
    column: int
    masked_preview: str
    context_snippet: str
    remediation: str
    description: str
    why_severity: str
    fingerprint: str


def _line_index(text: str) -> tuple[list[int], list[int]]:
    """Start offsets of every line (for 1-based line/col lookup)."""
    starts = [0]
    lengths = []
    for idx, ch in enumerate(text):
        if ch == "\n":
            lengths.append(idx + 1 - starts[-1])
            starts.append(idx + 1)
    lengths.append(len(text) + 1 - starts[-1])
    return starts, lengths


def _line_col(starts: list[int], offset: int) -> tuple[int, int]:
    line_idx = bisect.bisect_right(starts, offset) - 1
    return line_idx + 1, offset - starts[line_idx] + 1


def _overlaps(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    return a_start < b_end and b_start < a_end


def _resolve_overlaps(matches: list[RawMatch]) -> list[RawMatch]:
    """Keep the highest-priority rule wherever matches overlap."""
    ordered = sorted(
        matches, key=lambda m: (m.start, -(m.end - m.start), -m.rule.priority)
    )
    kept: list[RawMatch] = []
    for match in ordered:
        drop = False
        remove: list[RawMatch] = []
        for existing in kept:
            if _overlaps(match.start, match.end, existing.start, existing.end):
                if existing.rule.priority >= match.rule.priority:
                    drop = True  # equal-priority overlap counts as duplicate
                    break
                remove.append(existing)
        if not drop:
            for doomed in remove:
                kept.remove(doomed)
            kept.append(match)
    return kept


def _find_pem_block_end(text: str, start: int) -> int:
    """End offset of the PEM block (through the END line), capped for safety."""
    end_match = _PEM_END_RE.search(text, start)
    if end_match:
        return min(end_match.end(), start + 16_384)
    newline = text.find("\n", start)
    return newline + 1 if newline != -1 else len(text)


def _collect_matches(
    text: str,
    starts: list[int],
    entropy_enabled: bool,
    entropy_threshold: float,
) -> list[RawMatch]:
    matches: list[RawMatch] = []

    # Multiline private-key blocks first (they suppress everything inside).
    pem_rule = next(r for r in RULES if r.multiline)
    pem_regex = re.compile(pem_rule.pattern)
    for m in pem_regex.finditer(text):
        header = m.group(0)
        end = _find_pem_block_end(text, m.start())
        line, column = _line_col(starts, m.start())
        matches.append(
            RawMatch(rule=pem_rule, start=m.start(), end=end, value=header,
                     line=line, column=column)
        )

    for rule, compiled in _RULES_COMPILED:
        for m in compiled.finditer(text):
            try:
                value = m.group(rule.value_group)
            except IndexError:
                value = m.group(0)
            if value is None:
                value = m.group(0)
            value = value.strip()
            if not value or is_placeholder(value):
                continue
            if rule.entropy_gate is not None and shannon_entropy(value) < rule.entropy_gate:
                continue
            line, column = _line_col(
                starts, m.start(rule.value_group) if rule.value_group else m.start()
            )
            matches.append(
                RawMatch(rule=rule, start=m.start(), end=m.end(), value=value,
                         line=line, column=column)
            )

    if entropy_enabled:
        entropy_rule = ENTROPY_RULE_META
        for m in _TOKEN_CANDIDATE_RE.finditer(text):
            value = m.group(0)
            if is_placeholder(value):
                continue
            if not is_high_entropy_candidate(value, entropy_threshold):
                continue
            line, column = _line_col(starts, m.start())
            matches.append(
                RawMatch(rule=entropy_rule, start=m.start(), end=m.end(), value=value,
                         line=line, column=column)
            )

    return matches


def _clip(line: str, limit: int = MAX_LINE_CHARS) -> str:
    return line if len(line) <= limit else line[: limit - 1] + "\u2026"


def _build_context(
    text: str,
    match: RawMatch,
    starts: list[int],
    total_lines: int,
    all_values: list[str],
    is_pem: bool,
) -> str:
    line_idx = match.line - 1
    first = max(0, line_idx - CONTEXT_LINES)
    last = min(total_lines - 1, line_idx + CONTEXT_LINES)

    if is_pem:
        # Header line only — never slice far enough to touch the key body.
        line_start = starts[line_idx]
        line_end = starts[line_idx + 1] if line_idx + 1 < len(starts) else len(text)
        header = _clip(text[line_start:line_end].rstrip("\r\n"))
        body_lines = max(0, text.count("\n", match.start, match.end) - 1)
        return f"{header}\n[{body_lines} lines of key material redacted by SecretLeak]"

    lines_out: list[str] = []
    for idx in range(first, last + 1):
        line_start = starts[idx]
        line_end = starts[idx + 1] if idx + 1 < len(starts) else len(text)
        raw_line = text[line_start:line_end].rstrip("\r")
        marker = ">> " if idx == line_idx else "   "
        lines_out.append(marker + _clip(raw_line))
    return redact_context_snippet("\n".join(lines_out), all_values)


def scan_text(
    text: str,
    label: str = "input",
    *,
    entropy_enabled: bool = True,
    entropy_threshold: float = MIN_ENTROPY_DEFAULT,
) -> list[FindingDraft]:
    """Scan text and return redacted, fingerprinted findings (raw values discarded)."""
    if not text:
        return []
    if len(text) > MAX_INPUT_CHARS:
        text = text[:MAX_INPUT_CHARS]

    starts, _lengths = _line_index(text)
    raw = _collect_matches(text, starts, entropy_enabled, entropy_threshold)
    kept = _resolve_overlaps(raw)

    # Dedupe: same rule + same secret + same location.
    seen: set[tuple] = set()
    unique: list[RawMatch] = []
    for match in kept:
        key = (match.rule.id, fingerprint(match.rule.id, match.value), match.line, match.column)
        if key in seen:
            continue
        seen.add(key)
        unique.append(match)

    # All raw values from this scan, so contexts redact neighbouring secrets too.
    all_values = [m.value for m in unique if len(m.value) >= 6]

    drafts: list[FindingDraft] = []
    for match in unique:
        rule = match.rule
        is_pem = rule.multiline
        masked = mask_secret(match.value)
        if is_pem:
            body_lines = max(0, text.count("\n", match.start, match.end) - 1)
            masked = f"{mask_secret(match.value)} ({body_lines} lines redacted)"
        context = _build_context(text, match, starts, len(starts), all_values, is_pem)
        drafts.append(
            FindingDraft(
                rule_id=rule.id,
                rule_name=rule.name,
                category=rule.category,
                severity=rule.severity,
                confidence=rule.confidence,
                label=label,
                line=match.line,
                column=match.column,
                masked_preview=masked,
                context_snippet=context,
                remediation=rule.remediation,
                description=rule.description,
                why_severity=rule.why_severity,
                fingerprint=fingerprint(rule.id, match.value),
            )
        )

    drafts.sort(key=lambda d: (d.line, d.column, d.rule_id))
    return drafts
