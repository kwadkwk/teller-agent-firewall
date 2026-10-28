"""Content checks: prompt-injection screening and output DLP."""

from __future__ import annotations

import re
import unicodedata
from typing import Iterable

SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
# 12-19 digit account/card numbers, optionally grouped by spaces or dashes.
ACCOUNT = re.compile(r"\b(?:\d[ -]?){8,15}(\d{4})\b")

# Characters attackers use to hide instructions from a human reader.
_INVISIBLE = {"​", "‌", "‍", "⁠", "﻿"}


def normalize(text: str) -> str:
    """Fold look-alike characters and strip zero-width ones before matching."""
    text = unicodedata.normalize("NFKC", text)
    return "".join(ch for ch in text if ch not in _INVISIBLE)


def find_injection(text: str, patterns: Iterable[re.Pattern[str]]) -> str | None:
    """Return the first matching injection phrase, or None."""
    clean = normalize(text)
    for p in patterns:
        m = p.search(clean)
        if m:
            return m.group(0)
    return None


def has_hidden_characters(text: str) -> bool:
    return any(ch in _INVISIBLE for ch in text)


def mask(text: str, *, accounts: bool = True, ssn: bool = True) -> tuple[str, int]:
    """Mask SSNs and account numbers. Returns (masked_text, number_of_hits)."""
    hits = 0

    def _ssn(_: re.Match[str]) -> str:
        nonlocal hits
        hits += 1
        return "***-**-****"

    def _acct(m: re.Match[str]) -> str:
        nonlocal hits
        hits += 1
        return "•••• " + m.group(1)

    if ssn:
        text = SSN.sub(_ssn, text)
    if accounts:
        text = ACCOUNT.sub(_acct, text)
    return text, hits
