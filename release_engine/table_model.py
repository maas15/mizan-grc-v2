"""Table extraction helpers for scoped validators."""

from __future__ import annotations

import re
from typing import List

_TABLE_ROW_RE = re.compile(r'^\s*\|', re.MULTILINE)


def count_markdown_table_rows(text: str) -> int:
    if not text:
        return 0
    rows = [ln for ln in text.splitlines() if _TABLE_ROW_RE.match(ln)]
    data = [r for r in rows if not re.match(r'^\s*\|[\s\-:|]+\|\s*$', r)]
    return max(0, len(data) - 1)


def has_table(text: str) -> bool:
    return count_markdown_table_rows(text) >= 1
