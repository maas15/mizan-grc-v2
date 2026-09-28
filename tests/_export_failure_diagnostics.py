"""Sanitized export-failure diagnostics for clean-runner PDF refusals.

Retain status/error/blocking codes and candidate identity so a refused
PDF cannot collapse to raw=b''. Never persist font files, cookies,
passwords, Authorization values, or CSRF secrets.
"""
from __future__ import annotations

import io
import json
import os
import re
import sys
from typing import Any, Dict, Iterable, List, Mapping, Optional

_SECRET_KEYS = {
    'admin_password',
    'authorization',
    'cookie',
    'cookies',
    'csrf',
    'csrf_token',
    'openai_api_key',
    'password',
    'password_hash',
    'secret',
    'secret_key',
    'token',
    'x-csrftoken',
}
_SECRET_SUBSTR = (
    'password', 'secret', 'authorization', 'cookie', 'csrf', 'token', 'api_key',
)
_GATE_RE = re.compile(
    r'\[REL37-RETURNED-BYTES-GATE\].*?errors=(\[[^\]]*\])'
)
_BLOCKER_RE = re.compile(r"'(pdf_[a-z0-9_:]+)'")


def diagnostic_dir() -> str:
    path = os.environ.get('REL37_EXPORT_DIAG_DIR')
    if not path:
        path = os.path.join(
            os.environ.get('RUNNER_TEMP') or '/tmp',
            'rel37_export_diagnostics',
        )
    os.makedirs(path, exist_ok=True)
    return path


def sanitize(value: Any) -> Any:
    if isinstance(value, Mapping):
        out = {}
        for key, item in value.items():
            name = str(key).lower()
            if name in _SECRET_KEYS or any(part in name for part in _SECRET_SUBSTR):
                continue
            out[str(key)] = sanitize(item)
        return out
    if isinstance(value, list):
        return [sanitize(item) for item in value[:32]]
    if isinstance(value, tuple):
        return [sanitize(item) for item in value[:32]]
    if isinstance(value, bytes):
        return {'hex_prefix': value[:8].hex(), 'len': len(value)}
    if isinstance(value, str):
        return value[:500]
    if value is None or isinstance(value, (int, float, bool)):
        return value
    return str(value)[:200]


def blocking_errors_from_text(text: str) -> List[str]:
    found: List[str] = []
    for match in _GATE_RE.finditer(text or ''):
        found.extend(_BLOCKER_RE.findall(match.group(1)))
    for match in re.finditer(r'pdf_environment_[a-z0-9_]+:[0-9]+', text or ''):
        if match.group(0) not in found:
            found.append(match.group(0))
    return found


class _Tee(io.TextIOBase):
    def __init__(self, primary, secondary) -> None:
        self._primary = primary
        self._secondary = secondary

    def write(self, data: str) -> int:
        self._primary.write(data)
        self._secondary.write(data)
        return len(data)

    def flush(self) -> None:
        self._primary.flush()
        self._secondary.flush()


class StdoutCapture:
    def __init__(self) -> None:
        self._buf = io.StringIO()
        self._saved = None
        self.text = ''

    def __enter__(self) -> 'StdoutCapture':
        self._saved = sys.stdout
        sys.stdout = _Tee(self._saved, self._buf)
        return self

    def __exit__(self, *exc: Any) -> None:
        sys.stdout = self._saved
        self.text = self._buf.getvalue()


def build_export_diagnostic(
        *,
        submit_http: int,
        submit: Mapping[str, Any],
        status: Mapping[str, Any],
        raw: bytes,
        stdout_text: str = '',
        model_hash: str = '',
        font_path: str = '',
        fmt: str = '',
) -> Dict[str, Any]:
    blockers = []
    for source in (
            status.get('blocking_errors'),
            submit.get('blocking_errors'),
            blocking_errors_from_text(stdout_text),
    ):
        if isinstance(source, Iterable) and not isinstance(source, (str, bytes)):
            for item in source:
                token = str(item)
                if token and token not in blockers:
                    blockers.append(token)
    payload = {
        'submit_http': submit_http,
        'submit': sanitize(submit),
        'status': sanitize(status),
        'status_name': status.get('status'),
        'error': str(status.get('error') or '')[:300],
        'blocking_errors': blockers,
        'raw_len': len(raw or b''),
        'raw_prefix': (raw or b'')[:8].hex(),
        'model_hash': model_hash,
        'font_path': font_path,
        'fmt': fmt,
        'candidate_bytes_retained': False,
    }
    return payload


def persist_export_diagnostic(payload: Mapping[str, Any], stem: str) -> str:
    safe = ''.join(ch if ch.isalnum() or ch in '-_' else '_' for ch in stem)[:80]
    path = os.path.join(diagnostic_dir(), f'{safe}.json')
    with open(path, 'w', encoding='utf-8') as handle:
        json.dump(sanitize(payload), handle, ensure_ascii=False, indent=2)
        handle.write('\n')
    return path
