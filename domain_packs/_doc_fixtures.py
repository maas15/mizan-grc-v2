"""Deterministic E2E fixtures per document type (REL2.1)."""

from __future__ import annotations

from copy import deepcopy
from typing import Dict

from domains import _fixtures_shared as _fx
from domains.cyber import fixtures_ar as cyber_ar
from domains.cyber import fixtures_en as cyber_en


def _base_strategy(domain_code: str, lang: str) -> Dict[str, str]:
    if domain_code == 'cyber':
        fx = cyber_ar if lang == 'ar' else cyber_en
        return deepcopy(fx.technical_sections())
    mapping = {
        'data': _fx.DATA_SECTIONS,
        'ai': _fx.AI_SECTIONS,
        'dt': _fx.DT_SECTIONS,
        'erm': _fx.ERM_SECTIONS,
        'global': _fx.GLOBAL_SECTIONS,
    }
    raw = mapping.get(domain_code, _fx.DATA_SECTIONS)
    return deepcopy(_fx.ar_mirror(raw) if lang == 'ar' else raw)


def sections_for_document(
        domain_code: str, lang: str, document_type: str) -> Dict[str, str]:
    base = _base_strategy(domain_code, lang)
    dt = (document_type or 'strategy').strip().lower()
    if dt == 'strategy':
        return base

    # Cyber must preserve canonical SO/KPI/roadmap tables for PR-CY89.
    if domain_code == 'cyber':
        sec = deepcopy(base)
        if dt == 'policy':
            note = (
                '## Policy scope\n\nBoard-approved policy scope.\n\n'
                if lang == 'en'
                else '## نطاق السياسة\n\nنطاق السياسة المعتمد.\n\n')
            sec['vision'] = note + sec['vision']
        elif dt == 'procedure':
            note = (
                '## Procedure scope\n\nOperational procedure steps.\n\n'
                if lang == 'en'
                else '## نطاق الإجراء\n\nخطوات الإجراء التشغيلي.\n\n')
            sec['vision'] = note + sec['vision']
        elif dt == 'risk_register':
            extra = (
                '| ID | Risk | Owner | Treatment |\n|---|---|---|---|\n'
                '| R1 | Operational | CRO | Mitigate |\n\n'
            )
            sec['gaps'] = extra + (sec.get('gaps') or '')
        elif dt in ('audit', 'assessment'):
            sec['gaps'] = (
                '| # | Finding | Severity |\n|---|---|\n| 1 | Gap | High |\n\n'
                + (sec.get('gaps') or ''))
        elif dt == 'executive_summary':
            sec['vision'] = (
                ('## Executive Summary\n\n' if lang == 'en'
                 else '## ملخص تنفيذي\n\n')
                + sec['vision'])
        return sec

    sec = deepcopy(base)
    if dt == 'policy':
        sec['vision'] = (
            ('## 1. سياسة\n\n' if lang == 'ar' else '## 1. Policy\n\n')
            + sec.get('vision', '').split('\n\n', 1)[-1])
    elif dt == 'procedure':
        sec['vision'] = (
            ('## 1. إجراء\n\n' if lang == 'ar' else '## 1. Procedure\n\n')
            + sec.get('vision', '').split('\n\n', 1)[-1])
    elif dt == 'risk_register':
        sec['vision'] = (
            ('## 1. سجل المخاطر\n\n' if lang == 'ar' else '## 1. Risk Register\n\n')
            + '| ID | Risk | Owner | Treatment |\n|---|---|---|---|\n'
            + '| R1 | Ops risk | CRO | Mitigate |\n'
            + sec.get('vision', '').split('\n\n', 1)[-1][:200])
    elif dt in ('audit', 'assessment'):
        sec['gaps'] = (
            '| # | Finding | Severity |\n|---|---|\n| 1 | Gap | High |\n\n'
            + (sec.get('gaps') or ''))
    elif dt == 'executive_summary':
        sec['vision'] = (
            ('## 1. ملخص تنفيذي\n\n' if lang == 'ar'
             else '## 1. Executive Summary\n\n')
            + 'Board decision summary.\n'
            + sec.get('vision', ''))
    return sec
