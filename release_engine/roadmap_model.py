"""PR-REL2.3 — final roadmap model for Cyber strategy."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

ROADMAP_FAMILIES = (
    'governance_ciso',
    'governance_committee',
    'soc_siem',
    'iam_pam_mfa',
    'csirt_incident_response',
    'vulnerability_management',
    'awareness_training',
    'backup_dr_resilience',
    'data_classification',
    'encryption_key_management',
    'dlp',
    'sensitive_data_handling',
)

FORBIDDEN_OWNERS = frozenset({
    'Threat Intelligence',
    'Data Protection',
    'المسؤول',
    'مسؤول',
    'Owner',
    'owner',
    'Team',
    'team',
    '',
})

_INSTITUTIONAL_OWNERS = (
    'CISO / الإدارة العليا',
    'مدير SOC',
    'مدير IAM/PAM',
    'قائد CSIRT',
    'مدير الثغرات',
    'مدير التوعية',
    'مدير استمرارية الأعمال',
    'مدير حماية البيانات',
    'مدير الامتثال',
)

_ROADMAP_CATALOG_AR = {
    'governance_ciso': [
        'المرحلة 1: تأسيس', '1-6 أشهر',
        'تأسيس إدارة الأمن السيبراني وتعيين CISO',
        'CISO / الإدارة العليا', 'هيكل CISO ولجنة حوكمة معتمدة', 'NCA ECC',
    ],
    'governance_committee': [
        'المرحلة 1: تأسيس', '1-6 أشهر',
        'تفعيل لجنة حوكمة الأمن السيبراني',
        'CISO / الإدارة العليا', 'ميثاق لجنة حوكمة ومصفوفة RACI معتمدة', 'NCA ECC',
    ],
    'soc_siem': [
        'المرحلة 2: تمكين وتشغيل', '7-18 شهر', 'تشغيل SOC وSIEM',
        'مدير SOC', 'مركز SOC تشغيلي مع تغطية SIEM', 'NCA ECC',
    ],
    'iam_pam_mfa': [
        'المرحلة 2: تمكين وتشغيل', '7-18 شهر', 'تطبيق IAM/PAM/MFA',
        'مدير IAM/PAM', 'منصة IAM/PAM مع MFA للحسابات الحرجة', 'NCA ECC',
    ],
    'csirt_incident_response': [
        'المرحلة 2: تمكين وتشغيل', '7-18 شهر', 'تأسيس CSIRT وخطط الاستجابة',
        'قائد CSIRT', 'فريق CSIRT وخطط استجابة معتمدة', 'NCA ECC',
    ],
    'vulnerability_management': [
        'المرحلة 2: تمكين وتشغيل', '7-18 شهر', 'برنامج إدارة الثغرات',
        'مدير الثغرات', 'برنامج ثغرات مع SLA للمعالجة', 'NCA ECC',
    ],
    'awareness_training': [
        'المرحلة 2: تمكين وتشغيل', '7-18 شهر', 'برنامج التوعية الأمنية',
        'مدير التوعية', 'خطة توعية سنوية وتقارير إكمال', 'NCA ECC',
    ],
    'backup_dr_resilience': [
        'المرحلة 2: تمكين وتشغيل', '7-18 شهر', 'اختبار النسخ الاحتياطي والتعافي',
        'مدير استمرارية الأعمال', 'خطة DR واختبار استعادة ناجح', 'NCA ECC',
    ],
    'data_classification': [
        'المرحلة 1: تأسيس', '1-6 أشهر', 'تصنيف وجرد البيانات الحساسة',
        'مدير حماية البيانات', 'سجل بيانات مصنفة ومعتمد', 'NCA DCC',
    ],
    'encryption_key_management': [
        'المرحلة 2: تمكين وتشغيل', '7-18 شهر', 'تطبيق التشفير وإدارة المفاتيح',
        'مدير حماية البيانات', 'ضوابط تشفير وإدارة مفاتيح مطبقة', 'NCA DCC',
    ],
    'dlp': [
        'المرحلة 2: تمكين وتشغيل', '7-18 شهر', 'تفعيل DLP ومراقبة التسرب',
        'مدير حماية البيانات', 'منصة DLP وقواعد مراقبة تسرب مفعّلة', 'NCA DCC',
    ],
    'sensitive_data_handling': [
        'المرحلة 3: تحسين واستدامة', '19-24 شهر', 'معالجة وحماية البيانات الحساسة',
        'مدير حماية البيانات', 'إجراءات معالجة بيانات حساسة معتمدة', 'NCA DCC',
    ],
}

_FAMILY_TOKENS = {
    'governance_ciso': ('ciso', 'حوكمة', 'إدارة الأمن'),
    'governance_committee': ('لجنة', 'committee', 'raci', 'ميثاق'),
    'soc_siem': ('soc', 'siem', 'مركز العمليات'),
    'iam_pam_mfa': ('iam', 'pam', 'mfa', 'هوية'),
    'csirt_incident_response': ('csirt', 'استجابة', 'حوادث'),
    'vulnerability_management': ('ثغرات', 'vulnerab'),
    'awareness_training': (
        'توعية', 'تدريب', 'phishing', 'برنامج التوعية', 'توعية أمنية', 'تصيد'),
    'backup_dr_resilience': ('نسخ', 'backup', 'تعافي', 'dr', 'استمرارية'),
    'data_classification': ('تصنيف', 'جرد'),
    'encryption_key_management': ('تشفير', 'مفاتيح', 'encryption'),
    'dlp': ('dlp', 'تسرب'),
    'sensitive_data_handling': ('معالجة البيانات', 'sensitive data', 'حساسة'),
}


def _parse_roadmap_rows(text: str) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for ln in (text or '').splitlines():
        if not ln.strip().startswith('|') or '---' in ln:
            continue
        cells = [c.strip() for c in ln.strip('|').split('|')]
        if len(cells) < 4:
            continue
        if cells[0] in ('المرحلة', 'Phase', '#'):
            continue
        rows.append({
            'phase': cells[0],
            'period': cells[1] if len(cells) > 1 else '',
            'initiative': cells[2] if len(cells) > 2 else '',
            'owner': cells[3] if len(cells) > 3 else '',
            'output': cells[4] if len(cells) > 4 else '',
            'framework': cells[5] if len(cells) > 5 else '',
        })
    return rows


def _row_blob(row: Dict[str, str]) -> str:
    return ' '.join(str(v) for v in row.values()).lower()


def _families_for_row(row: Dict[str, str]) -> List[str]:
    blob = _row_blob(row)
    matched: List[str] = []
    for fam, tokens in _FAMILY_TOKENS.items():
        if any(
                (t.lower() in blob if t.isascii() else t in blob)
                for t in tokens):
            matched.append(fam)
    return matched


def _detect_families(rows: List[Dict[str, str]]) -> Dict[str, bool]:
    present = {f: False for f in ROADMAP_FAMILIES}
    for row in rows:
        for fam in _families_for_row(row):
            present[fam] = True
    return present


def _consolidate_rows_by_family(
        rows: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Keep one canonical row per roadmap family (max 12 before fill)."""
    by_fam: Dict[str, Dict[str, str]] = {}
    extras: List[Dict[str, str]] = []
    for row in rows:
        fams = _families_for_row(row)
        if len(fams) == 1:
            fam = fams[0]
            if fam not in by_fam:
                by_fam[fam] = row
            else:
                extras.append(row)
        elif len(fams) > 1:
            picked = fams[0]
            if picked not in by_fam:
                by_fam[picked] = row
            else:
                extras.append(row)
        else:
            extras.append(row)
    ordered = [by_fam[f] for f in ROADMAP_FAMILIES if f in by_fam]
    for row in extras:
        if len(ordered) >= 14:
            break
        if row not in ordered:
            ordered.append(row)
    return ordered


def _parse_rows(
        text: str,
        backend: Dict[str, Any],
        lang: str,
) -> List[Dict[str, str]]:
    parse_fn = backend.get('parse_roadmap_rows')
    if parse_fn:
        try:
            parsed = parse_fn(text, lang)
            if parsed:
                return parsed
        except Exception:  # noqa: BLE001
            pass
    return _parse_roadmap_rows(text)


def _rerender_rows(
        text: str,
        rows: List[Dict[str, str]],
        backend: Dict[str, Any],
        lang: str,
) -> str:
    rerender_fn = backend.get('rerender_roadmap')
    if rerender_fn:
        try:
            return rerender_fn(text, rows, lang)
        except Exception:  # noqa: BLE001
            pass
    header = text.split('\n')[0] if text.strip() else ''
    return _rerender_roadmap(header, rows)


def _drop_redundant_row(
        parsed: List[Dict[str, str]],
        *,
        protect: Optional[str] = None) -> bool:
    """Drop an unmapped or duplicate-covered row to free a roadmap slot."""
    for idx, row in enumerate(parsed):
        fams = _families_for_row(row)
        if not fams:
            parsed.pop(idx)
            return True
        for fam in fams:
            if protect and fam == protect:
                continue
            if any(
                    i != idx and fam in _families_for_row(parsed[i])
                    for i in range(len(parsed))):
                parsed.pop(idx)
                return True
    for idx in range(len(parsed) - 1, -1, -1):
        fams = _families_for_row(parsed[idx])
        if protect and protect in fams:
            continue
        parsed.pop(idx)
        return True
    return False


def _append_family_row(
        parsed: List[Dict[str, str]],
        fam: str,
        present: Dict[str, bool]) -> None:
    tpl = _ROADMAP_CATALOG_AR.get(fam)
    if not tpl:
        return
    while len(parsed) >= 14 and not present.get(fam):
        if not _drop_redundant_row(parsed, protect=fam):
            break
    if len(parsed) >= 14:
        return
    parsed.append({
        'phase': tpl[0], 'period': tpl[1], 'initiative': tpl[2],
        'owner': tpl[3], 'output': tpl[4], 'framework': tpl[5],
    })
    present[fam] = True


def _apply_roadmap_repairs(
        parsed: List[Dict[str, str]]) -> Tuple[List[Dict[str, str]], int]:
    """Consolidate, fill missing families, cap at 14 without losing coverage."""
    rows_before = len(parsed)
    parsed = _consolidate_rows_by_family(list(parsed))
    present = _detect_families(parsed)

    for row in parsed:
        own = (row.get('owner') or '').strip()
        if own in FORBIDDEN_OWNERS:
            row['owner'] = _owner_for_initiative(row.get('initiative', ''))

    for fam in ROADMAP_FAMILIES:
        if present.get(fam):
            continue
        _append_family_row(parsed, fam, present)

    while len(parsed) < 10:
        added = False
        for fam in ROADMAP_FAMILIES:
            if len(parsed) >= 10:
                break
            if not present.get(fam):
                before = len(parsed)
                _append_family_row(parsed, fam, present)
                if len(parsed) > before:
                    added = True
        if not added:
            break

    while len(parsed) > 14:
        present = _detect_families(parsed)
        drop_idx = None
        for idx, row in enumerate(parsed):
            fams = _families_for_row(row)
            if not fams:
                drop_idx = idx
                break
            covered_elsewhere = any(
                i != idx and fam in _families_for_row(parsed[i])
                for i in range(len(parsed))
                for fam in fams)
            if covered_elsewhere:
                drop_idx = idx
                break
        if drop_idx is None:
            drop_idx = len(parsed) - 1
        parsed.pop(drop_idx)
        present = _detect_families(parsed)
        for fam in ROADMAP_FAMILIES:
            if present.get(fam):
                continue
            _append_family_row(parsed, fam, present)

    return parsed, rows_before


def _phases_valid(rows: List[Dict[str, str]]) -> bool:
    phases = set()
    for row in rows:
        ph = (row.get('phase') or '')
        if 'المرحلة 1' in ph or 'phase 1' in ph.lower():
            phases.add(1)
        if 'المرحلة 2' in ph or 'phase 2' in ph.lower():
            phases.add(2)
        if 'المرحلة 3' in ph or 'phase 3' in ph.lower():
            phases.add(3)
    return {1, 2, 3}.issubset(phases)


def _owner_for_initiative(initiative: str) -> str:
    blob = (initiative or '').lower()
    if 'soc' in blob or 'siem' in blob:
        return 'مدير SOC'
    if 'iam' in blob or 'pam' in blob or 'mfa' in blob:
        return 'مدير IAM/PAM'
    if 'csirt' in blob or 'استجابة' in blob:
        return 'قائد CSIRT'
    if 'ثغر' in blob:
        return 'مدير الثغرات'
    if 'توعية' in blob or 'تدريب' in blob:
        return 'مدير التوعية'
    if 'نسخ' in blob or 'تعافي' in blob or 'dr' in blob:
        return 'مدير استمرارية الأعمال'
    if 'تصنيف' in blob or 'dlp' in blob or 'تشفير' in blob:
        return 'مدير حماية البيانات'
    if 'ciso' in blob or 'حوكمة' in blob:
        return 'CISO / الإدارة العليا'
    return 'مدير الامتثال'


def _rerender_roadmap(header: str, rows: List[Dict[str, str]]) -> str:
    lines = [header.rstrip(), '']
    if not header.strip():
        lines = [
            '## 5. خارطة الطريق التنفيذية',
            '',
            '| المرحلة | الفترة | المبادرة | المسؤول | المخرج | الإطار |',
            '|---|---|---|---|---|---|',
        ]
    for row in rows:
        lines.append('| ' + ' | '.join([
            row.get('phase', ''),
            row.get('period', ''),
            row.get('initiative', ''),
            row.get('owner', ''),
            row.get('output', ''),
            row.get('framework', ''),
        ]) + ' |')
    return '\n'.join(lines) + '\n'


def finalize_roadmap(
        sections: Dict[str, str],
        *,
        lang: str = 'ar',
        domain: str = 'cyber',
        selected_frameworks: Optional[List[str]] = None,
        backend: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, str], Dict[str, Any]]:
    """Repair/expand roadmap; emit [REL2-ROADMAP-FINAL-MODEL]."""
    backend = backend or {}
    dcode = (domain or '').strip().lower()
    if dcode not in ('cyber', 'cyber_security'):
        return sections, {'action_taken': 'skipped_non_cyber'}

    base_diag: Dict[str, Any] = {}
    baseline_fn = backend.get('baseline_roadmap')
    if baseline_fn:
        try:
            sections, base_diag = baseline_fn(
                dict(sections), lang, list(selected_frameworks or []))
        except Exception:  # noqa: BLE001
            base_diag = {}

    text = sections.get('roadmap', '') or ''
    parsed = _parse_rows(text, backend, lang)
    present_before = _detect_families(parsed)
    missing_before = [f for f in ROADMAP_FAMILIES if not present_before.get(f)]
    weak_before = [
        (r.get('owner') or '').strip()
        for r in parsed
        if (r.get('owner') or '').strip() in FORBIDDEN_OWNERS]

    parsed, rows_before = _apply_roadmap_repairs(parsed)
    present = _detect_families(parsed)
    missing_after = [f for f in ROADMAP_FAMILIES if not present.get(f)]
    weak_after = [
        (r.get('owner') or '').strip()
        for r in parsed
        if (r.get('owner') or '').strip() in FORBIDDEN_OWNERS]
    phases_ok = _phases_valid(parsed)
    row_count = len(parsed)

    new_text = _rerender_rows(text, parsed, backend, lang)
    out = dict(sections)
    out['roadmap'] = new_text

    blocking = ''
    if row_count < 10 or row_count > 14:
        blocking = 'rel2_roadmap_failed:row_count'
    elif missing_after:
        blocking = f'rel2_roadmap_failed:{missing_after[0]}'
    elif weak_after:
        blocking = 'rel2_roadmap_failed:weak_owners'
    elif not phases_ok:
        blocking = 'rel2_roadmap_failed:phases'

    diag = {
        'row_count_before': (
            base_diag.get('row_count_before')
            or base_diag.get('rows_before')
            or rows_before),
        'row_count_after': row_count,
        'missing_families_before': (
            base_diag.get('missing_families_before') or missing_before),
        'missing_families_after': missing_after,
        'weak_owners_before': (
            base_diag.get('weak_owners_before')
            or weak_before),
        'weak_owners_after': weak_after,
        'phases_valid': phases_ok,
        'action_taken': (
            base_diag.get('action_taken')
            if row_count == rows_before and not missing_after and not weak_after
            else (
                'roadmap_expanded' if row_count > rows_before
                else 'owners_repaired')),
        'blocking_error_if_any': blocking,
    }
    emit_roadmap_final_model(diag)
    return out, diag


def emit_roadmap_final_model(payload: Dict[str, Any]) -> None:
    try:
        print(
            '[REL2-ROADMAP-FINAL-MODEL] '
            + json.dumps(payload, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass
