"""PR-REL2.4 — traceability gap mapping substance model."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

# REL3 canonical traceability family registry (cyber strategy)
TRACE_CANONICAL_REGISTRY: Dict[str, Dict[str, str]] = {
    'data_classification': {
        'framework': 'NCA DCC',
        'capability': 'تصنيف البيانات',
        'expected_gap': 'ضعف تصنيف وجرد البيانات الحساسة',
        'initiative': 'جرد وتصنيف البيانات الحساسة',
        'metric': 'نسبة التصنيف',
        'risk': 'مخاطر بيانات غير مصنفة',
    },
    'encryption': {
        'framework': 'NCA DCC',
        'capability': 'التشفير',
        'expected_gap': 'ضعف ضوابط التشفير وإدارة المفاتيح',
        'initiative': 'تطبيق التشفير وإدارة المفاتيح',
        'metric': 'نسبة التشفير',
        'risk': 'مخاطر تشفير',
    },
    'dlp': {
        'framework': 'NCA DCC',
        'capability': 'منع تسرب البيانات / DLP',
        'expected_gap': 'ضعف ضوابط منع تسرب البيانات',
        'initiative': 'تفعيل DLP',
        'metric': 'نسبة تغطية DLP',
        'risk': 'مخاطر تسرب',
    },
    'sensitive_handling': {
        'framework': 'NCA DCC',
        'capability': 'معالجة البيانات الحساسة',
        'expected_gap': 'ضعف معالجة البيانات الحساسة',
        'initiative': 'إجراءات المعالجة',
        'metric': 'نسبة الامتثال',
        'risk': 'مخاطر معالجة',
    },
    'data_protection': {
        'framework': 'NCA DCC',
        'capability': 'حماية البيانات',
        'expected_gap': 'ضعف حماية البيانات أثناء النقل والتخزين',
        'initiative': 'ضوابط الحماية',
        'metric': 'نسبة الامتثال',
        'risk': 'مخاطر بيانات',
    },
    'ecc_governance': {
        'framework': 'NCA ECC',
        'capability': 'حوكمة الأمن السيبراني',
        'expected_gap': (
            'غياب وظيفة CISO وهيكل حوكمة الأمن السيبراني'),
        'initiative': 'تأسيس حوكمة CISO',
        'metric': 'نسبة الامتثال',
        'risk': 'مخاطر حوكمة',
    },
    'ecc_iam': {
        'framework': 'NCA ECC',
        'capability': 'إدارة الهوية والوصول',
        'expected_gap': 'ضعف إدارة الهوية والوصول IAM/PAM/MFA',
        'initiative': 'تفعيل IAM/PAM/MFA',
        'metric': 'نسبة التغطية',
        'risk': 'مخاطر وصول',
    },
    'ecc_soc': {
        'framework': 'NCA ECC',
        'capability': 'الرصد الأمني SOC/SIEM',
        'expected_gap': 'غياب مركز العمليات الأمنية SOC ومنصة SIEM',
        'initiative': 'تأسيس SOC/SIEM',
        'metric': 'MTTD',
        'risk': 'مخاطر رصد',
    },
    'ecc_incident_response': {
        'framework': 'NCA ECC',
        'capability': 'الاستجابة للحوادث',
        'expected_gap': (
            'غياب فريق الاستجابة للحوادث CSIRT وخطط الاستجابة'),
        'initiative': 'تأسيس CSIRT',
        'metric': 'MTTR',
        'risk': 'مخاطر حوادث',
    },
    'ecc_vulnerability': {
        'framework': 'NCA ECC',
        'capability': 'إدارة الثغرات',
        'expected_gap': (
            'ضعف إدارة الثغرات الأمنية وبرنامج التصحيح الدوري'),
        'initiative': 'برنامج إدارة الثغرات',
        'metric': 'نسبة التصحيح',
        'risk': 'مخاطر ثغرات',
    },
}

_EXPECTED_GAPS = {
    fam: spec['expected_gap'] for fam, spec in TRACE_CANONICAL_REGISTRY.items()
}

_FAMILY_DETECT = {
    'dlp': ('dlp', 'تسرب', 'منع تسرب'),
    'data_classification': ('تصنيف البيانات', 'تصنيف', 'جرد', 'classification'),
    'data_protection': ('حماية البيانات', 'نقل', 'تخزين', 'data protection'),
    'encryption': ('تشفير', 'مفاتيح', 'encryption'),
    'sensitive_handling': ('معالجة البيانات', 'حساسة', 'sensitive'),
    'ecc_governance': ('حوكمة الأمن', 'ciso', 'حوكمة'),
    'ecc_iam': ('إدارة الهوية', 'iam', 'pam', 'mfa', 'هوية'),
    'ecc_soc': ('soc', 'siem', 'الرصد الأمني', 'مركز العمليات'),
    'ecc_incident_response': (
        'الاستجابة للحوادث', 'استجابة', 'incident', 'حوادث', 'csirt'),
    'ecc_vulnerability': (
        'إدارة الثغرات', 'ثغرات', 'vulnerability', 'patch', 'تصحيح'),
}

_DCC_REGISTRY_ORDER = (
    'dlp', 'data_classification', 'encryption',
    'sensitive_handling', 'data_protection',
)
_ECC_REGISTRY_ORDER = (
    'ecc_governance', 'ecc_iam', 'ecc_soc',
    'ecc_incident_response', 'ecc_vulnerability',
)


def resolve_traceability_canonical_family(
        capability: str,
        gap: str = '',
) -> Optional[str]:
    """Map a traceability capability/gap pair to one canonical family."""
    blob = f'{(capability or "").lower()} {(gap or "").lower()}'
    cap = (capability or '').strip()
    for fam, kws in _FAMILY_DETECT.items():
        if any(k in blob or k in cap for k in kws):
            return fam
    return None


def _parse_trace_rows(text: str) -> Tuple[List[str], int, List[List[str]]]:
    lines = (text or '').splitlines()
    hdr = -1
    for i, ln in enumerate(lines):
        if not ln.strip().startswith('|'):
            continue
        hdr_blob = ln.lower()
        is_trace = (
            ('مجال القدرة' in ln or 'capability' in hdr_blob)
            and (
                'الفجوة المرتبطة' in ln
                or 'الإطار المرجعي' in ln
                or 'المبادرة' in ln
                or 'المؤشر' in ln))
        if is_trace or (
                'الإطار المرجعي' in ln
                and ('مجال القدرة' in ln or 'الفجوة' in ln)):
            hdr = i
            break
    if hdr < 0:
        return lines, -1, []
    rows = []
    for ln in lines[hdr + 1:]:
        if not ln.strip().startswith('|') or '---' in ln:
            if rows:
                break
            continue
        cells = [c.strip() for c in ln.strip('|').split('|')]
        if cells:
            rows.append(cells)
    return lines, hdr, rows


def _gap_col_idx(header: str) -> int:
    cells = [c.strip() for c in header.strip('|').split('|')]
    for i, c in enumerate(cells):
        if 'الفجوة' in c or 'gap' in c.lower():
            return i
    return 2 if len(cells) > 2 else 1


def _cap_col_idx(header: str) -> int:
    cells = [c.strip() for c in header.strip('|').split('|')]
    for i, c in enumerate(cells):
        if 'قدرة' in c or 'capability' in c.lower() or 'ضابط' in c:
            return i
    return 1


def _detect_family(row: List[str], cap_idx: int) -> str:
    cap = (row[cap_idx] if len(row) > cap_idx else '').strip().lower()
    if cap:
        for fam, kws in _FAMILY_DETECT.items():
            if any(k in cap for k in kws):
                return fam
    blob = ' '.join(row).lower()
    blob = f'{blob} {cap}'
    for fam, kws in _FAMILY_DETECT.items():
        if any(k in blob for k in kws):
            return fam
    return ''


def _is_blank_gap(gap: str) -> bool:
    g = (gap or '').strip()
    return not g or g in ('—', '-', 'n/a', 'N/A')


_PDF_TRACE_COL_MARKERS = (
    ':مجال القدرة',
    ':المبادرة',
    ':الفجوة',
    ':المؤشر',
    ':الخطر',
    '| مجال القدرة |',
    '| الفجوة |',
    'الفجوة | مجال القدرة',
)


def pdf_trace_extract_artifact(text: str) -> bool:
    """True when PDF table text extraction merged column headers into cells."""
    t = (text or '').strip()
    if not t:
        return False
    if any(m in t for m in _PDF_TRACE_COL_MARKERS):
        return True
    if t.startswith(':') and len(t) < 50:
        return True
    if re.search(r':المبادرة', t) and re.search(
            r'تطبيق|تأسيس|تنفيذ|وتفعيل|وتطوير', t):
        return True
    return False


def is_diagnostic_gap_label(text: str) -> bool:
    """Gap-analysis row labels are not traceability capability/gap mappings."""
    t = (text or '').strip()
    if not t:
        return False
    return any(t.startswith(p) for p in (
        'غياب ', 'قصور ', 'ضعف ', 'عدم ', 'Limited ', 'limited ',
        'Absence ', 'absence ', 'Missing ', 'missing '))


def _incident_gap_valid(gap: str) -> bool:
    g = (gap or '').lower()
    return (
        'csirt' in g
        and ('خطط' in gap or 'خطة' in gap or 'فريق' in gap))


def _bad_mapping(family: str, gap: str) -> bool:
    if pdf_trace_extract_artifact(gap):
        return False
    g = (gap or '').lower()
    expected = _EXPECTED_GAPS.get(family, '')
    if expected and expected in gap:
        return False
    if family == 'ecc_incident_response':
        if _incident_gap_valid(gap):
            return False
        if 'soc' in g and 'siem' in g and 'csirt' not in g:
            return True
        if 'غياب فريق' not in g and 'خطة' not in gap and 'خطط' not in gap:
            if 'soc' in g or 'siem' in g:
                return True
        if 'roadmap' in g or 'مبادرة' in gap and 'csirt' not in g:
            return True
        return not _incident_gap_valid(gap) and bool(gap)
    if family == 'ecc_vulnerability':
        if expected and expected in gap:
            return False
        if any(m in g for m in ('dlp', 'تسرب', 'remote', 'بعيد', 'وصول')):
            return True
        if 'ثغر' not in g and 'vulnerability' not in g:
            return True
        return bool(gap) and expected not in gap
    if family == 'data_protection' and gap:
        if expected in gap or ('حماية' in gap and 'نقل' in gap):
            return False
        if 'dlp' in g and 'حماية' not in gap:
            return True
        if expected and expected not in gap:
            return True
    if family == 'data_classification' and gap:
        if expected in gap:
            return False
        if any(m in g for m in ('iam', 'pam', 'مميزة', 'حسابات', 'privileged')):
            return True
        if any(m in g for m in (
                'حوكمة', 'إطار تنظيمي', 'سياسة عامة', 'ecc-1-1')):
            return True
        if 'وجرد' in gap or 'ضعف تصنيف' in gap:
            return False
        return expected not in gap
    if family == 'dlp' and _is_blank_gap(gap):
        return True
    if family in _EXPECTED_GAPS and gap and expected not in gap:
        if family == 'data_classification' and 'تصنيف' in gap:
            if 'وجرد' in gap or 'ضعف' in gap:
                return False
            if any(m in g for m in ('حوكمة', 'إطار تنظيمي', 'سياسة عامة')):
                return True
            return True
        if family not in ('dlp', 'ecc_incident_response', 'ecc_vulnerability'):
            return True
        return True
    return False


def _collect_bad_mappings(text: str) -> List[str]:
    bad: List[str] = []
    lines, hdr, rows = _parse_trace_rows(text or '')
    if hdr < 0:
        return bad
    gap_idx = _gap_col_idx(lines[hdr])
    cap_idx = _cap_col_idx(lines[hdr])
    for cells in rows:
        fam = _detect_family(cells, cap_idx)
        gap = cells[gap_idx] if len(cells) > gap_idx else ''
        cap = cells[cap_idx] if len(cells) > cap_idx else fam
        if fam and _bad_mapping(fam, gap):
            bad.append(f'{fam}:{cap}')
    return bad


def build_traceability_matrix_rows_from_registry(
        *,
        lang: str = 'ar',
) -> Dict[str, Any]:
    """Build traceability matrix model rows from TRACE_CANONICAL_REGISTRY only."""
    if lang == 'ar':
        header = [
            'الإطار المرجعي', 'مجال القدرة / الضابط',
            'الفجوة المرتبطة', 'المبادرة / النشاط',
            'المؤشر', 'الخطر المرتبط',
        ]
    else:
        header = [
            'Reference Framework', 'Capability / Control',
            'Related Gap', 'Initiative / Activity',
            'Metric', 'Related Risk',
        ]

    rows: List[List[str]] = []
    for fam in _DCC_REGISTRY_ORDER + _ECC_REGISTRY_ORDER:
        spec = TRACE_CANONICAL_REGISTRY[fam]
        rows.append([
            spec['framework'],
            spec['capability'],
            spec['expected_gap'],
            spec['initiative'],
            spec['metric'],
            spec['risk'],
        ])

    def _is_dash(v: Any) -> bool:
        if v is None:
            return True
        s = str(v).strip()
        return (not s) or s in ('—', '-', '--', '–')

    informative_rows = [
        r for r in rows
        if len(r) >= 6
        and not _is_dash(r[2])
        and not _is_dash(r[3])
        and (not _is_dash(r[4]) or not _is_dash(r[5]))
    ]
    return {
        'header': header,
        'rows': rows,
        'informative_rows': informative_rows,
        'source': 'trace_canonical_registry',
    }


def build_canonical_traceability_from_registry(
        *,
        lang: str = 'ar',
) -> str:
    """Build full traceability matrix from canonical family registry only."""
    _ = lang
    header = (
        '| الإطار المرجعي | مجال القدرة / الضابط | الفجوة المرتبطة | '
        'المبادرة / النشاط | المؤشر | الخطر المرتبط |')
    sep = '|' + '---|' * 6
    rows: List[str] = []
    for fam in _DCC_REGISTRY_ORDER + _ECC_REGISTRY_ORDER:
        spec = TRACE_CANONICAL_REGISTRY[fam]
        rows.append(
            '| {fw} | {cap} | {gap} | {init} | {met} | {risk} |'.format(
                fw=spec['framework'],
                cap=spec['capability'],
                gap=spec['expected_gap'],
                init=spec['initiative'],
                met=spec['metric'],
                risk=spec['risk'],
            ))
    return (
        '## مصفوفة التتبع\n\n'
        + header + '\n'
        + sep + '\n'
        + '\n'.join(rows) + '\n'
    )


def _build_canonical_traceability() -> str:
    return build_canonical_traceability_from_registry()


def repair_traceability_canonical_families(
        sections: Dict[str, str],
        *,
        lang: str = 'ar',
        backend: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, str], Dict[str, Any]]:
    """Rebuild traceability from canonical gap families before REL3 freeze."""
    _ = backend
    text = (
        sections.get('traceability')
        or sections.get('traceability_matrix')
        or ''
    )
    bad_before = _collect_bad_mappings(text)
    if not bad_before and text.strip():
        try:
            from release_engine.rel31_content_substance_checks import (
                check_traceability_bad_mappings,
            )
            for defect in check_traceability_bad_mappings(text):
                if defect.startswith('trace_gap_mismatch:'):
                    bad_before.append(defect)
        except Exception:  # noqa: BLE001
            pass

    canonical_text = build_canonical_traceability_from_registry(lang=lang)
    bad_after: List[str] = []
    try:
        from release_engine.rel31_content_substance_checks import (
            check_traceability_bad_mappings,
        )
        bad_after = check_traceability_bad_mappings(canonical_text)
    except Exception:  # noqa: BLE001
        bad_after = _collect_bad_mappings(canonical_text)

    repaired_mappings = [
        f'{fam}->{TRACE_CANONICAL_REGISTRY[fam]["expected_gap"]}'
        for fam in _DCC_REGISTRY_ORDER + _ECC_REGISTRY_ORDER
    ]
    blockers = list(bad_after)
    passed = not blockers
    out = dict(sections)
    unchanged = (text or '').strip() == canonical_text.strip()
    out['traceability'] = canonical_text
    if 'traceability_matrix' in out:
        out['traceability_matrix'] = canonical_text

    action = 'no_changes' if unchanged and not bad_before else (
        'traceability_canonical_families_repaired')

    diag = {
        'bad_mappings_before': list(dict.fromkeys(bad_before)),
        'repaired_mappings': repaired_mappings,
        'canonical_gap_families_after': list(
            _DCC_REGISTRY_ORDER + _ECC_REGISTRY_ORDER),
        'trace_gap_mismatch_after': blockers,
        'traceability_canonical_passed': passed,
        'blocking_errors': blockers,
        'action_taken': action,
    }
    emit_rel3_traceability_canonical_repair(diag)
    return out, diag


def emit_rel3_traceability_canonical_repair(payload: Dict[str, Any]) -> None:
    try:
        print(
            '[REL3-TRACEABILITY-CANONICAL-REPAIR] '
            + json.dumps(payload, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass


def finalize_traceability_substance(
        sections: Dict[str, str],
        *,
        lang: str = 'ar',
) -> Tuple[Dict[str, str], Dict[str, Any]]:
    out, diag = repair_traceability_canonical_families(
        sections, lang=lang)
    if diag.get('action_taken') == 'no_changes':
        text = out.get('traceability') or ''
        action = 'validated'
        blank_before: List[str] = []
        bad_before = _collect_bad_mappings(text)
        blank_after: List[str] = []
        bad_after = list(diag.get('trace_gap_mismatch_after') or [])
        passed = not blank_after and not bad_after
        blocking = ''
        if bad_after:
            blocking = 'rel2_substantive_quality_failed:traceability:bad_mapping'
        diag = {
            'blank_gap_rows_before': blank_before,
            'blank_gap_rows_after': blank_after,
            'bad_mappings_before': bad_before,
            'bad_mappings_after': bad_after,
            'traceability_substance_passed': passed,
            'action_taken': action if not bad_before else 'traceability_repaired',
            'blocking_error_if_any': blocking,
        }
    else:
        diag = {
            'blank_gap_rows_before': [],
            'blank_gap_rows_after': [],
            'bad_mappings_before': diag.get('bad_mappings_before') or [],
            'bad_mappings_after': diag.get('trace_gap_mismatch_after') or [],
            'traceability_substance_passed': diag.get(
                'traceability_canonical_passed', False),
            'action_taken': diag.get('action_taken'),
            'blocking_error_if_any': (
                (diag.get('blocking_errors') or [''])[0]
                if not diag.get('traceability_canonical_passed') else ''),
        }
    return out, diag


def emit_traceability_substance_model(payload: Dict[str, Any]) -> None:
    try:
        print(
            '[REL2-TRACEABILITY-SUBSTANCE-MODEL] '
            + json.dumps(payload, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass
