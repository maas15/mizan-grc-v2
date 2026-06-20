"""PR-REL2.3 — final pillar model for strategy artifacts."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

CYBER_PILLAR_FAMILIES = (
    'governance_operating_model',
    'protection_detection_response',
    'identity_data_protection',
    'resilience_continuity',
)

_PILLAR_CATALOG_AR: Tuple[Tuple[str, Tuple[Tuple[str, str, str], ...]], ...] = (
    ('### حوكمة ونموذج التشغيل', (
        ('سياسات الحوكمة السيبرانية',
         'اعتماد وتحديث سياسات الحوكمة السيبرانية وفق NCA ECC بشكل دوري',
         'منصة حوكمة معتمدة'),
        ('لجنة حوكمة الأمن',
         'ميثاق لجنة حوكمة أمن سيبراني معتمد مع اجتماعات ربع سنوية',
         'لجنة حوكمة فعّالة'),
        ('مصفوفة RACI',
         'توزيع مسؤوليات RACI للأمن السيبراني عبر الإدارات',
         'مصفوفة RACI معتمدة'),
    )),
    ('### الحماية والكشف والاستجابة', (
        ('تشغيل SOC/SIEM', 'تشغيل المركز', 'مركز SOC تشغيلي'),
        ('فريق CSIRT',
         'تأسيس فريق الاستجابة للحوادث وخطط الاستجابة المعتمدة والمختبرة',
         'فريق CSIRT جاهز'),
        ('الرصد والمراقبة', 'قواعد المراقبة', 'تغطية SIEM للأصول الحرجة'),
    )),
    ('### الهوية وحماية البيانات', (
        ('IAM/PAM/MFA', 'ضوابط الهوية', 'تغطية MFA للحسابات الحرجة'),
        ('تصنيف البيانات', 'جرد وتصنيف', 'سجل بيانات مصنف'),
        ('DLP', 'تفعيل منصة DLP ومراقبة تسرب البيانات الحساسة بشكل مستمر',
         'منصة DLP مفعّلة'),
    )),
    ('### المرونة واستمرارية الأعمال', (
        ('النسخ الاحتياطي', 'اختبار النسخ', 'خطة نسخ احتياطي معتمدة'),
        ('التعافي من الكوارث', 'اختبار DR', 'خطة DR مختبرة'),
        ('استمرارية الأعمال', 'خطط BCP', 'خطط استمرارية معتمدة'),
    )),
)

_PILLAR_MISMATCH_RULES = (
    (('dlp', 'تسرب'), ('حوكمة', 'governance'), 'منصة DLP مفعّلة'),
    (('تشفير', 'مفاتيح'), ('نسخ', 'backup', 'احتياطي'), 'تشفير للبيانات الحساسة'),
)


def _count_pillar_blocks(text: str) -> Tuple[int, List[int], List[str]]:
    """Count ###-level pillar blocks only (ignore section ## title)."""
    blocks: List[Tuple[str, List[List[str]]]] = []
    chunks = re.split(
        r'(?=^#{3,4}\s+)',
        text or '', flags=re.MULTILINE)
    for chunk in chunks:
        chunk = chunk.strip()
        if not chunk:
            continue
        lines = chunk.split('\n')
        title = lines[0].lstrip('#').strip() if lines else ''
        rows: List[List[str]] = []
        for ln in lines[1:]:
            if ln.strip().startswith('|') and '---' not in ln:
                cells = [c.strip() for c in ln.strip('|').split('|')]
                if len(cells) >= 3 and not any(
                        k in ' '.join(cells).lower()
                        for k in ('مبادرة', 'initiative')):
                    if cells[0] not in ('المبادرة', 'Initiative', '#'):
                        rows.append(cells)
                elif len(cells) >= 3:
                    rows.append(cells)
        if title.startswith('###') or rows:
            blocks.append((title, rows))
    empty = [b[0] or f'pillar_{i}' for i, b in enumerate(blocks) if not b[1]]
    counts = [len(r) for _, r in blocks]
    return len(blocks), counts, empty


def _pillar_families_present(text: str) -> Dict[str, bool]:
    blob = (text or '').lower()
    return {
        'governance_operating_model': any(
            k in blob for k in ('حوكمة', 'governance', 'raci', 'لجنة')),
        'protection_detection_response': any(
            k in blob for k in ('soc', 'siem', 'csirt', 'استجابة', 'رصد')),
        'identity_data_protection': any(
            k in blob for k in ('iam', 'pam', 'mfa', 'تصنيف', 'dlp', 'هوية')),
        'resilience_continuity': any(
            k in blob for k in (
                'نسخ', 'backup', 'تعافي', 'dr', 'استمرارية', 'bcp')),
    }


def _build_canonical_pillars(lang: str) -> str:
    is_ar = str(lang or '').lower() != 'en'
    title = '## 2. الركائز الاستراتيجية' if is_ar else '## 2. Strategic Pillars'
    parts = [title, '']
    catalog = _PILLAR_CATALOG_AR
    for heading, rows in catalog:
        parts.append(heading)
        parts.append('')
        parts.append(
            '| المبادرة | الوصف | المخرج المتوقع |\n'
            '|---|---|---|')
        for cells in rows:
            parts.append('| ' + ' | '.join(cells) + ' |')
        parts.append('')
    return '\n'.join(parts).rstrip() + '\n'


def _fix_mismatched_outputs(text: str) -> Tuple[str, int, int]:
    mismatched_before = 0
    mismatched_after = 0
    blocks = []
    chunks = re.split(r'(?=^#{2,4}\s+)', text or '', flags=re.MULTILINE)
    for chunk in chunks:
        if not chunk.strip():
            continue
        lines = chunk.split('\n')
        title = lines[0]
        out_lines = [title]
        for ln in lines[1:]:
            if ln.strip().startswith('|') and '---' not in ln:
                cells = [c.strip() for c in ln.strip('|').split('|')]
                if len(cells) >= 3:
                    init = cells[0] if len(cells) == 3 else cells[1]
                    output = cells[-1]
                    blob = f'{init} {output}'.lower()
                    fixed = output
                    for init_kws, bad_kws, good_out in _PILLAR_MISMATCH_RULES:
                        if any(k in blob for k in init_kws) and any(
                                b in blob for b in bad_kws):
                            mismatched_before += 1
                            fixed = good_out
                            break
                    cells[-1] = fixed
                    chk = f'{init} {fixed}'.lower()
                    for init_kws, bad_kws, _ in _PILLAR_MISMATCH_RULES:
                        if any(k in chk for k in init_kws) and any(
                                b in chk for b in bad_kws):
                            mismatched_after += 1
                    ln = '| ' + ' | '.join(cells) + ' |'
            out_lines.append(ln)
        blocks.append('\n'.join(out_lines))
    return '\n\n'.join(blocks), mismatched_before, mismatched_after


def finalize_pillars(
        sections: Dict[str, str],
        *,
        lang: str = 'ar',
        domain: str = 'cyber',
        backend: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, str], Dict[str, Any]]:
    """Build/repair pillar section; emit [REL2-PILLAR-FINAL-MODEL]."""
    backend = backend or {}
    dcode = (domain or '').strip().lower()
    if dcode not in ('cyber', 'cyber_security'):
        return sections, {
            'action_taken': 'skipped_non_cyber',
            'rendered_table_valid': True,
            'blocking_error_if_any': '',
        }

    text = sections.get('pillars', '') or ''
    count_before, counts_before, empty_before = _count_pillar_blocks(text)
    families_before = _pillar_families_present(text)
    missing_before = [
        f for f in CYBER_PILLAR_FAMILIES if not families_before.get(f)]

    action = 'no_changes'
    blocking = ''
    text_fixed, mm_b, mm_a = _fix_mismatched_outputs(text)
    mismatched_before, mismatched_after = mm_b, mm_a

    export_parseable = True
    build_model = backend.get('build_professional_model')
    if build_model and text_fixed.strip():
        try:
            from release_engine.section_parity import _pillars_export_present
            probe = build_model(
                '',
                metadata={},
                sections={**sections, 'pillars': text_fixed},
                selected_frameworks=[],
                lang=lang,
                domain=domain,
            )
            export_parseable = _pillars_export_present(
                probe, {**sections, 'pillars': text_fixed})
        except Exception:  # noqa: BLE001
            export_parseable = False

    needs_rebuild = (
        not text.strip()
        or count_before < 3
        or any(c < 3 for c in counts_before)
        or empty_before
        or missing_before
        or not re.search(r'^#{3,4}\s+', text_fixed, re.MULTILINE)
        or not export_parseable
        or bool(re.search(
            r'\|\s*#\s*\|\s*(?:المبادرة|Initiative)',
            text_fixed, re.MULTILINE | re.IGNORECASE)))

    if needs_rebuild:
        baseline_fn = backend.get('baseline_pillars')
        if baseline_fn and text_fixed.strip():
            try:
                sections, _ = baseline_fn(dict(sections), lang)
                text_fixed = sections.get('pillars', '') or text_fixed
            except Exception:  # noqa: BLE001
                pass
        text_fixed = _build_canonical_pillars(lang)
        action = 'rebuilt_canonical_pillars'

    count_after, counts_after, empty_after = _count_pillar_blocks(text_fixed)
    families_after = _pillar_families_present(text_fixed)
    missing_after = [
        f for f in CYBER_PILLAR_FAMILIES if not families_after.get(f)]

    rendered_valid = (
        count_after >= 3
        and all(c >= 3 for c in counts_after)
        and not empty_after
        and not missing_after
        and mismatched_after == 0)

    if not rendered_valid:
        blocking = 'rel2_pillars_failed:empty_or_invalid'

    out_sections = dict(sections)
    out_sections['pillars'] = text_fixed

    diag = {
        'pillar_count_before': count_before,
        'pillar_count_after': count_after,
        'initiative_count_by_pillar': counts_after,
        'empty_pillars_before': empty_before,
        'empty_pillars_after': empty_after,
        'missing_pillar_families_before': missing_before,
        'missing_pillar_families_after': missing_after,
        'mismatched_outputs_before': mismatched_before,
        'mismatched_outputs_after': mismatched_after,
        'rendered_table_valid': rendered_valid,
        'action_taken': action,
        'blocking_error_if_any': blocking,
    }
    return out_sections, diag


def emit_pillar_final_model(payload: Dict[str, Any]) -> None:
    try:
        print(
            '[REL2-PILLAR-FINAL-MODEL] '
            + json.dumps(payload, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass
