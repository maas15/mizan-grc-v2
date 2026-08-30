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

_PILLAR_CATALOG_EN: Tuple[Tuple[str, Tuple[Tuple[str, str, str, str], ...]], ...] = (
    ('### Cybersecurity Governance & Operating Model', (
        ('Governance policy suite',
         'Adopt and refresh cybersecurity governance policies aligned to NCA ECC',
         'Approved governance platform with policy library',
         'CISO'),
        ('Cybersecurity governance committee',
         'Ratify a cybersecurity governance committee charter with quarterly meetings',
         'Active governance committee with charter and minutes',
         'CISO'),
        ('RACI accountability matrix',
         'Assign cybersecurity RACI across departments aligned to NCA ECC',
         'Approved cybersecurity RACI matrix',
         'CISO'),
    )),
    ('### Protection, Detection & Response — NCA ECC', (
        ('SOC/SIEM operations',
         'Operate SOC with SIEM use cases and response aligned to NCA ECC',
         '24x7 SOC with SIEM for critical assets',
         'SOC Manager'),
        ('CSIRT capability',
         'Establish CSIRT with approved and tested incident response plans',
         'Ready CSIRT with annual tabletop exercises',
         'CSIRT Lead'),
        ('Continuous monitoring',
         'Operate SIEM rules and continuous monitoring of critical assets',
         'SIEM coverage of critical assets',
         'CISO'),
    )),
    ('### Identity & Data Protection — NCA DCC', (
        ('IAM/PAM/MFA controls',
         'Enforce IAM/PAM/MFA for privileged and critical accounts aligned to NCA DCC',
         'MFA coverage for privileged accounts',
         'IAM/PAM Manager'),
        ('Data classification',
         'Classify and inventory sensitive data and keep the classification register current under NCA DCC',
         'Approved classified data register with sensitive-data inventory',
         'Data Protection Officer'),
        ('DLP controls',
         'Enable DLP and continuous monitoring of sensitive data leakage',
         'Operational DLP platform with leakage-prevention rules',
         'Data Protection Officer'),
    )),
    ('### Resilience & Business Continuity — NCA ECC', (
        ('Backup validation',
         'Test backups and recovery of critical data periodically under NCA ECC',
         'Approved backup plan with successful restore tests',
         'Business Continuity Manager'),
        ('Disaster recovery',
         'Test disaster-recovery plans and system continuity under NCA ECC',
         'Tested DR plan with approved RTO/RPO',
         'Business Continuity Manager'),
        ('Business continuity',
         'Approve and periodically test BCP for critical operations under NCA ECC',
         'Approved BCP for critical operations',
         'Business Continuity Manager'),
    )),
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
         'توزيع مسؤوليات RACI للأمن السيبراني عبر الإدارات والوظائف وفق NCA ECC',
         'مصفوفة RACI معتمدة'),
    )),
    ('### الحماية والكشف والاستجابة — NCA ECC', (
        ('تشغيل SOC/SIEM',
         'تشغيل مركز عمليات الأمن مع قواعد SIEM والاستجابة وفق NCA ECC',
         'مركز SOC تشغيلي'),
        ('فريق CSIRT',
         'تأسيس فريق الاستجابة للحوادث وخطط الاستجابة المعتمدة والمختبرة',
         'فريق CSIRT جاهز'),
        ('الرصد والمراقبة',
         'تشغيل قواعد SIEM والمراقبة المستمرة للأصول الحرجة والشبكات وفق NCA ECC',
         'تغطية SIEM للأصول الحرجة'),
    )),
    ('### الهوية وحماية البيانات — NCA DCC', (
        ('IAM/PAM/MFA',
         'تطبيق ضوابط IAM/PAM/MFA شاملة للحسابات الحرجة والامتيازات والوصول وفق NCA DCC',
         'تغطية MFA للحسابات الحرجة'),
        ('تصنيف البيانات',
         'جرد وتصنيف البيانات الحساسة وتحديث سجل التصنيف وفق NCA DCC',
         'سجل بيانات مصنف'),
        ('DLP', 'تفعيل منصة DLP ومراقبة تسرب البيانات الحساسة بشكل مستمر',
         'منصة DLP مفعّلة'),
    )),
    ('### المرونة واستمرارية الأعمال — NCA ECC', (
        ('النسخ الاحتياطي',
         'اختبار النسخ الاحتياطي واستعادة البيانات الحرجة دورياً وفق NCA ECC',
         'خطة نسخ احتياطي معتمدة'),
        ('التعافي من الكوارث',
         'اختبار خطط التعافي من الكوارث واستمرارية الأنظمة وفق NCA ECC',
         'خطة DR مختبرة'),
        ('استمرارية الأعمال',
         'اعتماد خطط BCP للعمليات الحرجة واختبارها دورياً والتحديث وفق NCA ECC',
         'خطط استمرارية معتمدة'),
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


def _pillar_lang(lang: str) -> str:
    raw = str(lang or '').strip().lower()
    if raw.startswith('en'):
        return 'en'
    return 'ar'


def _build_canonical_pillars(lang: str) -> str:
    from release_engine.pillar_substance_model import _ENRICHED_OUTPUTS

    if _pillar_lang(lang) == 'en':
        parts = ['## 2. Strategic Pillars', '']
        for heading, rows in _PILLAR_CATALOG_EN:
            parts.append(heading)
            parts.append('')
            parts.append(
                '| Initiative | Description | Expected Deliverable | Owner |\n'
                '|---|---|---|---|')
            for init, desc, output, owner in rows:
                parts.append(f'| {init} | {desc} | {output} | {owner} |')
            parts.append('')
        return '\n'.join(parts).rstrip() + '\n'

    _owners = {}
    for _heading, _rows in _PILLAR_CATALOG_AR:
        for init, _desc, _output in _rows:
            if init == 'فريق CSIRT':
                _owners[init] = 'قائد CSIRT'
            elif init == 'IAM/PAM/MFA':
                _owners[init] = 'مدير IAM/PAM'
            elif init in ('تصنيف البيانات', 'DLP'):
                _owners[init] = 'مدير حماية البيانات'
            elif init == 'النسخ الاحتياطي':
                _owners[init] = 'مدير IT'
            elif init in ('التعافي من الكوارث', 'استمرارية الأعمال'):
                _owners[init] = 'مدير BCP'
            elif 'SOC' in init:
                _owners[init] = 'مدير SOC'
            else:
                _owners[init] = 'CISO'
    title = '## 2. الركائز الاستراتيجية'
    parts = [title, '']
    for heading, rows in _PILLAR_CATALOG_AR:
        parts.append(heading)
        parts.append('')
        parts.append(
            '| المبادرة | الوصف | المخرج المتوقع | المسؤول |\n'
            '|---|---|---|---|')
        for init, desc, output in rows:
            out_cell = _ENRICHED_OUTPUTS.get(output, output)
            owner = _owners.get(init, 'CISO')
            parts.append(f'| {init} | {desc} | {out_cell} | {owner} |')
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
        domain: str = '',
        backend: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, str], Dict[str, Any]]:
    """Build/repair pillar section; emit [REL2-PILLAR-FINAL-MODEL]."""
    backend = backend or {}
    try:
        from release_engine_v3.domain_codes import normalize_domain_code
        dcode = normalize_domain_code(
            str(domain or backend.get('domain') or ''), default='')
    except Exception:  # noqa: BLE001
        dcode = (domain or '').strip().lower()
    if dcode != 'cyber':
        return sections, {
            'action_taken': 'skipped_non_cyber',
            'rendered_table_valid': True,
            'blocking_error_if_any': '',
        }

    if _pillar_lang(lang) == 'en':
        try:
            from release_engine_v3.rel36_8_en_cyber_pillars_parity import (
                apply_rel36_8_en_cyber_pillars_parity,
            )
            sections, _rel368 = apply_rel36_8_en_cyber_pillars_parity(
                sections,
                domain=dcode,
                lang=lang,
                document_type=str(
                    backend.get('document_type') or 'strategy'),
                selected_frameworks=backend.get('selected_frameworks') or [],
                backend=None,
                task_id=backend.get('task_id'),
                repair_stage='finalize_pillars',
            )
        except Exception:  # noqa: BLE001
            pass

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
            # REL3.3 — nested professional-model probe must carry domain
            # in both kwargs and metadata (document model reads metadata).
            _probe_domain = dcode or domain
            probe = build_model(
                '',
                metadata={'domain': _probe_domain},
                sections={**sections, 'pillars': text_fixed},
                selected_frameworks=[],
                lang=lang,
                domain=_probe_domain,
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
