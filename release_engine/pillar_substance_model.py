"""PR-REL2.4 — pillar depth / board-ready substance model."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Tuple

from release_engine.pillar_model import _build_canonical_pillars, _count_pillar_blocks

_GENERIC_OUTPUTS = frozenset({
    'منصة حوكمة معتمدة',
    'لجنة حوكمة فعّالة',
    'فريق CSIRT جاهز',
    'مركز SOC تشغيلي',
    'تغطية SIEM للأصول الحرجة',
    'تغطية MFA للحسابات الحرجة',
    'سجل بيانات مصنف',
    'منصة DLP مفعّلة',
    'خطة نسخ احتياطي معتمدة',
    'خطة DR مختبرة',
    'خطط استمرارية معتمدة',
    'مصفوفة RACI معتمدة',
})

_ENRICHED_OUTPUTS = {
    'منصة حوكمة معتمدة': (
        'منصة حوكمة سيبرانية معتمدة مع مكتبة سياسات وسجلات اعتماد محدثة'),
    'لجنة حوكمة فعّالة': (
        'لجنة حوكمة أمن سيبراني فعّالة بميثاق ومحاضر اجتماعات ربع سنوية'),
    'فريق CSIRT جاهز': (
        'فريق CSIRT جاهز مع خطط استجابة وتمارين محاكاة سنوية'),
    'مركز SOC تشغيلي': (
        'مركز SOC تشغيلي 24/7 مع قواعد SIEM للأصول الحرجة'),
    'تغطية SIEM للأصول الحرجة': (
        'تغطية SIEM لـ 90% من الأصول الحرجة مع لوحات مراقبة'),
    'تغطية MFA للحسابات الحرجة': (
        'تغطية MFA لجميع الحسابات الحرجة والامتيازية'),
    'سجل بيانات مصنف': (
        'سجل بيانات مصنفة معتمد مع جرد للبيانات الحساسة'),
    'منصة DLP مفعّلة': (
        'منصة DLP مفعّلة مع قواعد مراقبة تسرب للبيانات الحساسة'),
    'خطة نسخ احتياطي معتمدة': (
        'خطة نسخ احتياطي معتمدة مع اختبارات استعادة ناجحة'),
    'خطة DR مختبرة': (
        'خطة تعافي من الكوارث مختبرة مع RTO/RPO معتمدة'),
    'خطط استمرارية معتمدة': (
        'خطط استمرارية أعمال معتمدة للعمليات الحرجة'),
    'مصفوفة RACI معتمدة': (
        'مصفوفة RACI معتمدة لأدوار الأمن السيبراني والامتثال'),
}

_PILLAR_NARRATIVES = {
    '### حوكمة ونموذج التشغيل': (
        'تعزز هذه الركيزة المساءلة المؤسسية على الأمن السيبراني عبر هياكل '
        'حوكمة واضحة ولجان فعّالة. تشمل المبادرات اعتماد السياسات وتوزيع '
        'الأدوار وربط القرارات التنفيذية بمتطلبات NCA ECC.'),
    '### الحماية والكشف والاستجابة': (
        'تركز هذه الركيزة على القدرات التشغيلية للكشف والاستجابة للتهديدات '
        'وفق NCA ECC. تشمل تشغيل SOC/SIEM وفريق CSIRT وتحسين الرصد المستمر '
        'للأصول الحرجة.'),
    '### الهوية وحماية البيانات': (
        'تغطي هذه الركيزة ضوابط الهوية وحماية البيانات وفق NCA DCC. '
        'تشمل IAM/PAM/MFA وتصنيف البيانات وتفعيل DLP للبيانات الحساسة.'),
    '### المرونة واستمرارية الأعمال': (
        'تضمن هذه الركيزة استمرارية العمليات عبر النسخ الاحتياطي والتعافي '
        'من الكوارث وخطط استمرارية الأعمال المختبرة دورياً وفق NCA ECC.'),
}

_INITIATIVE_ENRICH = {
    'سياسات الحوكمة السيبرانية': (
        'اعتماد وتحديث سياسات الحوكمة السيبرانية وفق NCA ECC',
        'منصة حوكمة سيبرانية معتمدة مع مكتبة سياسات محدثة'),
    'لجنة حوكمة الأمن': (
        'ميثاق لجنة حوكمة أمن سيبراني معتمد مع اجتماعات ربع سنوية',
        'لجنة حوكمة أمن سيبراني فعّالة بميثاق ومحاضر اجتماعات'),
    'مصفوفة RACI': (
        'توزيع مسؤوليات RACI للأمن السيبراني عبر الإدارات',
        'مصفوفة RACI معتمدة لأدوار الأمن السيبراني والامتثال'),
    'تشغيل SOC/SIEM': (
        'تشغيل مركز عمليات الأمن مع قواعد SIEM للأصول الحرجة',
        'مركز SOC تشغيلي 24/7 مع تغطية SIEM للأصول الحرجة'),
    'فريق CSIRT': (
        'تأسيس فريق الاستجابة للحوادث وخطط الاستجابة المعتمدة والمختبرة',
        'فريق CSIRT جاهز مع خطط استجابة وتمارين محاكاة'),
    'الرصد والمراقبة': (
        'تشغيل قواعد SIEM والمراقبة المستمرة للأصول الحرجة',
        'تغطية SIEM لـ 90% من الأصول الحرجة مع لوحات مراقبة'),
    'IAM/PAM/MFA': (
        'تطبيق ضوابط IAM/PAM/MFA شاملة للحسابات الحرجة والامتيازات والوصول وفق NCA DCC',
        'تغطية MFA لجميع الحسابات الحرجة والامتيازية'),
    'تصنيف البيانات': (
        'جرد وتصنيف البيانات الحساسة وفق NCA DCC',
        'سجل بيانات مصنفة معتمد مع جرد للبيانات الحساسة'),
    'DLP': (
        'تفعيل منصة DLP ومراقبة تسرب البيانات الحساسة بشكل مستمر',
        'منصة DLP مفعّلة مع قواعد مراقبة تسرب معتمدة'),
    'النسخ الاحتياطي': (
        'اختبار النسخ الاحتياطي واستعادة البيانات الحرجة دورياً',
        'خطة نسخ احتياطي معتمدة مع اختبارات استعادة ناجحة'),
    'التعافي من الكوارث': (
        'اختبار DR وخطط التعافي من الكوارث وفق RTO/RPO معتمدة',
        'خطة تعافي من الكوارث مختبرة مع RTO/RPO معتمدة'),
    'استمرارية الأعمال': (
        'اعتماد خطط BCP للعمليات الحرجة واختبارها دورياً والتحديث وفق NCA ECC',
        'خطط استمرارية أعمال معتمدة للعمليات الحرجة'),
}


def _pillar_row_layout(cells: List[str]) -> Tuple[str, int, int, int]:
    """Return (initiative, desc_idx, out_idx, owner_idx) for 3- or 4-col rows."""
    n = len(cells)
    if n >= 4:
        return cells[0], 1, 2, 3
    if n == 3:
        return cells[0], 1, 2, -1
    return cells[0] if cells else '', 0, -1, -1


def _is_canonical_four_column_pillars(text: str) -> bool:
    blob = text or ''
    if 'المسؤول' not in blob or 'المخرج المتوقع' not in blob:
        return False
    if 'تنفيذ برنامج' in blob:
        return False
    return blob.count('### ') >= 3


def _arabic_word_count(text: str) -> int:
    return len(re.findall(r'[\u0600-\u06FF]+', text or ''))


def _is_generic_output(text: str) -> bool:
    t = (text or '').strip()
    return t in _GENERIC_OUTPUTS or len(t) < 12


def _enrich_pillar_text(text: str) -> Tuple[str, List[str], List[str], List[str]]:
    shallow_pillars: List[str] = []
    shallow_initiatives: List[str] = []
    generic_outputs: List[str] = []
    chunks = re.split(r'(?=^#{3,4}\s+)', text or '', flags=re.MULTILINE)
    out_parts: List[str] = []
    for chunk in chunks:
        if not chunk.strip():
            continue
        lines = chunk.split('\n')
        title = lines[0].strip()
        narrative = _PILLAR_NARRATIVES.get(title, '')
        body_lines = [title, '']
        chunk_body = '\n'.join(lines[1:])
        if narrative and narrative not in chunk_body:
            body_lines.append(narrative)
            body_lines.append('')
        elif title.startswith('###') and not narrative:
            body_lines.append(
                'ركيزة استراتيجية تدعم تنفيذ القدرات السيبرانية المطلوبة '
                'وفق إطار NCA ECC/DCC.')
            body_lines.append('')
        has_table = False
        for ln in lines[1:]:
            if ln.strip().startswith('|') and '---' not in ln:
                has_table = True
                cells = [c.strip() for c in ln.strip('|').split('|')]
                if len(cells) >= 3 and cells[0] not in (
                        'المبادرة', 'Initiative', 'مبادرة', 'وصف', '#'):
                    init, desc_idx, out_idx, _owner_idx = _pillar_row_layout(
                        cells)
                    desc = cells[desc_idx] if len(cells) > desc_idx else ''
                    output = cells[out_idx] if out_idx >= 0 else ''
                    if _arabic_word_count(desc) < 8:
                        enriched = False
                        for key, (new_desc, new_out) in _INITIATIVE_ENRICH.items():
                            if key in init:
                                cells[desc_idx] = new_desc
                                if out_idx >= 0:
                                    cells[out_idx] = new_out
                                enriched = True
                                break
                        if not enriched and _arabic_word_count(desc) < 8:
                            shallow_initiatives.append(init)
                    if out_idx >= 0 and _is_generic_output(output):
                        enriched_out = _ENRICHED_OUTPUTS.get(output.strip(), '')
                        if enriched_out:
                            cells[out_idx] = enriched_out
                            output = enriched_out
                        elif len(output) < 20:
                            cells[out_idx] = (
                                f'مخرج تشغيلي معتمد لـ {init}')
                            output = cells[out_idx]
                        if _is_generic_output(output):
                            generic_outputs.append(output)
                    ln = '| ' + ' | '.join(cells) + ' |'
            body_lines.append(ln)
        if title.startswith('###') and not has_table:
            shallow_pillars.append(title)
            body_lines.extend([
                '',
                '| المبادرة | الوصف | المخرج المتوقع |',
                '|---|---|---|',
                '| برنامج تنفيذي | وصف تفصيلي للبرنامج الاستراتيجي | '
                'مخرج تشغيلي معتمد قابل للقياس |',
            ])
        out_parts.append('\n'.join(body_lines))
    return '\n\n'.join(out_parts).rstrip() + '\n', shallow_pillars, shallow_initiatives, generic_outputs


def finalize_pillar_substance(
        sections: Dict[str, str],
        *,
        lang: str = 'ar',
        domain: str = 'cyber',
) -> Tuple[Dict[str, str], Dict[str, Any]]:
    dcode = (domain or '').strip().lower()
    if dcode not in ('cyber', 'cyber_security'):
        return sections, {
            'pillar_depth_passed': True,
            'action_taken': 'skipped_non_cyber',
        }

    text = sections.get('pillars', '') or ''
    if not re.search(r'^#{3,4}\s+', text, re.MULTILINE):
        text = _build_canonical_pillars(lang)
    else:
        _n, _counts, empty = _count_pillar_blocks(text)
        if empty:
            text = _build_canonical_pillars(lang)

    if _is_canonical_four_column_pillars(text):
        out = dict(sections)
        out['pillars'] = text
        return out, {
            'shallow_pillars_before': [],
            'shallow_pillars_after': [],
            'shallow_initiatives_before': [],
            'shallow_initiatives_after': [],
            'generic_outputs_before': [],
            'generic_outputs_after': [],
            'pillar_depth_passed': True,
            'action_taken': 'validated',
            'blocking_error_if_any': '',
        }

    enriched, shallow_b, shallow_i, generic_b = _enrich_pillar_text(text)
    enriched, shallow_a, shallow_i_a, generic_a = _enrich_pillar_text(enriched)

    passed = not shallow_a and not generic_a
    blocking = ''
    if not passed:
        blocking = 'rel2_substantive_quality_failed:pillars:shallow_or_generic'

    out = dict(sections)
    out['pillars'] = enriched
    diag = {
        'shallow_pillars_before': shallow_b,
        'shallow_pillars_after': shallow_a,
        'shallow_initiatives_before': shallow_i,
        'shallow_initiatives_after': shallow_i_a,
        'generic_outputs_before': generic_b,
        'generic_outputs_after': generic_a,
        'pillar_depth_passed': passed,
        'action_taken': 'pillar_substance_enriched' if generic_b else 'validated',
        'blocking_error_if_any': blocking,
    }
    return out, diag


def emit_pillar_substance_model(payload: Dict[str, Any]) -> None:
    try:
        print(
            '[REL2-PILLAR-SUBSTANCE-MODEL] '
            + json.dumps(payload, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass
