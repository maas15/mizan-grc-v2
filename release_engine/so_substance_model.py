"""PR-REL2.4 — strategic objectives substance model."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Tuple

from release_engine.arabic_language_gate import _repair_text

_WEAK_TARGET_RE = re.compile(
    r'^(≥\s*)?(\d+)\s*%$|^<\s*(\d+)\s*(ساعات?|دقائق?|س)$',
    re.IGNORECASE,
)

_SO_REPAIRS: Tuple[Tuple[str, Dict[str, str]], ...] = (
    ('مركز عمليات الأمن السيبراني', {
        'objective': 'إنشاء وتشغيل مركز عمليات الأمن السيبراني SOC/SIEM',
        'target': (
            'تشغيل مراقبة أمنية مستمرة 24/7 وتغطية 90% من الأنظمة الحرجة '
            'خلال 12 شهراً'),
        'rationale': (
            'معالجة فجوة الرصد المستمر وتحسين القدرة على الكشف المبكر '
            'والاستجابة للتهديدات'),
        'timeframe': '12 شهراً',
    }),
    ('إدارة الثغرات', {
        'objective': 'تطوير برنامج إدارة الثغرات الأمنية المستمر',
        'target': 'معالجة 95% من الثغرات الحرجة خلال 72 ساعة وفق SLA',
        'rationale': (
            'تقليل نوافذ التعرض للهجمات وتعزيز الامتثال لمتطلبات NCA ECC'),
        'timeframe': '12 شهراً',
    }),
    ('soc', {
        'objective': 'تأسيس وتشغيل مركز عمليات الأمن SOC/SIEM',
        'target': (
            'تشغيل مراقبة أمنية مستمرة 24/7 وتغطية 90% من الأنظمة الحرجة '
            'خلال 12 شهراً'),
        'rationale': 'تعزيز الكشف المبكر والاستجابة للحوادث السيبرانية',
        'timeframe': '12 شهراً',
    }),
    ('csirt', {
        'objective': 'تأسيس فريق الاستجابة للحوادث CSIRT',
        'target': 'تشغيل فريق CSIRT مع خطط استجابة معتمدة خلال 12 شهراً',
        'rationale': 'ضمان الاستجابة المنظمة للحوادث السيبرانية الحرجة',
        'timeframe': '12 شهراً',
    }),
    ('ciso', {
        'objective': 'إنشاء إدارة الأمن السيبراني وتعيين CISO',
        'target': 'اعتماد هيكل CISO ولجنة حوكمة معتمدة خلال 6 أشهر',
        'rationale': 'تعزيز الحوكمة والمساءلة على الأمن السيبراني',
        'timeframe': '6 أشهر',
    }),
    ('معلومات', {
        'objective': 'حوكمة ومعالجة المعلومات والبيانات الحساسة',
        'target': 'تصنيف 90% من البيانات الحساسة وتطبيق ضوابط DLP خلال 18 شهراً',
        'rationale': 'تعزيز حماية البيانات وفق NCA DCC',
        'timeframe': '18 شهراً',
    }),
    ('بيانات', {
        'objective': 'حماية ومعالجة البيانات الحساسة',
        'target': 'تصنيف 90% من البيانات الحساسة وتفعيل DLP خلال 18 شهراً',
        'rationale': 'تقليل مخاطر تسرب البيانات',
        'timeframe': '18 شهراً',
    }),
)


def _parse_so_rows(text: str) -> Tuple[List[str], int, List[List[str]], int]:
    lines = (text or '').splitlines()
    hdr = -1
    for i, ln in enumerate(lines):
        if ln.strip().startswith('|') and (
                'الهدف' in ln or 'objective' in ln.lower()):
            hdr = i
            break
    if hdr < 0:
        return lines, -1, [], 0
    rows = []
    table_end = hdr + 1
    for j, ln in enumerate(lines[hdr + 1:], start=hdr + 1):
        if not ln.strip().startswith('|') or '---' in ln:
            if rows:
                break
            continue
        cells = [c.strip() for c in ln.strip('|').split('|')]
        if cells and (cells[0].isdigit() or cells[0] in ('#', 'رقم')):
            if cells[0] in ('#', 'رقم'):
                cells = cells[1:]
            rows.append(cells)
            table_end = j + 1
    return lines, hdr, rows, table_end


def _is_weak_target(target: str, objective: str) -> bool:
    t = (target or '').strip()
    if not t:
        return True
    if _WEAK_TARGET_RE.match(t):
        return True
    if re.match(r'^≥?\s*\d+\s*%$', t):
        return True
    return False


def _is_timeframe(text: str) -> bool:
    t = (text or '').strip()
    if not t:
        return False
    return bool(re.search(
        r'شهر|أشهر|سنة|سنوات|أسابيع|يوم|days?|months?|years?',
        t, re.IGNORECASE))


def _looks_measurable_target(target: str) -> bool:
    t = (target or '').strip()
    if not t or t in ('—', '-', '–'):
        return False
    if re.search(r'[%≥≤]|\d', t):
        return True
    return _is_timeframe(t) and len(t) < 35


def _shifted_row(cells: List[str]) -> bool:
    if len(cells) < 5:
        return True
    obj = cells[1]
    tgt = cells[2]
    rat = cells[3]
    tfm = cells[4]
    if any(k in (obj or '') for k in (
            'الأجهزة', 'معدات', 'مليون', 'trace:section=roadmap')):
        return True
    if _is_timeframe(rat) and tfm and _is_timeframe(tfm):
        return True
    if _is_timeframe(rat) and (
            not tgt or tgt in ('—', '-', '–')
            or ('%' not in tgt and '≥' not in tgt and '≤' not in tgt)):
        return True
    if tgt and len(tgt) > 45 and '%' not in tgt and '≥' not in tgt and '≤' not in tgt:
        if rat and len(rat) > 25 and not _is_timeframe(rat):
            return True
    if tgt and not _looks_measurable_target(tgt) and len(tgt) > 20:
        if _is_timeframe(rat):
            return True
        if 'شهر' in (rat or '') and 'شهر' in (tfm or ''):
            return True
    return False


def _repair_row(cells: List[str]) -> Tuple[List[str], bool]:
    if len(cells) < 4:
        return cells, False
    changed = False
    idx_off = 1 if len(cells) >= 5 and cells[0].isdigit() else 0
    obj = cells[idx_off] if len(cells) > idx_off else ''
    tgt_idx = idx_off + 1
    rat_idx = idx_off + 2
    time_idx = idx_off + 3
    tgt = cells[tgt_idx] if len(cells) > tgt_idx else ''
    blob = (obj or '').lower()
    if _shifted_row(cells):
        cells = []
        changed = True
        return cells, changed
    if not _is_weak_target(tgt, obj):
        cells[idx_off] = _repair_text(obj)
        return cells, obj != cells[idx_off]
    for key, rep in _SO_REPAIRS:
        if key.lower() in blob or key in (obj or ''):
            cells[idx_off] = rep['objective']
            if len(cells) > tgt_idx:
                cells[tgt_idx] = rep['target']
            if len(cells) > rat_idx:
                cells[rat_idx] = rep['rationale']
            if len(cells) > time_idx:
                cells[time_idx] = rep['timeframe']
            changed = True
            break
    if not changed and _is_weak_target(tgt, obj):
        if len(cells) > tgt_idx:
            cells[tgt_idx] = (
                f'تحقيق {tgt} لـ {obj[:45]} ضمن نطاق تشغيلي خلال 12 شهراً')
        if len(cells) > rat_idx and not cells[rat_idx].strip():
            cells[rat_idx] = 'دعم التنفيذ الاستراتيجي للأمن السيبراني'
        if len(cells) > time_idx and not cells[time_idx].strip():
            cells[time_idx] = '12 شهراً'
        changed = True
    cells[idx_off] = _repair_text(cells[idx_off])
    return cells, changed


def finalize_so_substance(
        sections: Dict[str, str],
        *,
        lang: str = 'ar',
) -> Tuple[Dict[str, str], Dict[str, Any]]:
    text = sections.get('vision', '') or ''
    lines, hdr, rows, table_end = _parse_so_rows(text)
    weak_before: List[str] = []
    shifted_before = 0
    target_like_before = 0
    for cells in rows:
        idx_off = 1 if len(cells) >= 5 and str(cells[0]).isdigit() else 0
        obj = cells[idx_off] if len(cells) > idx_off else ''
        tgt = cells[idx_off + 1] if len(cells) > idx_off + 1 else ''
        if _shifted_row(cells):
            shifted_before += 1
        if _is_weak_target(tgt, obj):
            weak_before.append(tgt or obj[:30])
        if _WEAK_TARGET_RE.match((tgt or '').strip()):
            target_like_before += 1

    new_rows = []
    for cells in rows:
        repaired, _ = _repair_row(list(cells))
        if repaired:
            new_rows.append(repaired)

    text = sections.get('vision', '') or ''
    if hdr >= 0 and new_rows:
        out_lines = lines[:hdr + 1]
        for i, cells in enumerate(new_rows, 1):
            c = list(cells)
            if c and not str(c[0]).isdigit():
                out_lines.append('| ' + ' | '.join([str(i)] + c) + ' |')
            else:
                if c:
                    c[0] = str(i)
                out_lines.append('| ' + ' | '.join(c) + ' |')
        out_lines.extend(lines[table_end:])
        text = '\n'.join(out_lines)

    for _ in range(3):
        cur_lines, cur_hdr, rows_after, cur_end = _parse_so_rows(text)
        weak = []
        for cells in rows_after:
            idx_off = 1 if len(cells) >= 5 and str(cells[0]).isdigit() else 0
            obj = cells[idx_off] if len(cells) > idx_off else ''
            tgt = cells[idx_off + 1] if len(cells) > idx_off + 1 else ''
            if _is_weak_target(tgt, obj):
                weak.append(tgt)
        if not weak:
            break
        fixed_rows = []
        for cells in rows_after:
            repaired, _ = _repair_row(list(cells))
            if repaired:
                fixed_rows.append(repaired)
        if cur_hdr >= 0 and fixed_rows:
            out_lines = cur_lines[:cur_hdr + 1]
            for i, cells in enumerate(fixed_rows, 1):
                c = list(cells)
                if c:
                    c[0] = str(i)
                out_lines.append('| ' + ' | '.join(c) + ' |')
            out_lines.extend(cur_lines[cur_end:])
            text = '\n'.join(out_lines)

    _, _, rows_after, _ = _parse_so_rows(text)
    weak_after: List[str] = []
    shifted_after = 0
    target_like_after = 0
    for cells in rows_after:
        idx_off = 1 if len(cells) >= 5 and str(cells[0]).isdigit() else 0
        obj = cells[idx_off] if len(cells) > idx_off else ''
        tgt = cells[idx_off + 1] if len(cells) > idx_off + 1 else ''
        if _shifted_row(cells):
            shifted_after += 1
        if _is_weak_target(tgt, obj):
            weak_after.append(tgt or obj[:30])
        if _WEAK_TARGET_RE.match((tgt or '').strip()):
            target_like_after += 1

    passed = not weak_after and shifted_after == 0
    blocking = ''
    if not passed:
        blocking = (
            f'rel2_substantive_quality_failed:objectives:'
            f'{"weak_target" if weak_after else "shifted_row"}')

    out = dict(sections)
    out['vision'] = text
    diag = {
        'weak_targets_before': weak_before,
        'weak_targets_after': weak_after,
        'target_like_objectives_before': target_like_before,
        'target_like_objectives_after': target_like_after,
        'shifted_rows_before': shifted_before,
        'shifted_rows_after': shifted_after,
        'objectives_quality_passed': passed,
        'action_taken': 'so_substance_repaired' if weak_before else 'validated',
        'blocking_error_if_any': blocking,
    }
    return out, diag


def emit_so_substance_model(payload: Dict[str, Any]) -> None:
    try:
        print(
            '[REL2-SO-SUBSTANCE-MODEL] '
            + json.dumps(payload, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass
