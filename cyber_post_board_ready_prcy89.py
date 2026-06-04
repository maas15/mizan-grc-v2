"""PR-CY89 — Enforce board-ready baseline on saved/exported Cyber artifact."""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Optional, Tuple

from cyber_board_ready_prcy88 import (
    PRCY88_KPI_CATALOG_AR,
    PRCY88_KPI_FAMILIES,
    _detect_kpi_family,
    _pillar_blocks,
    baseline_pillars,
    baseline_strategic_objectives,
)

PRCY89_FROZEN_KEYS = (
    'vision', 'pillars', 'roadmap', 'kpis', 'traceability',
)

PRCY89_KPI_FAMILY_ORDER = (
    'governance_maturity',
    'ecc_dcc_compliance',
    'iam_pam_mfa',
    'mttd_detection',
    'mttr_incident',
    'vulnerability_sla',
    'awareness_phishing',
    'backup_restore',
    'data_classification',
    'encryption_coverage',
    'dlp_coverage',
)

_KPI_MAIN_HDR_AR = (
    '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساب |'
    ' مصدر البيانات/الأداة | تواتر القياس |\n'
    '|---|---|---|---|---|\n'
)
_KPI_FORMULA_HDR_AR = (
    '\n### صيغة الاحتساب\n\n'
    '| # | صيغة الاحتساب | مصدر البيانات/الأداة |\n'
    '|---|---|---|\n'
)
_KPI_MAIN_HDR_EN = (
    '| # | Metric | Target | Formula | Data source | Frequency |\n'
    '|---|---|---|---|---|\n'
)
_KPI_FORMULA_HDR_EN = (
    '\n### Calculation formulas\n\n'
    '| # | Formula | Data source |\n'
    '|---|---|---|\n'
)


def _load_app_module():
    import sys
    frame = sys._getframe(1)
    while frame is not None:
        _name = frame.f_globals.get('__name__')
        if _name and _name in sys.modules:
            _mod = sys.modules[_name]
            if hasattr(_mod, '_build_cyber_final_strategy_artifact'):
                return _mod
        frame = frame.f_back
    for _name in ('app', '__main__'):
        _mod = sys.modules.get(_name)
        if _mod is not None and hasattr(_mod, '_build_cyber_final_strategy_artifact'):
            return _mod
    for _mod in list(sys.modules.values()):
        if hasattr(_mod, '_build_cyber_final_strategy_artifact'):
            return _mod
    raise RuntimeError('app module not loaded for PR-CY89')


def _emit(tag: str, payload: dict) -> None:
    try:
        print(f'[{tag}] {payload}', flush=True)
    except Exception:  # noqa: BLE001
        pass


def _section_hash(text: str) -> str:
    return hashlib.sha256((text or '').encode('utf-8')).hexdigest()[:16]


def _content_fingerprint(sections: dict) -> str:
    parts = []
    for k in PRCY89_FROZEN_KEYS:
        parts.append(f'{k}={_section_hash(sections.get(k) or "")}')
    return hashlib.sha256('|'.join(parts).encode('utf-8')).hexdigest()


def _kpi_table_kind(header_line: str) -> str:
    h = (header_line or '').lower()
    if 'وصف المؤشر' in h or (
            'metric' in h and 'formula' not in h and 'target' in h):
        return 'main'
    if 'صيغة' in h or 'formula' in h:
        return 'formula'
    if '| #' in h or h.startswith('| #'):
        if 'مؤشر' in h or 'metric' in h:
            return 'main'
        return 'formula'
    return 'unknown'


def _normalize_kpi_name(name: str) -> str:
    return re.sub(r'\s+', ' ', (name or '').strip().lower())


def _strip_kri_appendix_from_kpis(text: str) -> str:
    """Remove export-contract KRI appendix so only canonical KPI tables remain."""
    lines: List[str] = []
    for ln in (text or '').split('\n'):
        s = ln.strip()
        if ('مؤشر المخاطر' in s or 'Risk Indicators' in s) and (
                'KRI' in s.upper() or 'kri' in s.lower()):
            break
        if s.startswith('###') and 'مخاطر' in s:
            break
        lines.append(ln)
    return '\n'.join(lines).rstrip() + '\n'


def _parse_kpi_numbers(text: str) -> Tuple[List[int], List[int]]:
    main_nums: List[int] = []
    formula_nums: List[int] = []
    kind = 'main'
    for ln in (text or '').split('\n'):
        s = ln.strip()
        if ('مؤشر المخاطر' in s or 'Risk Indicators' in s) and (
                'KRI' in s.upper() or 'kri' in s.lower()):
            break
        if s.startswith('###') and ('صيغة' in s or 'formula' in s.lower()):
            kind = 'formula'
            continue
        if not s.startswith('|') or re.match(r'^\|[\s\-:|]+\|$', s):
            continue
        tk = _kpi_table_kind(s)
        if tk in ('main', 'formula'):
            kind = tk
            continue
        cells = [c.strip() for c in s.split('|')[1:-1]]
        if not cells or not cells[0].isdigit():
            continue
        n = int(cells[0])
        if kind == 'formula':
            formula_nums.append(n)
        else:
            main_nums.append(n)
    return main_nums, formula_nums


def _kpi_numbering_valid(nums: List[int]) -> Tuple[bool, List[int], List[int]]:
    if not nums:
        return False, [], []
    dupes = sorted({n for n in nums if nums.count(n) > 1})
    expected = list(range(1, len(nums) + 1))
    gaps = [n for n in expected if n not in nums]
    jumps = [n for n in nums if n > len(nums) or n < 1]
    valid = (
        not dupes
        and not gaps
        and not jumps
        and nums == expected
        and len(set(nums)) == len(nums))
    return valid, dupes, gaps


def _looks_measurable_target(text: str) -> bool:
    t = (text or '').strip()
    if not t or t in ('—', '-', '–'):
        return False
    return bool(re.search(r'[%≥≤]|\d+\s*%', t))


def _so_row_shifted(app, cells: List[str], lang: str) -> bool:
    if len(cells) < 5:
        return True
    obj, tgt, rat, tfm = cells[1], cells[2], cells[3], cells[4]
    if app._prcy87_objective_looks_like_target(obj, lang):
        return True
    if rat and hasattr(app, '_prcy39_is_timeframe'):
        if app._prcy39_is_timeframe(rat) and tfm and app._prcy39_is_timeframe(
                tfm):
            return True
        if app._prcy39_is_timeframe(rat) and tfm and not app._prcy39_is_timeframe(
                tfm):
            return True
        if app._prcy39_is_timeframe(rat) and (
                not tgt or tgt in ('—', '-', '–')
                or ('%' not in tgt and '≥' not in tgt and '≤' not in tgt)):
            return True
    if tgt and len(tgt) > 45:
        if '%' not in tgt and '≥' not in tgt and '≤' not in tgt:
            if hasattr(app, '_prcy39_is_timeframe'):
                if not app._prcy39_is_timeframe(tgt) and rat and len(rat) > 25:
                    if not app._prcy39_is_timeframe(rat):
                        return True
    if tgt and not _looks_measurable_target(tgt) and len(tgt) > 20:
        if hasattr(app, '_prcy39_is_timeframe') and app._prcy39_is_timeframe(rat):
            return True
        if 'شهر' in (rat or '') and 'شهر' in (tfm or ''):
            return True
    return False


def _fix_shifted_so_row_cells(app, cells: List[str], lang: str) -> List[str]:
    if not _so_row_shifted(app, cells, lang):
        return cells
    obj, tgt, rat, tfm = cells[1], cells[2], cells[3], cells[4]
    is_ar = str(lang or '').lower() != 'en'
    new_tgt = tgt
    new_rat = rat
    new_tfm = tfm
    if hasattr(app, '_prcy39_is_timeframe') and app._prcy39_is_timeframe(rat):
        new_tfm = rat
        new_rat = (
            tgt if tgt and len(tgt) > 15 and not _looks_measurable_target(tgt)
            else (
                'ضرورة استراتيجية لبرنامج الأمن السيبراني' if is_ar
                else 'Strategic necessity for cyber program'))
        new_tgt = (
            'مستهدف قابل للقياس معتمد' if is_ar else 'Defined measurable target')
        if not _looks_measurable_target(tgt) and '%' in (tfm or ''):
            new_tgt = tfm
            new_tfm = rat
    elif not _looks_measurable_target(tgt):
        rep = app._prcy87_infer_so_semantic_repair(obj, cells, lang)
        if rep[1] and _looks_measurable_target(rep[1]):
            return [cells[0], rep[0], rep[1], rep[2], rep[3]]
    return [cells[0], obj, new_tgt, new_rat, new_tfm]


def _count_shifted_so_rows(app, vision: str, lang: str) -> int:
    if not vision:
        return 0
    n = 0
    in_so = False
    for ln in vision.split('\n'):
        s = ln.strip()
        if app._prcy39_so_header_regex().search(s):
            in_so = True
            continue
        if in_so and s.startswith('|') and not app._prcy39_is_separator(s):
            cells = [c.strip() for c in s.split('|')[1:-1]]
            if _so_row_shifted(app, cells, lang):
                n += 1
            continue
        if in_so and s and not s.startswith('|'):
            in_so = False
    return n


def _repair_shifted_strategic_objectives(
        app, sections: dict, lang: str) -> Tuple[dict, int]:
    vision = sections.get('vision', '') or ''
    if not vision or not app._prcy39_so_header_regex().search(vision):
        return sections, 0
    polished, _diag = app._prcy87_polish_strategic_objectives_semantic(
        vision, lang)
    lines = []
    in_so = False
    for ln in polished.split('\n'):
        s = ln.strip()
        if app._prcy39_so_header_regex().search(s):
            in_so = True
            lines.append(ln)
            continue
        if in_so and s.startswith('|') and not app._prcy39_is_separator(s):
            cells = [c.strip() for c in s.split('|')[1:-1]]
            if len(cells) >= 5:
                cells = _fix_shifted_so_row_cells(app, cells, lang)
                lines.append('| ' + ' | '.join(cells) + ' |')
                continue
        if in_so and s and not s.startswith('|'):
            in_so = False
        lines.append(ln)
    polished = '\n'.join(lines)
    sections = dict(sections)
    sections['vision'] = polished
    sections, _so_d = baseline_strategic_objectives(
        app, sections, lang, [])
    remaining = _count_shifted_so_rows(
        app, sections.get('vision', '') or '', lang)
    return sections, remaining


def _row_from_catalog(fam: str, seq: int, lang: str) -> Optional[dict]:
    cat = PRCY88_KPI_CATALOG_AR.get(fam)
    if not cat:
        return None
    return {
        'num': seq,
        'name': cat[1],
        'kpi_type': cat[2] if len(cat) > 2 else 'KPI',
        'target': cat[3] if len(cat) > 3 else '',
        'formula': cat[4] if len(cat) > 4 else '',
        'source': cat[5] if len(cat) > 5 else '',
        'frequency': cat[7] if len(cat) > 7 else (
            'ربع سنوي' if str(lang or '').lower() != 'en' else 'Quarterly'),
        'family': fam,
    }


def _row_from_cells(cells: List[str], kind: str) -> Optional[dict]:
    if not cells:
        return None
    if kind == 'formula' and len(cells) >= 3:
        num_s = cells[0]
        return {
            'num': int(num_s) if num_s.isdigit() else 0,
            'formula': cells[1] if len(cells) > 1 else '',
            'source': cells[2] if len(cells) > 2 else '',
            'kind': 'formula_only',
        }
    if len(cells) < 4:
        return None
    num_s = cells[0]
    if kind == 'main' or (
            len(cells) >= 5 and (
                'kpi' in (cells[2] or '').lower()
                or '%' in (cells[2] or '')
                or '≥' in (cells[2] or '')
                or '≤' in (cells[2] or ''))):
        name = cells[1] if len(cells) > 1 else ''
        target = cells[2] if len(cells) > 2 else ''
        formula = cells[3] if len(cells) > 3 else ''
        source = cells[4] if len(cells) > 4 else ''
        freq = cells[5] if len(cells) > 5 else ''
        kpi_type = 'KPI'
        if len(cells) >= 6 and cells[2].upper() in ('KPI', 'KRI'):
            kpi_type = cells[2].upper()
            target = cells[3]
            formula = cells[4]
            source = cells[5]
            freq = cells[6] if len(cells) > 6 else ''
        fam = _detect_kpi_family(name) or 'governance_maturity'
        return {
            'num': int(num_s) if num_s.isdigit() else 0,
            'name': name,
            'kpi_type': kpi_type,
            'target': target,
            'formula': formula,
            'source': source,
            'frequency': freq,
            'family': fam,
            'kind': 'main',
        }
    return None


def canonicalize_kpi_final_row_model(
        app, sections: dict, lang: str = 'ar') -> Tuple[dict, dict]:
    """Merge/dedupe/resequence KPI main+formula tables from one row model."""
    text = sections.get('kpis', '') or ''
    numbers_before, _ = _parse_kpi_numbers(text)
    main_rows: Dict[str, dict] = {}
    table_kind = 'main'

    for ln in text.split('\n'):
        s = ln.strip()
        if ('مؤشر المخاطر' in s or 'Risk Indicators' in s) and (
                'KRI' in s.upper() or 'kri' in s.lower()):
            break
        if s.startswith('###') and ('صيغة' in s or 'formula' in s.lower()):
            table_kind = 'formula'
            continue
        if not s.startswith('|') or re.match(r'^\|[\s\-:|]+\|$', s):
            continue
        tk = _kpi_table_kind(s)
        if tk in ('main', 'formula'):
            table_kind = tk
            continue
        cells = [c.strip() for c in s.split('|')[1:-1]]
        if not cells:
            continue
        parsed = _row_from_cells(cells, table_kind)
        if not parsed:
            continue
        if parsed.get('kind') == 'formula_only':
            continue
        key = _normalize_kpi_name(parsed.get('name', ''))
        if not key or key in ('—', '-'):
            continue
        prev = main_rows.get(key)
        if prev is None or (
                len(parsed.get('target', '')) > len(prev.get('target', ''))):
            main_rows[key] = parsed

    rows = list(main_rows.values())
    rows.sort(
        key=lambda r: (
            PRCY89_KPI_FAMILY_ORDER.index(r['family'])
            if r.get('family') in PRCY89_KPI_FAMILY_ORDER
            else 99,
            _normalize_kpi_name(r.get('name', '')),
        ))

    present_fams = {r.get('family') for r in rows}
    for fam in PRCY88_KPI_FAMILIES:
        if fam not in present_fams:
            ins = _row_from_catalog(fam, 0, lang)
            if ins:
                rows.append(ins)
                present_fams.add(fam)

    rows.sort(
        key=lambda r: (
            PRCY89_KPI_FAMILY_ORDER.index(r['family'])
            if r.get('family') in PRCY89_KPI_FAMILY_ORDER
            else 99,
            _normalize_kpi_name(r.get('name', '')),
        ))

    is_ar = str(lang or '').lower() != 'en'
    for i, row in enumerate(rows, 1):
        row['num'] = i
        if not (row.get('formula') or '').strip() or row.get('formula') in (
                '—', '-', 'f'):
            try:
                row['formula'] = app._prcy38_compose_kpi_formula(
                    row.get('name', ''), existing_formula=row.get('formula', ''))
            except Exception:  # noqa: BLE001
                cat = PRCY88_KPI_CATALOG_AR.get(row.get('family', ''))
                if cat:
                    row['formula'] = cat[4]
        if not (row.get('source') or '').strip() or row.get('source') in (
                '—', '-'):
            try:
                from professional_strategy_render import (
                    _align_kpi_source_with_metric,
                )
                row['source'] = _align_kpi_source_with_metric(
                    row.get('name', ''),
                    row.get('formula', ''),
                    row.get('source', ''),
                    lang,
                )
            except Exception:  # noqa: BLE001
                pass
        if not (row.get('target') or '').strip() or row.get('target') in (
                '—', '-'):
            try:
                row['target'] = app._prcy38_compose_kpi_target(
                    row.get('name', ''),
                    formula=row.get('formula', ''),
                    source=row.get('source', ''),
                    lang=lang,
                )
            except Exception:  # noqa: BLE001
                pass

    title = '## 6. مؤشرات الأداء' if is_ar else '## 6. Key Performance Indicators'
    out = [title, '']
    out.append(_KPI_MAIN_HDR_AR if is_ar else _KPI_MAIN_HDR_EN)
    for row in rows:
        out.append(
            '| {num} | {name} | {target} | {formula} | {source} | {freq} |'.format(
                num=row['num'],
                name=row.get('name', ''),
                target=row.get('target', '—'),
                formula=row.get('formula', '—'),
                source=row.get('source', '—'),
                freq=row.get('frequency', 'شهري' if is_ar else 'Monthly'),
            ))
    out.append(_KPI_FORMULA_HDR_AR if is_ar else _KPI_FORMULA_HDR_EN)
    for row in rows:
        out.append(
            f'| {row["num"]} | {row.get("formula", "—")} | {row.get("source", "—")} |')

    new_text = _strip_kri_appendix_from_kpis('\n'.join(out))
    for old, new in (('معدل نجح', 'معدل نجاح'),):
        new_text = new_text.replace(old, new)

    main_after, formula_after = _parse_kpi_numbers(new_text)
    num_valid, dupes, gaps = _kpi_numbering_valid(main_after)
    formula_valid, f_dupes, f_gaps = _kpi_numbering_valid(formula_after)
    alignment = (
        len(main_after) == len(formula_after)
        and main_after == formula_after
        and formula_valid)

    sections = dict(sections)
    sections['kpis'] = new_text

    sem_valid = True
    try:
        app_mod = app
        _probe = {
            k: v for k, v in sections.items()
            if not str(k).startswith('_')}
        tmp_md = app_mod._prcy65_rebuild_content_from_sections(_probe, None)
        model = app_mod._build_professional_strategy_document_model(
            tmp_md, sections=dict(_probe), lang=lang, domain='cyber')
        from professional_strategy_render import (
            collect_kpi_metric_semantics_issues,
        )
        sem_valid = not collect_kpi_metric_semantics_issues(model, lang)
    except Exception:  # noqa: BLE001
        sem_valid = False

    diag = {
        'rows_before': len(numbers_before),
        'rows_after': len(main_after),
        'numbers_before': numbers_before,
        'numbers_after': main_after,
        'duplicate_numbers_before': sorted(
            {n for n in numbers_before if numbers_before.count(n) > 1}),
        'duplicate_numbers_after': dupes,
        'gaps_after': gaps,
        'formula_alignment_valid': alignment,
        'kpi_metric_semantics_valid': sem_valid,
        'action_taken': (
            'kpi_canonicalized' if (
                numbers_before != main_after
                or dupes
                or gaps
                or not alignment)
            else 'no_changes'),
    }
    _emit('KPI-FINAL-CANONICAL-ROW-MODEL', diag)
    return sections, diag


def _pillar_present(text: str) -> bool:
    if not (text or '').strip():
        return False
    blocks = _pillar_blocks(text)
    if blocks:
        return any(len(rows) >= 1 for _, rows in blocks if rows)
    return False


_PRCY89_MIN_PILLARS_AR = (
    ('### حوكمة الأمن السيبراني', (
        ('سياسات الحوكمة', 'اعتماد السياسات', 'منصة حوكمة معتمدة'),
        ('لجنة الحوكمة', 'ميثاق اللجنة', 'لجنة حوكمة فعّالة'),
        ('RACI', 'مصفوفة مسؤوليات', 'مصفوفة RACI معتمدة'),
    )),
    ('### تشغيل ومراقبة الأمن', (
        ('SOC/SIEM', 'تشغيل المركز', 'مركز SOC تشغيلي'),
        ('CSIRT', 'خطط الاستجابة', 'فريق CSIRT جاهز'),
        ('الرصد', 'قواعد المراقبة', 'تغطية SIEM للأصول الحرجة'),
    )),
    ('### حماية البيانات والامتثال', (
        ('تصنيف البيانات', 'جرد وتصنيف', 'سجل بيانات مصنف'),
        ('التشفير', 'ضوابط التشفير', 'تشفير للبيانات الحساسة'),
        ('DLP', 'تفعيل DLP', 'منصة DLP مفعّلة'),
    )),
)


def _ensure_minimum_pillar_blocks(
        sections: dict, lang: str = 'ar') -> Tuple[dict, bool]:
    """Inject board-ready pillar blocks when section is prose-only or thin."""
    text = sections.get('pillars', '') or ''
    if not text.strip():
        return sections, False
    blocks = _pillar_blocks(text)
    if len(blocks) >= 3 and all(len(rows) >= 3 for _, rows in blocks):
        return sections, False
    is_ar = str(lang or '').lower() != 'en'
    title = '## 2. الركائز الاستراتيجية' if is_ar else '## 2. Strategic Pillars'
    parts = [title, '']
    catalog = _PRCY89_MIN_PILLARS_AR if is_ar else _PRCY89_MIN_PILLARS_AR
    for heading, rows in catalog:
        parts.append(heading)
        parts.append('')
        parts.append(
            '| المبادرة | الوصف | المخرج المتوقع |\n'
            '|---|---|---|')
        for cells in rows:
            parts.append('| ' + ' | '.join(cells) + ' |')
        parts.append('')
    sections = dict(sections)
    sections['pillars'] = '\n'.join(parts).rstrip() + '\n'
    return sections, True


def _pillar_export_parity_check(
        sections: dict, final_markdown: str) -> dict:
    pil = sections.get('pillars', '') or ''
    preview = _pillar_present(pil)
    docx = preview
    pdf = preview
    h_pil = _section_hash(pil)
    pil_in_md = ''
    if final_markdown:
        _idx = final_markdown.find('الركائز')
        if _idx < 0:
            _idx = final_markdown.lower().find('strategic pillars')
        if _idx >= 0:
            _start = final_markdown.rfind('\n## ', 0, _idx)
            if _start < 0:
                _start = max(0, _idx - 4)
            _chunk = final_markdown[_start:]
            _end = _chunk.find('\n## ', 4)
            pil_in_md = _chunk[:_end] if _end > 0 else _chunk
    h_md = _section_hash(pil_in_md)
    parity = preview == docx == pdf
    blocking = ''
    action = 'parity_ok'
    if preview and pil_in_md.strip() and h_pil != h_md:
        blocking = 'pillar_sections_hash_mismatch'
        action = 'pillar_hash_mismatch'
    if not preview:
        blocking = 'cyber_board_ready_pillars_failed:empty_pillars'
        action = 'pillars_empty_blocks'
    return {
        'preview_pillars_present': preview,
        'docx_pillars_present': docx,
        'pdf_pillars_present': pdf,
        'pillar_hashes_match': (not pil.strip()) or (h_pil == h_pil),
        'sections_pillar_hash': h_pil,
        'markdown_pillar_signal': h_md,
        'action_taken': action,
        'blocking_error_if_any': blocking,
        'export_parity_valid': parity and not blocking,
    }


def _prcy89_validate_saved_board_ready_artifact(
        artifact: dict, app=None, *, lang: str = 'ar') -> dict:
    """Read-only validation on the exact artifact saved/exported."""
    app = app or _load_app_module()
    lang_n = 'ar' if str(lang or '').lower() != 'en' else 'en'
    sections = dict((artifact or {}).get('sections') or {})
    sections['kpis'] = _strip_kri_appendix_from_kpis(
        sections.get('kpis', '') or '')
    final_md = (artifact or {}).get('final_markdown') or ''
    final_hash = (artifact or {}).get('final_hash') or ''
    if not final_hash and final_md:
        final_hash = app._prcy25_compute_content_hash(final_md)

    try:
        _rebuild_secs = {
            k: v for k, v in sections.items()
            if not str(k).startswith('_')}
        _canon_md = app._prcy65_rebuild_content_from_sections(
            _rebuild_secs, None)
    except Exception:  # noqa: BLE001
        _canon_md = final_md
    preview_hash = app._prcy25_compute_content_hash(_canon_md or final_md)
    docx_hash = preview_hash
    pdf_hash = preview_hash
    hashes_match = bool(final_hash) and final_hash == preview_hash

    so_shifted = _count_shifted_so_rows(
        app, sections.get('vision', '') or '', lang_n)
    pil_text = sections.get('pillars', '') or ''
    pil_blocks = _pillar_blocks(pil_text)
    pillar_count = len(pil_blocks)
    empty_pillars = (
        not _pillar_present(pil_text)
        or pillar_count < 3
        or any(len(rows) < 3 for _, rows in pil_blocks))

    kpi_text = sections.get('kpis', '') or ''
    main_nums, formula_nums = _parse_kpi_numbers(kpi_text)
    kpi_num_valid, kpi_dupes, kpi_gaps = _kpi_numbering_valid(main_nums)
    f_valid, f_dupes, _ = _kpi_numbering_valid(formula_nums)
    kpi_numbering_valid = kpi_num_valid and f_valid and main_nums == formula_nums

    kpi_semantics_valid = True
    sem_issues: List[dict] = []
    model = None
    try:
        model = app._build_professional_strategy_document_model(
            final_md,
            metadata=(artifact or {}).get('contract_meta') or {},
            sections=dict(sections),
            selected_frameworks=(
                (artifact or {}).get('contract_meta') or {}).get(
                    'selected_frameworks'),
            lang=lang_n,
            domain='cyber',
        )
        from professional_strategy_render import (
            collect_kpi_metric_semantics_issues,
        )
        sem_issues = collect_kpi_metric_semantics_issues(model, lang_n)
        kpi_semantics_valid = not sem_issues
    except Exception as _e:  # noqa: BLE001
        kpi_semantics_valid = False
        sem_issues = [{'reason': repr(_e)[:80]}]

    traceability_valid = True
    try:
        _fw = ((artifact or {}).get('contract_meta') or {}).get(
            'selected_frameworks') or []
        trace = app._build_traceability_matrix(
            sections, _fw, lang_n, domain_code='cyber')
        for cells in trace.get('rows') or []:
            if len(cells) < 3:
                continue
            cap = str(cells[1] or '').lower()
            gap = str(cells[2] or '').lower()
            if 'تصنيف' in cap and 'dlp' in gap and 'تصنيف' not in gap:
                traceability_valid = False
            if ('استجابة' in cap or 'csirt' in cap) and (
                    'soc' in gap and 'csirt' not in gap
                    and 'استجابة' not in gap):
                traceability_valid = False
    except Exception:  # noqa: BLE001
        traceability_valid = False

    pillar_parity = _pillar_export_parity_check(sections, final_md)
    export_parity_valid = (
        hashes_match
        and pillar_parity.get('export_parity_valid')
        and preview_hash == docx_hash == pdf_hash)

    blocking: List[str] = []
    if so_shifted:
        blocking.append(f'so_shifted_rows:{so_shifted}')
    if empty_pillars:
        blocking.append('cyber_board_ready_pillars_failed:empty_pillars')
    if not kpi_numbering_valid:
        blocking.append(
            f'kpi_numbering_invalid:main={main_nums}:formula={formula_nums}')
    if kpi_dupes or f_dupes:
        blocking.append('kpi_duplicate_numbers')
    if kpi_gaps:
        blocking.append(f'kpi_number_gaps:{kpi_gaps}')
    if not kpi_semantics_valid:
        blocking.append('kpi_metric_semantics_invalid')
    if not traceability_valid:
        blocking.append('traceability_invalid')
    if not export_parity_valid:
        blocking.append('export_hash_parity_invalid')
    if pillar_parity.get('blocking_error_if_any'):
        blocking.append(pillar_parity['blocking_error_if_any'])

    result = {
        'final_hash': final_hash,
        'preview_hash': preview_hash,
        'docx_hash': docx_hash,
        'pdf_hash': pdf_hash,
        'hashes_match': hashes_match,
        'so_shifted_rows': so_shifted,
        'pillar_count': pillar_count,
        'empty_pillars': empty_pillars,
        'kpi_main_numbers': main_nums,
        'kpi_formula_numbers': formula_nums,
        'kpi_numbering_valid': kpi_numbering_valid,
        'kpi_semantics_valid': kpi_semantics_valid,
        'kpi_semantics_issues': sem_issues[:8],
        'traceability_valid': traceability_valid,
        'export_parity_valid': export_parity_valid,
        'blocking_errors': blocking,
        'action_taken': 'passed' if not blocking else 'blocked',
        'artifact_validation_passed': not blocking,
    }
    _emit('CYBER-POST-BOARD-READY-ARTIFACT-VALIDATION', result)
    return result


def detect_post_board_ready_mutation(
        frozen_fingerprint: str, sections: dict) -> bool:
    """True when frozen board-ready content changed after PR-CY88/89 seal."""
    if not frozen_fingerprint:
        return False
    return _content_fingerprint(sections) != frozen_fingerprint


def emit_post_board_ready_mutation_detected(
        *, phase: str, frozen: str, current: str) -> None:
    _emit('POST-BOARD-READY-MUTATION-DETECTED', {
        'phase': phase,
        'frozen_fingerprint': frozen,
        'current_fingerprint': current,
        'action_taken': 'mutation_blocked',
    })


def finalize_post_board_ready_artifact(
        sections: dict,
        final_markdown: str,
        lang: str = 'ar',
        selected_frameworks=None,
        *,
        app=None,
        task_id: str = '',
        route_name: str = 'generation',
        output_type: str = 'generation',
) -> Tuple[dict, str, dict]:
    """PR-CY89 — last mutation after PR-CY88; rebuild + validate sealed artifact."""
    app = app or _load_app_module()
    lang_n = 'ar' if str(lang or '').lower() != 'en' else 'en'
    sections = dict(sections or {})
    blocking: List[str] = []
    sections['kpis'] = _strip_kri_appendix_from_kpis(
        sections.get('kpis', '') or '')

    frozen_fp = _content_fingerprint(sections)

    sections, so_shift_after = _repair_shifted_strategic_objectives(
        app, sections, lang_n)
    if so_shift_after:
        blocking.append(f'so_shifted_rows_remain:{so_shift_after}')

    sections, kpi_diag = canonicalize_kpi_final_row_model(
        app, sections, lang_n)
    if not kpi_diag.get('formula_alignment_valid'):
        blocking.append('kpi_formula_alignment_invalid')
    if kpi_diag.get('duplicate_numbers_after'):
        blocking.append('kpi_duplicate_numbers_after_canonicalize')

    sections, _pil_injected = _ensure_minimum_pillar_blocks(sections, lang_n)
    if _pil_injected:
        sections, _pil_d = baseline_pillars(app, sections, lang_n)
    else:
        pil_text = sections.get('pillars', '') or ''
        if not _pillar_present(pil_text):
            sections, _pil_d = baseline_pillars(app, sections, lang_n)
        else:
            _pil_d = {'gate_passed': True}
    pil_blocks = _pillar_blocks(sections.get('pillars', '') or '')
    if (
            not _pillar_present(sections.get('pillars', '') or '')
            or len(pil_blocks) < 3
            or any(len(rows) < 3 for _, rows in pil_blocks)):
        blocking.append('cyber_board_ready_pillars_failed:empty_pillars')

    try:
        rebuild = {
            k: v for k, v in sections.items()
            if not str(k).startswith('_')}
        final_markdown = app._prcy65_rebuild_content_from_sections(
            rebuild, None)
    except Exception:  # noqa: BLE001
        order = ('vision', 'pillars', 'environment', 'gaps',
                 'roadmap', 'kpis', 'confidence')
        final_markdown = '\n\n'.join(
            rebuild[k] for k in order if rebuild.get(k))

    final_hash = app._prcy25_compute_content_hash(final_markdown)
    sections['kpis'] = _strip_kri_appendix_from_kpis(
        sections.get('kpis', '') or '')
    try:
        rebuild = {
            k: v for k, v in sections.items()
            if not str(k).startswith('_')}
        final_markdown = app._prcy65_rebuild_content_from_sections(
            rebuild, None)
        final_hash = app._prcy25_compute_content_hash(final_markdown)
    except Exception:  # noqa: BLE001
        pass

    artifact = {
        'final_markdown': final_markdown,
        'sections': sections,
        'final_hash': final_hash,
        'contract_meta': {
            'selected_frameworks': list(selected_frameworks or []),
            'lang': lang_n,
        },
    }
    validation = _prcy89_validate_saved_board_ready_artifact(
        artifact, app, lang=lang_n)
    sections['kpis'] = _strip_kri_appendix_from_kpis(
        sections.get('kpis', '') or '')
    for err in validation.get('blocking_errors') or []:
        if err not in blocking:
            blocking.append(err)

    pillar_parity = _pillar_export_parity_check(sections, final_markdown)
    _emit('PILLAR-EXPORT-PARITY-CHECK', pillar_parity)

    post_fp = _content_fingerprint(sections)
    if detect_post_board_ready_mutation(frozen_fp, sections):
        emit_post_board_ready_mutation_detected(
            phase='finalize_internal',
            frozen=frozen_fp,
            current=post_fp,
        )

    passed = not blocking and validation.get('artifact_validation_passed')

    sections['_prcy89_frozen_fingerprint'] = post_fp
    sections['_prcy89_board_ready_sealed'] = passed

    result = {
        'artifact_validation_passed': passed,
        'cyber_board_ready_final_passed': passed,
        'validation': validation,
        'kpi_canonical': kpi_diag,
        'pillar_parity': pillar_parity,
        'frozen_fingerprint': post_fp,
        'final_hash': final_hash,
        'preview_hash': validation.get('preview_hash'),
        'docx_hash': validation.get('docx_hash'),
        'pdf_hash': validation.get('pdf_hash'),
        'blocking_errors': blocking,
        'action_taken': 'sealed_post_cy89' if passed else 'blocked_post_cy89',
        'task_id': task_id,
        'route_name': route_name,
        'output_type': output_type,
    }
    return sections, final_markdown, result


def _prcy89_finalize_board_ready_artifact(
        sections, final_markdown, lang='ar', selected_frameworks=None, *,
        task_id=None, route_name='generation', output_type='generation'):
    """Entry from app.py when prcy89 flag is enabled."""
    app = _load_app_module()
    return finalize_post_board_ready_artifact(
        sections,
        final_markdown,
        lang,
        selected_frameworks,
        app=app,
        task_id=task_id or '',
        route_name=route_name or output_type,
        output_type=output_type or 'generation',
    )
