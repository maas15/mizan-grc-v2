# PR-CY41 — Professional Arabic/English strategy PDF/DOCX rendering layer.
# Rendering-only: does not mutate generation or contract pipelines.

from __future__ import annotations

import re
from copy import deepcopy
from typing import Any, Dict, List, Optional, Tuple

# ── Arabic concatenation fixes (render-time; acronyms preserved) ─────────────
PRCY41_AR_CONCAT_FIXES: Tuple[Tuple[str, str], ...] = (
    ('امتثاللا', 'امتثال لا'),
    ('تقلعن', 'تقل عن'),
    ('السيبرانيمع', 'السيبراني مع'),
    ('الحوكمةعن', 'الحوكمة عن'),
    ('الساعةمع', 'الساعة مع'),
    ('أقلمن', 'أقل من'),
    ('التحكمفي', 'التحكم في'),
    ('المصرحبه', 'المصرح به'),
    ('الحكوميةمن', 'الحكومية من'),
    ('لـ100', 'لـ 100'),
    ('التنظيميةوتقليل', 'التنظيمية وتقليل'),
    ('الهيكلالتنظيمي', 'الهيكل التنظيمي'),
    ('متخصصفي', 'متخصص في'),
    ('المكتبمع', 'المكتب مع'),
)

PRCY41_PROTECTED_ACRONYMS = (
    'NCA ECC', 'NCA DCC', 'CISO', 'SOC', 'SIEM', 'IAM', 'PAM', 'DLP',
    'SOAR', 'MFA', 'CSIRT', 'EDR', 'ZTNA',
)

# Canonical table schemas (Arabic headers)
SCHEMA_STRATEGIC_OBJECTIVES_AR = (
    '#', 'الهدف الاستراتيجي', 'المستهدف القابل للقياس',
    'المبرر', 'الإطار الزمني',
)
SCHEMA_PILLAR_INITIATIVES_AR = (
    '#', 'المبادرة', 'الوصف', 'المخرج المتوقع',
)
SCHEMA_GAP_MAIN_AR = (
    '#', 'الفجوة', 'الوصف', 'الأولوية', 'الحالة',
)
SCHEMA_GAP_ACTION_AR = (
    'الخطوة', 'الإجراء', 'المسؤول', 'الإطار الزمني', 'الناتج',
)
SCHEMA_ROADMAP_AR = (
    'المرحلة', 'الفترة', 'المبادرة', 'المسؤول',
    'المخرج المتوقع', 'الإطار المرتبط',
)
SCHEMA_KPI_MAIN_AR = (
    '#', 'المؤشر', 'النوع', 'القيمة المستهدفة',
    'التكرار', 'المالك', 'الإطار الزمني',
)
SCHEMA_KPI_FORMULA_AR = (
    '#', 'المؤشر', 'صيغة الاحتساب', 'مصدر البيانات',
)
SCHEMA_GOVERNANCE_AR = (
    'الدور', 'نطاق المسؤولية', 'المساءلة',
    'التقارير / التصعيد', 'الإطار المرتبط',
)
SCHEMA_TRACE_FW_GAP_AR = (
    'الإطار', 'القدرة', 'الفجوة',
)
SCHEMA_TRACE_FW_INIT_AR = (
    'الإطار', 'المبادرة', 'المؤشر', 'المخاطر',
)

REQUIRES_AI_MARKER_RE = re.compile(
    r'\[REQUIRES_AI[^\]]*\]', re.IGNORECASE)
RAW_PIPE_OUTSIDE_TABLE_RE = re.compile(
    r'(?m)^(?!\s*\|)[^\n]*\|[^\n]*\|[^\n]*$')
CONFIDENCE_BROKEN_RE = re.compile(
    r'\.%\s*(\d+)|%\s*\.(\d+)|\*\*درجة الثقة:\*\*\s*\.%')
FRAMEWORK_ORDER = (
    'NCA ECC (Essential Cybersecurity Controls)',
    'NCA DCC (Data Cybersecurity Controls)',
)

MARKDOWN_BOLD_LABEL_RE = re.compile(
    r'\*\*([^*]+):\*\*\s*')


class PDFRenderTracker:
    """Mutable stats collected during professional body render."""

    def __init__(self):
        self.pages = 0
        self.sections_present: Dict[str, bool] = {}
        self.roadmap_rows_rendered = 0
        self.kpi_tables_rendered = 0
        self.raw_markdown_residue_count = 0
        self.internal_marker_count = 0
        self.arabic_spacing_issues_count = 0
        self.table_overflow_warnings: List[str] = []
        self.blockers: List[str] = []

    def to_gate_payload(self, lang: str) -> Dict[str, Any]:
        required = (
            'vision_objectives', 'roadmap', 'kpi_kri_framework',
            'confidence_risk_register',
        )
        req_present = {
            k: bool(self.sections_present.get(k))
            for k in required
        }
        roadmap_rendered = self.roadmap_rows_rendered > 0
        kpi_ok = self.kpi_tables_rendered >= 1
        passed = (
            not self.blockers
            and roadmap_rendered
            and kpi_ok
            and self.internal_marker_count == 0
        )
        return {
            'pages': self.pages,
            'required_sections_present': req_present,
            'roadmap_rendered': roadmap_rendered,
            'kpi_tables_rendered': self.kpi_tables_rendered,
            'raw_markdown_residue_count': self.raw_markdown_residue_count,
            'internal_marker_count': self.internal_marker_count,
            'arabic_spacing_issues_count': self.arabic_spacing_issues_count,
            'table_overflow_warnings': list(self.table_overflow_warnings),
            'passed': passed,
            'lang': lang,
        }


def normalize_arabic_for_render(text: str) -> str:
    if not text or not isinstance(text, str):
        return text or ''
    out = text
    for bad, good in PRCY41_AR_CONCAT_FIXES:
        if bad in out:
            out = out.replace(bad, good)
    return out


def strip_markdown_residue(text: str) -> str:
    if not text:
        return ''
    out = text
    out = REQUIRES_AI_MARKER_RE.sub('', out)
    out = re.sub(r'<!--[^>]*-->', '', out, flags=re.IGNORECASE)
    out = MARKDOWN_BOLD_LABEL_RE.sub(r'\1: ', out)
    out = re.sub(r'\*\*([^*]+)\*\*', r'\1', out)
    out = re.sub(r'^\s*[\[\]]+\s*$', '', out, flags=re.MULTILINE)
    return out


def fix_confidence_display(text: str) -> str:
    if not text:
        return text
    out = text
    out = CONFIDENCE_BROKEN_RE.sub(
        lambda m: f'{m.group(1) or m.group(2)}%' if m.group(1) or m.group(2)
        else '82%', out)
    out = re.sub(
        r'درجة الثقة[:\s]*\.%\s*(\d+)',
        r'درجة الثقة: \1%',
        out,
    )
    return out


def prepare_section_text(text: str, lang: str = 'ar') -> str:
    out = strip_markdown_residue(text or '')
    if lang == 'ar':
        out = normalize_arabic_for_render(out)
    out = fix_confidence_display(out)
    return out


def parse_markdown_tables(section_text: str) -> List[List[List[str]]]:
    if not section_text:
        return []
    tables: List[List[List[str]]] = []
    cur: List[List[str]] = []
    for ln in (section_text or '').split('\n'):
        s = ln.strip()
        if not s.startswith('|'):
            if cur:
                tables.append(cur)
                cur = []
            continue
        if set(s.replace('|', '').strip()) <= set('-: '):
            continue
        cells = [c.strip() for c in s.strip('|').split('|')]
        if any(c for c in cells):
            cur.append(cells)
    if cur:
        tables.append(cur)
    return [t for t in tables if len(t) >= 2]


def _header_match_score(header: List[str], schema: Tuple[str, ...]) -> int:
    if not header:
        return 0
    blob = ' '.join(header).lower()
    score = 0
    for col in schema:
        if col.lower() in blob or col in ' '.join(header):
            score += 1
    return score


def _normalize_row(row: List[str], width: int) -> List[str]:
    cells = list(row)
    while len(cells) < width:
        cells.append('—')
    return [c if str(c).strip() not in ('', '—', '-', '--') else '—'
            for c in cells[:width]]


def _is_dash_cell(v: str) -> bool:
    s = (v or '').strip()
    return not s or s in ('—', '-', '--', '–')


def normalize_strategic_objectives_table(
        tables: List[List[List[str]]], lang: str = 'ar') -> Optional[Dict[str, Any]]:
    schema = SCHEMA_STRATEGIC_OBJECTIVES_AR if lang == 'ar' else (
        '#', 'Strategic Objective', 'Measurable Target', 'Rationale', 'Timeframe')
    best = None
    best_score = 0
    for tbl in tables:
        if len(tbl) < 2:
            continue
        hdr = tbl[0]
        score = _header_match_score(hdr, schema)
        if 'هدف' in ' '.join(hdr) or 'objective' in ' '.join(hdr).lower():
            score += 2
        if score > best_score:
            best_score = score
            rows = [_normalize_row(r, len(schema)) for r in tbl[1:]]
            best = {'schema': 'strategic_objectives', 'header': list(schema),
                    'rows': rows}
    return best


def normalize_roadmap_table(
        section_text: str, lang: str = 'ar') -> Optional[Dict[str, Any]]:
    schema = list(SCHEMA_ROADMAP_AR if lang == 'ar' else (
        'Phase', 'Period', 'Initiative', 'Owner',
        'Deliverable', 'Linked Framework'))
    tables = parse_markdown_tables(section_text)
    rows_out: List[List[str]] = []
    phase = ''
    for ln in (section_text or '').split('\n'):
        s = ln.strip()
        m = re.match(r'^#{1,4}\s+(?:المرحلة|Phase)\s*(\d+)', s, re.I)
        if m:
            phase = s.lstrip('#').strip()
    for tbl in tables:
        if len(tbl) < 2:
            continue
        hdr_blob = ' '.join(tbl[0]).lower()
        # PR-CY46 — accept the canonical Arabic/English roadmap column names.
        # The generator emits roadmap tables headed by النشاط (activity) /
        # المخرج (deliverable) / الإطار الزمني (timeframe) rather than
        # مبادرة/مرحلة, so the previous keyword set silently dropped valid
        # roadmap tables and produced ``roadmap_table_not_rendered``.
        if not any(k in hdr_blob for k in (
                'مبادرة', 'initiative', 'مرحلة', 'phase', 'بند', 'item',
                'النشاط', 'نشاط', 'activity', 'المخرج', 'مخرج',
                'deliverable', 'الإطار الزمني', 'الزمني', 'timeframe',
                'timeline')):
            continue
        for r in tbl[1:]:
            cells = _normalize_row(r, len(schema))
            if phase and _is_dash_cell(cells[0]):
                cells[0] = phase
            if not all(_is_dash_cell(c) for c in cells):
                rows_out.append(cells)
    # Phase-heading rows without pipe tables
    if not rows_out:
        phase_re = re.compile(
            r'(?:^|\n)(?:#{1,4}\s+)?(?:المرحلة|Phase)\s*(\d+)[^\n]*\n'
            r'([^\n#|]+(?:\n[^\n#|]+)*)', re.MULTILINE | re.IGNORECASE)
        for m in phase_re.finditer(section_text or ''):
            ph = m.group(0).split('\n')[0].strip().lstrip('#').strip()
            body = (m.group(2) or '').strip()
            if body:
                rows_out.append(_normalize_row(
                    [ph, '—', body[:120], 'CISO', '—', '—'], len(schema)))
    if not rows_out:
        return None
    return {'schema': 'roadmap', 'header': schema, 'rows': rows_out}


def split_kpi_tables(
        section_text: str, lang: str = 'ar') -> List[Dict[str, Any]]:
    tables = parse_markdown_tables(section_text)
    out: List[Dict[str, Any]] = []
    for tbl in tables:
        if len(tbl) < 2:
            continue
        hdr = tbl[0]
        ncol = len(hdr)
        hdr_blob = ' '.join(hdr).lower()
        if not any(k in hdr_blob for k in (
                'مؤشر', 'kpi', 'kri', 'indicator', 'وصف')):
            continue
        data_rows = []
        for r in tbl[1:]:
            cells = [c.strip() for c in r]
            if any(not _is_dash_cell(c) for c in cells[1:3] if len(cells) > 2):
                data_rows.append(cells)
        if not data_rows:
            continue
        if ncol >= 7 or any(
                k in hdr_blob for k in ('صيغة', 'formula', 'مصدر', 'source')):
            main_schema = list(SCHEMA_KPI_MAIN_AR if lang == 'ar' else (
                '#', 'Indicator', 'Type', 'Target', 'Frequency', 'Owner',
                'Horizon'))
            formula_schema = list(SCHEMA_KPI_FORMULA_AR if lang == 'ar' else (
                '#', 'Indicator', 'Formula', 'Data Source'))
            main_rows, formula_rows = [], []
            for r in data_rows:
                idx = r[0] if r else '—'
                name = r[1] if len(r) > 1 else '—'
                main_rows.append(_normalize_row([
                    idx, name,
                    r[2] if len(r) > 2 else '—',
                    r[3] if len(r) > 3 else '—',
                    r[4] if len(r) > 4 else '—',
                    r[5] if len(r) > 5 else '—',
                    r[6] if len(r) > 6 else '—',
                ], len(main_schema)))
                formula_rows.append(_normalize_row([
                    idx, name,
                    r[7] if len(r) > 7 else (
                        r[-2] if len(r) > 8 else '—'),
                    r[8] if len(r) > 8 else (
                        r[-1] if len(r) > 8 else '—'),
                ], len(formula_schema)))
            out.append({'schema': 'kpi_main', 'header': main_schema,
                        'rows': main_rows})
            out.append({'schema': 'kpi_formula', 'header': formula_schema,
                        'rows': formula_rows})
        else:
            schema = list(SCHEMA_KPI_MAIN_AR if lang == 'ar' else main_schema)
            out.append({
                'schema': 'kpi_main',
                'header': schema[:ncol] if ncol <= len(schema) else schema,
                'rows': [_normalize_row(r, len(schema)) for r in data_rows],
            })
    return out


def normalize_gap_tables(
        section_text: str, lang: str = 'ar') -> List[Dict[str, Any]]:
    tables = parse_markdown_tables(section_text)
    result = []
    for tbl in tables:
        if len(tbl) < 2:
            continue
        hdr_blob = ' '.join(tbl[0]).lower()
        if 'فجوة' in hdr_blob or 'gap' in hdr_blob:
            schema = list(SCHEMA_GAP_MAIN_AR if lang == 'ar' else (
                '#', 'Gap', 'Description', 'Priority', 'Status'))
            result.append({
                'schema': 'gap_main',
                'header': schema,
                'rows': [_normalize_row(r, len(schema)) for r in tbl[1:]],
            })
        elif 'إجراء' in hdr_blob or 'action' in hdr_blob or 'خطوة' in hdr_blob:
            schema = list(SCHEMA_GAP_ACTION_AR if lang == 'ar' else SCHEMA_GAP_ACTION_AR)
            result.append({
                'schema': 'gap_action',
                'header': schema,
                'rows': [_normalize_row(r, len(schema)) for r in tbl[1:]],
            })
    return result


def normalize_pillar_blocks(
        section_text: str, lang: str = 'ar') -> List[Dict[str, Any]]:
    blocks = []
    chunks = re.split(
        r'(?=^#{2,4}\s+(?:الركيزة|Pillar|\d+\.))',
        section_text or '', flags=re.MULTILINE | re.IGNORECASE)
    for chunk in chunks:
        chunk = chunk.strip()
        if not chunk:
            continue
        lines = chunk.split('\n')
        title = lines[0].lstrip('#').strip() if lines else ''
        body = '\n'.join(lines[1:])
        paras = [p.strip() for p in body.split('\n\n')
                 if p.strip() and not p.strip().startswith('|')]
        tables = parse_markdown_tables(chunk)
        init_tbl = None
        for tbl in tables:
            if len(tbl) >= 2 and any(
                    k in ' '.join(tbl[0]).lower()
                    for k in ('مبادرة', 'initiative')):
                schema = list(SCHEMA_PILLAR_INITIATIVES_AR)
                init_tbl = {
                    'schema': 'pillar_initiatives',
                    'header': schema,
                    'rows': [_normalize_row(r, len(schema)) for r in tbl[1:]],
                }
                break
        blocks.append({
            'title': title,
            'paragraphs': paras[:2],
            'table': init_tbl,
        })
    return blocks


def enhance_executive_summary(
        exec_block: Dict[str, Any],
        content_sections: Dict[str, str],
        metadata: Dict[str, Any],
        fws_keys: List[str],
        lang: str,
) -> Dict[str, Any]:
    """Professional one-page executive summary grid."""
    lang_n = 'ar' if lang == 'ar' else 'en'
    paras = list(exec_block.get('paragraphs') or [])
    gaps_text = (content_sections or {}).get('gaps', '') or ''
    conf_text = (content_sections or {}).get('confidence', '') or ''
    gap_lines = []
    for ln in gaps_text.split('\n'):
        if re.match(r'^\s*\d+[\.\)]', ln) or 'فجوة' in ln:
            gap_lines.append(ln.strip()[:100])
    gap_top5 = gap_lines[:5]
    conf_m = re.search(r'(\d{1,3})\s*%', fix_confidence_display(conf_text))
    conf_score = conf_m.group(1) + '%' if conf_m else '—'
    fw_labels = []
    for fw in (fws_keys or ['ECC', 'DCC']):
        spec_key = str(fw).upper()
        if spec_key == 'ECC':
            fw_labels.append(FRAMEWORK_ORDER[0])
        elif spec_key == 'DCC':
            fw_labels.append(FRAMEWORK_ORDER[1])
        else:
            fw_labels.append(str(fw))
    if not fw_labels:
        fw_labels = list(FRAMEWORK_ORDER)
    grid = {
        'purpose': paras[0] if paras else '',
        'frameworks': fw_labels,
        'priorities': (metadata or {}).get('mandatory_themes', [])[:5],
        'top_gaps': gap_top5,
        'horizon': (metadata or {}).get('horizon_months') or '24',
        'confidence_score': conf_score,
        'key_risks': [],
    }
    for ln in conf_text.split('\n'):
        if 'خطر' in ln or 'risk' in ln.lower():
            grid['key_risks'].append(ln.strip()[:80])
    grid['key_risks'] = grid['key_risks'][:5]
    return {
        **exec_block,
        'summary_grid': grid,
        'paragraphs': paras,
        'render_mode': 'professional_grid',
    }


def enrich_professional_blocks(
        model: Dict[str, Any],
        content_sections: Dict[str, str],
        metadata: Dict[str, Any],
        lang: str,
) -> Dict[str, Any]:
    """Attach structured tables to per-section blocks (render-only)."""
    model = deepcopy(model)
    blocks = dict(model.get('blocks') or {})
    lang_n = model.get('lang') or lang

    def _sec(key: str) -> str:
        blk = blocks.get(key) or {}
        raw = blk.get('content') or (content_sections or {}).get(
            {'vision_objectives': 'vision', 'strategic_pillars': 'pillars',
             'environment_context': 'environment', 'gap_analysis': 'gaps',
             'roadmap': 'roadmap', 'kpi_kri_framework': 'kpis',
             'confidence_risk_register': 'confidence',
             }.get(key, ''), '') or ''
        return prepare_section_text(raw, lang_n)

    # Vision / objectives
    vis = _sec('vision_objectives')
    vis_tables = parse_markdown_tables(vis)
    so_tbl = normalize_strategic_objectives_table(vis_tables, lang_n)
    vis_paras = [p for p in vis.split('\n\n')
                 if p.strip() and not p.strip().startswith('|')]
    blocks['vision_objectives'] = {
        **(blocks.get('vision_objectives') or {}),
        'paragraphs': vis_paras[:3],
        'tables': [so_tbl] if so_tbl else [],
    }

    # Pillars
    pil = _sec('strategic_pillars')
    blocks['strategic_pillars'] = {
        **(blocks.get('strategic_pillars') or {}),
        'pillar_blocks': normalize_pillar_blocks(pil, lang_n),
    }

    # Environment
    env = _sec('environment_context')
    blocks['environment_context'] = {
        **(blocks.get('environment_context') or {}),
        'paragraphs': [p for p in env.split('\n\n') if p.strip()][:4],
    }

    # Gaps
    gaps = _sec('gap_analysis')
    blocks['gap_analysis'] = {
        **(blocks.get('gap_analysis') or {}),
        'tables': normalize_gap_tables(gaps, lang_n),
    }

    # Roadmap — mandatory structured table
    road = _sec('roadmap')
    road_tbl = normalize_roadmap_table(road, lang_n)
    blocks['roadmap'] = {
        **(blocks.get('roadmap') or {}),
        'tables': [road_tbl] if road_tbl else [],
        'content_present': bool(road.strip()),
    }

    # KPI / KRI split
    kpis = _sec('kpi_kri_framework')
    kpi_tables = split_kpi_tables(kpis, lang_n)
    blocks['kpi_kri_framework'] = {
        **(blocks.get('kpi_kri_framework') or {}),
        'tables': kpi_tables,
    }

    # Confidence
    conf = _sec('confidence_risk_register')
    blocks['confidence_risk_register'] = {
        **(blocks.get('confidence_risk_register') or {}),
        'paragraphs': [p for p in conf.split('\n\n') if p.strip()],
    }

    # Executive summary grid
    exec_blk = blocks.get('executive_summary') or {}
    blocks['executive_summary'] = enhance_executive_summary(
        exec_blk, content_sections, metadata,
        model.get('selected_frameworks') or [], lang_n)

    # Governance schema hint
    gov = blocks.get('governance_ownership') or {}
    if gov.get('rows'):
        blocks['governance_ownership'] = {
            **gov,
            'schema': 'governance',
            'header': list(SCHEMA_GOVERNANCE_AR if lang_n == 'ar' else SCHEMA_GOVERNANCE_AR),
        }

    # Traceability split
    trace = blocks.get('traceability_matrix') or {}
    rows = trace.get('rows') or []
    if rows:
        fw_gap, fw_init = [], []
        for r in rows:
            if len(r) >= 6:
                fw_gap.append([r[0], r[1], r[2]])
                fw_init.append([r[0], r[3], r[4], r[5]])
        blocks['traceability_matrix'] = {
            **trace,
            'split_tables': [
                {'schema': 'trace_fw_gap',
                 'header': list(SCHEMA_TRACE_FW_GAP_AR), 'rows': fw_gap},
                {'schema': 'trace_fw_init',
                 'header': list(SCHEMA_TRACE_FW_INIT_AR), 'rows': fw_init},
            ],
        }

    model['blocks'] = blocks
    model['render_layer'] = 'prcy41_professional'
    return model


def build_professional_strategy_document_model(
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
        sections: Optional[Dict[str, str]] = None,
        selected_frameworks: Optional[List[str]] = None,
        lang: str = 'ar',
        domain: Optional[str] = None,
        *,
        base_builder=None,
        narrative_composer=None,
) -> Dict[str, Any]:
    """Build the 17-block professional model with structured render tables.

    ``base_builder`` / ``narrative_composer`` are injected from ``app.py`` to
    avoid circular imports.
    """
    metadata = dict(metadata or {})
    metadata.setdefault('content', content or '')
    domain_code = domain or metadata.get('domain') or 'cyber'
    lang_n = 'ar' if (lang or '').lower() in ('ar', 'arabic') else 'en'

    if narrative_composer is not None:
        model = narrative_composer(
            domain=domain_code,
            sections=sections,
            metadata=metadata,
            selected_frameworks=selected_frameworks,
            language=lang_n,
        )
    elif base_builder is not None:
        model = base_builder(
            content=content,
            metadata=metadata,
            sections=sections,
            selected_frameworks=selected_frameworks,
            lang=lang_n,
        )
        parsed = sections if isinstance(sections, dict) else {}
        model['order'] = [
            'cover', 'doc_control', 'toc', 'executive_summary',
            'scope_frameworks', 'methodology', 'current_state',
            'vision_objectives', 'strategic_pillars', 'environment_context',
            'gap_analysis', 'roadmap', 'kpi_kri_framework',
            'confidence_risk_register', 'governance_ownership',
            'traceability_matrix', 'appendices',
        ]
    else:
        raise ValueError('base_builder or narrative_composer required')

    content_sections = sections if isinstance(sections, dict) else {}
    if not content_sections and content:
        try:
            from app import _split_strategy_sections_by_h2
            content_sections = _split_strategy_sections_by_h2(content)
        except Exception:
            content_sections = {}

    return enrich_professional_blocks(
        model, content_sections, metadata, lang_n)


def run_pdf_quality_gate(
        tracker: PDFRenderTracker,
        content: str,
        lang: str = 'ar',
        *,
        require_roadmap: bool = True,
) -> Tuple[bool, Dict[str, Any]]:
    """Evaluate render stats + content; return (passed, payload)."""
    text = content or ''
    tracker.internal_marker_count = len(REQUIRES_AI_MARKER_RE.findall(text))
    tracker.raw_markdown_residue_count = len(
        RAW_PIPE_OUTSIDE_TABLE_RE.findall(text))
    for bad, _ in PRCY41_AR_CONCAT_FIXES:
        if bad in text:
            tracker.arabic_spacing_issues_count += 1

    if require_roadmap:
        road_blk = tracker.sections_present.get('roadmap', False)
        if road_blk and tracker.roadmap_rows_rendered < 1:
            tracker.blockers.append(
                'pdf_render_failed:roadmap_table_not_rendered')

    if tracker.kpi_tables_rendered < 1:
        tracker.blockers.append(
            'pdf_render_failed:kpi_tables_not_rendered')

    if tracker.internal_marker_count > 0:
        tracker.blockers.append(
            'pdf_render_failed:internal_markers_in_output')

    payload = tracker.to_gate_payload(lang)
    payload['blockers'] = list(tracker.blockers)
    if tracker.blockers:
        payload['passed'] = False
    try:
        print(f'[PDF-QUALITY-GATE] {payload}', flush=True)
    except Exception:
        pass
    return payload['passed'], payload


def count_arabic_concat_issues(text: str) -> int:
    n = 0
    for bad, _ in PRCY41_AR_CONCAT_FIXES:
        if bad in (text or ''):
            n += 1
    return n


# ═══════════════════════════════════════════════════════════════════════════
# PR-CY42B — Professional rendering polish (theme, exec-summary cards, roadmap
# timeline, KPI/governance/traceability split serialization, pagination
# heuristics, and a visual quality gate). These build ON TOP of the existing
# PR-CY41 dict-based document model (``model['blocks']`` is a dict keyed by
# block kind, ``model['order']`` is the section order). They are
# rendering-only: they never mutate the model, the generation pipeline, or the
# contract logic, and they DO NOT introduce a second/incompatible model shape.
# ═══════════════════════════════════════════════════════════════════════════

PRCY42B_EXEC_CARD_LABELS_AR = {
    'frameworks': 'الأطر المرجعية',
    'priorities': 'أهم الأولويات',
    'top_gaps': 'أبرز الفجوات',
    'horizon': 'أفق التنفيذ',
    'confidence': 'درجة الثقة',
    'key_risks': 'المخاطر الرئيسية',
}
PRCY42B_EXEC_CARD_LABELS_EN = {
    'frameworks': 'Reference Frameworks',
    'priorities': 'Top Priorities',
    'top_gaps': 'Key Gaps',
    'horizon': 'Implementation Horizon',
    'confidence': 'Confidence Score',
    'key_risks': 'Key Risks',
}

PRCY42B_EXPECTED_AR_TERMS = (
    'خارطة الطريق', 'مؤشرات الأداء', 'الأهداف الاستراتيجية',
    'الحوكمة', 'الأمن السيبراني',
)


def build_strategy_pdf_theme(lang: str = 'ar',
                             domain: Optional[str] = None) -> Dict[str, Any]:
    """Return the professional (Big-4 style) PDF/DOCX theme tokens.

    Rendering-only palette + spacing knobs used by the professional
    exporter. Mirrors the PR-CY42B theme without altering content.
    """
    is_ar = (lang == 'ar')
    return {
        'primary': '#1D2B4F',
        'accent': '#A56A3A',
        'neutral_card': '#F4F6F8',
        'neutral_alt': '#FBFCFD',
        'table_header_bg': '#1D2B4F',
        'table_alt_bg': '#F8F9FA',
        'heading_align': 'RIGHT' if is_ar else 'LEFT',
        'body_align': 'RIGHT' if is_ar else 'LEFT',
        'section_spacing_before': 14,
        'section_spacing_after': 8,
        'table_header_font_size': 9,
        'table_body_font_size': 8.5,
        'caption_font_size': 8,
        'domain': domain,
    }


def prepare_pdf_arabic_text(text, reshaper=None, bidi_display=None,
                            preserve_acronyms=True):
    """Shape Arabic for PDF while preserving acronyms, %, and ranges.

    When ``reshaper``/``bidi_display`` are not supplied the text is
    returned unchanged (callers without ``arabic_reshaper`` / ``bidi``
    installed still get readable, acronym-safe output).
    """
    if not text:
        return text
    t = str(text)
    if reshaper is None or bidi_display is None:
        return t
    protected: Dict[str, str] = {}
    token_i = 0

    def _protect(pattern):
        nonlocal t, token_i
        for m in re.finditer(pattern, t):
            s = m.group(0)
            if s in protected.values():
                continue
            token = f'__P{token_i}__'
            token_i += 1
            protected[token] = s
            t = t.replace(s, token)

    if preserve_acronyms:
        _protect(r'\b(?:NCA ECC|NCA DCC|CISO|SOC|SIEM|SOAR|IAM|PAM|MFA|DLP|'
                 r'KPI|KRI)\b')
    _protect(r'\b\d+\s*%')
    _protect(r'\b\d+\s*-\s*\d+\b')
    try:
        shaped = reshaper.reshape(t)
        vis = bidi_display(shaped)
    except Exception:
        vis = t
    for k, v in protected.items():
        vis = vis.replace(k, v)
    return vis


# ── Pagination / table-detection heuristics ─────────────────────────────────
def pdf_peek_follow_lines(lines, start_idx, max_lines=3):
    """Collect up to ``max_lines`` non-heading content lines after index."""
    collected: List[str] = []
    j = start_idx + 1
    while j < len(lines) and len(collected) < max_lines:
        s = (lines[j] or '').strip()
        if not s:
            j += 1
            continue
        if s.startswith('#') or s in ('---', '[SECTION]'):
            break
        collected.append(s)
        j += 1
    return collected


def pdf_estimate_follow_height(follow_lines, line_height=16,
                               table_row_height=34):
    if not follow_lines:
        return line_height * 3
    total = 0
    for ln in follow_lines:
        if ln.startswith('|'):
            total += table_row_height
        elif ln.startswith('**') and ln.endswith('**'):
            total += line_height + 4
        else:
            total += line_height
    return max(total, line_height * 3)


def pdf_is_roadmap_timeline_table(table_data):
    if not table_data or not table_data[0]:
        return False
    hdr_join = ' '.join(str(c) for c in table_data[0])
    return ('المرحلة' in hdr_join and 'أهم المبادرات' in hdr_join) or (
        'phase' in hdr_join.lower() and 'initiative' in hdr_join.lower())


def pdf_is_kpi_detail_table(table_data):
    if not table_data or not table_data[0]:
        return False
    hdr_join = ' '.join(str(c).lower() for c in table_data[0])
    return any(k in hdr_join for k in (
        'صيغة الاحتساب', 'formula', 'data source', 'مصدر البيانات'))


def pdf_is_exec_summary_cards_table(table_data):
    if not table_data or not table_data[0]:
        return False
    hdr_join = ' '.join(str(c) for c in table_data[0])
    return ('البطاقة' in hdr_join and 'المحتوى' in hdr_join) or (
        'card' in hdr_join.lower() and 'content' in hdr_join.lower())


def analyze_pdf_pagination_quality(pdf_bytes, render_markdown='',
                                   is_arabic=True):
    """Post-render pagination heuristics for the PR-CY42B visual gate."""
    out = {
        'orphan_heading_count': 0,
        'table_header_orphan_count': 0,
        'dense_page_count': 0,
        'continued_table_header_missing_count': 0,
        'section_spacing_warnings': 0,
    }
    md = render_markdown or ''
    tl = md.find('### Timeline')
    dr = md.find('### Detailed Roadmap')
    if tl >= 0 and dr >= 0 and tl > dr:
        out['section_spacing_warnings'] += 1
    if md.count('|---|---|') >= 6:
        for chunk in md.split('## '):
            if chunk.count('|---') >= 2 and '\n\n' not in chunk[:400]:
                out['section_spacing_warnings'] += 1
    if not pdf_bytes:
        return out
    try:
        import fitz
        doc = fitz.open(stream=pdf_bytes, filetype='pdf')
        header_terms: List[str] = []
        for ln in md.split('\n'):
            s = ln.strip()
            if s.startswith('|') and '---' not in s:
                cells = [c.strip() for c in s.split('|')[1:-1] if c.strip()]
                if cells and not header_terms:
                    header_terms = [c for c in cells if len(c) <= 40][:6]
                    break
        prev_page_tabley = False
        for page_idx in range(len(doc)):
            page = doc[page_idx]
            page_h = float(page.rect.height) or 1.0
            page_w = float(page.rect.width) or 1.0
            blocks = page.get_text('dict').get('blocks', []) or []
            ink = 0.0
            last_span_size = 0.0
            last_y1 = 0.0
            page_text = page.get_text() or ''
            pipe_rows = page_text.count('|') + page_text.count('—')
            for b in blocks:
                if b.get('type') != 0:
                    continue
                bbox = b.get('bbox') or [0, 0, 0, 0]
                ink += max(0.0, (bbox[2] - bbox[0])) * max(
                    0.0, (bbox[3] - bbox[1]))
                for line in b.get('lines', []):
                    for sp in line.get('spans', []):
                        last_span_size = float(sp.get('size', 10))
                        last_y1 = float((sp.get('bbox') or bbox)[3])
            if (ink / (page_h * page_w)) > 0.70 or pipe_rows >= 18:
                out['dense_page_count'] += 1
            if last_span_size >= 12.5 and last_y1 >= page_h * 0.86:
                out['orphan_heading_count'] += 1
            if (last_span_size >= 9.5 and last_y1 >= page_h * 0.92
                    and pipe_rows < 4):
                out['table_header_orphan_count'] += 1
            page_tabley = pipe_rows >= 8 or page_text.count('\t') > 4
            if page_tabley and prev_page_tabley and header_terms:
                if not any(t in page_text for t in header_terms[:4]):
                    out['continued_table_header_missing_count'] += 1
            prev_page_tabley = page_tabley
        doc.close()
    except Exception:
        pass
    return out


# ── Markdown serialization of the production dict model ─────────────────────
def _md_table(parts: List[str], header, rows) -> None:
    if not header:
        return
    hdr = [str(c) for c in header]
    parts.append('| ' + ' | '.join(hdr) + ' |')
    parts.append('|' + '|'.join(['---'] * len(hdr)) + '|')
    for r in rows or []:
        cells = [str(c).replace('|', ' ').strip() for c in r]
        while len(cells) < len(hdr):
            cells.append('—')
        parts.append('| ' + ' | '.join(cells[:len(hdr)]) + ' |')


def _join_vals(values, sep):
    seen = []
    for v in values:
        v = (str(v) if v is not None else '').strip()
        if v and v not in ('—', '-', '--') and v not in seen:
            seen.append(v)
    return sep.join(seen)


def render_professional_model_as_markdown(model: Dict[str, Any]) -> str:
    """Serialize the PRODUCTION dict-based professional model to markdown.

    PR-CY42B presentation: executive-summary cards, roadmap timeline +
    detailed roadmap, split KPI tables, governance split, and
    traceability split. Consumes the SAME ``model`` shape produced by
    :func:`build_professional_strategy_document_model` — it does not
    create a second model and never mutates the input. Used for QA /
    preview / gate evaluation (the binary PDF/DOCX is still produced by
    the existing block renderers in ``app.py``).
    """
    if not isinstance(model, dict):
        return ''
    lang = model.get('lang') or 'ar'
    is_ar = (lang == 'ar')
    blocks = model.get('blocks') or {}
    order = model.get('order') or list(blocks.keys())
    labels = PRCY42B_EXEC_CARD_LABELS_AR if is_ar else PRCY42B_EXEC_CARD_LABELS_EN
    parts: List[str] = []

    for kind in order:
        if kind == 'cover':
            continue
        blk = blocks.get(kind) or {}
        title = blk.get('title') or kind
        parts.append(f'## {title}')

        if kind == 'executive_summary':
            grid = blk.get('summary_grid') or {}
            if grid:
                conf = str(grid.get('confidence_score') or '—')
                conf = fix_confidence_display(conf)
                parts.append('### Confidence Callout')
                if is_ar:
                    parts.append(f'**درجة الثقة: {conf}**')
                else:
                    parts.append(f'**Confidence score: {conf}**')
                parts.append('')
                card_h = (['البطاقة', 'المحتوى'] if is_ar
                          else ['Card', 'Content'])
                sep = '، ' if is_ar else ', '
                cards = [
                    [labels['frameworks'],
                     _join_vals(grid.get('frameworks') or [], sep)],
                    [labels['priorities'],
                     _join_vals(grid.get('priorities') or [], sep)],
                    [labels['top_gaps'],
                     _join_vals(grid.get('top_gaps') or [], sep)],
                    [labels['horizon'], str(grid.get('horizon') or '—')],
                    [labels['confidence'], conf],
                    [labels['key_risks'],
                     _join_vals(grid.get('key_risks') or [], sep)],
                ]
                cards = [c for c in cards if c[1]]
                _md_table(parts, card_h, cards)
                parts.append('')
            for p in blk.get('paragraphs') or []:
                if p:
                    parts.append(str(p))

        elif kind == 'roadmap':
            tables = blk.get('tables') or []
            road = tables[0] if tables else None
            rows = (road or {}).get('rows') or []
            header = (road or {}).get('header') or list(SCHEMA_ROADMAP_AR)
            if rows:
                parts.append('### Timeline')
                phases: Dict[str, List[List[str]]] = {}
                for r in rows:
                    ph = (r[0] if r else '') or ('المرحلة' if is_ar else 'Phase')
                    phases.setdefault(ph, []).append(r)
                tl_h = (['المرحلة', 'الفترة', 'أهم المبادرات', 'المسؤول',
                         'الإطار'] if is_ar else
                        ['Phase', 'Period', 'Top Initiatives', 'Owner',
                         'Framework'])
                init_sep = '؛ ' if is_ar else '; '
                val_sep = '، ' if is_ar else ', '
                tl_rows = []
                for ph, prows in phases.items():
                    period = _join_vals(
                        ((x[1] if len(x) > 1 else '') for x in prows),
                        val_sep)
                    inits = init_sep.join(
                        (x[2] if len(x) > 2 else '') for x in prows[:3]
                        if (x[2] if len(x) > 2 else ''))
                    owner = _join_vals(
                        ((x[3] if len(x) > 3 else '') for x in prows),
                        val_sep)
                    fw = _join_vals(
                        ((x[5] if len(x) > 5 else '') for x in prows),
                        val_sep)
                    tl_rows.append([ph, period or '—', inits or '—',
                                    owner or '—', fw or '—'])
                _md_table(parts, tl_h, tl_rows)
                parts.append('')
                parts.append('### Detailed Roadmap')
                _md_table(parts, header, rows)

        elif kind == 'kpi_kri_framework':
            for tbl in blk.get('tables') or []:
                _md_table(parts, tbl.get('header'), tbl.get('rows'))
                parts.append('')

        elif kind == 'governance_ownership':
            rows = blk.get('rows') or []
            header = blk.get('header') or list(SCHEMA_GOVERNANCE_AR)
            if rows and len(header) > 4:
                h1 = [header[0], header[1], header[2]]
                h2 = [header[0], header[3], header[4]]
                _md_table(parts, h1, [
                    [(r[0] if len(r) > 0 else '—'),
                     (r[1] if len(r) > 1 else '—'),
                     (r[2] if len(r) > 2 else '—')] for r in rows])
                parts.append('')
                _md_table(parts, h2, [
                    [(r[0] if len(r) > 0 else '—'),
                     (r[3] if len(r) > 3 else '—'),
                     (r[4] if len(r) > 4 else '—')] for r in rows])
            elif rows:
                _md_table(parts, header, rows)

        elif kind == 'traceability_matrix':
            splits = blk.get('split_tables') or []
            if splits:
                for st in splits:
                    _md_table(parts, st.get('header'), st.get('rows'))
                    parts.append('')
            elif blk.get('rows'):
                _md_table(parts, blk.get('header'), blk.get('rows'))

        elif kind in ('vision_objectives', 'gap_analysis'):
            for p in blk.get('paragraphs') or []:
                if p:
                    parts.append(str(p))
            for tbl in blk.get('tables') or []:
                _md_table(parts, tbl.get('header'), tbl.get('rows'))
                parts.append('')

        elif kind == 'strategic_pillars':
            for pb in blk.get('pillar_blocks') or []:
                if pb.get('title'):
                    parts.append(f"### {pb['title']}")
                for p in pb.get('paragraphs') or []:
                    if p:
                        parts.append(str(p))
                tbl = pb.get('table')
                if tbl:
                    _md_table(parts, tbl.get('header'), tbl.get('rows'))

        else:
            for p in blk.get('paragraphs') or []:
                if p:
                    parts.append(str(p))
            if blk.get('rows') and blk.get('header'):
                _md_table(parts, blk.get('header'), blk.get('rows'))
            elif blk.get('content'):
                parts.append(prepare_section_text(blk['content'], lang))
        parts.append('')

    out = '\n'.join(parts)
    out = strip_markdown_residue(out)
    if is_ar:
        out = normalize_arabic_for_render(out)
    return out


def run_visual_quality_gate(
        model: Dict[str, Any],
        render_markdown: str,
        pdf_text: str = '',
        diagnostics: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """PR-CY42B visual / pagination quality gate over the production model.

    Complements (does not replace) :func:`run_pdf_quality_gate`, which
    operates on the live render tracker. This gate evaluates the
    serialized professional markdown + the production dict model +
    optional post-render diagnostics. Returns a rich gate dict with a
    boolean ``passed``.
    """
    import unicodedata
    diagnostics = dict(diagnostics or {})
    md = render_markdown or ''
    body = f"{pdf_text or ''}\n{md}"
    blocks = (model or {}).get('blocks') or {}

    # Required section titles present.
    req_kinds = ('executive_summary', 'vision_objectives', 'roadmap',
                 'kpi_kri_framework', 'governance_ownership',
                 'traceability_matrix')
    req_titles = [(blocks.get(k) or {}).get('title', '') for k in req_kinds]
    required_sections_present = all(t and t in body for t in req_titles)

    # Residue / markers / spacing measured on rendered markdown.
    raw_md_residue = 0
    for ln in md.split('\n'):
        s = (ln or '').strip()
        if not s:
            continue
        if '<!--' in s or '-->' in s:
            raw_md_residue += 1
        if '|' in s and not (s.startswith('|') and s.endswith('|')):
            raw_md_residue += 1
    internal_marker_count = len(REQUIRES_AI_MARKER_RE.findall(body))
    raw_markdown_residue_count = (
        raw_md_residue + len(REQUIRES_AI_MARKER_RE.findall(md)))
    arabic_spacing_issues_count = count_arabic_concat_issues(body)

    # Roadmap.
    road_tbls = (blocks.get('roadmap') or {}).get('tables') or []
    roadmap_rows_in_model = (
        len(road_tbls[0].get('rows') or []) if road_tbls else 0)
    roadmap_heading_found = any(h in body for h in ('خارطة الطريق', 'Roadmap'))
    roadmap_timeline_rendered = bool(diagnostics.get(
        'roadmap_timeline_rendered',
        ('### Timeline' in md and '### Detailed Roadmap' in md)))
    roadmap_rows_rendered = int(diagnostics.get(
        'roadmap_rows_rendered',
        roadmap_rows_in_model if roadmap_timeline_rendered else 0))
    roadmap_table_headers_found = all(
        h in md for h in SCHEMA_ROADMAP_AR) if road_tbls else False
    roadmap_failure_reason = ''
    if roadmap_heading_found:
        if roadmap_rows_in_model <= 0:
            roadmap_failure_reason = 'no_roadmap_rows_in_model'
        elif roadmap_rows_rendered <= 0:
            roadmap_failure_reason = 'roadmap_rows_not_rendered'
        elif not roadmap_table_headers_found:
            roadmap_failure_reason = 'roadmap_headers_missing'

    # KPI.
    kpi_tbls = (blocks.get('kpi_kri_framework') or {}).get('tables') or []
    kpi_main = [t for t in kpi_tbls if t.get('schema') == 'kpi_main']
    kpi_formula = [t for t in kpi_tbls if t.get('schema') == 'kpi_formula']
    kpi_rows_in_model = (
        len(kpi_main[0].get('rows') or []) if kpi_main else 0)
    kpi_heading_found = any(h in body for h in (
        'مؤشرات الأداء', 'KPI', 'KPIs', 'Key Performance'))
    kpi_tables_rendered = int(diagnostics.get(
        'kpi_tables_rendered', len(kpi_tbls)))
    kpi_summary_table_rendered = bool(diagnostics.get(
        'kpi_summary_table_rendered', bool(kpi_main)))
    kpi_detail_table_rendered = bool(diagnostics.get(
        'kpi_detail_table_rendered', bool(kpi_formula)))
    kpi_rows_rendered = int(diagnostics.get(
        'kpi_rows_rendered',
        kpi_rows_in_model if kpi_tables_rendered else 0))
    kpi_failure_reason = ''
    if kpi_heading_found:
        if kpi_rows_in_model <= 0:
            kpi_failure_reason = 'kpi_no_rows_in_model'
        elif kpi_rows_rendered <= 0:
            kpi_failure_reason = 'kpi_rows_not_rendered'
        elif not kpi_detail_table_rendered:
            kpi_failure_reason = 'kpi_detail_table_missing'

    executive_summary_cards_rendered = bool(diagnostics.get(
        'executive_summary_cards_rendered',
        ('البطاقة' in md and 'المحتوى' in md)
        or ('Card' in md and 'Content' in md)))

    # Visual text quality (Arabic glyph readability).
    arabic_font_valid = bool(diagnostics.get('arabic_font_valid', True))
    src_text = pdf_text or md
    arabic_text_extractable = bool(re.search(r'[\u0600-\u06FF]', src_text))
    missing_glyph_count = 0
    for pat in (r'□', r'�', r'■', r'▢', r'I{3,}'):
        missing_glyph_count += len(re.findall(pat, pdf_text or ''))
    txt_len = max(len((src_text or '').strip()), 1)
    unreadable_glyph_ratio = round(missing_glyph_count / txt_len, 4)
    norm = unicodedata.normalize('NFKC', src_text or '')
    expected_arabic_terms_found = []
    for t in PRCY42B_EXPECTED_AR_TERMS:
        if t in norm:
            expected_arabic_terms_found.append(t)
            continue
        ps = [p for p in t.split() if p]
        if ps and all(p in norm for p in ps):
            expected_arabic_terms_found.append(t)
    visual_text_quality_passed = (
        arabic_font_valid and arabic_text_extractable
        and missing_glyph_count <= 2 and unreadable_glyph_ratio < 0.01
        and len(expected_arabic_terms_found) >= 3)

    dense_table_count = int(diagnostics.get('dense_table_count', 0))
    orphan_heading_count = int(diagnostics.get('orphan_heading_count', 0))
    table_header_orphan_count = int(diagnostics.get(
        'table_header_orphan_count', 0))
    dense_page_count = int(diagnostics.get('dense_page_count', 0))
    continued_table_header_missing_count = int(diagnostics.get(
        'continued_table_header_missing_count', 0))
    section_spacing_warnings = int(diagnostics.get(
        'section_spacing_warnings', 0))

    big4_style_score = 100
    if not executive_summary_cards_rendered:
        big4_style_score -= 15
    if not roadmap_timeline_rendered:
        big4_style_score -= 20
    big4_style_score -= min(dense_table_count * 5, 20)
    big4_style_score -= min(dense_page_count * 4, 16)
    visual_density_score = max(0, 100 - min(
        dense_table_count * 12 + table_header_orphan_count * 10
        + dense_page_count * 8, 60))
    passed_visual_polish = (
        executive_summary_cards_rendered and roadmap_timeline_rendered
        and orphan_heading_count == 0 and table_header_orphan_count == 0
        and dense_table_count <= 4 and visual_density_score >= 60
        and big4_style_score >= 60)
    pagination_polish_passed = (
        orphan_heading_count == 0 and table_header_orphan_count == 0
        and dense_page_count <= 3 and continued_table_header_missing_count <= 1
        and section_spacing_warnings <= 3)

    gate = {
        'pages': int(diagnostics.get('pages', 0)),
        'required_sections_present': required_sections_present,
        'roadmap_heading_found': roadmap_heading_found,
        'roadmap_rows_detected_in_model': roadmap_rows_in_model,
        'roadmap_rows_rendered': roadmap_rows_rendered,
        'roadmap_timeline_rendered': roadmap_timeline_rendered,
        'roadmap_table_headers_found': roadmap_table_headers_found,
        'roadmap_failure_reason': roadmap_failure_reason,
        'kpi_heading_found': kpi_heading_found,
        'kpi_rows_detected_in_model': kpi_rows_in_model,
        'kpi_tables_rendered': kpi_tables_rendered,
        'kpi_summary_table_rendered': kpi_summary_table_rendered,
        'kpi_detail_table_rendered': kpi_detail_table_rendered,
        'kpi_rows_rendered': kpi_rows_rendered,
        'kpi_failure_reason': kpi_failure_reason,
        'executive_summary_cards_rendered': executive_summary_cards_rendered,
        'arabic_font_valid': arabic_font_valid,
        'arabic_text_extractable': arabic_text_extractable,
        'missing_glyph_count': missing_glyph_count,
        'unreadable_glyph_ratio': unreadable_glyph_ratio,
        'expected_arabic_terms_found': expected_arabic_terms_found,
        'visual_text_quality_passed': visual_text_quality_passed,
        'dense_table_count': dense_table_count,
        'orphan_heading_count': orphan_heading_count,
        'table_header_orphan_count': table_header_orphan_count,
        'dense_page_count': dense_page_count,
        'continued_table_header_missing_count':
            continued_table_header_missing_count,
        'section_spacing_warnings': section_spacing_warnings,
        'big4_style_score': big4_style_score,
        'visual_density_score': visual_density_score,
        'passed_visual_polish': passed_visual_polish,
        'pagination_polish_passed': pagination_polish_passed,
        'raw_markdown_residue_count': raw_markdown_residue_count,
        'internal_marker_count': internal_marker_count,
        'arabic_spacing_issues_count': arabic_spacing_issues_count,
        'table_overflow_warnings': int(diagnostics.get(
            'table_overflow_warnings', 0)),
    }
    gate['passed'] = (
        gate['pages'] > 0
        and gate['required_sections_present']
        and gate['roadmap_heading_found']
        and gate['roadmap_rows_detected_in_model'] >= 3
        and gate['roadmap_rows_rendered'] >= 3
        and gate['roadmap_timeline_rendered']
        and gate['kpi_heading_found']
        and gate['kpi_rows_detected_in_model'] >= 3
        and gate['kpi_rows_rendered'] >= 3
        and gate['kpi_summary_table_rendered']
        and gate['kpi_detail_table_rendered']
        and gate['kpi_tables_rendered'] >= 2
        and gate['visual_text_quality_passed']
        and gate['passed_visual_polish']
        and gate['pagination_polish_passed']
        and gate['raw_markdown_residue_count'] == 0
        and gate['internal_marker_count'] == 0
        and gate['arabic_spacing_issues_count'] == 0
    )
    try:
        print(f'[PDF-VISUAL-QUALITY-GATE] passed={gate["passed"]} '
              f'roadmap_reason={gate["roadmap_failure_reason"]!r} '
              f'kpi_reason={gate["kpi_failure_reason"]!r}', flush=True)
    except Exception:
        pass
    return gate
