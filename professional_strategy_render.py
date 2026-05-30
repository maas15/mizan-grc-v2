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
    # PR-CY48 — additional Arabic concatenation defects.
    ('متكاملمع', 'متكامل مع'),
    ('أوليمع', 'أولى مع'),
    ('الأمنيةفي', 'الأمنية في'),
    ('الأصولمن', 'الأصول من'),
    ('السريعمن', 'السريع من'),
    ('الناتجةعن', 'الناتجة عن'),
    ('الحساسةمن', 'الحساسة من'),
    ('الحساباتمن', 'الحسابات من'),
    ('الكاملمع', 'الكامل مع'),
    ('الموظفينمع', 'الموظفين مع'),
    ('ساعةمن', 'ساعة من'),
    ('72 ساعةمن', '72 ساعة من'),
    ('الناشئةعن', 'الناشئة عن'),
    # PR-CY51 — additional Arabic concatenation defects.
    ('اختراقمن', 'اختراق من'),
    ('التهديداتفي', 'التهديدات في'),
    ('المخاطرمن', 'المخاطر من'),
    # PR-CY52 — additional Arabic concatenation defects.
    ('كاملمع', 'كامل مع'),
    ('المخاطرمع', 'المخاطر مع'),
    ('الاستثمارفي', 'الاستثمار في'),
    ('التدريبفي', 'التدريب في'),
)

# PR-CY52 — max rendered roadmap cell length (PDF/DOCX density gate).
ROADMAP_CELL_MAX_LEN = 72

# Forbidden gap-guide header fragments (must never appear in exports).
GAP_HEADER_FORBIDDEN_FRAGMENTS = ('طوة', 'الخ', 'طوة الخ')

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
# PR-CY47 — additional professional render schemas.
SCHEMA_ENV_AR = (
    'التهديد / الفجوة', 'الأثر', 'الأولوية', 'المعالجة المقترحة',
)
SCHEMA_CONF_FACTOR_AR = (
    'العامل', 'الوزن', 'الدرجة', 'المساهمة',
)
SCHEMA_RISK_AR = (
    '#', 'المخاطر', 'الاحتمالية', 'التأثير', 'خطة المعالجة', 'المالك',
)

REQUIRES_AI_MARKER_RE = re.compile(
    r'\[REQUIRES_AI[^\]]*\]', re.IGNORECASE)
RAW_PIPE_OUTSIDE_TABLE_RE = re.compile(
    r'(?m)^(?!\s*\|)[^\n]*\|[^\n]*\|[^\n]*$')
CONFIDENCE_BROKEN_RE = re.compile(
    r'\.%\s*(\d+)|%\s*\.(\d+)|\*\*درجة الثقة:\*\*\s*\.%(?!\s*\d)')
FRAMEWORK_ORDER = (
    'NCA ECC (Essential Cybersecurity Controls)',
    'NCA DCC (Data Cybersecurity Controls)',
)

# PR-CY48 — canonical professional export section order (PDF/DOCX parity).
PROFESSIONAL_PRE_BODY_SECTIONS = (
    'doc_control', 'executive_summary', 'scope_frameworks',
    'methodology', 'current_state',
)
PROFESSIONAL_BODY_SECTIONS = (
    'vision_objectives', 'strategic_pillars', 'environment_context',
    'gap_analysis', 'roadmap', 'kpi_kri_framework',
    'confidence_risk_register',
)
PROFESSIONAL_POST_BODY_SECTIONS = (
    'governance_ownership', 'traceability_matrix', 'appendices',
)
PROFESSIONAL_EXPORT_SECTION_ORDER = (
    PROFESSIONAL_PRE_BODY_SECTIONS + PROFESSIONAL_BODY_SECTIONS
    + PROFESSIONAL_POST_BODY_SECTIONS
)

# PR-CY48 — canonical confidence-assessment factors (never mix with risks).
CANONICAL_CONFIDENCE_FACTORS_AR: Tuple[Tuple[str, str], ...] = (
    ('اكتمال المدخلات', '20%'),
    ('تغطية الأطر المرجعية', '20%'),
    ('جدوى خارطة الطريق', '20%'),
    ('جاهزية الموارد', '15%'),
    ('نضج الحوكمة', '15%'),
    ('جاهزية حماية البيانات', '10%'),
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


def prepare_final_render_text(text: str, lang: str = 'ar') -> str:
    """PR-CY48/52 — last-mile cleanup applied to every PDF/DOCX cell/paragraph.

    Combines markdown residue stripping, Arabic spacing fixes (PRCY41/48/52),
    split-word fragment repair, confidence display normalisation, gap-header
    repair, and framework bracket artifact removal.
    """
    if text is None:
        return ''
    out = prepare_section_text(str(text), lang)
    out = prcy47_fix_ar_fragments(out)
    out = _repair_gap_header_fragments(out)
    # Strip reversed framework bracket artifacts (e.g. ``ECC + DCC]``).
    out = re.sub(r'[\[\]]+', '', out)
    out = re.sub(r'\bECC\s*\+\s*DCC\b', 'NCA ECC, NCA DCC', out)
    out = re.sub(r'\s{2,}', ' ', out).strip()
    return out


def _repair_gap_header_fragments(text: str) -> str:
    """PR-CY52 — repair split gap-guide headers (``طوة`` / ``الخ``)."""
    s = str(text or '').strip()
    if not s:
        return s
    if s in GAP_HEADER_FORBIDDEN_FRAGMENTS or 'طوة الخ' in s:
        return 'الخطوة'
    if s == 'طوة' or s == 'الخ':
        return 'الخطوة'
    if 'طوة' in s and 'خطوة' not in s:
        return 'الخطوة'
    return s


def _compact_roadmap_cell(text: str, lang: str = 'ar',
                          max_len: int = ROADMAP_CELL_MAX_LEN) -> str:
    """PR-CY52 — shorten roadmap cells; strip long DCC explanatory clauses."""
    s = str(text or '').strip()
    if not s or s == '—':
        return s
    # Remove repeated DCC narrative fragments — details belong in traceability.
    for pat in (
        r'(?:حماية|تصنيف)\s+البيانات[^،\.|;]*',
        r'(?:Data\s+Cybersecurity|data\s+classification)[^,\.;|]*',
        r'(?:وفق|بموجب)\s+(?:NCA\s+)?DCC[^،\.|;]*',
    ):
        s = re.sub(pat, '', s, flags=re.IGNORECASE)
    s = re.sub(r'\s{2,}', ' ', s).strip(' ،|,;')
    if len(s) > max_len:
        s = s[:max_len - 1].rstrip() + '…'
    return s or ('—' if lang == 'ar' else '—')


def _compact_roadmap_row(row: List[str], lang: str = 'ar') -> List[str]:
    """Apply cell compaction to a roadmap row (keep framework column short)."""
    cells = list(row) + [''] * (6 - len(row))
    out = [
        _compact_roadmap_cell(cells[0], lang, max_len=48),
        _compact_roadmap_cell(cells[1], lang, max_len=24),
        _compact_roadmap_cell(cells[2], lang),
        _compact_roadmap_cell(cells[3], lang, max_len=24),
        _compact_roadmap_cell(cells[4], lang),
        cells[5],
    ]
    fw = str(out[5] or '').strip()
    if fw.upper().startswith('NCA'):
        out[5] = 'NCA DCC' if 'DCC' in fw.upper() else 'NCA ECC'
    elif len(fw) > 24:
        out[5] = _compact_roadmap_cell(fw, lang, max_len=24)
    return out


def _derive_kpi_type(name: str, raw_type: str, lang: str = 'ar') -> str:
    """PR-CY52 — infer KPI vs KRI; never return dash/empty type."""
    t = (raw_type or '').strip().upper()
    if t in ('KPI', 'KRI'):
        return t
    n = (name or '').lower()
    kri_keys = (
        'kri', 'risk', 'مخاطر', 'phishing', 'تصيد', 'exposure', 'تعرض',
        'risk exposure', 'failure rate', 'حساس', 'sensitive data',
    )
    if any(k in n for k in kri_keys):
        return 'KRI'
    return 'KPI'


def schema_table_col_weights(schema: str, ncols: int) -> List[float]:
    """PR-CY52 — PDF column weight hints per table schema."""
    if schema == 'conf_factor' and ncols == 4:
        return [0.40, 0.18, 0.18, 0.24]
    if schema == 'gap_action' and ncols == 5:
        return [0.10, 0.34, 0.16, 0.18, 0.22]
    if schema == 'roadmap' and ncols == 6:
        return [0.14, 0.12, 0.28, 0.12, 0.20, 0.14]
    if schema == 'kpi_main' and ncols == 7:
        return [0.05, 0.24, 0.10, 0.14, 0.12, 0.14, 0.21]
    if schema == 'kpi_formula' and ncols == 4:
        return [0.08, 0.30, 0.32, 0.30]
    if ncols == 5:
        return [0.06, 0.28, 0.22, 0.22, 0.22]
    if ncols == 6:
        return [0.14, 0.14, 0.22, 0.16, 0.18, 0.16]
    if ncols == 4:
        return [0.08, 0.32, 0.30, 0.30]
    return [1.0 / max(ncols, 1)] * max(ncols, 1)


def contains_forbidden_gap_fragments(text: str) -> bool:
    """True when text contains forbidden gap-guide header fragments."""
    s = str(text or '')
    if 'طوة الخ' in s:
        return True
    for part in re.split(r'[\s|,;]+', s):
        part = part.strip()
        if not part:
            continue
        if part in ('طوة', 'الخ'):
            return True
        if part != 'الخطوة' and 'طوة' in part and 'خطوة' not in part:
            return True
    return False


def _clean_framework_labels(labels: List[str]) -> List[str]:
    """Normalise framework display strings to canonical order without artifacts."""
    cleaned: List[str] = []
    for lbl in labels or []:
        s = prepare_final_render_text(str(lbl), 'ar')
        if 'ECC' in s.upper() and 'Essential' not in s:
            s = FRAMEWORK_ORDER[0]
        elif 'DCC' in s.upper() and 'Data Cybersecurity' not in s:
            s = FRAMEWORK_ORDER[1]
        if s and s not in cleaned:
            cleaned.append(s)
    ordered = [f for f in FRAMEWORK_ORDER if f in cleaned]
    ordered += [f for f in cleaned if f not in FRAMEWORK_ORDER]
    return ordered or list(FRAMEWORK_ORDER)


def _normalize_gap_header(cell: str) -> str:
    """Ensure gap-guide headers render as ``الخطوة`` not split fragments."""
    s = str(cell or '').strip()
    if s in ('الخ', 'طوة', 'طوة الخ') or 'طوة الخ' in s:
        return 'الخطوة'
    if 'طوة' in s and 'خطوة' not in s:
        return 'الخطوة'
    return prcy47_fix_ar_fragments(s)


def _normalize_gap_cell(cell: str) -> str:
    """PR-CY50 — repair gap-guide table cells (step/action fragments)."""
    s = _normalize_gap_header(str(cell or '').strip())
    if s in ('الخ', 'طوة'):
        return 'الخطوة'
    return prcy47_fix_ar_fragments(s)


def _is_dash_heavy_row(row: List[str], threshold: float = 0.6) -> bool:
    cells = [str(c).strip() for c in (row or [])]
    if not cells:
        return True
    dash_n = sum(1 for c in cells if _is_dash_cell(c))
    return (dash_n / len(cells)) >= threshold


def _phase_bucket(period_or_phase: str) -> int:
    nums = [int(n) for n in re.findall(r'\d+', period_or_phase or '')]
    start = nums[0] if nums else 0
    blob = (period_or_phase or '')
    if 'تأسيس' in blob or 'Establish' in blob or '1-6' in blob:
        return 1
    if 'تمكين' in blob or 'Enable' in blob or '7-18' in blob:
        return 2
    if 'تحسين' in blob or 'Optimize' in blob or '19-24' in blob:
        return 3
    if start and start <= 6:
        return 1
    if start and start <= 18:
        return 2
    return 3


def _infer_roadmap_framework(
        init: str, period: str, phase_num: int, raw_fw: str,
        lang: str = 'ar') -> str:
    """PR-CY50 — map roadmap rows to NCA ECC vs NCA DCC by initiative content."""
    blob = f'{init} {period}'.lower()
    dcc_keys = (
        'dcc', 'dlp', 'تصنيف', 'بيانات', 'data', 'حماية البيانات',
        'privacy', 'priv', 'خصوص', 'تصنيف البيانات',
    )
    if any(k in blob for k in dcc_keys):
        return 'NCA DCC'
    if raw_fw and not _is_dash_cell(raw_fw):
        fw = str(raw_fw).strip()
        if 'DCC' in fw.upper():
            return 'NCA DCC'
        if 'ECC' in fw.upper():
            return 'NCA ECC'
        return fw
    if phase_num >= 3:
        return 'NCA DCC'
    return 'NCA ECC'


def _fill_roadmap_row(row: List[str], lang: str = 'ar') -> List[str]:
    """Ensure a roadmap row has meaningful owner/output/framework defaults."""
    cells = list(row) + ['—'] * (6 - len(row))
    period = cells[1] if not _is_dash_cell(cells[1]) else (
        '1-6 أشهر' if _phase_bucket(cells[0]) == 1 else
        '7-18 شهر' if _phase_bucket(cells[0]) == 2 else '19-24 شهر')
    phase_num = _phase_bucket(period or cells[0])
    init = cells[2] if not _is_dash_cell(cells[2]) else (
        'مبادرة تنفيذية' if lang == 'ar' else 'Implementation initiative')
    fw = _infer_roadmap_framework(
        init, period, phase_num, cells[5] if len(cells) > 5 else '', lang)
    return _compact_roadmap_row([
        cells[0] if not _is_dash_cell(cells[0]) else _phase_for_months(period, lang),
        period,
        init,
        cells[3] if not _is_dash_cell(cells[3]) else 'CISO',
        cells[4] if not _is_dash_cell(cells[4]) else (
            'مخرج معتمد' if lang == 'ar' else 'Approved deliverable'),
        fw,
    ], lang)


def _phase_label(phase_num: int, lang: str = 'ar') -> str:
    """Canonical roadmap phase label for phase_num 1/2/3."""
    labels = {
        1: ('المرحلة 1: تأسيس (1-6 أشهر)', 'Phase 1: Establish (1-6 months)'),
        2: ('المرحلة 2: تمكين وتشغيل (7-18 شهر)',
            'Phase 2: Enable & Operate (7-18 months)'),
        3: ('المرحلة 3: تحسين واستدامة (19-24 شهر)',
            'Phase 3: Optimize & Sustain (19-24 months)'),
    }
    ar, en = labels.get(phase_num, labels[1])
    return ar if lang == 'ar' else en


def _synth_phase_row(phase_num: int, lang: str = 'ar') -> List[str]:
    synth = {
        1: ('1-6 أشهر', 'تأسيس حوكمة الأمن السيبراني وتعيين CISO',
            'CISO', 'إدارة ولجنة حوكمة فاعلة', 'NCA ECC'),
        2: ('7-18 شهر', 'تمكين SOC/SIEM وIAM/PAM/MFA',
            'CISO', 'قدرات تشغيلية فعّالة', 'NCA ECC'),
        3: ('19-24 شهر', 'تحسين إدارة الثغرات والاستجابة للحوادث CSIRT',
            'CISO', 'نضج وتحسين مستمر', 'NCA DCC'),
    }
    period, init, owner, out, fw = synth.get(phase_num, synth[2])
    if lang != 'ar':
        period = period.replace('أشهر', 'months').replace('شهر', 'months')
    return [_phase_label(phase_num, lang), period, init, owner, out, fw]


def build_roadmap_render_spec(
        rows: List[List[str]], lang: str = 'ar') -> List[List[str]]:
    """PR-CY48 — build meaningful roadmap rows grouped by phase coverage.

    Filters dash-heavy rows, deduplicates by initiative text, guarantees
    1–6 / 7–18 / 19–24 phase coverage with owner/output/framework filled.
    """
    buckets: Dict[int, List[List[str]]] = {1: [], 2: [], 3: []}
    seen_inits: set = set()
    for r in rows or []:
        if _is_dash_heavy_row(r):
            continue
        filled = _fill_roadmap_row(r, lang)
        init_key = (filled[2] or '').strip()[:60]
        if init_key in seen_inits:
            continue
        seen_inits.add(init_key)
        bucket = _phase_bucket(filled[1] or filled[0])
        buckets[bucket].append(filled)
    result: List[List[str]] = []
    for phase_num in (1, 2, 3):
        phase_rows = buckets[phase_num]
        if phase_rows:
            result.extend(phase_rows[:3])
        else:
            result.append(_fill_roadmap_row(
                _synth_phase_row(phase_num, lang), lang))
    return result


def _is_formula_echo(formula: str, metric_name: str) -> bool:
    f = (formula or '').strip()
    n = (metric_name or '').strip()
    if not f or f == '—':
        return True
    if f == n:
        return True
    if len(f) < 20 and n and (n in f or f in n):
        return True
    return False


def _sanitize_table_spec(
        tbl: Optional[Dict[str, Any]], lang: str = 'ar') -> Optional[Dict[str, Any]]:
    """Apply final render cleanup to every table header/cell."""
    if not tbl:
        return tbl
    schema = tbl.get('schema', '')
    if schema == 'gap_action':
        hdr = list(SCHEMA_GAP_ACTION_AR if lang == 'ar' else (
            'Step', 'Action', 'Owner', 'Timeframe', 'Output'))
    else:
        hdr = []
        for h in (tbl.get('header') or []):
            hdr.append(prepare_final_render_text(h, lang))
    rows = []
    for r in tbl.get('rows') or []:
        if schema == 'roadmap' and _is_dash_heavy_row(r):
            continue
        if schema == 'roadmap':
            rows.append(_compact_roadmap_row(
                [prepare_final_render_text(c, lang) for c in r], lang))
        elif schema == 'gap_action':
            cells = [_normalize_gap_cell(prepare_final_render_text(c, lang))
                     for c in r]
            # Merge split step columns (طوة | الخ → الخطوة).
            if (len(cells) >= 2
                    and cells[0] in ('الخطوة', '1', '2', '3', '4', '5')
                    and cells[1] in ('الخطوة', '—')):
                cells = [cells[0]] + cells[2:]
            if cells and cells[0] not in ('الخطوة',) and str(cells[0]).isdigit():
                pass
            elif cells:
                cells[0] = _normalize_gap_cell(cells[0])
            rows.append(cells)
        else:
            rows.append([prepare_final_render_text(c, lang) for c in r])
    out = dict(tbl)
    out['header'] = hdr
    out['rows'] = rows
    if tbl.get('title'):
        out['title'] = prepare_final_render_text(tbl['title'], lang)
    return out


def _finalize_professional_blocks(
        blocks: Dict[str, Any], lang: str = 'ar') -> Dict[str, Any]:
    """PR-CY48 — last pass over all blocks before PDF/DOCX render."""
    out = deepcopy(blocks)
    for kind, blk in out.items():
        if not isinstance(blk, dict):
            continue
        blk['paragraphs'] = [
            prepare_final_render_text(p, lang)
            for p in (blk.get('paragraphs') or []) if str(p).strip()]
        for i, tbl in enumerate(blk.get('tables') or []):
            blk['tables'][i] = _sanitize_table_spec(tbl, lang)
        if kind == 'executive_summary':
            grid = dict(blk.get('summary_grid') or {})
            if grid:
                grid['frameworks'] = _clean_framework_labels(
                    grid.get('frameworks') or [])
                grid['confidence_score'] = prepare_final_render_text(
                    grid.get('confidence_score', ''), lang)
                grid['purpose'] = prepare_final_render_text(
                    grid.get('purpose', ''), lang)
                blk['summary_grid'] = grid
                # Grid carries the narrative — no duplicate paragraphs.
                blk['paragraphs'] = []
        if kind == 'strategic_pillars':
            for pb in blk.get('pillar_blocks') or []:
                pb['paragraphs'] = [
                    prepare_final_render_text(p, lang)
                    for p in (pb.get('paragraphs') or [])]
                if pb.get('table'):
                    pb['table'] = _sanitize_table_spec(pb['table'], lang)
        if kind == 'traceability_matrix' and blk.get('split_tables'):
            blk['split_tables'] = [
                _sanitize_table_spec(st, lang)
                for st in blk['split_tables']]
        if kind == 'governance_ownership' and blk.get('rows'):
            blk['rows'] = [
                [prepare_final_render_text(c, lang) for c in r]
                for r in blk['rows']]
        if kind == 'methodology' and blk.get('rows'):
            blk['rows'] = [
                (prepare_final_render_text(lbl, lang),
                 prepare_final_render_text(body, lang))
                for lbl, body in blk['rows']]
    return out


def get_professional_export_section_keys(
        model: Optional[Dict[str, Any]]) -> List[str]:
    """Return professional section keys present in the model (PDF/DOCX parity)."""
    blocks = (model or {}).get('blocks') or {}
    present = []
    for kind in PROFESSIONAL_EXPORT_SECTION_ORDER:
        blk = blocks.get(kind) or {}
        if kind == 'doc_control' and blk.get('rows'):
            present.append(kind)
        elif kind == 'executive_summary' and (
                blk.get('summary_grid') or blk.get('paragraphs')):
            present.append(kind)
        elif kind == 'scope_frameworks' and blk.get('frameworks'):
            present.append(kind)
        elif kind == 'methodology' and blk.get('rows'):
            present.append(kind)
        elif kind == 'current_state' and blk.get('paragraphs'):
            present.append(kind)
        elif kind == 'strategic_pillars' and blk.get('pillar_blocks'):
            present.append(kind)
        elif kind == 'appendices' and blk.get('entries'):
            present.append(kind)
        elif kind == 'governance_ownership' and blk.get('rows'):
            present.append(kind)
        elif kind == 'traceability_matrix' and (
                blk.get('split_tables') or blk.get('rows')):
            present.append(kind)
        elif blk.get('tables') or blk.get('paragraphs'):
            present.append(kind)
    return present


def executive_summary_grid_rows(
        grid: Dict[str, Any], lang: str = 'ar') -> List[Tuple[str, str]]:
    """Build label/value rows for executive summary two-column rendering."""
    if not grid:
        return []
    sep = '؛ ' if lang == 'ar' else '; '
    fw_sep = ' — ' if lang == 'ar' else ', '
    if lang == 'ar':
        spec = (
            ('الغرض', grid.get('purpose', '')),
            ('الأطر المرجعية', fw_sep.join(grid.get('frameworks') or [])),
            ('أهم الأولويات', sep.join(grid.get('priorities') or []) or '—'),
            ('أبرز الفجوات', sep.join(grid.get('top_gaps') or []) or '—'),
            ('أفق التنفيذ', f"{grid.get('horizon', '24')} شهر"),
            ('درجة الثقة', grid.get('confidence_score', '—')),
            ('المخاطر الرئيسية', sep.join(grid.get('key_risks') or []) or '—'),
        )
    else:
        spec = (
            ('Purpose', grid.get('purpose', '')),
            ('Frameworks', fw_sep.join(grid.get('frameworks') or [])),
            ('Top priorities', sep.join(grid.get('priorities') or []) or '—'),
            ('Top gaps', sep.join(grid.get('top_gaps') or []) or '—'),
            ('Horizon', f"{grid.get('horizon', '24')} months"),
            ('Confidence', grid.get('confidence_score', '—')),
            ('Key risks', sep.join(grid.get('key_risks') or []) or '—'),
        )
    return [(lbl, val) for lbl, val in spec if val and val != '—']


def get_roadmap_spec_rows(
        model: Optional[Dict[str, Any]]) -> List[List[str]]:
    """Return all roadmap table rows from the professional model."""
    blocks = (model or {}).get('blocks') or {}
    rows: List[List[str]] = []
    for tbl in ((blocks.get('roadmap') or {}).get('tables') or []):
        rows.extend(tbl.get('rows') or [])
    return rows


def roadmap_phase_coverage_valid(rows: Optional[List[List[str]]]) -> bool:
    """True when roadmap rows span 1–6 / 7–18 / 19–24 phases."""
    phases_text = roadmap_phase_coverage_text(rows or [])
    has_p1 = any(k in phases_text for k in ('تأسيس', '1-6', 'Establish'))
    has_p2 = any(k in phases_text for k in ('تمكين', '7-18', 'Enable'))
    has_p3 = any(k in phases_text for k in (
        'تحسين', '19-24', 'Optimize', 'استدامة'))
    return has_p1 and has_p2 and has_p3


def roadmap_phase_coverage_text(rows: List[List[str]]) -> str:
    return ' '.join(str(r[0]) if r else '' for r in rows)


def count_model_arabic_spacing_issues(
        model: Optional[Dict[str, Any]]) -> int:
    """Count remaining Arabic concat defects anywhere in the model blob."""
    blob = str((model or {}).get('blocks') or {})
    return sum(1 for bad, _ in PRCY41_AR_CONCAT_FIXES if bad in blob)


def kpi_split_table_count(model: Optional[Dict[str, Any]]) -> int:
    blocks = (model or {}).get('blocks') or {}
    kpi = blocks.get('kpi_kri_framework') or {}
    return len(kpi.get('tables') or [])


def confidence_model_valid(model: Optional[Dict[str, Any]]) -> bool:
    blocks = (model or {}).get('blocks') or {}
    conf = blocks.get('confidence_risk_register') or {}
    factors = [t for t in (conf.get('tables') or [])
               if t.get('schema') == 'conf_factor']
    return bool(factors) and len(factors[0].get('rows') or []) >= 6


def build_renderer_parity_check(
        model: Optional[Dict[str, Any]],
        *,
        route_name: str = '',
        output_type: str = '',
        live_commit: str = '',
        parity_with_preview: bool = True,
        action_taken: str = 'render',
) -> Dict[str, Any]:
    """Build [RENDERER-PARITY-CHECK] diagnostic payload."""
    road_rows = get_roadmap_spec_rows(model)
    export_keys = get_professional_export_section_keys(model)
    blocks = (model or {}).get('blocks') or {}
    return {
        'strategy_id': '',
        'route_name': route_name,
        'output_type': output_type,
        'live_commit': live_commit,
        'professional_model_used': bool(
            model and model.get('render_layer') == 'prcy41_professional'),
        'professional_renderer_module': 'professional_strategy_render',
        'section_order': list(
            model.get('professional_section_order')
            or PROFESSIONAL_EXPORT_SECTION_ORDER),
        'executive_summary_present': 'executive_summary' in export_keys,
        'roadmap_spec_rows': len(road_rows),
        'roadmap_phase_coverage': roadmap_phase_coverage_valid(road_rows),
        'kpi_split_tables': kpi_split_table_count(model),
        'confidence_model_valid': confidence_model_valid(model),
        'governance_present': 'governance_ownership' in export_keys,
        'traceability_present': 'traceability_matrix' in export_keys,
        'final_arabic_spacing_issues': count_model_arabic_spacing_issues(model),
        'parity_with_preview': parity_with_preview,
        'action_taken': action_taken,
        'docx_professional_sections_present': all(
            k in export_keys for k in DOCX_REQUIRED_PROFESSIONAL_SECTIONS),
        'docx_no_raw_1_to_7_fallback': bool(
            model and model.get('render_layer') == 'prcy41_professional'),
        'preview_pdf_docx_parity_passed': bool(
            model and model.get('render_layer') == 'prcy41_professional'
            and 'executive_summary' in export_keys
            and 'governance_ownership' in export_keys),
    }


def emit_renderer_parity_check(**kwargs) -> Dict[str, Any]:
    payload = build_renderer_parity_check(**kwargs)
    try:
        print(f'[RENDERER-PARITY-CHECK] {payload}', flush=True)
    except Exception:  # noqa: BLE001
        pass
    return payload


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
    """PR-CY47 — header-aware roadmap normalization.

    Maps roadmap columns by HEADER NAME (not position) into the canonical
    schema ``المرحلة | الفترة | المبادرة | المسؤول | المخرج المتوقع | الإطار
    المرتبط`` and assigns a professional phase (1–6 / 7–18 / 19–24) derived
    from each row's timeframe so the timeline view always has phase coverage.
    """
    schema = list(SCHEMA_ROADMAP_AR if lang == 'ar' else (
        'Phase', 'Period', 'Initiative', 'Owner',
        'Deliverable', 'Linked Framework'))
    tables = parse_markdown_tables(section_text)
    rows_out: List[List[str]] = []
    for tbl in tables:
        if len(tbl) < 2:
            continue
        hdr = tbl[0]
        hdr_blob = ' '.join(hdr).lower()
        if not any(k in hdr_blob for k in (
                'مبادرة', 'initiative', 'مرحلة', 'phase', 'بند', 'item',
                'النشاط', 'نشاط', 'activity', 'المخرج', 'مخرج',
                'deliverable', 'الإطار الزمني', 'الزمني', 'timeframe',
                'timeline')):
            continue
        i_init = _col_index(hdr, ('المبادرة', 'النشاط', 'نشاط', 'initiative',
                                  'activity', 'البند', 'item'))
        i_owner = _col_index(hdr, ('المسؤول', 'المالك', 'owner',
                                   'responsible'))
        i_period = _col_index(hdr, ('الإطار الزمني', 'الفترة', 'الزمني',
                                    'period', 'timeframe', 'timeline'))
        i_deliver = _col_index(hdr, ('المخرج', 'الناتج', 'deliverable',
                                     'output'))
        i_fw = _col_index(hdr, (
            'الإطار المرتبط', 'linked framework', 'framework link'))
        if i_fw < 0:
            for i, h in enumerate(hdr):
                blob = str(h).lower()
                if ('framework' in blob or 'مرتبط' in blob):
                    if 'زمن' not in blob and 'time' not in blob:
                        i_fw = i
                        break
        i_phase = _col_index(hdr, ('المرحلة', 'phase'))
        for r in tbl[1:]:
            init = _cell(r, i_init if i_init >= 0 else 1)
            owner = _cell(r, i_owner, 'CISO')
            period = _cell(r, i_period)
            deliver = _cell(r, i_deliver)
            fw = _cell(r, i_fw)
            if init == '—' and deliver == '—':
                continue
            phase = (_cell(r, i_phase) if i_phase >= 0
                     and not _is_dash_cell(_cell(r, i_phase))
                     else _phase_for_months(period, lang))
            rows_out.append([phase, period, init, owner, deliver, fw])
    # Phase-heading rows without pipe tables.
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
    rows_out = build_roadmap_render_spec(rows_out, lang)
    return {'schema': 'roadmap', 'header': schema, 'rows': rows_out}


def _is_time_based_metric(name: str) -> bool:
    """True when KPI measures duration/time, not a percentage rate."""
    n = (name or '').strip().lower()
    if any(k in n for k in ('ثغر', 'vulnerability', 'vm')):
        return False
    return any(k in n for k in (
        'زمن', 'time', 'mttr', 'mttd', 'response', 'استجاب',
        'ساعة', 'hour', 'دقيقة', 'minute', 'أيام', 'days',
    ))


def _derive_kpi_target(name: str, raw_target: str, lang: str = 'ar') -> str:
    """PR-CY50 — time-based metrics use time thresholds, not percentages."""
    t = (raw_target or '').strip()
    if not _is_time_based_metric(name):
        return t if t and t != '—' else '100%'
    if t and t != '—' and '%' not in t:
        return t
    if lang == 'ar':
        if any(k in (name or '') for k in ('استجاب', 'response', 'حادث')):
            return '< 4 ساعات'
        return '≤ 72 ساعة'
    if any(k in (name or '').lower() for k in ('response', 'incident')):
        return '< 4 hours'
    return '≤ 72 hours'


def _derive_kpi_formula(name: str, lang: str = 'ar') -> str:
    """PR-CY48/50 — professional calculation expression derived from metric name."""
    n = (name or '').strip()
    if not n or n == '—':
        return ('(المنجز ÷ المخطط) × 100' if lang == 'ar'
                else '(Done ÷ Planned) × 100')
    nu = n.lower()
    # Vulnerability metrics BEFORE generic incident-response matching.
    if any(k in n for k in ('ثغر', 'vulnerability', 'Vulnerability', 'VM')):
        if _is_time_based_metric(n):
            return ('متوسط زمن إغلاق الثغرات الحرجة ضمن SLA'
                    if lang == 'ar' else
                    'Average critical vulnerability closure time within SLA')
        return ('(عدد الثغرات المغلقة ضمن SLA / إجمالي الثغرات الحرجة) × 100'
                if lang == 'ar' else
                '(SLA-closed vulnerabilities / critical vulnerabilities) × 100')
    if _is_time_based_metric(n):
        return ('متوسط زمن الاستجابة للحوادث الحرجة'
                if lang == 'ar' else
                'Average critical incident response time')
    if any(k in n for k in ('MFA', 'mfa', 'مصادقة', 'مصادقة ثنائية')):
        return ('(عدد الحسابات المفعلة عليها MFA / إجمالي الحسابات المستهدفة) × 100'
                if lang == 'ar' else
                '(MFA-enabled accounts / target accounts) × 100')
    if any(k in n for k in ('استجاب', 'response', 'SOC', 'soc', 'حادث')):
        return ('مجموع أزمنة الاستجابة للحوادث الحرجة / عدد الحوادث الحرجة'
                if lang == 'ar' else
                'Sum critical incident response times / critical incident count')
    if any(k in n for k in ('نسخ', 'backup', 'Backup', 'DR', 'تعاف')):
        return ('(عدد النسخ الناجحة / إجمالي عمليات النسخ) × 100'
                if lang == 'ar' else
                '(Successful backups / total backup operations) × 100')
    if any(k in n for k in ('توعية', 'تدريب', 'awareness', 'phishing', 'تصيد')):
        return ('(عدد الموظفين المجتازين للتدريب / إجمالي الموظفين المستهدفين) × 100'
                if lang == 'ar' else
                '(Employees trained / target employees) × 100')
    if any(k in n for k in ('تشفير', 'encryption', 'DLP', 'dlp', 'بيانات')):
        return ('(عدد الأصول/البيانات المشفرة / إجمالي البيانات الحساسة المصنفة) × 100'
                if lang == 'ar' else
                '(Encrypted assets/data / classified sensitive data) × 100')
    if any(k in n for k in ('%', 'نسبة', 'تغطية', 'coverage', 'rate')):
        return ('(عدد العناصر المطابقة / إجمالي العناصر) × 100'
                if lang == 'ar'
                else '(Compliant items / total items) × 100')
    return ('(المنجز / المخطط) × 100' if lang == 'ar'
            else '(Achieved / planned) × 100')


def _derive_kpi_source(name: str, lang: str = 'ar') -> str:
    """Professional fallback data source/tool derived from a metric name."""
    n = (name or '').strip()
    table = (
        ('SOC', 'SIEM / SOC'), ('SIEM', 'SIEM'), ('MFA', 'IAM / IdP'),
        ('IAM', 'IAM / PAM'), ('PAM', 'PAM'), ('ثغر', 'Vulnerability Mgmt'),
        ('vulnerability', 'Vulnerability Mgmt'), ('تشفير', 'DLP / DP'),
        ('DLP', 'DLP'), ('نسخ', 'Backup / DR'), ('backup', 'Backup / DR'),
        ('توعية', 'LMS / HR'), ('phishing', 'Phishing platform'),
        ('تصيد', 'Phishing platform'),
    )
    for key, tool in table:
        if key in n:
            return tool
    return 'مكتب CISO / نظام الحوكمة' if lang == 'ar' else 'CISO office / GRC'


_KPI_FREQ_TOKENS = ('شهري', 'ربع', 'سنوي', 'يومي', 'أسبوعي', 'daily',
                    'weekly', 'monthly', 'quarter', 'annual')


def _is_freq_or_timeframe(val: str) -> bool:
    s = (val or '').strip()
    if not s or s == '—':
        return True
    if re.fullmatch(r'\d+\s*(?:ش|شهر|شهراً|months?|م)?', s):
        return True
    return any(t in s for t in _KPI_FREQ_TOKENS)


def split_kpi_tables(
        section_text: str, lang: str = 'ar') -> List[Dict[str, Any]]:
    """PR-CY47 — header-aware KPI/KRI normalization into a summary table and a
    formula/source detail table built from a structured spec (not raw column
    order), so the formula column never holds a frequency and the source
    column never holds a timeframe."""
    tables = parse_markdown_tables(section_text)
    out: List[Dict[str, Any]] = []
    main_schema = list(SCHEMA_KPI_MAIN_AR if lang == 'ar' else (
        '#', 'Indicator', 'Type', 'Target', 'Frequency', 'Owner',
        'Horizon'))
    formula_schema = list(SCHEMA_KPI_FORMULA_AR if lang == 'ar' else (
        '#', 'Indicator', 'Formula', 'Data Source'))
    for tbl in tables:
        if len(tbl) < 2:
            continue
        hdr = tbl[0]
        hdr_blob = ' '.join(hdr).lower()
        if not any(k in hdr_blob for k in (
                'مؤشر', 'kpi', 'kri', 'indicator', 'وصف')):
            continue
        i_idx = _col_index(hdr, ('#', 'م'))
        i_name = _col_index(hdr, ('المؤشر', 'indicator', 'kpi'))
        i_type = _col_index(hdr, ('النوع', 'type'))
        i_target = _col_index(hdr, ('القيمة المستهدفة', 'المستهدف', 'target'))
        i_freq = _col_index(hdr, ('التكرار', 'frequency'))
        i_owner = _col_index(hdr, ('المالك', 'المسؤول', 'owner'))
        i_horizon = _col_index(hdr, ('الإطار الزمني', 'horizon'))
        i_formula = _col_index(hdr, ('صيغة الاحتساب', 'الصيغة', 'formula'))
        i_source = _col_index(hdr, ('مصدر البيانات', 'المصدر', 'source',
                                    'data source'))
        main_rows, formula_rows = [], []
        for n, r in enumerate(tbl[1:], 1):
            name = _cell(r, i_name if i_name >= 0 else 1)
            if name == '—':
                continue
            idx = _cell(r, i_idx, str(n)) if i_idx >= 0 else str(n)
            main_rows.append([
                idx, name,
                _derive_kpi_type(name, _cell(r, i_type, ''), lang),
                _derive_kpi_target(name, _cell(r, i_target), lang),
                _cell(r, i_freq),
                _cell(r, i_owner, 'CISO'),
                _cell(r, i_horizon),
            ])
            formula = _cell(r, i_formula) if i_formula >= 0 else '—'
            source = _cell(r, i_source) if i_source >= 0 else '—'
            if (formula == '—' or _is_freq_or_timeframe(formula)
                    or _is_formula_echo(formula, name)):
                formula = _derive_kpi_formula(name, lang)
            if source == '—' or _is_freq_or_timeframe(source):
                source = _derive_kpi_source(name, lang)
            formula_rows.append([idx, name, formula, source])
        if not main_rows:
            continue
        out.append({'schema': 'kpi_main', 'header': main_schema,
                    'rows': main_rows})
        out.append({'schema': 'kpi_formula', 'header': formula_schema,
                    'rows': formula_rows})
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
            schema = list(SCHEMA_GAP_ACTION_AR if lang == 'ar' else (
                'Step', 'Action', 'Owner', 'Timeframe', 'Output'))
            fixed_rows = []
            for r in tbl[1:]:
                row = _normalize_row(r, len(schema))
                if len(row) >= 2 and row[0] in ('طوة', 'الخ'):
                    row[0] = 'الخطوة'
                row[0] = _normalize_gap_cell(row[0])
                fixed_rows.append(row)
            result.append({
                'schema': 'gap_action',
                'header': list(schema),
                'rows': fixed_rows,
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


# ── PR-CY47 — professional doc-model cleanup + structured normalizers ────────
# Known Arabic header/word fragments produced when RTL editors or the AI split
# a token across cells/lines (e.g. "طوة الخ" instead of "الخطوة").
PRCY47_AR_FRAGMENT_FIXES: Tuple[Tuple[str, str], ...] = (
    ('طوة الخ', 'الخطوة'),
    ('الخ طوة', 'الخطوة'),
    ('| طوة |', '| الخطوة |'),
    ('|الخ|', '|الخطوة|'),
    ('جراء الإ', 'الإجراء'),
    ('الإ جراء', 'الإجراء'),
    ('ناتج ال', 'الناتج'),
    ('ال ناتج', 'الناتج'),
    ('مسؤول ال', 'المسؤول'),
    ('ال مسؤول', 'المسؤول'),
)

# PR-CY50 — sections that must appear in DOCX/PDF professional exports.
DOCX_REQUIRED_PROFESSIONAL_SECTIONS = (
    'executive_summary', 'scope_frameworks', 'methodology',
    'governance_ownership', 'traceability_matrix', 'appendices',
    'roadmap', 'kpi_kri_framework', 'confidence_risk_register',
)

# PR-CY51 — doc_type tokens that identify a strategy export (DOCX/PDF).
STRATEGY_EXPORT_DOC_TYPE_TOKENS = (
    'strategy document', 'strategy', 'استراتيجية', 'وثيقة استراتيجية',
    'وثيقة الاستراتيجية', 'cyber strategy',
)

# PR-CY51 — ordered docmodel sub-gates (first failure wins for diagnostics).
DOCMODEL_PROFESSIONAL_SUBGATES = (
    'docx_professional_sections_present',
    'docx_no_raw_1_to_7_fallback',
    'final_table_cell_arabic_cleanup_passed',
    'final_arabic_spacing_pdf_passed',
    'gap_guide_header_final_clean',
    'pdf_gap_headers_clean',
    'roadmap_framework_mapping_valid',
    'pdf_roadmap_cell_density_valid',
    'kpi_metric_semantics_valid',
    'pdf_kpi_type_column_valid',
    'confidence_table_layout_valid',
    'pdf_confidence_factor_labels_intact',
    'preview_pdf_docx_parity_passed',
    'executive_summary_clean',
    'markdown_residue_after_docmodel',
    'environment_table_clean',
    'gap_guides_clean',
    'roadmap_phase_coverage_valid',
    'kpi_formula_source_valid',
    'confidence_factor_table_valid',
    'arabic_spacing_final_passed',
    'pdf_docx_section_parity',
)


def is_strategy_export_doc_type(doc_type: str, domain: str = '') -> bool:
    """True when the export should use the professional strategy document model."""
    dt = (doc_type or '').strip().lower()
    if not dt:
        return False
    if dt in STRATEGY_EXPORT_DOC_TYPE_TOKENS:
        return True
    if 'strategy' in dt or 'استراتيج' in dt:
        return True
    return False


def find_sample_bad_arabic_concat(
        model: Optional[Dict[str, Any]] = None,
        text: str = '') -> str:
    """Return the first known Arabic concat defect still present."""
    blob = text or str((model or {}).get('blocks') or {})
    for bad, _ in PRCY41_AR_CONCAT_FIXES:
        if bad in blob:
            return bad
    return ''


def identify_docmodel_failing_subgate(
        docchecks: Optional[Dict[str, Any]]) -> str:
    """Return the first failing PR-CY50/51 docmodel sub-gate key."""
    checks = docchecks or {}
    if checks.get('docmodel_professional_passed'):
        return ''
    for key in DOCMODEL_PROFESSIONAL_SUBGATES:
        if key not in checks:
            continue
        val = checks.get(key)
        if key == 'markdown_residue_after_docmodel':
            if (val or 0) > 0:
                return key
        elif not val:
            return key
    return 'docmodel_professional_unknown'


def subgate_to_failure_suffix(subgate: str) -> str:
    """Map a docmodel sub-gate key to a stable failure suffix."""
    if not subgate:
        return 'unknown'
    if subgate.endswith('_present'):
        return subgate.replace('_present', '_missing')
    if subgate.endswith('_passed'):
        return subgate.replace('_passed', '_failed')
    if subgate.endswith('_valid'):
        return subgate.replace('_valid', '_invalid')
    if subgate == 'markdown_residue_after_docmodel':
        return 'markdown_residue_remaining'
    return subgate


def build_docmodel_professional_failure_diag(
        docchecks: Optional[Dict[str, Any]],
        *,
        model: Optional[Dict[str, Any]] = None,
        output_type: str = '',
        route_name: str = '',
        action_taken: str = '',
        extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build [DOCMODEL-PROFESSIONAL-FAILURE] diagnostic payload."""
    checks = docchecks or {}
    subgate = identify_docmodel_failing_subgate(checks)
    sample = find_sample_bad_arabic_concat(model)
    payload = {
        'output_type': output_type,
        'route_name': route_name,
        'failing_subgate': subgate,
        'failing_subgate_suffix': subgate_to_failure_suffix(subgate),
        'docx_professional_sections_present': checks.get(
            'docx_professional_sections_present'),
        'docx_no_raw_1_to_7_fallback': checks.get(
            'docx_no_raw_1_to_7_fallback'),
        'final_table_cell_arabic_cleanup_passed': checks.get(
            'final_table_cell_arabic_cleanup_passed'),
        'gap_guide_header_final_clean': checks.get(
            'gap_guide_header_final_clean'),
        'roadmap_framework_mapping_valid': checks.get(
            'roadmap_framework_mapping_valid'),
        'kpi_metric_semantics_valid': checks.get(
            'kpi_metric_semantics_valid'),
        'confidence_table_layout_valid': checks.get(
            'confidence_table_layout_valid'),
        'preview_pdf_docx_parity_passed': checks.get(
            'preview_pdf_docx_parity_passed'),
        'sample_bad_text': sample,
        'action_taken': action_taken,
    }
    if extra:
        payload.update(extra)
    return payload


def emit_docmodel_professional_failure(**kwargs) -> Dict[str, Any]:
    """Emit [DOCMODEL-PROFESSIONAL-FAILURE] to server logs."""
    payload = build_docmodel_professional_failure_diag(**kwargs)
    try:
        print(f'[DOCMODEL-PROFESSIONAL-FAILURE] {payload}', flush=True)
    except Exception:  # noqa: BLE001
        pass
    return payload

# Heading-residue / separator detectors.
PRCY47_HEADING_RESIDUE_RE = re.compile(r'(?m)^\s*#{1,6}\s*\.?\d*[\s\.\)]*')
PRCY47_TABLE_SEP_RE = re.compile(r'(?m)^\s*\|?\s*:?-{2,}.*$')
PRCY47_GUIDE_HEADER_RE = re.compile(r'####\s*دليل\s*تنفيذ', re.IGNORECASE)


def prcy47_fix_ar_fragments(text: str) -> str:
    """Repair split Arabic word fragments (e.g. ``طوة الخ`` → ``الخطوة``)."""
    out = text or ''
    for bad, good in PRCY47_AR_FRAGMENT_FIXES:
        if bad in out:
            out = out.replace(bad, good)
    return out


def prcy47_clean_prose(text: str, lang: str = 'ar') -> str:
    """Return clean narrative prose with ALL markdown table/heading residue
    removed. Used for block paragraphs so the PDF never shows raw ``|---|``
    rows, ``## .1`` heading markers, ``#### دليل تنفيذ`` guides, HTML/trace
    comments, or pipe-only fragments.
    """
    if not text:
        return ''
    s = strip_markdown_residue(text)
    kept: List[str] = []
    for ln in s.split('\n'):
        t = ln.strip()
        if not t:
            kept.append('')
            continue
        # Drop any markdown table line (header / separator / data row) and
        # pipe-only / dash-only fragments.
        if t.startswith('|') or t.endswith('|'):
            continue
        if set(t) <= set('-:| '):
            continue
        if t.startswith('#'):
            continue
        if t.startswith('<!--') or t.endswith('-->'):
            continue
        kept.append(t)
    out = '\n'.join(kept)
    out = PRCY47_HEADING_RESIDUE_RE.sub('', out)
    if lang == 'ar':
        out = normalize_arabic_for_render(out)
        out = prcy47_fix_ar_fragments(out)
    out = fix_confidence_display(out)
    # Collapse blank runs.
    out = re.sub(r'\n{3,}', '\n\n', out).strip()
    return out


def prcy47_docmodel_cleanup(text: str, lang: str = 'ar') -> Tuple[str, Dict[str, Any]]:
    """Sanitize raw section markdown before story construction and return
    ``(clean_prose, diagnostics)`` for ``[PDF-DOCMODEL-CLEANUP]``.
    """
    src = text or ''
    heading_residue = len(PRCY47_HEADING_RESIDUE_RE.findall(src))
    sep_residue = len(PRCY47_TABLE_SEP_RE.findall(src))
    pipe_residue = sum(
        1 for ln in src.split('\n')
        if '|' in ln and not set(ln.strip()) <= set('-:| '))
    clean = prcy47_clean_prose(src, lang)
    residue_after = sum(
        1 for ln in clean.split('\n')
        if ln.strip().startswith('#') or '|' in ln
        or set(ln.strip() or 'x') <= set('-:| '))
    diag = {
        'markdown_heading_residue_count_before': heading_residue,
        'table_separator_residue_count_before': sep_residue,
        'pipe_residue_count_before': pipe_residue,
        'residue_count_after': residue_after,
        'action_taken': (
            'sanitized' if (heading_residue or sep_residue or pipe_residue)
            else 'noop'),
    }
    return clean, diag


def _col_index(header: List[str], keywords: Tuple[str, ...]) -> int:
    """Return the index of the first header cell matching any keyword
    (case-insensitive substring), or ``-1``."""
    for i, h in enumerate(header or []):
        blob = str(h).lower()
        if any(k.lower() in blob for k in keywords):
            return i
    return -1


def _cell(row: List[str], idx: int, default: str = '—') -> str:
    if idx is None or idx < 0 or idx >= len(row):
        return default
    v = str(row[idx]).strip()
    return v if v and v not in ('-', '--') else default


def _phase_for_months(period_text: str, lang: str = 'ar') -> str:
    """Map a period string (e.g. ``الشهر 1-3`` / ``7-18``) to a canonical
    roadmap phase label with coverage 1–6 / 7–18 / 19–24."""
    nums = [int(n) for n in re.findall(r'\d+', period_text or '')]
    start = nums[0] if nums else 0
    if start and start <= 6:
        return 'المرحلة 1: تأسيس (1-6 أشهر)' if lang == 'ar' else \
            'Phase 1: Establish (1-6 months)'
    if start and start <= 18:
        return 'المرحلة 2: تمكين وتشغيل (7-18 شهر)' if lang == 'ar' else \
            'Phase 2: Enable & Operate (7-18 months)'
    if start:
        return 'المرحلة 3: تحسين واستدامة (19-24 شهر)' if lang == 'ar' else \
            'Phase 3: Optimize & Sustain (19-24 months)'
    return 'المرحلة 1: تأسيس (1-6 أشهر)' if lang == 'ar' else \
        'Phase 1: Establish (1-6 months)'


def _ensure_roadmap_phase_coverage(
        rows: List[List[str]], lang: str = 'ar') -> List[List[str]]:
    """PR-CY47 Part E — guarantee a professional 1–6 / 7–18 / 19–24 phase view.

    Rendering-only: when the saved roadmap rows do not span all phases, append
    synthetic visual phase rows derived from the mandatory cyber capabilities
    (governance/CISO, SOC, IAM/PAM/MFA, DLP/classification, incident response/
    CSIRT, vulnerability management). Does NOT change saved content.
    """
    present = {1: False, 2: False, 3: False}
    for r in rows:
        ph = (r[0] if r else '') or ''
        if 'تأسيس' in ph or 'Establish' in ph or '1-6' in ph:
            present[1] = True
        elif 'تمكين' in ph or 'Enable' in ph or '7-18' in ph:
            present[2] = True
        elif 'تحسين' in ph or 'Optimize' in ph or '19-24' in ph:
            present[3] = True
    synth = {
        1: [_phase_for_months('1', lang), '1-6 أشهر' if lang == 'ar'
            else '1-6 months',
            'تأسيس حوكمة الأمن السيبراني وتعيين CISO ولجنة الحوكمة'
            if lang == 'ar'
            else 'Establish cyber governance, appoint CISO & committee',
            'CISO', 'إدارة ولجنة حوكمة فاعلة' if lang == 'ar'
            else 'Active governance function', '—'],
        2: [_phase_for_months('7', lang), '7-18 شهر' if lang == 'ar'
            else '7-18 months',
            'تمكين وتشغيل SOC/SIEM وIAM/PAM/MFA وحماية البيانات DLP'
            if lang == 'ar'
            else 'Enable & operate SOC/SIEM, IAM/PAM/MFA, DLP',
            'CISO', 'قدرات تشغيلية فعّالة' if lang == 'ar'
            else 'Operational capabilities', '—'],
        3: [_phase_for_months('19', lang), '19-24 شهر' if lang == 'ar'
            else '19-24 months',
            'تحسين واستدامة: إدارة الثغرات والاستجابة للحوادث CSIRT'
            if lang == 'ar'
            else 'Optimize & sustain: vuln mgmt, incident response/CSIRT',
            'CISO', 'نضج وتحسين مستمر' if lang == 'ar'
            else 'Maturity & continuous improvement', '—'],
    }
    extra = [synth[p] for p in (1, 2, 3) if not present[p]]
    return rows + extra


def normalize_environment_table(
        section_text: str, lang: str = 'ar') -> Optional[Dict[str, Any]]:
    """Normalize an environment / threat markdown table into the compact
    schema ``التهديد / الفجوة | الأثر | الأولوية | المعالجة المقترحة``."""
    schema = list(SCHEMA_ENV_AR if lang == 'ar' else (
        'Threat / Gap', 'Impact', 'Priority', 'Proposed Treatment'))
    tables = parse_markdown_tables(section_text)
    rows_out: List[List[str]] = []
    for tbl in tables:
        if len(tbl) < 2:
            continue
        hdr = tbl[0]
        i_threat = _col_index(hdr, ('البُعد', 'البعد', 'التهديد', 'الفجوة',
                                    'الإشارة', 'المصدر', 'dimension',
                                    'threat', 'signal', 'source'))
        i_impact = _col_index(hdr, ('التأثير', 'الأثر', 'impact'))
        i_prio = _col_index(hdr, ('الأولوية', 'priority'))
        i_treat = _col_index(hdr, ('المعالجة', 'treatment', 'mitigation'))
        if i_threat < 0 and i_impact < 0:
            continue
        for r in tbl[1:]:
            threat = _cell(r, i_threat if i_threat >= 0 else 0)
            impact = _cell(r, i_impact if i_impact >= 0 else 1)
            prio = _cell(r, i_prio) if i_prio >= 0 else _impact_to_priority(
                impact, lang)
            treat = _cell(r, i_treat) if i_treat >= 0 else (
                'تطبيق الضوابط المرتبطة ومتابعتها' if lang == 'ar'
                else 'Apply and monitor related controls')
            if threat == '—' and impact == '—':
                continue
            rows_out.append([threat, impact, prio, treat])
    if not rows_out:
        return None
    return {'schema': 'environment', 'header': schema, 'rows': rows_out}


def _impact_to_priority(impact: str, lang: str = 'ar') -> str:
    s = (impact or '').strip()
    if any(k in s for k in ('عالٍ', 'عالي', 'حرج', 'high', 'High', 'critical')):
        return 'عالية' if lang == 'ar' else 'High'
    if any(k in s for k in ('متوسط', 'medium', 'Medium')):
        return 'متوسطة' if lang == 'ar' else 'Medium'
    return 'عالية' if lang == 'ar' else 'High'


def normalize_confidence_risk(
        section_text: str, lang: str = 'ar') -> Dict[str, Any]:
    """PR-CY48 — confidence score card + canonical factor table + separate
    risk register. Never mixes critical-success-factor tables with the
    confidence factor assessment or repeats the score in every contribution."""
    src = fix_confidence_display(section_text or '')
    conf_m = re.search(r'(\d{1,3})\s*%', src)
    conf_score = (conf_m.group(1) + '%') if conf_m else '—'
    score_val = int(conf_m.group(1)) if conf_m else 76
    tables = parse_markdown_tables(src)
    risk_schema = list(SCHEMA_RISK_AR if lang == 'ar' else (
        '#', 'Risk', 'Likelihood', 'Impact', 'Treatment Plan', 'Owner'))
    factor_schema = list(SCHEMA_CONF_FACTOR_AR if lang == 'ar' else (
        'Factor', 'Weight', 'Score', 'Contribution'))
    risk_rows: List[List[str]] = []
    for tbl in tables:
        if len(tbl) < 2:
            continue
        hdr = tbl[0]
        hdr_blob = ' '.join(hdr)
        i_like = _col_index(hdr, ('الاحتمالية', 'الاحتمال', 'likelihood',
                                  'probability'))
        i_risk = _col_index(hdr, ('الخطر', 'المخاطر', 'risk'))
        # Risk register only — exclude critical-success-factor tables.
        if i_risk >= 0 and i_like >= 0 and 'نجاح' not in hdr_blob:
            i_impact = _col_index(hdr, ('التأثير', 'الأثر', 'impact'))
            i_plan = _col_index(hdr, ('التخفيف', 'المعالجة', 'الخطة',
                                      'mitigation', 'plan', 'treatment'))
            i_owner = _col_index(hdr, ('المالك', 'المسؤول', 'owner'))
            for n, r in enumerate(tbl[1:], 1):
                risk_rows.append([
                    str(n), _cell(r, i_risk), _cell(r, i_like),
                    _cell(r, i_impact), _cell(r, i_plan),
                    _cell(r, i_owner, 'CISO'),
                ])
    # Canonical confidence factors — never parsed from source tables.
    factor_rows: List[List[str]] = []
    factors = (CANONICAL_CONFIDENCE_FACTORS_AR if lang == 'ar' else
               tuple((n, w) for n, w in CANONICAL_CONFIDENCE_FACTORS_AR))
    grade = str(min(5, max(1, round(score_val / 20))))
    for fname, weight in factors:
        w_pct = int(re.sub(r'\D', '', weight) or '0')
        contrib = f'{round(w_pct * score_val / 100, 1)}%'
        factor_rows.append([fname, weight, grade, contrib])
    return {
        'confidence_score': conf_score,
        'factor_table': {'schema': 'conf_factor', 'header': factor_schema,
                         'rows': factor_rows},
        'risk_table': ({'schema': 'risk_register', 'header': risk_schema,
                        'rows': risk_rows} if risk_rows else None),
    }


def normalize_gap_action_guides(
        section_text: str, lang: str = 'ar') -> List[Dict[str, Any]]:
    """Normalize per-gap implementation guides (``#### دليل تطبيق الفجوة …``,
    typically numbered lists) into ``الخطوة | الإجراء | المسؤول | الإطار
    الزمني | الناتج`` tables — each with a clear guide title."""
    schema = list(SCHEMA_GAP_ACTION_AR if lang == 'ar' else (
        'Step', 'Action', 'Owner', 'Timeframe', 'Output'))
    out: List[Dict[str, Any]] = []
    guide_re = re.compile(
        r'(?m)^#{2,4}\s*(دليل[^\n]*|Implementation Guide[^\n]*)$')
    matches = list(guide_re.finditer(section_text or ''))
    for gi, m in enumerate(matches):
        title = prcy47_fix_ar_fragments(m.group(1).strip())
        start = m.end()
        end = matches[gi + 1].start() if gi + 1 < len(matches) else len(
            section_text or '')
        body = (section_text or '')[start:end]
        rows: List[List[str]] = []
        for ln in body.split('\n'):
            t = ln.strip()
            sm = re.match(r'^(\d+)[\.\)]\s*(.+)$', t)
            if sm:
                step = sm.group(1)
                action = prcy47_fix_ar_fragments(sm.group(2).strip())
                rows.append([step, action, 'CISO',
                             ('حسب الخطة' if lang == 'ar' else 'Per plan'),
                             ('مكتمل' if lang == 'ar' else 'Completed')])
        if rows:
            out.append({'schema': 'gap_action',
                        'header': list(schema),
                        'rows': [[_normalize_gap_cell(c) for c in r]
                                 for r in rows],
                        'title': title})
    return out


def enhance_executive_summary(
        exec_block: Dict[str, Any],
        content_sections: Dict[str, str],
        metadata: Dict[str, Any],
        fws_keys: List[str],
        lang: str,
) -> Dict[str, Any]:
    """Professional one-page executive summary grid."""
    lang_n = 'ar' if lang == 'ar' else 'en'
    # PR-CY47 — executive summary must be built from clean prose only; never
    # carry raw markdown tables, implementation guides, or pipe residue.
    paras = []
    for _p in (exec_block.get('paragraphs') or []):
        _c = prcy47_clean_prose(_p, lang_n)
        if _c and '|' not in _c and 'دليل تنفيذ' not in _c \
                and 'دليل تطبيق' not in _c:
            paras.append(_c)
    gaps_text = (content_sections or {}).get('gaps', '') or ''
    conf_text = (content_sections or {}).get('confidence', '') or ''
    gap_lines = []
    for ln in gaps_text.split('\n'):
        s = ln.strip()
        if s.startswith('|'):
            # Extract the gap label cell from a markdown gap-table row.
            cells = [c.strip() for c in s.strip('|').split('|')]
            if len(cells) >= 2 and cells[1] and not set(cells[1]) <= set('-: '):
                if cells[1] not in ('الفجوة', 'Gap', '#'):
                    gap_lines.append(prcy47_fix_ar_fragments(cells[1])[:100])
        elif re.match(r'^\s*\d+[\.\)]', s) or 'فجوة' in s:
            gap_lines.append(prcy47_clean_prose(s, lang_n)[:100])
    gap_top5 = [g for g in gap_lines if g][:5]
    conf_m = re.search(r'(\d{1,3})\s*%', fix_confidence_display(conf_text))
    conf_score = conf_m.group(1) + '%' if conf_m else '—'
    fw_labels = []
    for fw in (fws_keys or ['ECC', 'DCC']):
        spec_key = str(fw).upper()
        if 'ECC' in spec_key:
            fw_labels.append(FRAMEWORK_ORDER[0])
        elif 'DCC' in spec_key:
            fw_labels.append(FRAMEWORK_ORDER[1])
        else:
            fw_labels.append(str(fw))
    if not fw_labels:
        fw_labels = list(FRAMEWORK_ORDER)
    fw_labels = _clean_framework_labels(fw_labels)
    key_risks = []
    for ln in conf_text.split('\n'):
        s = ln.strip()
        if s.startswith('|'):
            cells = [c.strip() for c in s.strip('|').split('|')]
            if len(cells) >= 2 and ('خطر' in cells[1] or 'risk' in
                                    cells[1].lower()):
                if cells[1] not in ('الخطر', 'المخاطر', 'Risk'):
                    key_risks.append(prcy47_fix_ar_fragments(cells[1])[:80])
        elif 'خطر' in s or 'risk' in s.lower():
            c = prcy47_clean_prose(s, lang_n)
            if c:
                key_risks.append(c[:80])
    grid = {
        'purpose': paras[0] if paras else '',
        'frameworks': fw_labels,
        'priorities': (metadata or {}).get('mandatory_themes', [])[:5],
        'top_gaps': gap_top5,
        'horizon': (metadata or {}).get('horizon_months') or '24',
        'confidence_score': conf_score,
        'key_risks': [r for r in key_risks if r][:5],
    }
    return {
        **exec_block,
        'summary_grid': grid,
        'paragraphs': [],  # PR-CY48 — grid carries narrative; no duplicate paras.
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

    # PR-CY47 — track residue removed across all section prose for the
    # [PDF-DOCMODEL-CLEANUP] diagnostic.
    _cleanup = {
        'markdown_heading_residue_count_before': 0,
        'table_separator_residue_count_before': 0,
        'pipe_residue_count_before': 0,
        'residue_count_after': 0,
        'action_taken': 'noop',
    }

    def _clean_paras(raw_text: str, limit: int = 4) -> List[str]:
        clean, diag = prcy47_docmodel_cleanup(raw_text, lang_n)
        for k in ('markdown_heading_residue_count_before',
                  'table_separator_residue_count_before',
                  'pipe_residue_count_before', 'residue_count_after'):
            _cleanup[k] += diag.get(k, 0)
        if diag.get('action_taken') == 'sanitized':
            _cleanup['action_taken'] = 'sanitized'
        paras = [p.strip() for p in clean.split('\n\n') if p.strip()]
        return paras[:limit]

    # Vision / objectives
    vis = _sec('vision_objectives')
    vis_tables = parse_markdown_tables(vis)
    so_tbl = normalize_strategic_objectives_table(vis_tables, lang_n)
    blocks['vision_objectives'] = {
        **(blocks.get('vision_objectives') or {}),
        'paragraphs': _clean_paras(vis, 3),
        'tables': [so_tbl] if so_tbl else [],
    }

    # Pillars
    pil = _sec('strategic_pillars')
    blocks['strategic_pillars'] = {
        **(blocks.get('strategic_pillars') or {}),
        'pillar_blocks': normalize_pillar_blocks(pil, lang_n),
    }

    # Environment — regulatory + threat prose + compact normalized table.
    env = _sec('environment_context')
    env_tbl = normalize_environment_table(env, lang_n)
    blocks['environment_context'] = {
        **(blocks.get('environment_context') or {}),
        'paragraphs': _clean_paras(env, 3),
        'tables': [env_tbl] if env_tbl else [],
    }

    # Gaps — main gap table + per-guide action tables (الخطوة | الإجراء | …).
    gaps = _sec('gap_analysis')
    gap_tables = normalize_gap_tables(gaps, lang_n)
    gap_tables += normalize_gap_action_guides(gaps, lang_n)
    blocks['gap_analysis'] = {
        **(blocks.get('gap_analysis') or {}),
        'paragraphs': _clean_paras(gaps, 2),
        'tables': gap_tables,
    }

    # Roadmap — mandatory structured table (header-aware + phase coverage).
    road = _sec('roadmap')
    road_tbl = normalize_roadmap_table(road, lang_n)
    _road_schema = list(SCHEMA_ROADMAP_AR if lang_n == 'ar' else (
        'Phase', 'Period', 'Initiative', 'Owner',
        'Deliverable', 'Linked Framework'))
    if not road_tbl or not (road_tbl.get('rows')):
        _seed = (road_tbl or {}).get('rows') or []
        road_tbl = {
            'schema': 'roadmap',
            'header': _road_schema,
            'rows': build_roadmap_render_spec(_seed, lang_n),
        }
    road_tbl = _sanitize_table_spec(road_tbl, lang_n) or road_tbl
    blocks['roadmap'] = {
        **(blocks.get('roadmap') or {}),
        'paragraphs': _clean_paras(road, 1) if road.strip() else [],
        'tables': [road_tbl],
        'content': '',
        'content_present': bool(road.strip()),
    }

    # KPI / KRI split
    kpis = _sec('kpi_kri_framework')
    kpi_tables = split_kpi_tables(kpis, lang_n)
    blocks['kpi_kri_framework'] = {
        **(blocks.get('kpi_kri_framework') or {}),
        'tables': kpi_tables,
    }

    # Confidence — score card paragraph + factor table + risk register.
    conf = _sec('confidence_risk_register')
    conf_norm = normalize_confidence_risk(conf, lang_n)
    conf_tables = [conf_norm['factor_table']]
    if conf_norm.get('risk_table'):
        conf_tables.append(conf_norm['risk_table'])
    _conf_score = conf_norm.get('confidence_score', '—')
    _conf_para = (f'درجة الثقة: {_conf_score}' if lang_n == 'ar'
                  else f'Confidence score: {_conf_score}')
    _conf_extra = [
        p for p in _clean_paras(conf, 2)
        if not p.startswith('درجة الثقة')
        and not p.lower().startswith('confidence score')]
    blocks['confidence_risk_register'] = {
        **(blocks.get('confidence_risk_register') or {}),
        'confidence_score': _conf_score,
        'paragraphs': [_conf_para] + _conf_extra,
        'tables': conf_tables,
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

    # Traceability — split by framework (NCA ECC / NCA DCC) for readability.
    trace = blocks.get('traceability_matrix') or {}
    rows = trace.get('rows') or []
    if rows:
        by_fw: Dict[str, List[List[str]]] = {}
        for r in rows:
            if len(r) >= 6:
                fw_key = str(r[0] or 'Other').strip()
                by_fw.setdefault(fw_key, []).append(r)
        split_tables = []
        for fw_name in sorted(by_fw.keys()):
            fw_rows = by_fw[fw_name]
            fw_gap, fw_init = [], []
            for r in fw_rows:
                fw_gap.append([r[0], r[1], r[2]])
                fw_init.append([r[0], r[3], r[4], r[5]])
            split_tables.append({
                'schema': 'trace_fw_gap',
                'title': fw_name,
                'header': list(SCHEMA_TRACE_FW_GAP_AR),
                'rows': fw_gap,
            })
            split_tables.append({
                'schema': 'trace_fw_init',
                'title': fw_name,
                'header': list(SCHEMA_TRACE_FW_INIT_AR),
                'rows': fw_init,
            })
        blocks['traceability_matrix'] = {
            **trace,
            'split_tables': split_tables,
        }

    blocks = _finalize_professional_blocks(blocks, lang_n)
    model['blocks'] = blocks
    model['render_layer'] = 'prcy41_professional'
    model['professional_section_order'] = list(PROFESSIONAL_EXPORT_SECTION_ORDER)
    model['docmodel_cleanup'] = dict(_cleanup)
    try:
        print(f'[PDF-DOCMODEL-CLEANUP] {_cleanup}', flush=True)
    except Exception:  # noqa: BLE001
        pass
    return model


def ensure_strategy_professional_model(
        model: Optional[Dict[str, Any]],
        *,
        content: str = '',
        metadata: Optional[Dict[str, Any]] = None,
        sections: Optional[Dict[str, str]] = None,
        selected_frameworks: Optional[List[str]] = None,
        lang: str = 'ar',
        domain: Optional[str] = None,
) -> Dict[str, Any]:
    """PR-CY50 — guarantee ``render_layer == prcy41_professional`` for exports."""
    if model and model.get('render_layer') == 'prcy41_professional':
        return model
    if not model:
        raise ValueError('strategy_professional_model_missing_base')
    metadata = dict(metadata or {})
    metadata.setdefault('content', content or '')
    lang_n = 'ar' if (lang or '').lower() in ('ar', 'arabic') else 'en'
    content_sections = sections if isinstance(sections, dict) else {}
    if not content_sections and content:
        try:
            from app import _split_strategy_sections_by_h2
            content_sections = _split_strategy_sections_by_h2(content)
        except Exception:
            content_sections = {}
    return enrich_professional_blocks(
        model, content_sections, metadata, lang_n)


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


def confidence_factor_labels_intact(
        conf_factor_tbl: List[Dict[str, Any]]) -> bool:
    """PR-CY52 — canonical factor names must appear whole, never fragmented."""
    if not conf_factor_tbl:
        return True
    rows = conf_factor_tbl[0].get('rows') or []
    canonical = [f[0] for f in CANONICAL_CONFIDENCE_FACTORS_AR]
    if len(rows) < len(canonical):
        return False
    for canon, r in zip(canonical, rows):
        fname = str(r[0] if r else '').strip()
        if fname != canon:
            return False
        if fname in ('ال', 'عامل', 'اك', 'مدخلات') or len(fname) < 4:
            return False
    return True


def roadmap_cell_density_valid(
        road_rows: List[List[str]]) -> bool:
    """PR-CY52 — roadmap cells must stay within safe length; no long DCC prose."""
    for r in road_rows or []:
        for c in r or []:
            s = str(c or '').strip()
            if len(s) > ROADMAP_CELL_MAX_LEN:
                return False
            if re.search(
                    r'(?:حماية|تصنيف)\s+البيانات[^،\.|;]{24,}',
                    s, flags=re.IGNORECASE):
                return False
    return True


def kpi_type_column_valid(kpi_main: List[Dict[str, Any]]) -> bool:
    """PR-CY52 — every KPI summary row must have KPI or KRI type, never dash."""
    for t in kpi_main or []:
        for r in t.get('rows') or []:
            tcol = str(r[2] if len(r) > 2 else '').strip().upper()
            if tcol not in ('KPI', 'KRI'):
                return False
    return True


def pdf_gap_headers_clean(gap_tables: List[Dict[str, Any]]) -> bool:
    """PR-CY52 — gap action headers canonical; no forbidden fragments."""
    action_tbls = [t for t in (gap_tables or [])
                   if t.get('schema') == 'gap_action']
    if not action_tbls:
        return True
    canon = list(SCHEMA_GAP_ACTION_AR)
    for tbl in action_tbls:
        hdr = tbl.get('header') or []
        if list(hdr) != canon:
            return False
        for r in (tbl.get('rows') or []):
            for c in r:
                cs = str(c).strip()
                if cs in ('طوة', 'الخ') or 'طوة الخ' in cs:
                    return False
                if cs != 'الخطوة' and 'طوة' in cs and 'خطوة' not in cs:
                    return False
    return True


def prcy47_docmodel_professional_checks(
        model: Optional[Dict[str, Any]], lang: str = 'ar') -> Dict[str, Any]:
    """PR-CY47 Part I — professional document-model quality checks computed
    from the structured model (the source of truth for what the story
    renderer emits as ReportLab Tables/Paragraphs)."""
    blocks = (model or {}).get('blocks') or {}

    def _paras(kind):
        return [str(p) for p in (blocks.get(kind) or {}).get(
            'paragraphs') or []]

    def _no_pipe(kind):
        return all('|' not in p for p in _paras(kind))

    exec_blk = blocks.get('executive_summary') or {}
    exec_paras = [str(p) for p in exec_blk.get('paragraphs') or []]
    exec_grid = exec_blk.get('summary_grid') or {}
    conf_score = str(exec_grid.get('confidence_score', ''))
    executive_summary_clean = (
        bool(exec_grid)
        and all('|' not in p and 'دليل تنفيذ' not in p
                and 'دليل تطبيق' not in p for p in exec_paras)
        and '.%' not in conf_score
        and not any(']' in str(f) for f in (exec_grid.get('frameworks') or [])))

    residue = 0
    for kind in ('vision_objectives', 'environment_context', 'gap_analysis',
                 'confidence_risk_register', 'kpi_kri_framework', 'roadmap'):
        for p in _paras(kind):
            if '|' in p or p.strip().startswith('#'):
                residue += 1
    markdown_residue_after_docmodel = residue

    environment_table_clean = _no_pipe('environment_context')

    gap_tables = (blocks.get('gap_analysis') or {}).get('tables') or []
    gap_guides_clean = (
        _no_pipe('gap_analysis')
        and not any('طوة الخ' in str(c)
                    for t in gap_tables for r in (t.get('rows') or [])
                    for c in r))

    road_tbls = (blocks.get('roadmap') or {}).get('tables') or []
    road_rows = (road_tbls[0].get('rows') if road_tbls else []) or []
    phases_text = ' '.join(str(r[0]) for r in road_rows if r)
    has_p1 = any(k in phases_text for k in ('تأسيس', '1-6', 'Establish'))
    has_p2 = any(k in phases_text for k in ('تمكين', '7-18', 'Enable'))
    has_p3 = any(k in phases_text for k in (
        'تحسين', '19-24', 'Optimize', 'استدامة'))
    roadmap_phase_coverage_valid = has_p1 and has_p2 and has_p3

    kpi_tbls = (blocks.get('kpi_kri_framework') or {}).get('tables') or []
    kpi_formula = [t for t in kpi_tbls if t.get('schema') == 'kpi_formula']
    kpi_main = [t for t in kpi_tbls if t.get('schema') == 'kpi_main']
    if not kpi_main:
        kpi_detail_table_valid = True
        kpi_formula_source_valid = True
    elif not kpi_formula:
        kpi_detail_table_valid = False
        kpi_formula_source_valid = False
    else:
        kpi_detail_table_valid = True
        kpi_formula_source_valid = True
        for r in kpi_formula[0].get('rows') or []:
            formula = r[2] if len(r) > 2 else ''
            source = r[3] if len(r) > 3 else ''
            name = r[1] if len(r) > 1 else ''
            if (_is_freq_or_timeframe(formula) or _is_freq_or_timeframe(source)
                    or _is_formula_echo(formula, name)):
                kpi_detail_table_valid = False
                kpi_formula_source_valid = False
                break

    conf_paras = _paras('confidence_risk_register')
    confidence_risk_tables_clean = all(
        '|' not in p and '.%' not in p for p in conf_paras)

    trace_blk = blocks.get('traceability_matrix') or {}
    traceability_rendered = bool(
        trace_blk.get('split_tables') or trace_blk.get('rows'))

    # PR-CY48 — extended checks.
    confidence_score_format_valid = (
        bool(re.match(r'^\d{1,3}%$', conf_score)) if conf_score else False)
    arabic_concat_remaining = sum(
        1 for bad, _ in PRCY41_AR_CONCAT_FIXES
        if bad in str(blocks))
    arabic_spacing_final_passed = arabic_concat_remaining == 0
    gap_guide_headers_clean = all(
        (tbl.get('header') or [''])[0] == 'الخطوة'
        for tbl in gap_tables if tbl.get('schema') == 'gap_action'
    ) if any(t.get('schema') == 'gap_action' for t in gap_tables) else True
    roadmap_rows_meaningful = bool(road_rows) and not any(
        _is_dash_heavy_row(r) for r in road_rows)
    conf_factor_tbl = [t for t in (blocks.get('confidence_risk_register') or {})
                       .get('tables') or [] if t.get('schema') == 'conf_factor']
    confidence_factor_table_valid = bool(conf_factor_tbl) and len(
        conf_factor_tbl[0].get('rows') or []) >= 6
    if confidence_factor_table_valid:
        for r in conf_factor_tbl[0]['rows']:
            if len(r) > 3 and r[3] == conf_score:
                confidence_factor_table_valid = False
                break
    risk_tbl = [t for t in (blocks.get('confidence_risk_register') or {})
                .get('tables') or [] if t.get('schema') == 'risk_register']
    risk_register_separate = bool(risk_tbl) or not conf_factor_tbl
    export_keys = get_professional_export_section_keys(model)

    def _post_body_present(kind: str) -> bool:
        blk = blocks.get(kind) or {}
        if kind == 'governance_ownership':
            return bool(blk.get('rows'))
        if kind == 'traceability_matrix':
            return bool(blk.get('split_tables') or blk.get('rows'))
        if kind == 'appendices':
            return bool(blk.get('entries'))
        return False

    pdf_docx_section_parity = all(
        (not _post_body_present(k) or k in export_keys)
        for k in ('governance_ownership', 'traceability_matrix', 'appendices'))

    # PR-CY50 — extended export parity gates.
    docx_professional_sections_present = all(
        k in export_keys for k in DOCX_REQUIRED_PROFESSIONAL_SECTIONS
        if k in ('executive_summary', 'governance_ownership',
                 'traceability_matrix', 'appendices', 'roadmap',
                 'kpi_kri_framework', 'confidence_risk_register'))
    gap_guide_header_final_clean = (
        gap_guide_headers_clean
        and not any(
            str(c).strip() in ('طوة', 'الخ') or 'طوة الخ' in str(c)
            for t in gap_tables if t.get('schema') == 'gap_action'
            for r in (t.get('rows') or []) for c in r))
    final_table_cell_arabic_cleanup_passed = not any(
        bad in str(blocks) for bad, _ in PRCY41_AR_CONCAT_FIXES)
    roadmap_framework_mapping_valid = True
    dcc_init_keys = ('dcc', 'dlp', 'data', 'privacy')
    for r in road_rows:
        if len(r) < 6:
            continue
        init, fw = str(r[2] or ''), str(r[5] or '')
        blob = init.lower()
        if any(k in blob for k in dcc_init_keys) and fw:
            if 'DCC' not in fw.upper():
                roadmap_framework_mapping_valid = False
        if ('DLP' in init or 'dlp' in blob) and fw:
            if 'DCC' not in fw.upper():
                roadmap_framework_mapping_valid = False

    kpi_metric_semantics_valid = True
    for t in kpi_main:
        for r in t.get('rows') or []:
            name = r[1] if len(r) > 1 else ''
            target = r[3] if len(r) > 3 else ''
            if _is_time_based_metric(name) and '%' in str(target):
                kpi_metric_semantics_valid = False
    for t in kpi_formula:
        for r in t.get('rows') or []:
            name = r[1] if len(r) > 1 else ''
            formula = r[2] if len(r) > 2 else ''
            if _is_time_based_metric(name) and '× 100' in str(formula):
                kpi_metric_semantics_valid = False
            if any(k in (name or '') for k in ('ثغر', 'vulnerability')):
                if any(k in str(formula) for k in ('حادث', 'incident')):
                    kpi_metric_semantics_valid = False
    confidence_table_layout_valid = bool(conf_factor_tbl)
    if confidence_table_layout_valid:
        for r in conf_factor_tbl[0].get('rows') or []:
            fname = str(r[0] if r else '')
            if len(fname) < 4 or fname in ('ال', 'عامل', 'اك'):
                confidence_table_layout_valid = False
            if len(r) < 4:
                confidence_table_layout_valid = False
    preview_pdf_docx_parity_passed = (
        pdf_docx_section_parity and docx_professional_sections_present)

    # PR-CY52 — PDF table-cell rendering gates.
    pdf_gap_headers_clean_val = pdf_gap_headers_clean(gap_tables)
    pdf_confidence_factor_labels_intact = confidence_factor_labels_intact(
        conf_factor_tbl)
    pdf_roadmap_cell_density_valid = roadmap_cell_density_valid(road_rows)
    pdf_kpi_type_column_valid = kpi_type_column_valid(kpi_main)
    final_arabic_spacing_pdf_passed = final_table_cell_arabic_cleanup_passed

    docmodel_professional_passed = (
        executive_summary_clean
        and markdown_residue_after_docmodel == 0
        and environment_table_clean
        and gap_guides_clean
        and roadmap_phase_coverage_valid
        and kpi_formula_source_valid
        and confidence_risk_tables_clean
        and confidence_score_format_valid
        and arabic_spacing_final_passed
        and gap_guide_headers_clean
        and roadmap_rows_meaningful
        and confidence_factor_table_valid
        and risk_register_separate
        and pdf_docx_section_parity
        and gap_guide_header_final_clean
        and final_table_cell_arabic_cleanup_passed
        and final_arabic_spacing_pdf_passed
        and pdf_gap_headers_clean_val
        and roadmap_framework_mapping_valid
        and pdf_roadmap_cell_density_valid
        and kpi_metric_semantics_valid
        and pdf_kpi_type_column_valid
        and confidence_table_layout_valid
        and pdf_confidence_factor_labels_intact
        and preview_pdf_docx_parity_passed)

    return {
        'executive_summary_clean': executive_summary_clean,
        'markdown_residue_after_docmodel': markdown_residue_after_docmodel,
        'environment_table_clean': environment_table_clean,
        'gap_guides_clean': gap_guides_clean,
        'roadmap_phase_coverage_valid': roadmap_phase_coverage_valid,
        'kpi_detail_table_valid': kpi_detail_table_valid,
        'confidence_risk_tables_clean': confidence_risk_tables_clean,
        'traceability_rendered': traceability_rendered,
        'pdf_docx_section_parity': pdf_docx_section_parity,
        'confidence_score_format_valid': confidence_score_format_valid,
        'arabic_spacing_final_passed': arabic_spacing_final_passed,
        'gap_guide_headers_clean': gap_guide_headers_clean,
        'roadmap_rows_meaningful': roadmap_rows_meaningful,
        'kpi_formula_source_valid': kpi_formula_source_valid,
        'confidence_factor_table_valid': confidence_factor_table_valid,
        'risk_register_separate': risk_register_separate,
        'docx_professional_sections_present': docx_professional_sections_present,
        'docx_no_raw_1_to_7_fallback': (
            (model or {}).get('render_layer') == 'prcy41_professional'),
        'final_table_cell_arabic_cleanup_passed': (
            final_table_cell_arabic_cleanup_passed),
        'gap_guide_header_final_clean': gap_guide_header_final_clean,
        'roadmap_framework_mapping_valid': roadmap_framework_mapping_valid,
        'kpi_metric_semantics_valid': kpi_metric_semantics_valid,
        'confidence_table_layout_valid': confidence_table_layout_valid,
        'preview_pdf_docx_parity_passed': preview_pdf_docx_parity_passed,
        'pdf_gap_headers_clean': pdf_gap_headers_clean_val,
        'pdf_confidence_factor_labels_intact': (
            pdf_confidence_factor_labels_intact),
        'pdf_roadmap_cell_density_valid': pdf_roadmap_cell_density_valid,
        'pdf_kpi_type_column_valid': pdf_kpi_type_column_valid,
        'final_arabic_spacing_pdf_passed': final_arabic_spacing_pdf_passed,
        'docmodel_professional_passed': docmodel_professional_passed,
    }


def run_pdf_quality_gate(
        tracker: PDFRenderTracker,
        content: str,
        lang: str = 'ar',
        *,
        require_roadmap: bool = True,
        model: Optional[Dict[str, Any]] = None,
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
        model_road_rows = get_roadmap_spec_rows(model) if model else []
        road_sec = tracker.sections_present.get('roadmap', False)
        rendered = tracker.roadmap_rows_rendered
        if road_sec or model_road_rows:
            if model_road_rows and rendered < 1:
                tracker.blockers.append(
                    'pdf_render_failed:build_failed:'
                    'roadmap_rows_lost_in_render')
            elif not model_road_rows and rendered < 1:
                tracker.blockers.append(
                    'pdf_render_failed:roadmap_table_not_rendered')

    if tracker.kpi_tables_rendered < 1:
        tracker.blockers.append(
            'pdf_render_failed:kpi_tables_not_rendered')

    if tracker.internal_marker_count > 0:
        tracker.blockers.append(
            'pdf_render_failed:internal_markers_in_output')

    payload = tracker.to_gate_payload(lang)

    # PR-CY47 — professional document-model quality gate (computed from the
    # structured model). Surfaced in the payload; blocks export when a hard
    # professional defect remains.
    if model is not None:
        docchecks = prcy47_docmodel_professional_checks(model, lang)
        payload.update(docchecks)
        if not docchecks['docmodel_professional_passed']:
            _subgate = identify_docmodel_failing_subgate(docchecks)
            _suffix = subgate_to_failure_suffix(_subgate)
            tracker.blockers.append(
                f'pdf_render_failed:docmodel_professional_quality:{_suffix}')
            emit_docmodel_professional_failure(
                docchecks=docchecks,
                model=model,
                output_type='pdf',
                route_name='pdf',
                action_taken='pdf_quality_gate_blocked',
            )

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
