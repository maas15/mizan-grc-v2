# PR-CY41 — Professional Arabic/English strategy PDF/DOCX rendering layer.
# Rendering-only: does not mutate generation or contract pipelines.

from __future__ import annotations

import re
from copy import deepcopy
from typing import Any, Dict, List, Optional, Tuple

# ── Arabic concatenation fixes (render-time; acronyms preserved) ─────────────
# Longest patterns first — shorter keys must not run before longer ones.
PRCY41_AR_CONCAT_FIXES: Tuple[Tuple[str, str], ...] = (
    # PR-CY59 — executive-role and compound spacing defects (longest first).
    ('الالمسؤولتنفيذي', 'المسؤول التنفيذي'),
    ('امتثاللا تقلعن', 'امتثال لا تقل عن'),
    ('المسؤولتنفيذي', 'المسؤول التنفيذي'),
    ('الالمسؤول', 'المسؤول'),
    ('متخصصمن', 'متخصص من'),
    ('الأساسيةفي', 'الأساسية في'),
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
    # PR-CY57 — additional Arabic concatenation defects.
    ('مكتملمع', 'مكتمل مع'),
    ('البرنامجمع', 'البرنامج مع'),
    ('الثغراتكل', 'الثغرات كل'),
    ('التعافيمن', 'التعافي من'),
    ('الحيويةفي', 'الحيوية في'),
    ('الأضعففي', 'الأضعف في'),
    # PR-CY58 — additional Arabic concatenation defects.
    ('بناءخط', 'بناء خط'),
    ('الأولضد', 'الأول ضد'),
    ('البياناتفي', 'البيانات في'),
    ('متخصصةللأمن', 'متخصصة للأمن'),
    # PR-CY62 — final Arabic spacing defects (longest first).
    ('الحوكمةالفعالة', 'الحوكمة الفعالة'),
    ('السيبرانيةعلى', 'السيبرانية على'),
    ('التشغيليةعن', 'التشغيلية عن'),
    ('الإشرافيةعن', 'الإشرافية عن'),
    ('التوافقمع', 'التوافق مع'),
    ('تنفيذيةمع', 'تنفيذية مع'),
    ('الحدمن', 'الحد من'),
)

# PR-CY52 — max rendered roadmap cell length (PDF/DOCX density gate).
ROADMAP_CELL_MAX_LEN = 72

# PR-CY53 — generic roadmap phrases that must be rewritten or rejected.
ROADMAP_GENERIC_INITIATIVES = (
    'تنفيذ حلول', 'مبادرة تنفيذية', 'Implementation initiative',
    'solution implementation', 'implement solutions',
    'تطبيق ضوابط', 'تنفيذ ضوابط', 'ضوابط',
)
ROADMAP_GENERIC_OUTPUTS = (
    'مخرج معتمد', 'Approved deliverable',
    'قدرات تشغيلية فعّالة', 'Operational SOC/SIEM capability',
    'سياسة', 'إجراء', 'مخرج',
)
ROADMAP_GENERIC_INIT_PHRASES = frozenset({
    'تطبيق ضوابط', 'تنفيذ ضوابط', 'ضوابط', 'تنفيذ حلول',
    'مبادرة تنفيذية', 'Implementation initiative',
})
ROADMAP_GENERIC_OUTPUT_PHRASES = frozenset({
    'سياسة', 'إجراء', 'مخرج', 'مخرج معتمد', 'Approved deliverable',
})
ROADMAP_CAPABILITY_FAMILIES = (
    'governance', 'soc', 'iam', 'pam', 'mfa', 'csirt', 'vulnerability',
    'data_classification', 'encryption', 'dlp', 'sensitive_data',
)
ROADMAP_WEAK_OWNERS = ('خبير', 'Expert', 'expert', 'Mgr', 'mgr', 'Manager', 'manager')

# PR-CY53 — PDF table layout profiles (rendering-only).
PDF_TABLE_LAYOUT_PROFILES: Dict[str, Dict[str, Any]] = {
    'strategic_objectives': {
        'col_weights': [0.04, 0.28, 0.24, 0.28, 0.16],
        'font_size': 9, 'header_font_size': 9, 'padding': 6,
        'max_cell_len': 120, 'render_mode': 'table',
    },
    'pillar_initiatives': {
        'col_weights': [0.06, 0.30, 0.34, 0.30],
        'font_size': 9, 'header_font_size': 9, 'padding': 6,
        'max_cell_len': 100, 'render_mode': 'table',
    },
    'gap_main': {
        'col_weights': [0.05, 0.22, 0.38, 0.15, 0.20],
        'font_size': 8, 'header_font_size': 9, 'padding': 6,
        'max_cell_len': 90, 'render_mode': 'table',
    },
    'gap_action': {
        'col_weights': [0.10, 0.34, 0.16, 0.18, 0.22],
        'font_size': 8, 'header_font_size': 9, 'padding': 5,
        'max_cell_len': 80, 'render_mode': 'table',
    },
    'roadmap': {
        'col_weights': [0.14, 0.12, 0.28, 0.12, 0.20, 0.14],
        'font_size': 8, 'header_font_size': 9, 'padding': 6,
        'max_cell_len': ROADMAP_CELL_MAX_LEN, 'render_mode': 'table',
    },
    'kpi_main': {
        'col_weights': [0.05, 0.24, 0.10, 0.14, 0.12, 0.14, 0.21],
        'font_size': 8, 'header_font_size': 9, 'padding': 6,
        'max_cell_len': 72, 'render_mode': 'table',
    },
    'kpi_formula': {
        'col_weights': [0.08, 0.30, 0.32, 0.30],
        'font_size': 8, 'header_font_size': 9, 'padding': 6,
        'max_cell_len': 110, 'render_mode': 'table',
    },
    'conf_factor': {
        'render_mode': 'cards', 'font_size': 9, 'padding': 6,
        'max_cell_len': 48,
    },
    'risk_register': {
        'col_weights': [0.05, 0.24, 0.14, 0.12, 0.28, 0.17],
        'font_size': 8, 'header_font_size': 9, 'padding': 5,
        'max_cell_len': 90, 'render_mode': 'table',
    },
    'governance': {
        'col_weights': [0.14, 0.28, 0.22, 0.18, 0.18],
        'font_size': 8, 'header_font_size': 9, 'padding': 6,
        'max_cell_len': 100, 'render_mode': 'table',
        'split_if_wide': True, 'split_at_cols': 3,
    },
    'traceability': {
        'col_weights': [0.20, 0.26, 0.27, 0.27],
        'font_size': 8, 'header_font_size': 9, 'padding': 5,
        'max_cell_len': 90, 'render_mode': 'table',
    },
    'trace_fw_gap': {
        'col_weights': [0.22, 0.38, 0.40],
        'font_size': 8, 'header_font_size': 9, 'padding': 5,
        'max_cell_len': 90, 'render_mode': 'table',
    },
    'trace_fw_init': {
        'col_weights': [0.20, 0.26, 0.27, 0.27],
        'font_size': 8, 'header_font_size': 9, 'padding': 5,
        'max_cell_len': 90, 'render_mode': 'table',
    },
    'env': {
        'col_weights': [0.28, 0.18, 0.14, 0.40],
        'font_size': 8, 'header_font_size': 9, 'padding': 5,
        'max_cell_len': 90, 'render_mode': 'table',
    },
}

# Schema aliases → profile keys.
_PDF_LAYOUT_SCHEMA_ALIASES = {
    'gap_table': 'gap_main',
    'kpi_summary': 'kpi_main',
    'kpi_details': 'kpi_formula',
    'confidence_factors': 'conf_factor',
    'environment': 'env',
}

# Known table schemas that must have a layout profile (PR-CY53 gate).
PDF_LAYOUT_REQUIRED_SCHEMAS = (
    'strategic_objectives', 'pillar_initiatives', 'gap_main', 'gap_action',
    'roadmap', 'kpi_main', 'kpi_formula', 'conf_factor', 'risk_register',
    'governance', 'traceability',
)

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
        self.table_vertical_stack_warnings: List[Dict[str, Any]] = []
        self.layout_profiles_applied: List[str] = []
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
            'table_vertical_stack_warnings': list(
                self.table_vertical_stack_warnings),
            'layout_profiles_applied': list(self.layout_profiles_applied),
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


def find_arabic_concat_issues(text: str) -> List[Tuple[str, str]]:
    """PR-CY59 — return (bad, replacement) pairs still present in text."""
    issues: List[Tuple[str, str]] = []
    blob = text or ''
    for bad, good in PRCY41_AR_CONCAT_FIXES:
        if bad in blob:
            issues.append((bad, good))
    return issues


def apply_final_arabic_cleanup_to_value(val: Any, lang: str = 'ar') -> Any:
    """PR-CY59 — recursively apply final Arabic cleanup to block values."""
    if isinstance(val, str):
        if lang == 'ar':
            return prepare_final_render_text(val, lang)
        return prepare_section_text(val, lang)
    if isinstance(val, list):
        return [apply_final_arabic_cleanup_to_value(v, lang) for v in val]
    if isinstance(val, tuple):
        return tuple(apply_final_arabic_cleanup_to_value(v, lang) for v in val)
    if isinstance(val, dict):
        return {
            k: apply_final_arabic_cleanup_to_value(v, lang)
            for k, v in val.items()}
    return val


def apply_final_arabic_cleanup_to_blocks(
        blocks: Dict[str, Any], lang: str = 'ar') -> Dict[str, Any]:
    """PR-CY59 — walk all professional block text before quality gates."""
    if lang != 'ar':
        return blocks
    return apply_final_arabic_cleanup_to_value(deepcopy(blocks), lang)


def build_arabic_final_cleanup_diag(
        model: Optional[Dict[str, Any]] = None,
        *,
        output_type: str = '',
        lang: str = 'ar',
        cleanup_applied_count: int = 0) -> Dict[str, Any]:
    """PR-CY59 — [ARABIC-FINAL-CLEANUP-DIAG] payload."""
    blob = str((model or {}).get('blocks') or {})
    remaining = find_arabic_concat_issues(blob)
    return {
        'output_type': output_type,
        'bad_text_samples': [bad for bad, _ in remaining],
        'replacement_candidates': [good for _, good in remaining],
        'cleanup_applied_count': cleanup_applied_count,
        'remaining_issue_count': len(remaining),
        'action_taken': (
            'violations_remain' if remaining else 'validated'),
    }


def emit_arabic_final_cleanup_diag(
        model: Optional[Dict[str, Any]] = None,
        *,
        output_type: str = '',
        lang: str = 'ar',
        cleanup_applied_count: int = 0) -> Dict[str, Any]:
    """Emit [ARABIC-FINAL-CLEANUP-DIAG] to server logs."""
    payload = build_arabic_final_cleanup_diag(
        model, output_type=output_type, lang=lang,
        cleanup_applied_count=cleanup_applied_count)
    try:
        print(f'[ARABIC-FINAL-CLEANUP-DIAG] {payload}', flush=True)
    except Exception:  # noqa: BLE001
        pass
    return payload


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
    # PR-CY59 — concat fixes must run last; fragment repair can revert them.
    if lang == 'ar':
        out = normalize_arabic_for_render(out)
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
                          max_len: int = ROADMAP_CELL_MAX_LEN,
                          strip_dcc_clauses: bool = True) -> str:
    """PR-CY52 — shorten roadmap cells; strip long DCC explanatory clauses."""
    s = str(text or '').strip()
    if not s or s == '—':
        return s
    # Remove repeated DCC narrative fragments — details belong in traceability.
    if strip_dcc_clauses:
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
        _compact_roadmap_cell(cells[3], lang, max_len=24,
                              strip_dcc_clauses=False),
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


def get_pdf_table_layout_profile(
        schema: str, ncols: int = 0) -> Dict[str, Any]:
    """PR-CY53 — return PDF table layout profile for a schema."""
    key = _PDF_LAYOUT_SCHEMA_ALIASES.get(schema, schema)
    prof = dict(PDF_TABLE_LAYOUT_PROFILES.get(key) or {})
    if not prof:
        prof = {
            'render_mode': 'table', 'font_size': 8, 'header_font_size': 9,
            'padding': 5, 'max_cell_len': 100,
        }
    weights = prof.get('col_weights')
    if not weights and ncols:
        weights = schema_table_col_weights_fallback(schema, ncols)
        prof['col_weights'] = weights
    return prof


def schema_table_col_weights_fallback(schema: str, ncols: int) -> List[float]:
    """Legacy column-weight fallback when profile has no explicit weights."""
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
    if schema == 'strategic_objectives' and ncols == 5:
        return [0.04, 0.28, 0.24, 0.28, 0.16]
    if schema == 'pillar_initiatives' and ncols == 4:
        return [0.06, 0.30, 0.34, 0.30]
    if ncols == 5:
        return [0.06, 0.28, 0.22, 0.22, 0.22]
    if ncols == 6:
        return [0.14, 0.14, 0.22, 0.16, 0.18, 0.16]
    if ncols == 4:
        return [0.08, 0.32, 0.30, 0.30]
    return [1.0 / max(ncols, 1)] * max(ncols, 1)


def schema_table_col_weights(schema: str, ncols: int) -> List[float]:
    """PR-CY52/53 — PDF column weight hints per table schema."""
    prof = get_pdf_table_layout_profile(schema, ncols)
    return list(prof.get('col_weights') or schema_table_col_weights_fallback(
        schema, ncols))


def _truncate_cell_for_profile(text: str, profile: Dict[str, Any]) -> str:
    """Trim cell text to profile max length."""
    max_len = profile.get('max_cell_len') or 120
    s = str(text or '').strip()
    if len(s) <= max_len:
        return s
    return s[:max_len - 1].rstrip() + '…'


# PR-CY54 — vertical stack detection threshold (estimated lines).
VERTICAL_STACK_LINE_THRESHOLD = 5

# PR-CY54 — targeted PDF fallback when stacking risk is detected.
SCHEMA_STACK_FALLBACK: Dict[str, str] = {
    'strategic_objectives': 'objective_cards',
    'governance': 'governance_cards',
    'trace_fw_gap': 'trace_cards',
    'trace_fw_init': 'trace_cards',
    'traceability': 'trace_cards',
    'conf_factor': 'cards',
    'pillar_initiatives': 'pillar_initiative_cards',
    'gap_action': 'gap_action_cards',
}

# Map block kinds to human section categories for diagnostics.
_BLOCK_SECTION_CATEGORY = {
    'vision_objectives': 'strategic_objectives',
    'strategic_pillars': 'pillars',
    'roadmap': 'roadmap',
    'kpi_kri_framework': 'KPI',
    'confidence_risk_register': 'confidence',
    'governance_ownership': 'governance',
    'traceability_matrix': 'traceability',
    'gap_analysis': 'gap',
    'environment_context': 'environment',
}


def _cell_preview(text: str, limit: int = 80) -> str:
    s = str(text or '').strip()
    if len(s) <= limit:
        return s
    return s[:limit - 1] + '…'


def collect_vertical_stack_warnings(
        model: Optional[Dict[str, Any]],
        page_width: float = 480.0) -> List[Dict[str, Any]]:
    """PR-CY54 — detect cells likely to stack excessively; return rich dicts."""
    warnings: List[Dict[str, Any]] = []
    blocks = (model or {}).get('blocks') or {}
    for kind, blk in blocks.items():
        section_title = str(blk.get('title') or kind)
        section_category = _BLOCK_SECTION_CATEGORY.get(kind, kind)
        tables: List[Tuple[Dict[str, Any], str]] = []
        for tbl in blk.get('tables') or []:
            tables.append((tbl, section_title))
        if kind == 'strategic_pillars':
            for pb in blk.get('pillar_blocks') or []:
                pt = pb.get('table')
                if pt:
                    tables.append((pt, str(pb.get('title') or section_title)))
        if kind == 'governance_ownership' and blk.get('rows'):
            header = blk.get('header') or list(SCHEMA_GOVERNANCE_AR)
            tables.append(({
                'schema': 'governance', 'header': header,
                'rows': blk.get('rows') or [],
            }, section_title))
        if kind == 'traceability_matrix':
            for st in blk.get('split_tables') or []:
                tables.append((st, str(st.get('title') or section_title)))
        for tbl, tbl_title in tables:
            schema = tbl.get('schema', kind)
            hdr = tbl.get('header') or []
            ncols = len(hdr)
            if not ncols:
                continue
            prof = get_pdf_table_layout_profile(schema, ncols)
            if prof.get('render_mode') == 'cards':
                continue
            weights = prof.get('col_weights') or schema_table_col_weights(
                schema, ncols)
            fs = prof.get('font_size', 8)
            max_len = prof.get('max_cell_len', 120)
            threshold = VERTICAL_STACK_LINE_THRESHOLD
            for ri, row in enumerate(tbl.get('rows') or []):
                for ci, cell in enumerate(row):
                    if ci >= len(weights):
                        break
                    s = str(cell or '').strip()
                    if not s or s == '—':
                        continue
                    col_name = str(hdr[ci]) if ci < len(hdr) else str(ci)
                    col_w = weights[ci] * page_width
                    chars_per_line = max(14, int(col_w / (fs * 0.52)))
                    est_lines = max(
                        1, (len(s) + chars_per_line - 1) // chars_per_line)
                    reason = ''
                    if len(s) > max_len:
                        reason = 'overflow'
                    elif est_lines >= threshold:
                        reason = 'stack'
                    if not reason:
                        continue
                    warnings.append({
                        'schema': schema,
                        'block_kind': kind,
                        'section_title': tbl_title,
                        'section_category': section_category,
                        'row_index': ri,
                        'column_index': ci,
                        'column_name': col_name,
                        'cell_preview': _cell_preview(s),
                        'char_count': len(s),
                        'estimated_lines': est_lines,
                        'threshold': threshold,
                        'action_taken': '',
                    })
    return warnings


def compute_pdf_stack_fallbacks(
        model: Optional[Dict[str, Any]]) -> Dict[str, str]:
    """PR-CY54 — map schemas with stack warnings to render fallback modes."""
    warnings = collect_vertical_stack_warnings(model)
    fallbacks: Dict[str, str] = {}
    for w in warnings:
        schema = w.get('schema', '')
        if schema and schema not in fallbacks:
            fb = SCHEMA_STACK_FALLBACK.get(schema)
            if fb:
                fallbacks[schema] = fb
    return fallbacks


# PR-CY62 — schemas that receive proactive PDF polish for Arabic exports.
PRCY62_PROACTIVE_PDF_POLISH: Dict[str, str] = {
    'strategic_objectives': 'objective_cards',
    'pillar_initiatives': 'pillar_initiative_cards',
    'governance': 'governance_cards',
    'trace_fw_gap': 'trace_cards',
    'trace_fw_init': 'trace_cards',
    'traceability': 'trace_cards',
    'gap_action': 'gap_action_cards',
}


def _model_has_table_rows(blocks: Dict[str, Any], kind: str,
                          schema: str = '') -> bool:
    blk = blocks.get(kind) or {}
    if kind == 'strategic_pillars':
        return any(
            (pb.get('table') or {}).get('rows')
            for pb in (blk.get('pillar_blocks') or []))
    if kind == 'governance_ownership':
        return bool(blk.get('rows'))
    if kind == 'traceability_matrix':
        return bool(blk.get('split_tables') or blk.get('rows'))
    for tbl in blk.get('tables') or []:
        if not schema or tbl.get('schema') == schema:
            if tbl.get('rows'):
                return True
    return False


def compute_pdf_proactive_polish_fallbacks(
        model: Optional[Dict[str, Any]], lang: str = 'ar') -> Dict[str, str]:
    """PR-CY62 — apply readable PDF layouts proactively for Arabic exports."""
    if lang != 'ar':
        return {}
    blocks = (model or {}).get('blocks') or {}
    fallbacks: Dict[str, str] = {}
    if _model_has_table_rows(
            blocks, 'vision_objectives', 'strategic_objectives'):
        fallbacks['strategic_objectives'] = 'objective_cards'
    if _model_has_table_rows(blocks, 'strategic_pillars'):
        fallbacks['pillar_initiatives'] = 'pillar_initiative_cards'
    gov_rows = (blocks.get('governance_ownership') or {}).get('rows') or []
    if gov_rows and max((len(r) for r in gov_rows), default=0) >= 4:
        fallbacks['governance'] = 'governance_cards'
    trace = blocks.get('traceability_matrix') or {}
    for st in trace.get('split_tables') or []:
        schema = st.get('schema', '')
        if schema in PRCY62_PROACTIVE_PDF_POLISH and st.get('rows'):
            fallbacks[schema] = PRCY62_PROACTIVE_PDF_POLISH[schema]
    for tbl in (blocks.get('gap_analysis') or {}).get('tables') or []:
        if tbl.get('schema') == 'gap_action' and tbl.get('rows'):
            fallbacks['gap_action'] = 'gap_action_cards'
    return fallbacks


def compute_pdf_export_layout_fallbacks(
        model: Optional[Dict[str, Any]], lang: str = 'ar') -> Dict[str, str]:
    """PR-CY62 — merge stack-triggered and proactive PDF layout fallbacks."""
    stack = compute_pdf_stack_fallbacks(model)
    proactive = compute_pdf_proactive_polish_fallbacks(model, lang)
    merged = dict(stack)
    merged.update(proactive)
    return merged


def count_arabic_spacing_issues(
        model: Optional[Dict[str, Any]] = None,
        *, text: str = '') -> int:
    """PR-CY62 — count remaining known Arabic concat defects."""
    blob = text or str((model or {}).get('blocks') or {})
    return sum(1 for bad, _ in PRCY41_AR_CONCAT_FIXES if bad in blob)


def collect_remaining_arabic_spacing_issues(
        model: Optional[Dict[str, Any]] = None,
        *, text: str = '') -> List[str]:
    """PR-CY62 — list concat defect tokens still present."""
    blob = text or str((model or {}).get('blocks') or {})
    return [bad for bad, _ in PRCY41_AR_CONCAT_FIXES if bad in blob]


PRCY62_POLISH_SCHEMAS = frozenset({
    'strategic_objectives', 'pillar_initiatives', 'governance',
    'trace_fw_gap', 'trace_fw_init', 'traceability', 'gap_action',
})


def _count_dense_table_schemas(
        model: Optional[Dict[str, Any]],
        fallbacks: Optional[Dict[str, str]] = None) -> int:
    """Count polish-target schemas with stack warnings."""
    warnings = collect_vertical_stack_warnings(model)
    schemas = {
        w.get('schema') for w in warnings
        if w.get('schema') in PRCY62_POLISH_SCHEMAS}
    if fallbacks:
        schemas = {s for s in schemas if s not in fallbacks}
    return len(schemas)


def pdf_objectives_readable_layout_applied(
        model: Optional[Dict[str, Any]], lang: str = 'ar') -> bool:
    """PR-CY62 — Arabic PDF objectives use cards, not a dense 5-col table."""
    if lang != 'ar':
        return True
    blocks = (model or {}).get('blocks') or {}
    has_obj = _model_has_table_rows(
        blocks, 'vision_objectives', 'strategic_objectives')
    if not has_obj:
        return True
    fb = compute_pdf_export_layout_fallbacks(model, lang)
    return fb.get('strategic_objectives') == 'objective_cards'


def pdf_pillars_no_duplicate_initiative_rendering(
        model: Optional[Dict[str, Any]], lang: str = 'ar') -> bool:
    """PR-CY62 — pillar initiatives render once (cards), not table + prose."""
    if lang != 'ar':
        return True
    blocks = (model or {}).get('blocks') or {}
    has_pillar_tbl = _model_has_table_rows(blocks, 'strategic_pillars')
    if not has_pillar_tbl:
        return True
    fb = compute_pdf_export_layout_fallbacks(model, lang)
    return fb.get('pillar_initiatives') in (
        'pillar_initiative_cards', 'compact_3col')


def pdf_arabic_spacing_final_cleanup_passed(
        model: Optional[Dict[str, Any]], lang: str = 'ar') -> bool:
    """PR-CY62 — no known Arabic concat defects remain in the model."""
    if lang != 'ar':
        return True
    return count_arabic_spacing_issues(model) == 0


def pdf_dense_table_polish_passed(
        model: Optional[Dict[str, Any]], lang: str = 'ar') -> bool:
    """PR-CY62 — polish-target schemas have a readable PDF fallback."""
    if lang != 'ar':
        return True
    fallbacks = compute_pdf_export_layout_fallbacks(model, lang)
    warnings = collect_vertical_stack_warnings(model)
    remaining = [
        w for w in warnings
        if w.get('schema') in PRCY62_POLISH_SCHEMAS
        and w.get('schema') not in fallbacks]
    return len(remaining) == 0


def build_pdf_final_polish_diag(
        model: Optional[Dict[str, Any]], lang: str = 'ar',
        *, action_taken: str = '') -> Dict[str, Any]:
    """PR-CY62 — [PDF-FINAL-POLISH-DIAG] payload."""
    fallbacks = compute_pdf_export_layout_fallbacks(model, lang)
    stack_before = compute_pdf_stack_fallbacks(model)
    dense_before = _count_dense_table_schemas(model)
    dense_after = _count_dense_table_schemas(model, fallbacks)
    remaining = collect_remaining_arabic_spacing_issues(model)
    return {
        'objectives_layout_mode': fallbacks.get(
            'strategic_objectives', 'table'),
        'pillars_layout_mode': fallbacks.get(
            'pillar_initiatives', 'table'),
        'duplicated_pillar_initiatives_removed': (
            fallbacks.get('pillar_initiatives')
            == 'pillar_initiative_cards'),
        'arabic_spacing_cleanup_count': len(PRCY41_AR_CONCAT_FIXES),
        'remaining_arabic_spacing_issues': remaining,
        'dense_tables_before': dense_before,
        'dense_tables_after': dense_after,
        'pdf_layout_fallbacks': fallbacks,
        'stack_fallbacks_before_polish': stack_before,
        'action_taken': action_taken or (
            'polish_applied' if fallbacks else 'validated'),
    }


def emit_pdf_final_polish_diag(
        model: Optional[Dict[str, Any]], lang: str = 'ar',
        *, action_taken: str = '') -> Dict[str, Any]:
    """Emit [PDF-FINAL-POLISH-DIAG] to server logs."""
    payload = build_pdf_final_polish_diag(
        model, lang, action_taken=action_taken)
    try:
        print(f'[PDF-FINAL-POLISH-DIAG] {payload}', flush=True)
    except Exception:  # noqa: BLE001
        pass
    return payload


def evaluate_vertical_stack_gate(
        model: Optional[Dict[str, Any]],
        fallbacks: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """PR-CY54/62 — evaluate stack warnings after targeted fallbacks."""
    all_warnings = collect_vertical_stack_warnings(model)
    if fallbacks is None:
        lang = ((model or {}).get('lang') or 'ar')
        fallbacks = compute_pdf_export_layout_fallbacks(model, lang)
    for w in all_warnings:
        schema = w.get('schema', '')
        if schema in fallbacks:
            w['action_taken'] = f"fallback:{fallbacks[schema]}"
    remaining = [
        w for w in all_warnings
        if not w.get('action_taken')]
    schemas_with = sorted({w['schema'] for w in all_warnings})
    count = len(remaining)
    return {
        'table_vertical_stack_warnings': remaining,
        'table_vertical_stack_warning_count': count,
        'all_stack_warnings_detected': all_warnings,
        'fallback_applied_by_schema': dict(fallbacks),
        'schemas_with_warnings': schemas_with,
        'count_list_consistent': True,
        'pdf_table_vertical_stack_warnings': count == 0,
    }


def emit_pdf_vertical_stack_diag(
        stack_eval: Dict[str, Any],
        *,
        gate_blocked: bool = False,
        action_taken: str = '',
) -> Dict[str, Any]:
    """PR-CY54 — emit [PDF-VERTICAL-STACK-DIAG] to server logs."""
    payload = {
        'warning_count': stack_eval.get('table_vertical_stack_warning_count', 0),
        'warnings': stack_eval.get('table_vertical_stack_warnings') or [],
        'schemas_with_warnings': stack_eval.get('schemas_with_warnings') or [],
        'fallback_applied_by_schema': (
            stack_eval.get('fallback_applied_by_schema') or {}),
        'count_list_consistent': stack_eval.get('count_list_consistent', True),
        'gate_blocked': gate_blocked,
        'action_taken': action_taken,
        'all_warnings_detected_count': len(
            stack_eval.get('all_stack_warnings_detected') or []),
    }
    try:
        print(f'[PDF-VERTICAL-STACK-DIAG] {payload}', flush=True)
    except Exception:  # noqa: BLE001
        pass
    return payload


def estimate_table_vertical_stack_warnings(
        model: Optional[Dict[str, Any]],
        page_width: float = 480.0) -> List[Dict[str, Any]]:
    """PR-CY53/54 — remaining actionable warnings after fallback resolution."""
    return evaluate_vertical_stack_gate(model).get(
        'table_vertical_stack_warnings') or []


def pdf_table_layout_profiles_applied(
        model: Optional[Dict[str, Any]]) -> bool:
    """True when every present table schema has a known layout profile."""
    blocks = (model or {}).get('blocks') or {}
    seen: set = set()
    for kind, blk in blocks.items():
        for tbl in blk.get('tables') or []:
            schema = tbl.get('schema', '')
            if schema:
                seen.add(schema)
        if kind == 'strategic_pillars':
            for pb in blk.get('pillar_blocks') or []:
                s = (pb.get('table') or {}).get('schema', '')
                if s:
                    seen.add(s)
        if kind == 'governance_ownership' and blk.get('rows'):
            seen.add('governance')
    if not seen:
        return True
    for schema in seen:
        key = _PDF_LAYOUT_SCHEMA_ALIASES.get(schema, schema)
        if key not in PDF_TABLE_LAYOUT_PROFILES:
            return False
    return True


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


# PR-CY55 — initiative keyword sets for NCA DCC vs NCA ECC (word-safe).
_ROADMAP_DCC_EN_WORDS = ('dcc', 'dlp', 'encryption', 'classification', 'privacy', 'sensitive')
_ROADMAP_DCC_EN_PHRASES = (
    'data loss', 'data classification', 'data protection', 'loss prevention',
    'sensitive data', 'sensitive-data',
)
_ROADMAP_DCC_AR = (
    'تشفير', 'تصنيف البيانات', 'حماية البيانات', 'بيانات حساسة', 'خصوص', 'تسرب',
)
_ROADMAP_ECC_EN_WORDS = ('soc', 'siem', 'iam', 'pam', 'mfa', 'csirt', 'ciso')
_ROADMAP_ECC_EN_PHRASES = (
    'vulnerability', 'governance', 'privileged', 'incident response',
)
_ROADMAP_ECC_AR = ('ثغر', 'حوكمة', 'مصادقة', 'حادث', 'استجاب')


def _roadmap_blob_has_en_word(blob: str, word: str) -> bool:
    return bool(re.search(
        rf'(?<![a-z0-9]){re.escape(word)}(?![a-z0-9])', blob, flags=re.IGNORECASE))


def _initiative_needs_dcc(init: str) -> bool:
    """True when initiative text maps to NCA DCC (not substring false positives)."""
    blob = (init or '').lower()
    if any(p in blob for p in _ROADMAP_DCC_EN_PHRASES):
        return True
    if any(_roadmap_blob_has_en_word(blob, w) for w in _ROADMAP_DCC_EN_WORDS):
        return True
    if any(p in (init or '') for p in _ROADMAP_DCC_AR):
        return True
    if 'بيانات' in (init or ''):
        if any(k in (init or '') for k in ('DLP', 'dlp', 'تصنيف', 'حساس', 'حماية', 'تشفير')):
            return True
    return False


def _initiative_needs_ecc(init: str) -> bool:
    """True when initiative text maps to NCA ECC."""
    blob = (init or '').lower()
    if any(p in blob for p in _ROADMAP_ECC_EN_PHRASES):
        return True
    if any(_roadmap_blob_has_en_word(blob, w) for w in _ROADMAP_ECC_EN_WORDS):
        return True
    return any(p in (init or '') for p in _ROADMAP_ECC_AR)


def _is_generic_roadmap_init(init: str) -> bool:
    """PR-CY58 — True when initiative text is too generic for framework inference."""
    s = str(init or '').strip()
    if not s or _is_dash_cell(s):
        return True
    if s in ROADMAP_GENERIC_INITIATIVES or s in ROADMAP_GENERIC_INIT_PHRASES:
        return True
    return len(s) <= 12 and not _roadmap_has_concrete_capability(s)


def _is_generic_roadmap_output(output: str) -> bool:
    """PR-CY58 — True when output text is too generic for framework inference."""
    s = str(output or '').strip()
    if not s or _is_dash_cell(s):
        return True
    if s in ROADMAP_GENERIC_OUTPUTS or s in ROADMAP_GENERIC_OUTPUT_PHRASES:
        return True
    return len(s) <= 8


def _framework_for_capability_family(family: str) -> str:
    """Map capability family to NCA ECC or NCA DCC."""
    if family in ('data_classification', 'encryption', 'dlp', 'sensitive_data'):
        return 'NCA DCC'
    return 'NCA ECC'


def _roadmap_spec_for_family(family: str, lang: str = 'ar') -> Dict[str, str]:
    """PR-CY58 — concrete initiative/output/owner/framework per capability."""
    if lang != 'ar':
        en_specs = {
            'data_classification': {
                'init': 'Implement sensitive data classification & labelling',
                'output': 'Approved data-classification policy & asset inventory',
                'owner': 'Data Protection Owner', 'fw': 'NCA DCC'},
            'encryption': {
                'init': 'Implement encryption controls & key management',
                'output': 'Encryption controls & key management in place',
                'owner': 'Data Protection Owner', 'fw': 'NCA DCC'},
            'dlp': {
                'init': 'Enable DLP & data-leak monitoring',
                'output': 'Operational DLP platform & monitoring rules',
                'owner': 'Data Protection Owner', 'fw': 'NCA DCC'},
            'sensitive_data': {
                'init': 'Control sensitive data processing',
                'output': 'Approved sensitive-data handling procedures',
                'owner': 'Data Protection Owner', 'fw': 'NCA DCC'},
            'governance': {
                'init': 'Establish cyber governance',
                'output': 'Approved governance structure & policies',
                'owner': 'CISO', 'fw': 'NCA ECC'},
            'soc': {
                'init': 'Enable & operate SOC/SIEM',
                'output': 'Operational SOC/SIEM capability',
                'owner': 'SOC Manager', 'fw': 'NCA ECC'},
            'iam': {
                'init': 'Implement IAM/PAM/MFA controls',
                'output': 'IAM/PAM/MFA enforced',
                'owner': 'IAM Owner', 'fw': 'NCA ECC'},
            'pam': {
                'init': 'Implement IAM/PAM/MFA controls',
                'output': 'IAM/PAM/MFA enforced',
                'owner': 'IAM Owner', 'fw': 'NCA ECC'},
            'mfa': {
                'init': 'Implement IAM/PAM/MFA controls',
                'output': 'IAM/PAM/MFA enforced',
                'owner': 'IAM Owner', 'fw': 'NCA ECC'},
            'csirt': {
                'init': 'Establish CSIRT & incident response',
                'output': 'Operational CSIRT & approved response plan',
                'owner': 'CSIRT Lead', 'fw': 'NCA ECC'},
            'vulnerability': {
                'init': 'Improve vulnerability management programme',
                'output': 'Effective vulnerability SLA programme',
                'owner': 'Vulnerability Manager', 'fw': 'NCA ECC'},
        }
        return en_specs.get(family, en_specs['governance'])
    ar_specs = {
        'data_classification': {
            'init': 'تطبيق تصنيف ووسم البيانات الحساسة',
            'output': 'سياسة تصنيف بيانات وجرد أصول معتمد',
            'owner': 'مسؤول حماية البيانات', 'fw': 'NCA DCC'},
        'encryption': {
            'init': 'تطبيق ضوابط التشفير وإدارة المفاتيح',
            'output': 'ضوابط تشفير ومفاتيح مطبقة',
            'owner': 'مسؤول حماية البيانات', 'fw': 'NCA DCC'},
        'dlp': {
            'init': 'تفعيل DLP ومراقبة تسريب البيانات',
            'output': 'منصة DLP وقواعد مراقبة مفعلة',
            'owner': 'مسؤول حماية البيانات', 'fw': 'NCA DCC'},
        'sensitive_data': {
            'init': 'ضبط معالجة البيانات الحساسة',
            'output': 'إجراءات معالجة بيانات حساسة معتمدة',
            'owner': 'مسؤول حماية البيانات', 'fw': 'NCA DCC'},
        'governance': {
            'init': 'تأسيس حوكمة الأمن السيبراني',
            'output': 'هيكل حوكمة وسياسات معتمدة',
            'owner': 'CISO', 'fw': 'NCA ECC'},
        'soc': {
            'init': 'تمكين وتشغيل SOC/SIEM',
            'output': 'SOC/SIEM تشغيلي',
            'owner': 'مدير SOC', 'fw': 'NCA ECC'},
        'iam': {
            'init': 'تطبيق ضوابط IAM/PAM/MFA',
            'output': 'IAM/PAM/MFA مطبق',
            'owner': 'مدير IAM', 'fw': 'NCA ECC'},
        'pam': {
            'init': 'تطبيق ضوابط IAM/PAM/MFA',
            'output': 'IAM/PAM/MFA مطبق',
            'owner': 'مدير IAM', 'fw': 'NCA ECC'},
        'mfa': {
            'init': 'تطبيق ضوابط IAM/PAM/MFA',
            'output': 'IAM/PAM/MFA مطبق',
            'owner': 'مدير IAM', 'fw': 'NCA ECC'},
        'csirt': {
            'init': 'تأسيس CSIRT والاستجابة للحوادث',
            'output': 'فريق CSIRT وخطة استجابة معتمدة',
            'owner': 'قائد CSIRT', 'fw': 'NCA ECC'},
        'vulnerability': {
            'init': 'تحسين برنامج إدارة الثغرات',
            'output': 'برنامج إدارة ثغرات وتشغيل SLA',
            'owner': 'مدير الثغرات', 'fw': 'NCA ECC'},
    }
    return ar_specs.get(family, ar_specs['governance'])


def _infer_capability_family(
        raw_init: str, raw_output: str, raw_fw: str = '',
        phase_num: int = 1, lang: str = 'ar') -> Tuple[str, str]:
    """PR-CY58 — derive capability family and inference source."""
    blob = f'{raw_init} {raw_output} {raw_fw}'.lower()
    ar_blob = f'{raw_init} {raw_output} {raw_fw}'
    if any(k in blob for k in ('dlp',)) or 'تسرب' in ar_blob:
        return 'dlp', 'raw_text_keyword'
    if any(k in blob for k in ('encryption', 'encrypt')) or 'تشفير' in ar_blob:
        return 'encryption', 'raw_text_keyword'
    if any(k in blob for k in ('classification',)) or any(
            k in ar_blob for k in ('تصنيف', 'وسم', 'جرد')):
        return 'data_classification', 'raw_text_keyword'
    if any(k in blob for k in ('sensitive',)) or 'حساس' in ar_blob:
        return 'sensitive_data', 'raw_text_keyword'
    if any(_roadmap_blob_has_en_word(blob, w) for w in ('soc', 'siem')):
        return 'soc', 'raw_text_keyword'
    if any(_roadmap_blob_has_en_word(blob, w) for w in ('iam',)):
        return 'iam', 'raw_text_keyword'
    if any(_roadmap_blob_has_en_word(blob, w) for w in ('pam',)):
        return 'pam', 'raw_text_keyword'
    if any(_roadmap_blob_has_en_word(blob, w) for w in ('mfa',)):
        return 'mfa', 'raw_text_keyword'
    if 'csirt' in blob or 'حادث' in ar_blob or 'incident' in blob:
        return 'csirt', 'raw_text_keyword'
    if 'vulnerability' in blob or 'vuln' in blob or 'ثغر' in ar_blob:
        return 'vulnerability', 'raw_text_keyword'
    if any(k in blob for k in ('governance', 'ciso')) or 'حوكمة' in ar_blob:
        return 'governance', 'raw_text_keyword'
    if 'DCC' in str(raw_fw).upper():
        dcc_by_phase = {1: 'data_classification', 2: 'dlp', 3: 'encryption'}
        return dcc_by_phase.get(phase_num, 'data_classification'), 'framework_hint'
    if 'ECC' in str(raw_fw).upper():
        ecc_by_phase = {1: 'governance', 2: 'soc', 3: 'vulnerability'}
        return ecc_by_phase.get(phase_num, 'governance'), 'framework_hint'
    if _is_generic_roadmap_init(raw_init) or _is_generic_roadmap_output(raw_output):
        if _initiative_needs_dcc(f'{raw_init} {raw_output}'):
            return 'data_classification', 'phase_default'
        ecc_by_phase = {1: 'governance', 2: 'soc', 3: 'vulnerability'}
        return ecc_by_phase.get(phase_num, 'governance'), 'phase_default'
    if _initiative_needs_dcc(f'{raw_init} {raw_output}'):
        return 'data_classification', 'raw_text_keyword'
    if _initiative_needs_ecc(f'{raw_init} {raw_output}'):
        return 'governance', 'raw_text_keyword'
    return 'governance', 'phase_default'


def collect_roadmap_framework_violations(
        rows: List[List[str]], lang: str = 'ar',
        row_meta: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, str]]:
    """PR-CY55/58 — roadmap rows that fail framework/output mapping rules."""
    violations: List[Dict[str, str]] = []
    meta_list = row_meta or [{} for _ in rows]
    for r, meta in zip(rows or [], meta_list):
        if len(r) < 6:
            continue
        phase = str(r[0] or '')
        display_init = str(r[2] or '')
        display_out = str(r[4] or '')
        fw = str(r[5] or '')
        period = str(r[1] or '')
        raw_init = str(meta.get('raw_initiative') or display_init)
        raw_out = str(meta.get('raw_output') or display_out)
        family = meta.get('capability_family') or _infer_capability_family(
            raw_init, raw_out,
            meta.get('raw_framework') or fw,
            _phase_bucket(period or phase), lang)[0]
        expected = _framework_for_capability_family(family)
        inferred = expected
        reasons: List[str] = []
        if fw and expected:
            if 'DCC' in expected.upper() and 'DCC' not in fw.upper():
                reasons.append('assigned_framework_missing_dcc')
            if 'ECC' in expected.upper() and 'ECC' not in fw.upper():
                reasons.append('assigned_framework_missing_ecc')
        tailored_out = _roadmap_output_for_initiative(
            _roadmap_spec_for_family(family, lang)['init'], lang)
        if (display_out == 'إدارة ولجنة حوكمة فاعلة'
                and tailored_out != display_out):
            reasons.append('generic_governance_output_on_capability_initiative')
        if (_is_generic_roadmap_init(display_init)
                or _is_generic_roadmap_output(display_out)) and not family:
            reasons.append('generic_row_missing_capability_family')
        if reasons:
            violations.append({
                'phase': phase,
                'initiative': display_init,
                'output': display_out,
                'raw_initiative': raw_init,
                'raw_output': raw_out,
                'display_initiative': display_init,
                'display_output': display_out,
                'capability_family': family,
                'assigned_framework': fw,
                'inferred_framework': inferred,
                'expected_framework': expected,
                'inference_source': meta.get('inference_source', 'capability_family'),
                'reason': '; '.join(reasons),
            })
    return violations


def build_roadmap_framework_mapping_diag(
        model: Optional[Dict[str, Any]], lang: str = 'ar') -> Dict[str, Any]:
    """PR-CY58 — [ROADMAP-FRAMEWORK-MAPPING-DIAG] payload."""
    rows = get_roadmap_spec_rows(model)
    meta = get_roadmap_row_meta(model)
    violations = collect_roadmap_framework_violations(rows, lang, meta)
    by_family: Dict[str, int] = {}
    for m in meta:
        fam = str(m.get('capability_family') or 'unknown')
        by_family[fam] = by_family.get(fam, 0) + 1
    dcc_rows = sum(
        1 for m in meta
        if 'DCC' in str(m.get('assigned_framework', '')).upper())
    ecc_rows = sum(
        1 for m in meta
        if 'ECC' in str(m.get('assigned_framework', '')).upper())
    action = 'validated'
    if any(_is_generic_roadmap_init(m.get('raw_initiative', ''))
           or _is_generic_roadmap_output(m.get('raw_output', ''))
           for m in meta):
        action = 'rewrote_generic_rows'
    if violations:
        action = 'violations_remain'
    return {
        'row_count': len(rows),
        'rows_by_capability_family': by_family,
        'dcc_rows': dcc_rows,
        'ecc_rows': ecc_rows,
        'violations': violations,
        'action_taken': action,
    }


def emit_roadmap_framework_mapping_diag(
        model: Optional[Dict[str, Any]], lang: str = 'ar') -> Dict[str, Any]:
    """Emit [ROADMAP-FRAMEWORK-MAPPING-DIAG] to server logs."""
    payload = build_roadmap_framework_mapping_diag(model, lang)
    try:
        print(f'[ROADMAP-FRAMEWORK-MAPPING-DIAG] {payload}', flush=True)
    except Exception:  # noqa: BLE001
        pass
    return payload


def _infer_roadmap_framework(
        init: str, period: str, phase_num: int, raw_fw: str,
        lang: str = 'ar', capability_family: str = '') -> str:
    """PR-CY50/55/58 — map roadmap rows to NCA ECC vs NCA DCC."""
    if capability_family:
        return _framework_for_capability_family(capability_family)
    family, _ = _infer_capability_family(
        init, '', raw_fw, phase_num, lang)
    if family:
        return _framework_for_capability_family(family)
    if _initiative_needs_dcc(init):
        return 'NCA DCC'
    if _initiative_needs_ecc(init):
        return 'NCA ECC'
    if raw_fw and not _is_dash_cell(raw_fw):
        fw = str(raw_fw).strip()
        if 'DCC' in fw.upper():
            return 'NCA DCC'
        if 'ECC' in fw.upper():
            return 'NCA ECC'
        return fw
    return 'NCA ECC'


def _roadmap_has_concrete_capability(init: str, fw: str = '') -> bool:
    """PR-CY53 — True when initiative names a concrete ECC/DCC capability."""
    blob = f'{init} {fw}'.lower()
    keys = (
        'soc', 'siem', 'iam', 'pam', 'mfa', 'csirt', 'ثغر', 'vulnerability',
        'حوكمة', 'governance', 'ciso', 'dcc', 'dlp', 'تصنيف', 'تشفير',
        'encryption', 'حماية', 'بيانات', 'data', 'iam/', 'soc/',
    )
    return any(k in blob for k in keys)


def _rewrite_weak_roadmap_initiative(
        init: str, fw: str, phase_num: int, lang: str = 'ar') -> str:
    """Replace generic roadmap initiatives with concrete capabilities."""
    s = str(init or '').strip()
    if s and s not in ROADMAP_GENERIC_INITIATIVES and _roadmap_has_concrete_capability(s, fw):
        return s
    is_dcc = 'DCC' in str(fw).upper() or phase_num >= 3
    if lang == 'ar':
        if is_dcc:
            dcc_by_phase = {
                1: 'تصنيف البيانات وحماية الأصول',
                2: 'DLP وحماية البيانات الحساسة',
                3: 'التشفير ومراقبة تسريب البيانات',
            }
            return dcc_by_phase.get(phase_num, 'حماية البيانات الحساسة')
        ecc_by_phase = {
            1: 'تأسيس حوكمة الأمن السيبراني وتعيين CISO',
            2: 'تمكين SOC/SIEM وIAM/PAM/MFA',
            3: 'تحسين إدارة الثغرات والاستجابة CSIRT',
        }
        return ecc_by_phase.get(phase_num, 'تمكين SOC/SIEM وIAM/PAM/MFA')
    if is_dcc:
        return 'Data classification & sensitive data protection'
    return 'Enable SOC/SIEM and IAM/PAM/MFA'


def _roadmap_output_for_initiative(
        init: str, lang: str = 'ar') -> str:
    """PR-CY55 — initiative-specific deliverable (never generic governance)."""
    blob = f'{init}'.lower()
    if lang == 'ar':
        if any(k in blob for k in ('csirt', 'حادث', 'incident')):
            return 'قدرة CSIRT تشغيلية'
        if any(k in blob for k in ('dlp', 'تسرب')):
            return 'سياسات DLP وتصنيف بيانات معتمدة'
        if any(k in blob for k in ('soc', 'siem')):
            return 'قدرات SOC/SIEM تشغيلية'
        if any(k in blob for k in ('iam', 'pam', 'mfa', 'مصادقة')):
            return 'سياسات IAM/PAM/MFA مطبقة'
        if any(k in blob for k in ('ثغر', 'vulnerability')):
            return 'برنامج إدارة الثغرات فعّال'
        if any(k in blob for k in ('تشفير', 'encryption')):
            return 'تشفير البيانات الحساسة مطبق'
        if any(k in blob for k in ('تصنيف', 'classification', 'بيانات')):
            return 'سياسة تصنيف البيانات معتمدة'
        if any(k in blob for k in ('حوكمة', 'governance', 'ciso')):
            return 'إدارة ولجنة حوكمة فاعلة'
        return 'مخرجات تنفيذية معتمدة'
    if any(k in blob for k in ('csirt', 'incident')):
        return 'Operational CSIRT capability'
    if any(k in blob for k in ('dlp',)):
        return 'Approved DLP and data-classification policies'
    if any(k in blob for k in ('soc', 'siem')):
        return 'Operational SOC/SIEM capability'
    if any(k in blob for k in ('iam', 'pam', 'mfa')):
        return 'IAM/PAM/MFA policies enforced'
    if any(k in blob for k in ('vulnerability', 'vuln')):
        return 'Effective vulnerability management programme'
    if any(k in blob for k in ('encrypt', 'classification', 'sensitive')):
        return 'Sensitive data encryption and classification in place'
    return 'Approved implementation deliverables'


def _roadmap_owner_for_initiative(init: str, lang: str = 'ar') -> str:
    """PR-CY57 — initiative-specific accountable owner."""
    blob = f'{init}'.lower()
    if lang == 'ar':
        if any(k in blob for k in ('csirt', 'حادث', 'incident')):
            return 'قائد CSIRT'
        if any(k in blob for k in ('soc', 'siem')):
            return 'مدير SOC'
        if any(k in blob for k in ('iam', 'pam', 'mfa', 'مصادقة')):
            return 'مسؤول IAM'
        if any(k in blob for k in (
                'dlp', 'تصنيف', 'بيانات', 'تشفير', 'encryption', 'data')):
            return 'مسؤول حماية البيانات'
        if any(k in blob for k in ('ثغر', 'vulnerability', 'vuln')):
            return 'مسؤول إدارة الثغرات'
        return 'CISO'
    if any(k in blob for k in ('csirt', 'incident')):
        return 'CSIRT Lead'
    if any(k in blob for k in ('soc', 'siem')):
        return 'SOC Manager'
    if any(k in blob for k in ('iam', 'pam', 'mfa')):
        return 'IAM Owner'
    if any(k in blob for k in ('dlp', 'classification', 'encrypt', 'data')):
        return 'Data Protection Owner'
    if any(k in blob for k in ('vulnerability', 'vuln')):
        return 'Vulnerability Manager'
    return 'CISO'


def _roadmap_owner_mismatches_initiative(owner: str, init: str) -> bool:
    """True when owner is weak or inconsistent with initiative type."""
    o = str(owner or '').strip()
    if not o or _is_dash_cell(o) or o in ROADMAP_WEAK_OWNERS:
        return True
    canonical = _roadmap_owner_for_initiative(init, 'ar').lower()
    ol = o.lower()
    if ol == canonical:
        return False
    blob = f'{init}'.lower()
    if any(k in blob for k in ('soc', 'siem')) and 'soc' not in ol:
        return True
    if any(k in blob for k in ('csirt',)) and 'csirt' not in ol:
        return True
    if any(k in blob for k in ('iam', 'pam', 'mfa')) and 'iam' not in ol:
        return True
    if any(k in blob for k in ('dlp', 'بيانات', 'تصنيف', 'تشفير')):
        if not any(k in ol for k in ('بيانات', 'data', 'dlp', 'dcc')):
            if ol == 'ciso':
                return True
    return False


def _roadmap_output_matches_initiative(
        output: str, init: str, lang: str = 'ar') -> bool:
    """PR-CY57 — True when output is a concrete deliverable for the initiative."""
    out = str(output or '').strip().lower()
    if not out or _is_dash_cell(out):
        return False
    if out in ROADMAP_GENERIC_OUTPUTS:
        return False
    tailored = _roadmap_output_for_initiative(init, lang).lower()
    if out == tailored:
        return True
    blob = f'{init}'.lower()
    domain_checks = (
        (('soc', 'siem'), ('soc', 'siem', 'مراقبة', 'monitor')),
        (('csirt', 'حادث', 'incident'), ('csirt', 'حادث', 'incident', 'استجاب')),
        (('dlp', 'تسرب'), ('dlp', 'تصنيف', 'classification')),
        (('iam', 'pam', 'mfa'), ('iam', 'pam', 'mfa', 'مصادقة')),
        (('ثغر', 'vulnerability', 'vuln'), ('ثغر', 'vulnerability', 'vuln')),
        (('تشفير', 'encryption'), ('تشفير', 'encrypt')),
        (('تصنيف', 'classification', 'بيانات'), (
            'تصنيف', 'classification', 'بيانات', 'dlp')),
        (('حوكمة', 'governance', 'ciso'), ('حوكمة', 'governance', 'ciso')),
    )
    for init_keys, out_keys in domain_checks:
        if any(k in blob for k in init_keys):
            return any(k in out for k in out_keys)
    return len(out) >= 12


def _rewrite_weak_roadmap_output(
        output: str, init: str, phase_num: int, lang: str = 'ar') -> str:
    """Replace generic roadmap outputs with concrete deliverables."""
    s = str(output or '').strip()
    tailored = _roadmap_output_for_initiative(init, lang)
    if s and s not in ROADMAP_GENERIC_OUTPUTS:
        if s == 'إدارة ولجنة حوكمة فاعلة' and tailored != s:
            return tailored
        if s == 'قدرات تشغيلية فعّالة' and tailored != s:
            return tailored
        return s
    return tailored


def _is_generic_roadmap_row(row: List[str]) -> bool:
    """True when roadmap row uses forbidden generic phrases."""
    if len(row) < 5:
        return False
    init = str(row[2] or '').strip()
    out = str(row[4] or '').strip()
    owner = str(row[3] or '').strip()
    if _is_generic_roadmap_init(init) or _is_generic_roadmap_output(out):
        return True
    if init in ROADMAP_GENERIC_INITIATIVES:
        return True
    if out in ROADMAP_GENERIC_OUTPUTS:
        return True
    if out == 'إدارة ولجنة حوكمة فاعلة':
        blob = init.lower()
        if any(k in blob for k in (
                'csirt', 'dlp', 'soc', 'siem', 'iam', 'pam', 'mfa',
                'ثغر', 'vulnerability', 'تشفير', 'encryption')):
            return True
    if owner in ROADMAP_WEAK_OWNERS:
        return True
    if init and not _roadmap_has_concrete_capability(init, row[5] if len(row) > 5 else ''):
        if len(init) < 10:
            return True
    return False


def roadmap_generic_rows_absent(rows: List[List[str]]) -> bool:
    """PR-CY53 — no generic roadmap rows in the model."""
    return not any(_is_generic_roadmap_row(r) for r in (rows or []))


def _fill_roadmap_row(
        row: List[str], lang: str = 'ar') -> Tuple[List[str], Dict[str, Any]]:
    """Ensure a roadmap row has meaningful owner/output/framework defaults."""
    cells = list(row) + ['—'] * (6 - len(row))
    raw_init = str(cells[2] or '').strip()
    raw_out = str(cells[4] or '').strip()
    raw_fw = str(cells[5] or '').strip()
    period = cells[1] if not _is_dash_cell(cells[1]) else (
        '1-6 أشهر' if _phase_bucket(cells[0]) == 1 else
        '7-18 شهر' if _phase_bucket(cells[0]) == 2 else '19-24 شهر')
    phase_num = _phase_bucket(period or cells[0])
    family, inference_source = _infer_capability_family(
        raw_init if not _is_dash_cell(raw_init) else '',
        raw_out if not _is_dash_cell(raw_out) else '',
        raw_fw, phase_num, lang)
    spec = _roadmap_spec_for_family(family, lang)
    init = (raw_init if not _is_generic_roadmap_init(raw_init)
            and _roadmap_has_concrete_capability(raw_init, raw_fw)
            else spec['init'])
    out = (raw_out if not _is_generic_roadmap_output(raw_out)
           and _roadmap_output_matches_initiative(raw_out, init, lang)
           else spec['output'])
    fw = spec['fw']
    owner = spec['owner']
    if not _is_dash_cell(cells[3]) and not _roadmap_owner_mismatches_initiative(
            cells[3], init):
        owner = cells[3]
    display = _compact_roadmap_row([
        cells[0] if not _is_dash_cell(cells[0]) else _phase_for_months(period, lang),
        period,
        init,
        owner,
        out,
        fw,
    ], lang)
    meta = {
        'raw_initiative': raw_init if raw_init else spec['init'],
        'raw_output': raw_out if raw_out else spec['output'],
        'raw_framework': raw_fw,
        'display_initiative': display[2],
        'display_output': display[4],
        'capability_family': family,
        'assigned_framework': fw,
        'expected_framework': _framework_for_capability_family(family),
        'inference_source': inference_source,
    }
    return display, meta


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
            'CISO', 'نضج CSIRT وإدارة الثغرات', 'NCA ECC'),
    }
    period, init, owner, out, fw = synth.get(phase_num, synth[2])
    if lang != 'ar':
        period = period.replace('أشهر', 'months').replace('شهر', 'months')
    return [_phase_label(phase_num, lang), period, init, owner, out, fw]


def build_roadmap_render_spec(
        rows: List[List[str]], lang: str = 'ar') -> Tuple[
            List[List[str]], List[Dict[str, Any]]]:
    """PR-CY48/58 — build meaningful roadmap rows grouped by phase coverage."""
    buckets: Dict[int, List[Tuple[List[str], Dict[str, Any]]]] = {
        1: [], 2: [], 3: []}
    seen_inits: set = set()
    for r in rows or []:
        if _is_dash_heavy_row(r):
            continue
        filled, meta = _fill_roadmap_row(r, lang)
        if _is_generic_roadmap_row(filled):
            phase_num = _phase_bucket(filled[1] or filled[0])
            family, inference_source = _infer_capability_family(
                meta.get('raw_initiative', ''), meta.get('raw_output', ''),
                meta.get('raw_framework', ''), phase_num, lang)
            spec = _roadmap_spec_for_family(family, lang)
            filled[2] = spec['init']
            filled[4] = spec['output']
            filled[3] = spec['owner']
            filled[5] = spec['fw']
            meta.update({
                'capability_family': family,
                'inference_source': inference_source,
                'assigned_framework': spec['fw'],
                'expected_framework': _framework_for_capability_family(family),
                'display_initiative': filled[2],
                'display_output': filled[4],
            })
        init_key = (filled[2] or '').strip()[:60]
        if init_key in seen_inits:
            continue
        seen_inits.add(init_key)
        bucket = _phase_bucket(filled[1] or filled[0])
        buckets[bucket].append((filled, meta))
    result: List[List[str]] = []
    result_meta: List[Dict[str, Any]] = []
    for phase_num in (1, 2, 3):
        phase_rows = buckets[phase_num]
        if phase_rows:
            for filled, meta in phase_rows[:3]:
                result.append(filled)
                result_meta.append(meta)
        else:
            filled, meta = _fill_roadmap_row(
                _synth_phase_row(phase_num, lang), lang)
            result.append(filled)
            result_meta.append(meta)
    return result, result_meta


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
        elif schema == 'kpi_main':
            cells = [prepare_final_render_text(c, lang) for c in r]
            if len(cells) > 3:
                name = cells[1] if len(cells) > 1 else ''
                kpi_type = cells[2] if len(cells) > 2 else ''
                target = cells[3] if len(cells) > 3 else ''
                cells[2] = _derive_kpi_type(name, kpi_type, lang)
                cells[3] = _derive_kpi_target(name, target, lang)
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
                for _gk in ('priorities', 'top_gaps', 'key_risks'):
                    grid[_gk] = [
                        prepare_final_render_text(str(x), lang)
                        for x in (grid.get(_gk) or []) if str(x).strip()]
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
        if kind == 'appendices' and blk.get('entries'):
            blk['entries'] = [
                (str(a), prepare_final_render_text(str(b), lang))
                for a, b in (blk.get('entries') or [])]
        if kind == 'scope_frameworks' and blk.get('frameworks'):
            blk['frameworks'] = [
                {**fw, 'display': prepare_final_render_text(
                    str(fw.get('display') or ''), lang)}
                if isinstance(fw, dict) else fw
                for fw in (blk.get('frameworks') or [])]
    out = _normalize_kpi_tables_semantics(out, lang)
    if lang == 'ar':
        out = apply_final_arabic_cleanup_to_blocks(out, lang)
    return out


def sync_professional_toc_entries(
        blocks: Dict[str, Any], lang: str = 'ar') -> Dict[str, Any]:
    """PR-CY55 — ensure TOC lists every professional section being rendered."""
    toc_blk = dict(blocks.get('toc') or {})
    existing = toc_blk.get('entries') or []
    if existing and len(existing) >= 10:
        return blocks
    entries: List[Tuple[str, str]] = []
    for n, (key, lbl_ar, lbl_en) in enumerate(_PROFESSIONAL_TOC_LABELS, 1):
        lbl = lbl_ar if lang == 'ar' else lbl_en
        blk = blocks.get(key) or {}
        title = str(blk.get('title') or lbl).strip()
        entries.append((str(n), title or lbl))
    toc_blk['entries'] = entries
    blocks['toc'] = toc_blk
    return blocks


def get_toc_entries_from_model(
        model: Optional[Dict[str, Any]]) -> List[Tuple[str, str]]:
    """PR-CY55 — TOC entries from the document model (PDF/DOCX parity)."""
    blocks = (model or {}).get('blocks') or {}
    toc = blocks.get('toc') or {}
    entries = toc.get('entries') or []
    if entries:
        return [(str(a), str(b)) for a, b in entries]
    return []


def professional_toc_includes_required_sections(
        model: Optional[Dict[str, Any]], lang: str = 'ar') -> bool:
    """PR-CY55 — TOC must list executive summary through appendices."""
    entries = get_toc_entries_from_model(model)
    if not entries:
        return False
    blob = ' '.join(str(t) for _, t in entries).lower()
    if lang == 'ar':
        required = (
            'الملخص', 'النطاق', 'المنهجية', 'الحوكمة',
            'تتبع', 'الملاحق',
        )
    else:
        required = (
            'executive summary', 'scope', 'methodology', 'governance',
            'traceability', 'appendices',
        )
    return all(k in blob for k in required)


def pdf_confidence_card_labels_readable(text: str = '') -> bool:
    """PR-CY55 — confidence card labels must not contain reversed Arabic."""
    blob = text or ''
    return not any(f in blob for f in REVERSED_CONFIDENCE_LABEL_FRAGMENTS)


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


def get_roadmap_row_meta(
        model: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """PR-CY58 — return capability-family metadata for roadmap validation."""
    blocks = (model or {}).get('blocks') or {}
    meta: List[Dict[str, Any]] = []
    for tbl in ((blocks.get('roadmap') or {}).get('tables') or []):
        meta.extend(tbl.get('row_meta') or [])
    return meta


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
    rows_out, row_meta = build_roadmap_render_spec(rows_out, lang)
    return {'schema': 'roadmap', 'header': schema, 'rows': rows_out,
            'row_meta': row_meta}


def _is_time_based_metric(name: str) -> bool:
    """True when KPI measures duration/time, not a percentage rate."""
    if _is_soc_detection_metric(name):
        return False
    n = (name or '').strip().lower()
    if any(k in n for k in ('ثغر', 'vulnerability', 'vm')):
        return False
    return any(k in n for k in (
        'زمن', 'time', 'mttr', 'mttd', 'response', 'استجاب',
        'ساعة', 'hour', 'دقيقة', 'minute', 'أيام', 'days',
    ))


def _is_soc_detection_metric(name: str) -> bool:
    """PR-CY58 — SOC/SIEM coverage or threat-detection effectiveness."""
    n = (name or '').strip().lower()
    if not any(k in n for k in ('soc', 'siem')):
        return False
    if any(k in n for k in (
            'coverage', 'تغطية', 'كشف', 'detection', 'detect',
            'تهديد', 'threat', 'effectiveness', 'فعالية', 'alert',
            'تنبيه', 'monitor', 'مراقبة')):
        return True
    if not _is_incident_response_metric(name):
        return True
    return False


def _is_incident_response_metric(name: str) -> bool:
    """PR-CY58 — incident response time metrics (not SOC detection)."""
    n = (name or '').strip().lower()
    ar = name or ''
    if _is_incident_detection_metric(name):
        return False
    return any(k in n for k in (
        'استجاب', 'response', 'حادث', 'incident', 'mttr', 'mttd',
    )) or any(k in ar for k in ('استجاب',))


def _is_incident_detection_metric(name: str) -> bool:
    """PR-CY68 — incident detection / MTTD metrics (not response)."""
    n = (name or '').strip().lower()
    ar = name or ''
    if any(k in n for k in ('vuln', 'vulnerability')) or 'ثغر' in ar:
        return False
    if any(k in ar for k in ('استجاب',)) or any(
            k in n for k in ('response', 'mttr')):
        return False
    if any(k in ar for k in ('اكتشاف',)):
        return any(k in ar for k in ('حاد', 'أمن')) or any(
            k in n for k in ('incident', 'security', 'mttd'))
    return any(k in n for k in (
        'mttd', 'time to detect', 'detection time',
        'mean time to detect', 'detect security incident',
    ))


def _normalize_kpi_name(name: str, lang: str = 'ar') -> str:
    """PR-CY55 — align KPI names with remediation/completion semantics."""
    n = (name or '').strip()
    if not n or n == '—':
        return n
    nu = n.lower()
    if lang == 'ar':
        if any(k in nu for k in ('ثغر', 'vulnerability', 'remediation', 'إغلاق', 'closure')):
            if 'اكتشاف' in n:
                n = n.replace('اكتشاف', 'إغلاق')
            if 'discovery' in nu:
                n = re.sub(r'discovery', 'closure', n, flags=re.IGNORECASE)
        if any(k in nu for k in ('توعية', 'awareness', 'تدريب', 'training')):
            if 'فعالية' in n:
                n = n.replace('فعالية', 'إكمال')
            if 'effectiveness' in nu:
                n = re.sub(r'effectiveness', 'completion', n, flags=re.IGNORECASE)
    else:
        if any(k in nu for k in ('vulnerability', 'vuln', 'remediation', 'closure')):
            if 'discovery' in nu:
                n = re.sub(r'discovery', 'closure', n, flags=re.IGNORECASE)
        if any(k in nu for k in ('awareness', 'training')):
            if 'effectiveness' in nu:
                n = re.sub(r'effectiveness', 'completion', n, flags=re.IGNORECASE)
    return n


def _align_kpi_name_with_formula(
        name: str, formula: str, lang: str = 'ar') -> str:
    """PR-CY55 — ensure KPI name matches formula semantics."""
    n = (name or '').strip()
    f = (formula or '').lower()
    if not n or not f:
        return n
    if lang == 'ar':
        if any(k in f for k in ('مغلقة', 'إغلاق', 'closed', 'remediation')):
            if 'اكتشاف' in n:
                n = n.replace('اكتشاف', 'إغلاق')
        if any(k in f for k in ('مجتازين', 'trained', 'completion', 'إكمال')):
            if 'فعالية' in n:
                n = n.replace('فعالية', 'إكمال')
    else:
        if any(k in f for k in ('closed', 'remediation', 'closure')):
            n = re.sub(r'discovery', 'closure', n, flags=re.IGNORECASE)
        if any(k in f for k in ('trained', 'completion')):
            n = re.sub(r'effectiveness', 'completion', n, flags=re.IGNORECASE)
    return n


def kpi_name_formula_aligned(name: str, formula: str, lang: str = 'ar') -> bool:
    """PR-CY55/61 — KPI name must not contradict its formula."""
    n = (name or '').lower()
    f = (formula or '').lower()
    if any(k in f for k in ('closed', 'remediation', 'مغلقة', 'إغلاق')):
        if 'discovery' in n or 'اكتشاف' in n:
            return False
        if 'زمن' in n and _is_percentage_formula(formula):
            return False
    if any(k in f for k in ('trained', 'completion', 'مجتازين', 'إكمال')):
        if 'effectiveness' in n or 'فعالية' in n:
            return False
    if _is_percentage_formula(formula):
        if _is_time_based_metric(name) and 'ثغر' not in name:
            return False
        if 'زمن' in (name or '') and any(
                k in n for k in ('ثغر', 'vulnerability')):
            return False
    if not _is_percentage_formula(formula):
        if any(k in n for k in ('نسبة', 'rate', '%')) and 'زمن' not in n:
            if 'mttr' not in n and 'mttd' not in n:
                pass
    return True


def _is_formula_like_target(val: str) -> bool:
    """PR-CY53 — True when a KPI target cell holds formula text, not a target."""
    s = (val or '').strip()
    if not s or s == '—':
        return False
    if '×' in s or '÷' in s:
        return True
    if s.count('(') >= 1 and s.count(')') >= 1:
        return True
    formula_keys = (
        'المنجز', 'Done', 'Planned', 'المخطط', 'إجمالي', 'total',
        'Average', 'متوسط', 'عدد', 'count', 'Sum ', 'مجموع',
        '/ ', ' SLA-closed', 'closed vulnerabilities',
    )
    if any(k in s for k in formula_keys):
        return True
    if len(s) > 60 and ('/' in s or '×' in s):
        return True
    return False


def _derive_kpi_target(name: str, raw_target: str, lang: str = 'ar') -> str:
    """PR-CY50/53 — measurable target only; never formula text."""
    t = (raw_target or '').strip()
    if t in ('—', '-', '--', '–'):
        t = ''
    if _is_formula_like_target(t):
        t = ''
    n = (name or '').strip()
    nu = n.lower()
    if _is_soc_detection_metric(n):
        return '≥95%' if lang == 'ar' else '≥95%'
    if lang == 'ar':
        if _is_incident_response_metric(n):
            if any(k in n for k in ('دقيقة', 'minute', '30')):
                return '≤ 30 دقيقة'
            if t and '%' not in t and not _is_formula_like_target(t):
                return t
            return '< 4 ساعات'
        if any(k in n for k in ('ثغر', 'vulnerability', 'VM')):
            if t in ('100%', '100'):
                t = ''
            if t and not _is_formula_like_target(t) and '%' in t:
                return t
            return '95% خلال 72 ساعة'
        if any(k in nu for k in ('phishing', 'تصيد', 'failure')):
            return 'أقل من 5%'
        if any(k in nu for k in ('mfa', 'مصادقة')):
            return '100% للحسابات المميزة أو ≥95% للمستخدمين'
        if any(k in nu for k in ('backup', 'نسخ', 'dr')):
            return '≥99%'
        if any(k in nu for k in ('encrypt', 'تشفير', 'dlp', 'بيانات')):
            return '≥95% أو 100% للبيانات الحساسة المصنفة'
    else:
        if _is_incident_response_metric(n):
            if any(k in nu for k in ('minute', '30')):
                return '≤ 30 minutes'
            if t and '%' not in t and not _is_formula_like_target(t):
                return t
            return '< 4 hours'
        if any(k in nu for k in ('vulnerability', 'vuln')):
            return '95% within 72 hours'
        if any(k in nu for k in ('phishing', 'failure')):
            return '< 5%'
        if 'mfa' in nu:
            return '100% privileged or ≥95% users'
        if any(k in nu for k in ('backup', 'dr')):
            return '≥99%'
        if any(k in nu for k in ('encrypt', 'dlp', 'sensitive')):
            return '≥95% or 100% classified sensitive data'
    if _is_time_based_metric(name):
        if t and t != '—' and '%' not in t and not _is_formula_like_target(t):
            return t
        if lang == 'ar':
            if any(k in n for k in ('استجاب', 'response', 'حادث')):
                return '< 4 ساعات'
            return '≤ 72 ساعة'
        if any(k in nu for k in ('response', 'incident')):
            return '< 4 hours'
        return '≤ 72 hours'
    if t and t != '—' and not _is_formula_like_target(t):
        return t
    return '100%'


def _derive_kpi_formula(name: str, lang: str = 'ar') -> str:
    """PR-CY48/50 — professional calculation expression derived from metric name."""
    n = (name or '').strip()
    if not n or n == '—':
        return ('(المنجز ÷ المخطط) × 100' if lang == 'ar'
                else '(Done ÷ Planned) × 100')
    nu = n.lower()
    if _is_soc_detection_metric(n):
        return (
            '(عدد التنبيهات/التهديدات المكتشفة الصحيحة / '
            'إجمالي التهديدات أو التنبيهات المؤكدة) × 100'
            if lang == 'ar' else
            '(True positive alerts/threats / confirmed alerts or threats) × 100')
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
    if _is_incident_response_metric(n):
        return ('مجموع أزمنة الاستجابة للحوادث الحرجة / عدد الحوادث الحرجة'
                if lang == 'ar' else
                'Sum critical incident response times / critical incident count')
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
    nu = n.lower()
    if _is_soc_detection_metric(n):
        return 'SIEM / SOC / SOAR'
    if _is_incident_response_metric(n):
        return 'ITSM / SOAR / SIEM'
    if _is_time_based_metric(n):
        return 'ITSM / SOAR / SIEM'
    if any(k in nu for k in ('mfa', 'مصادقة')):
        return ('منصة إدارة الهويات IAM' if lang == 'ar'
                else 'IAM / IdP platform')
    if any(k in nu for k in ('ثغر', 'vulnerability', 'vuln')):
        return ('منصة إدارة الثغرات' if lang == 'ar'
                else 'Vulnerability Management platform')
    if any(k in nu for k in ('نسخ', 'backup', 'dr', 'تعاف')):
        return ('منصة النسخ الاحتياطي' if lang == 'ar'
                else 'Backup platform')
    if any(k in nu for k in ('dlp',)):
        return 'DLP / منصة DLP' if lang == 'ar' else 'DLP platform'
    if any(k in nu for k in ('تشفير', 'encrypt')):
        return ('منصة التشفير' if lang == 'ar' else 'Encryption platform')
    if any(k in nu for k in ('تصنيف', 'classification', 'بيانات')):
        return ('منصة تصنيف البيانات' if lang == 'ar'
                else 'Data classification platform')
    table = (
        ('SOC', 'SIEM / SOC / SOAR'), ('SIEM', 'SIEM / SOC / SOAR'),
        ('IAM', 'IAM / PAM'), ('PAM', 'PAM'),
        ('توعية', 'LMS / HR'), ('تدريب', 'LMS / HR'),
        ('phishing', 'Phishing platform'), ('تصيد', 'Phishing platform'),
    )
    for key, tool in table:
        if key in n or key.lower() in nu:
            return tool
    return 'مكتب CISO / نظام الحوكمة' if lang == 'ar' else 'CISO office / GRC'


def _align_kpi_source_with_metric(
        name: str, formula: str, source: str, lang: str = 'ar') -> str:
    """PR-CY57 — align KPI data source with metric semantics."""
    derived = _derive_kpi_source(name, lang)
    s = str(source or '').strip()
    if s in ('—', '-', '--', ''):
        return derived
    if _is_freq_or_timeframe(s):
        return derived
    sl = s.lower()
    n = (name or '').lower()
    f = (formula or '').lower()
    if _is_soc_detection_metric(name):
        if not any(k in sl for k in ('siem', 'soc', 'soar')):
            return derived
    if _is_incident_response_metric(name):
        if not any(k in sl for k in ('itsm', 'soar', 'siem')):
            return derived
    if _is_time_based_metric(name) or any(
            k in f for k in ('حادث', 'incident', 'response', 'استجاب', 'زمن')):
        if any(k in sl for k in ('grc', 'حوكمة', 'ciso office', 'lms', 'hr')):
            return derived
    if any(k in n for k in ('ثغر', 'vulnerability', 'vuln')):
        if any(k in sl for k in ('grc', 'lms', 'hr', 'phishing', 'siem')):
            if 'vulnerability' not in sl and 'ثغر' not in s:
                return derived
    if any(k in n for k in ('توعية', 'awareness', 'تدريب', 'training', 'تصيد')):
        if any(k in sl for k in ('siem', 'soc', 'vulnerability', 'grc')):
            return derived
    if any(k in n for k in ('نسخ', 'backup', 'dr', 'تعاف')):
        if 'backup' not in sl and 'نسخ' not in s and 'dr' not in sl:
            return derived
    return s


def _is_percentage_formula(formula: str) -> bool:
    """PR-CY61 — True when formula computes a percentage rate."""
    f = (formula or '').lower()
    return any(k in f for k in ('× 100', 'x 100', '* 100', '×100', 'x100'))


def _is_time_target(target: str) -> bool:
    """PR-CY61 — True when target expresses duration, not a percentage."""
    t = (target or '').strip().lower()
    if not t or '%' in t:
        return False
    return any(k in t for k in (
        'ساع', 'hour', 'minute', 'دقيقة', 'دقائق', 'min',
        '<', '≤', '>', 'mttr', 'mttd', 'أيام', 'days',
    ))


def _target_repeats_metric_name(name: str, target: str) -> bool:
    """PR-CY61 — target cell echoes the metric name instead of a value."""
    n = (name or '').strip()
    t = (target or '').strip()
    if not n or not t or t in ('—', '-'):
        return False
    if t == n:
        return True
    if len(n) >= 12 and n in t:
        return True
    if len(t) >= 12 and t in n and '%' not in t:
        return True
    return False


def _is_iam_pam_metric(name: str) -> bool:
    n = (name or '').lower()
    return any(k in n for k in (
        'iam', 'pam', 'identity', 'الهوية', 'الوصول المميز', 'privileged',
    ))


def _detect_kpi_metric_family(
        name: str, target: str = '', formula: str = '',
        kpi_type: str = '', lang: str = 'ar') -> str:
    """PR-CY61 — classify KPI row into a semantic family for normalization."""
    n = (name or '').strip()
    nu = n.lower()
    t = (target or '').strip()
    pct = _is_percentage_formula(formula)
    if any(k in nu for k in ('تصيد', 'phishing')):
        if ((kpi_type or '').upper() == 'KRI'
                or '5%' in t or 'أقل' in t or '< 5' in t.lower()
                or 'فشل' in n or 'failure' in nu):
            return 'phishing_failure_kri'
    if _is_iam_pam_metric(n):
        return 'iam_pam_coverage'
    if any(k in nu for k in ('mfa', 'مصادقة متعددة', 'multi-factor')):
        return 'mfa_coverage'
    if _is_incident_detection_metric(n):
        return 'incident_detection_time'
    if any(k in nu for k in ('ثغر', 'vulnerability', 'vuln')):
        return 'vulnerability_sla'
    if _is_incident_response_metric(n) or (
            _is_soc_detection_metric(n) and pct):
        sla_name = any(k in n for k in (
            'ضمن SLA', 'within SLA', 'معالجة الحوادث', 'حل الحوادث',
            'SLA resolution', 'resolution rate'))
        time_name = any(k in n for k in (
            'زمن الاستجابة', 'زمن الاستجاب', 'response time',
            'MTTR', 'MTTD', 'mttr', 'mttd')) or (
            'زمن' in n and not sla_name)
        effectiveness_name = any(k in n for k in (
            'فعالية', 'effectiveness', 'معدل فعالية'))
        if sla_name or (effectiveness_name and pct):
            return 'incident_response_sla'
        if time_name and not (effectiveness_name and pct):
            return 'incident_response_time'
        if pct or ('%' in t and not _is_time_target(t)):
            return 'incident_response_sla'
        if _is_time_target(t) or (_is_time_based_metric(n) and not pct):
            return 'incident_response_time'
        return 'incident_response_sla' if pct else 'incident_response_time'
    if any(k in nu for k in ('نسخ', 'backup', 'dr', 'تعاف')):
        return 'backup_success'
    if any(k in nu for k in (
            'تشفير', 'encrypt', 'dlp', 'بيانات حساسة', 'حماية البيانات',
            'encryption')):
        return 'data_protection_encryption_dlp'
    if any(k in nu for k in (
            'امتثال', 'compliance', 'ecc', 'dcc', 'ضوابط')):
        return 'compliance_ecc_dcc'
    return 'generic_percentage' if pct else 'generic'


def _apply_kpi_metric_family_spec(
        family: str, name: str, kpi_type: str, target: str,
        formula: str, source: str, lang: str = 'ar') -> Tuple[
            str, str, str, str, str]:
    """PR-CY61 — return aligned (name, type, target, formula, source)."""
    n, kt, t, f, s = name, kpi_type, target, formula, source
    ar = lang == 'ar'
    if family == 'incident_response_sla':
        n = ('نسبة معالجة الحوادث الحرجة ضمن SLA' if ar else
             'Critical incident SLA resolution rate')
        kt = 'KPI'
        t = '≥95%'
        f = (('(عدد الحوادث المعالجة ضمن SLA ÷ إجمالي الحوادث) × 100')
             if ar else
             '(Incidents resolved within SLA ÷ total incidents) × 100')
        s = 'ITSM / SOAR / SIEM'
    elif family == 'incident_response_time':
        if ar:
            if any(k in n for k in ('فعالية', 'نسبة', 'معدل')):
                n = 'زمن الاستجابة للحوادث الحرجة'
        else:
            if any(k in n.lower() for k in ('effectiveness', 'rate', '%')):
                n = 'Critical incident response time'
        kt = 'KPI'
        if not _is_time_target(t):
            t = '< 4 ساعات' if ar else '< 4 hours'
        f = (('مجموع أزمنة الاستجابة للحوادث الحرجة / عدد الحوادث الحرجة')
             if ar else
             'Sum critical incident response times / critical incident count')
        s = 'ITSM / SOAR / SIEM'
    elif family == 'incident_detection_time':
        n = ('متوسط زمن اكتشاف الحوادث الأمنية' if ar else
             'Mean time to detect security incidents')
        kt = 'KPI'
        if not _is_time_target(t):
            t = '< 4 ساعات' if ar else '< 4 hours'
        f = (('مجموع أزمنة اكتشاف الحوادث / عدد الحوادث')
             if ar else
             'Sum incident detection times / incident count')
        s = 'SIEM / SOC'
    elif family == 'iam_pam_coverage':
        kt = 'KPI'
        if _target_repeats_metric_name(n, t) or not t or t == '—':
            t = ('≥95% للأنظمة الحرجة أو 100% للحسابات المميزة' if ar else
                 '≥95% critical systems or 100% privileged accounts')
        f = (('(عدد الحسابات أو الأنظمة المغطاة بضوابط IAM/PAM ÷ '
              'إجمالي الحسابات أو الأنظمة المستهدفة) × 100')
             if ar else
             '(IAM/PAM-covered accounts or systems ÷ target accounts or '
             'systems) × 100')
        s = ('منصة إدارة الهويات IAM / PAM' if ar else
             'IAM / PAM platform')
    elif family == 'mfa_coverage':
        kt = 'KPI'
        t = ('100% للحسابات المميزة أو ≥95% للمستخدمين' if ar else
             '100% privileged or ≥95% users')
        f = (('(عدد الحسابات المفعلة عليها MFA ÷ إجمالي الحسابات المستهدفة) '
              '× 100') if ar else
             '(MFA-enabled accounts ÷ target accounts) × 100')
        s = ('منصة إدارة الهويات IAM' if ar else 'IAM / IdP platform')
    elif family == 'vulnerability_sla':
        n = _normalize_kpi_name(n, lang)
        if ar and ('زمن' in n or 'time' in n.lower()):
            n = 'نسبة إغلاق الثغرات الحرجة ضمن SLA'
        elif not ar and 'time' in n.lower():
            n = 'Critical vulnerability SLA closure rate'
        kt = 'KPI'
        if not t or t == '—' or _target_repeats_metric_name(n, t):
            t = '95% خلال 72 ساعة' if ar else '95% within 72 hours'
        f = (('(عدد الثغرات الحرجة المغلقة ضمن SLA ÷ إجمالي الثغرات الحرجة) '
              '× 100') if ar else
             '(SLA-closed critical vulnerabilities ÷ total critical '
             'vulnerabilities) × 100')
        s = ('منصة إدارة الثغرات' if ar else
             'Vulnerability Management platform')
    elif family == 'phishing_failure_kri':
        n = ('معدل فشل اختبارات التصيد الاحتيالي' if ar else
             'Phishing simulation failure rate')
        kt = 'KRI'
        t = 'أقل من 5%' if ar else '< 5%'
        f = (('(عدد الموظفين الذين فشلوا في اختبار التصيد ÷ '
              'إجمالي الموظفين المختبَرين) × 100') if ar else
             '(Employees failing phishing test ÷ employees tested) × 100')
        s = ('منصة محاكاة التصيد' if ar else 'Phishing simulation platform')
    elif family == 'backup_success':
        kt = 'KPI'
        t = '≥99%'
        f = (('(عدد عمليات النسخ الناجحة ÷ إجمالي عمليات النسخ) × 100')
             if ar else
             '(Successful backups ÷ total backup operations) × 100')
        s = ('منصة النسخ الاحتياطي' if ar else 'Backup platform')
    elif family == 'data_protection_encryption_dlp':
        kt = 'KPI'
        t = ('≥95% أو 100% للبيانات الحساسة المصنفة' if ar else
             '≥95% or 100% classified sensitive data')
        f = (('(عدد الأصول أو البيانات الحساسة المحمية بالتشفير وDLP ÷ '
              'إجمالي الأصول أو البيانات الحساسة المستهدفة) × 100')
             if ar else
             '(Sensitive assets/data protected by encryption and DLP ÷ '
             'target sensitive assets/data) × 100')
        s = ('منصة التشفير / DLP / منصة تصنيف البيانات' if ar else
             'Encryption / DLP / data classification platform')
    elif family == 'compliance_ecc_dcc':
        kt = 'KPI'
        if not t or t == '—':
            t = '≥90%'
        f = (('(عدد الضوابط المحققة ÷ إجمالي الضوابط المستهدفة) × 100')
             if ar else
             '(Controls achieved ÷ target controls) × 100')
        s = ('منصة الحوكمة وقياس الامتثال' if ar else
             'GRC / compliance platform')
    return n, kt, t, f, s


def _normalize_kpi_semantic_row(
        name: str, kpi_type: str, target: str, formula: str,
        source: str, lang: str = 'ar') -> Tuple[
            str, str, str, str, str, str]:
    """PR-CY61 — align KPI name/type/target/formula/source to one family."""
    family = _detect_kpi_metric_family(
        name, target, formula, kpi_type, lang)
    if family in (
            'incident_response_sla', 'incident_response_time',
            'incident_detection_time',
            'iam_pam_coverage', 'mfa_coverage', 'vulnerability_sla',
            'phishing_failure_kri', 'backup_success',
            'data_protection_encryption_dlp', 'compliance_ecc_dcc',
    ):
        name, kpi_type, target, formula, source = _apply_kpi_metric_family_spec(
            family, name, kpi_type, target, formula, source, lang)
    else:
        name = _normalize_kpi_name(name, lang)
        if _is_formula_like_target(target) or _target_repeats_metric_name(
                name, target):
            target = _derive_kpi_target(name, '', lang)
        elif not target or target == '—':
            target = _derive_kpi_target(name, target, lang)
        if (not formula or formula == '—'
                or _is_freq_or_timeframe(formula)
                or _is_formula_echo(formula, name)):
            formula = _derive_kpi_formula(name, lang)
        name = _align_kpi_name_with_formula(name, formula, lang)
        source = _align_kpi_source_with_metric(name, formula, source, lang)
        if source == '—' or _is_freq_or_timeframe(source):
            source = _derive_kpi_source(name, lang)
        kpi_type = _derive_kpi_type(name, kpi_type, lang)
    return name, kpi_type, target, formula, source, family


def _kpi_metric_semantics_row_issue(
        name: str, kpi_type: str, target: str, formula: str,
        source: str, lang: str = 'ar',
        row_index: int = 0) -> Optional[Dict[str, Any]]:
    """PR-CY61 — return issue dict when row fails semantic gate, else None."""
    family = _detect_kpi_metric_family(
        name, target, formula, kpi_type, lang)
    reason = ''
    if _is_time_based_metric(name) and '%' in str(target):
        reason = 'time_metric_percentage_target'
    elif _is_time_based_metric(name) and _is_percentage_formula(formula):
        reason = 'time_metric_percentage_formula'
    elif any(k in (name or '') for k in ('ثغر', 'vulnerability')) and any(
            k in str(formula) for k in ('حادث', 'incident')):
        reason = 'vulnerability_incident_formula_mix'
    elif not kpi_name_formula_aligned(name, formula, lang):
        reason = 'name_formula_mismatch'
    elif _is_incident_detection_metric(name):
        if any(k in str(formula) for k in (
                'استجاب', 'response', 'critical incident response',
                'الاستجابة')):
            reason = 'detection_response_formula_mix'
    elif _is_soc_detection_metric(name):
        if any(k in str(formula) for k in (
                'حادث', 'incident', 'response', 'استجاب', 'زمن')):
            reason = 'soc_detection_incident_formula_mix'
    elif _target_repeats_metric_name(name, target):
        reason = 'target_repeats_metric_name'
    elif family == 'incident_response_time' and _is_percentage_formula(formula):
        reason = 'incident_time_percentage_formula'
    elif family == 'vulnerability_sla' and 'زمن' in (name or ''):
        reason = 'vulnerability_time_name_percentage_formula'
    elif family == 'phishing_failure_kri':
        if (kpi_type or '').upper() != 'KRI':
            reason = 'phishing_kri_type_mismatch'
        elif any(k in (name or '') for k in (
                'فعالية', 'awareness', 'وعي')):
            reason = 'phishing_awareness_not_failure_wording'
    if not reason:
        return None
    nn, nt, ntar, nform, nsrc, _ = _normalize_kpi_semantic_row(
        name, kpi_type, target, formula, source, lang)
    return {
        'row_index': row_index,
        'metric_name': name,
        'metric_type': kpi_type,
        'target': target,
        'formula': formula,
        'source': source,
        'detected_family': family,
        'reason': reason,
        'normalized_name': nn,
        'normalized_target': ntar,
        'normalized_formula': nform,
        'normalized_source': nsrc,
    }


def collect_kpi_metric_semantics_issues(
        model: Optional[Dict[str, Any]], lang: str = 'ar') -> List[Dict[str, Any]]:
    """PR-CY61 — invalid KPI rows for gate + diagnostics."""
    blocks = (model or {}).get('blocks') or {}
    kpi_blk = blocks.get('kpi_kri_framework') or {}
    tables = kpi_blk.get('tables') or []
    main_tbl = formula_tbl = None
    for tbl in tables:
        if tbl.get('schema') == 'kpi_main':
            main_tbl = tbl
        elif tbl.get('schema') == 'kpi_formula':
            formula_tbl = tbl
    if not main_tbl:
        return []
    formula_by_idx: Dict[str, List[str]] = {}
    for fr in (formula_tbl or {}).get('rows') or []:
        if fr:
            formula_by_idx[str(fr[0])] = list(fr)
    issues: List[Dict[str, Any]] = []
    for ri, mr in enumerate(main_tbl.get('rows') or []):
        idx = str(mr[0] if mr else ri + 1)
        name = mr[1] if len(mr) > 1 else ''
        kpi_type = mr[2] if len(mr) > 2 else ''
        target = mr[3] if len(mr) > 3 else ''
        fr = formula_by_idx.get(idx, [])
        formula = fr[2] if len(fr) > 2 else ''
        source = fr[3] if len(fr) > 3 else ''
        issue = _kpi_metric_semantics_row_issue(
            name, kpi_type, target, formula, source, lang, row_index=ri)
        if issue:
            issues.append(issue)
    return issues


def build_kpi_metric_semantics_diag(
        model: Optional[Dict[str, Any]], lang: str = 'ar',
        *, action_taken: str = '') -> Dict[str, Any]:
    """PR-CY61 — [KPI-METRIC-SEMANTICS-DIAG] payload."""
    issues = collect_kpi_metric_semantics_issues(model, lang)
    return {
        'invalid_rows': len(issues),
        'issues': issues,
        'action_taken': action_taken or (
            'validated' if not issues else 'violations_remain'),
    }


def emit_kpi_metric_semantics_diag(
        model: Optional[Dict[str, Any]], lang: str = 'ar',
        *, action_taken: str = '') -> Dict[str, Any]:
    """Emit [KPI-METRIC-SEMANTICS-DIAG] to server logs."""
    issues = collect_kpi_metric_semantics_issues(model, lang)
    payload = {
        'invalid_rows': len(issues),
        'action_taken': action_taken or (
            'validated' if not issues else 'violations_remain'),
    }
    for iss in issues:
        payload.setdefault('bad_text_samples', []).append(
            iss.get('metric_name'))
    for iss in issues:
        for key in (
                'row_index', 'metric_name', 'metric_type', 'target',
                'formula', 'source', 'detected_family', 'reason',
                'normalized_name', 'normalized_target', 'normalized_formula',
                'normalized_source'):
            if key in iss:
                payload[f'row_{iss["row_index"]}_{key}'] = iss[key]
    if issues:
        first = issues[0]
        payload.update({
            'row_index': first.get('row_index'),
            'metric_name': first.get('metric_name'),
            'metric_type': first.get('metric_type'),
            'target': first.get('target'),
            'formula': first.get('formula'),
            'source': first.get('source'),
            'detected_family': first.get('detected_family'),
            'reason': first.get('reason'),
            'normalized_name': first.get('normalized_name'),
            'normalized_target': first.get('normalized_target'),
            'normalized_formula': first.get('normalized_formula'),
            'normalized_source': first.get('normalized_source'),
        })
    try:
        print(f'[KPI-METRIC-SEMANTICS-DIAG] {payload}', flush=True)
    except Exception:  # noqa: BLE001
        pass
    return payload


def _normalize_kpi_tables_semantics(
        blocks: Dict[str, Any], lang: str = 'ar') -> Dict[str, Any]:
    """PR-CY61 — repair KPI main + formula tables before quality gates."""
    kpi_blk = blocks.get('kpi_kri_framework') or {}
    tables = kpi_blk.get('tables') or []
    main_tbl = formula_tbl = None
    for tbl in tables:
        if tbl.get('schema') == 'kpi_main':
            main_tbl = tbl
        elif tbl.get('schema') == 'kpi_formula':
            formula_tbl = tbl
    if not main_tbl:
        return blocks
    formula_by_idx: Dict[str, List[str]] = {}
    for fr in (formula_tbl or {}).get('rows') or []:
        if fr:
            formula_by_idx[str(fr[0])] = list(fr)
    new_main: List[List[str]] = []
    new_formula: List[List[str]] = []
    for mr in main_tbl.get('rows') or []:
        idx = str(mr[0] if mr else len(new_main) + 1)
        name = mr[1] if len(mr) > 1 else ''
        kpi_type = mr[2] if len(mr) > 2 else ''
        target = mr[3] if len(mr) > 3 else ''
        fr = formula_by_idx.get(idx, [])
        formula = fr[2] if len(fr) > 2 else ''
        source = fr[3] if len(fr) > 3 else ''
        name, kpi_type, target, formula, source, _fam = (
            _normalize_kpi_semantic_row(
                name, kpi_type, target, formula, source, lang))
        tail = list(mr[4:]) if len(mr) > 4 else []
        new_main.append([idx, name, kpi_type, target] + tail)
        new_formula.append([idx, name, formula, source])
    main_tbl['rows'] = new_main
    if formula_tbl:
        formula_tbl['rows'] = new_formula
    elif new_formula:
        hdr = list(SCHEMA_KPI_FORMULA_AR if lang == 'ar' else (
            '#', 'Indicator', 'Formula', 'Data Source'))
        tables.append({
            'schema': 'kpi_formula', 'header': hdr, 'rows': new_formula})
    kpi_blk['tables'] = tables
    blocks['kpi_kri_framework'] = kpi_blk
    return blocks


def kpi_formula_source_row_valid(
        name: str, formula: str, source: str, lang: str = 'ar') -> bool:
    """PR-CY58 — KPI formula/source row passes detail-table gate."""
    if _is_freq_or_timeframe(formula) or _is_freq_or_timeframe(source):
        return False
    if _is_formula_echo(formula, name):
        return False
    if _is_soc_detection_metric(name):
        f = (formula or '').lower()
        if any(k in f for k in ('حادث', 'incident', 'response', 'استجاب')):
            return False
    return True


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
            idx = _cell(r, i_idx, str(n)) if i_idx >= 0 else str(n)
            name = _cell(r, i_name if i_name >= 0 else 1)
            if not name or name == '—':
                continue
            kpi_type = _cell(r, i_type, '')
            target = _cell(r, i_target)
            formula = _cell(r, i_formula) if i_formula >= 0 else '—'
            source = _cell(r, i_source) if i_source >= 0 else '—'
            name, kpi_type, target, formula, source, _fam = (
                _normalize_kpi_semantic_row(
                    name, kpi_type, target, formula, source, lang))
            main_rows.append([
                idx, name, kpi_type, target,
                _cell(r, i_freq),
                _cell(r, i_owner, 'CISO'),
                _cell(r, i_horizon),
            ])
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

# PR-CY55 — reversed Arabic label fragments from broken Bidi confidence cards.
REVERSED_CONFIDENCE_LABEL_FRAGMENTS = (
    'ةمهاسملا', 'ةجردلا', 'نزولا', 'لماعلا',
)

# PR-CY55 — TOC section keys that must appear in professional exports.
PROFESSIONAL_TOC_SECTION_KEYS = (
    'executive_summary', 'scope_frameworks', 'methodology',
    'governance_ownership', 'traceability_matrix', 'appendices',
)

# PR-CY55 — canonical TOC labels (matches ``_STRATEGY_DOC_SECTION_LABELS``).
_PROFESSIONAL_TOC_LABELS: Tuple[Tuple[str, str, str], ...] = (
    ('executive_summary', 'الملخص التنفيذي', 'Executive Summary'),
    ('scope_frameworks', 'النطاق والأطر المرجعية المعتمدة',
     'Scope and Selected Frameworks'),
    ('methodology', 'المنهجية', 'Methodology'),
    ('current_state', 'ملخص الوضع الراهن ومستوى النضج',
     'Current-State and Maturity Summary'),
    ('vision_objectives', 'الرؤية والأهداف الاستراتيجية',
     'Strategic Vision and Objectives'),
    ('strategic_pillars', 'الركائز الاستراتيجية', 'Strategic Pillars'),
    ('environment_context', 'البيئة التنظيمية والتهديدات',
     'Regulatory Environment and Threat Landscape'),
    ('gap_analysis', 'تحليل الفجوات', 'Gap Analysis'),
    ('roadmap', 'خارطة الطريق التنفيذية', 'Implementation Roadmap'),
    ('kpi_kri_framework', 'مؤشرات الأداء الرئيسية', 'KPI / KRI Framework'),
    ('confidence_risk_register', 'تقييم الثقة والمخاطر',
     'Confidence Score and Risk Register'),
    ('governance_ownership', 'نموذج الحوكمة والمسؤوليات',
     'Governance and Ownership Model'),
    ('traceability_matrix', 'مصفوفة تتبع الأطر المرجعية',
     'Framework Traceability Matrix'),
    ('appendices', 'الملاحق', 'Appendices'),
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
    'pdf_arabic_spacing_final_cleanup_passed',
    'pdf_objectives_readable_layout_applied',
    'pdf_pillars_no_duplicate_initiative_rendering',
    'pdf_dense_table_polish_passed',
    'gap_guide_header_final_clean',
    'pdf_gap_headers_clean',
    'roadmap_framework_mapping_valid',
    'pdf_roadmap_cell_density_valid',
    'kpi_metric_semantics_valid',
    'pdf_kpi_type_column_valid',
    'confidence_table_layout_valid',
    'pdf_confidence_factor_labels_intact',
    'pdf_table_layout_profiles_applied',
    'pdf_confidence_factor_layout_valid',
    'pdf_governance_split_if_wide',
    'pdf_roadmap_generic_rows_absent',
    'pdf_kpi_target_column_valid',
    'pdf_table_vertical_stack_warnings',
    'preview_pdf_docx_parity_passed',
    'docx_toc_professional_sections',
    'pdf_confidence_card_labels_readable',
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
    if (subgate in (
            'final_table_cell_arabic_cleanup_passed',
            'arabic_spacing_final_passed',
            'final_arabic_spacing_pdf_passed',
    ) and model is not None):
        payload['arabic_final_cleanup_diag'] = build_arabic_final_cleanup_diag(
            model, output_type=output_type,
            lang=(model or {}).get('lang') or 'ar')
    if (subgate == 'roadmap_framework_mapping_valid'
            and model is not None):
        try:
            violations = collect_roadmap_framework_violations(
                get_roadmap_spec_rows(model),
                (model or {}).get('lang') or 'ar',
                get_roadmap_row_meta(model))
            if violations:
                payload['roadmap_framework_violations'] = violations
        except Exception:
            pass
    if (subgate == 'kpi_metric_semantics_valid' and model is not None):
        payload['kpi_metric_semantics_diag'] = build_kpi_metric_semantics_diag(
            model, lang=(model or {}).get('lang') or 'ar')
    return payload


def emit_docmodel_professional_failure(**kwargs) -> Dict[str, Any]:
    """Emit [DOCMODEL-PROFESSIONAL-FAILURE] to server logs."""
    payload = build_docmodel_professional_failure_diag(**kwargs)
    try:
        print(f'[DOCMODEL-PROFESSIONAL-FAILURE] {payload}', flush=True)
    except Exception:  # noqa: BLE001
        pass
    _subgate = payload.get('failing_subgate') or ''
    if _subgate in (
            'final_table_cell_arabic_cleanup_passed',
            'arabic_spacing_final_passed',
            'final_arabic_spacing_pdf_passed'):
        emit_arabic_final_cleanup_diag(
            kwargs.get('model'),
            output_type=kwargs.get('output_type') or '',
            lang=((kwargs.get('model') or {}).get('lang') or 'ar'))
    if _subgate == 'kpi_metric_semantics_valid':
        emit_kpi_metric_semantics_diag(
            kwargs.get('model'),
            lang=((kwargs.get('model') or {}).get('lang') or 'ar'),
            action_taken='gate_failed')
    return payload

# Heading-residue / separator detectors.
PRCY47_HEADING_RESIDUE_RE = re.compile(r'(?m)^\s*#{1,6}\s*\.?\d*[\s\.\)]*')
PRCY47_TABLE_SEP_RE = re.compile(r'(?m)^\s*\|?\s*:?-{2,}.*$')
PRCY47_GUIDE_HEADER_RE = re.compile(r'####\s*دليل\s*تنفيذ', re.IGNORECASE)
# Avoid matching ``مسؤول ال`` inside ``المسؤول التنفيذي`` (``ال`` starts ``التنفيذ``).
PRCY47_MASOUL_AL_FRAGMENT_RE = re.compile(r'مسؤول ال(?!ت)')


def prcy47_fix_ar_fragments(text: str) -> str:
    """Repair split Arabic word fragments (e.g. ``طوة الخ`` → ``الخطوة``)."""
    out = text or ''
    for bad, good in PRCY47_AR_FRAGMENT_FIXES:
        if bad == 'مسؤول ال':
            out = PRCY47_MASOUL_AL_FRAGMENT_RE.sub(good, out)
        elif bad in out:
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
        out = normalize_arabic_for_render(out)
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


CANONICAL_CYBER_EXEC_PRIORITIES_AR = (
    'حوكمة الأمن السيبراني',
    'حماية البيانات والامتثال',
    'SOC/SIEM والمراقبة',
    'IAM/PAM/MFA',
    'إدارة الثغرات والاستجابة',
)
CANONICAL_CYBER_EXEC_PRIORITIES_EN = (
    'Cybersecurity governance',
    'Data protection & compliance',
    'SOC/SIEM monitoring',
    'IAM/PAM/MFA',
    'Vulnerability management & response',
)
CANONICAL_CYBER_EXEC_RISKS_AR = (
    'اختراق البيانات الحساسة',
    'فشل الامتثال التنظيمي',
    'تعطل الخدمات الحيوية',
)
CANONICAL_CYBER_EXEC_RISKS_EN = (
    'Sensitive data breach',
    'Regulatory non-compliance',
    'Critical service outage',
)
_RISK_HEADER_TOKENS = frozenset({
    'الخطر', 'المخاطر', 'Risk', 'risk', '#', 'م', '—',
})


def _derive_executive_priorities(
        content_sections: Dict[str, str],
        metadata: Dict[str, Any],
        lang: str = 'ar') -> List[str]:
    """PR-CY57 — fill executive-summary priorities from themes, roadmap, pillars."""
    seen: set = set()
    out: List[str] = []
    for t in (metadata or {}).get('mandatory_themes', []):
        label = prcy47_fix_ar_fragments(str(t).strip())
        if label and label not in seen:
            seen.add(label)
            out.append(label)
    roadmap_text = (content_sections or {}).get('roadmap', '') or ''
    for tbl in parse_markdown_tables(roadmap_text):
        if len(tbl) < 2:
            continue
        hdr = tbl[0]
        i_init = _col_index(hdr, (
            'النشاط', 'المبادرة', 'initiative', 'activity', 'البرنامج'))
        col = i_init if i_init >= 0 else (
            2 if len(tbl[1]) > 2 else 1)
        for r in tbl[1:]:
            init = prcy47_fix_ar_fragments(_cell(r, col, ''))
            if init and init not in seen and init not in _RISK_HEADER_TOKENS:
                seen.add(init)
                out.append(init[:80])
    pillars_text = (content_sections or {}).get('pillars', '') or ''
    for ln in pillars_text.split('\n'):
        s = ln.strip()
        if not s.startswith('|'):
            continue
        cells = [c.strip() for c in s.strip('|').split('|')]
        if len(cells) >= 2 and cells[1] and cells[1] not in (
                '#', 'العمود', 'Pillar', '—'):
            label = prcy47_fix_ar_fragments(cells[1])
            if label not in seen:
                seen.add(label)
                out.append(label[:80])
    defaults = (CANONICAL_CYBER_EXEC_PRIORITIES_AR if lang == 'ar'
                else CANONICAL_CYBER_EXEC_PRIORITIES_EN)
    if len(out) < 3:
        for d in defaults:
            if d not in seen and len(out) < 5:
                seen.add(d)
                out.append(d)
    return out[:5]


def _derive_executive_risks(conf_text: str, lang: str = 'ar') -> List[str]:
    """PR-CY57 — extract risk register rows for executive summary."""
    risks: List[str] = []
    for tbl in parse_markdown_tables(conf_text or ''):
        if len(tbl) < 2:
            continue
        hdr = tbl[0]
        hdr_blob = ' '.join(hdr)
        if 'نجاح' in hdr_blob:
            continue
        i_risk = _col_index(hdr, ('الخطر', 'المخاطر', 'risk'))
        if i_risk < 0:
            continue
        for r in tbl[1:]:
            risk = prcy47_fix_ar_fragments(_cell(r, i_risk, ''))
            if risk and risk not in _RISK_HEADER_TOKENS and not risk.isdigit():
                risks.append(risk[:80])
    if not risks:
        for ln in (conf_text or '').split('\n'):
            s = ln.strip()
            if not s.startswith('|'):
                continue
            cells = [c.strip() for c in s.strip('|').split('|')]
            if len(cells) < 3:
                continue
            candidate = cells[2] if cells[0].isdigit() or cells[1].isdigit() else cells[1]
            if candidate and candidate not in _RISK_HEADER_TOKENS:
                risks.append(prcy47_fix_ar_fragments(candidate)[:80])
    if not risks:
        defaults = (CANONICAL_CYBER_EXEC_RISKS_AR if lang == 'ar'
                    else CANONICAL_CYBER_EXEC_RISKS_EN)
        risks = list(defaults)
    return [r for r in risks if r][:5]


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
    key_risks = _derive_executive_risks(conf_text, lang_n)
    priorities = _derive_executive_priorities(
        content_sections, metadata, lang_n)
    grid = {
        'purpose': paras[0] if paras else '',
        'frameworks': fw_labels,
        'priorities': priorities,
        'top_gaps': gap_top5,
        'horizon': (metadata or {}).get('horizon_months') or '24',
        'confidence_score': conf_score,
        'key_risks': key_risks,
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
        _rows, _meta = build_roadmap_render_spec(_seed, lang_n)
        road_tbl = {
            'schema': 'roadmap',
            'header': _road_schema,
            'rows': _rows,
            'row_meta': _meta,
        }
    road_tbl = _sanitize_table_spec(road_tbl, lang_n) or road_tbl
    emit_roadmap_framework_mapping_diag(
        {'blocks': {**blocks, 'roadmap': {'tables': [road_tbl]}}},
        lang_n)
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
    blocks = sync_professional_toc_entries(blocks, lang_n)
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
        lang_n = 'ar' if (lang or '').lower() in ('ar', 'arabic') else 'en'
        blocks = deepcopy(model.get('blocks') or {})
        blocks = _normalize_kpi_tables_semantics(blocks, lang_n)
        blocks = apply_final_arabic_cleanup_to_blocks(blocks, lang_n)
        return {**model, 'blocks': blocks}
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


def kpi_target_column_valid(kpi_main: List[Dict[str, Any]]) -> bool:
    """PR-CY53 — KPI summary target column must not contain formula text."""
    for t in kpi_main or []:
        for r in t.get('rows') or []:
            target = str(r[3] if len(r) > 3 else '').strip()
            if _is_formula_like_target(target):
                return False
            if not target or target in ('—', '-', '--', '–'):
                return False
    return True


def governance_pdf_split_valid(blocks: Dict[str, Any]) -> bool:
    """PR-CY53 — wide governance tables must be splittable (5 cols → 3+2)."""
    gov = blocks.get('governance_ownership') or {}
    rows = gov.get('rows') or []
    if not rows:
        return True
    max_cols = max((len(r) for r in rows), default=0)
    if max_cols <= 4:
        return True
    prof = get_pdf_table_layout_profile('governance', max_cols)
    return bool(prof.get('split_if_wide'))


def pdf_confidence_factor_layout_valid(
        conf_factor_tbl: List[Dict[str, Any]]) -> bool:
    """PR-CY53 — confidence factors use card layout; labels intact."""
    if not conf_factor_tbl:
        return True
    prof = get_pdf_table_layout_profile('conf_factor', 4)
    if prof.get('render_mode') != 'cards':
        return False
    return confidence_factor_labels_intact(conf_factor_tbl)


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
            if not kpi_formula_source_row_valid(name, formula, source, lang):
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
    _roadmap_violations = collect_roadmap_framework_violations(
        road_rows, lang, get_roadmap_row_meta(model))
    roadmap_framework_mapping_valid = not _roadmap_violations

    kpi_sem_issues = collect_kpi_metric_semantics_issues(model, lang)
    kpi_metric_semantics_valid = not kpi_sem_issues
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

    # PR-CY53 — PDF table layout hardening gates.
    pdf_table_layout_profiles_applied_val = pdf_table_layout_profiles_applied(
        model)
    pdf_confidence_factor_layout_valid_val = (
        pdf_confidence_factor_layout_valid(conf_factor_tbl))
    pdf_governance_split_if_wide_val = governance_pdf_split_valid(blocks)
    pdf_roadmap_generic_rows_absent_val = roadmap_generic_rows_absent(
        road_rows)
    pdf_kpi_target_column_valid_val = kpi_target_column_valid(kpi_main)
    _export_fallbacks = compute_pdf_export_layout_fallbacks(model, lang)
    _stack_eval = evaluate_vertical_stack_gate(
        model, fallbacks=_export_fallbacks)
    _stack_warnings = _stack_eval['table_vertical_stack_warnings']
    pdf_table_vertical_stack_warnings_val = (
        _stack_eval['pdf_table_vertical_stack_warnings'])

    # PR-CY55 — TOC parity and confidence card label readability.
    docx_toc_professional_sections = professional_toc_includes_required_sections(
        model, lang)
    _conf_card_blob = ' '.join(
        str(c) for t in conf_factor_tbl for r in (t.get('rows') or [])
        for c in r)
    pdf_confidence_card_labels_readable_val = pdf_confidence_card_labels_readable(
        _conf_card_blob)

    # PR-CY62 — final PDF visual polish gates.
    pdf_arabic_spacing_final_cleanup_passed_val = (
        pdf_arabic_spacing_final_cleanup_passed(model, lang))
    pdf_objectives_readable_layout_applied_val = (
        pdf_objectives_readable_layout_applied(model, lang))
    pdf_pillars_no_duplicate_initiative_rendering_val = (
        pdf_pillars_no_duplicate_initiative_rendering(model, lang))
    pdf_dense_table_polish_passed_val = pdf_dense_table_polish_passed(
        model, lang)

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
        and pdf_table_layout_profiles_applied_val
        and pdf_confidence_factor_layout_valid_val
        and pdf_governance_split_if_wide_val
        and pdf_roadmap_generic_rows_absent_val
        and pdf_kpi_target_column_valid_val
        and pdf_table_vertical_stack_warnings_val
        and preview_pdf_docx_parity_passed
        and docx_toc_professional_sections
        and pdf_confidence_card_labels_readable_val
        and pdf_arabic_spacing_final_cleanup_passed_val
        and pdf_objectives_readable_layout_applied_val
        and pdf_pillars_no_duplicate_initiative_rendering_val
        and pdf_dense_table_polish_passed_val)

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
        'roadmap_framework_violations': _roadmap_violations,
        'kpi_metric_semantics_valid': kpi_metric_semantics_valid,
        'confidence_table_layout_valid': confidence_table_layout_valid,
        'preview_pdf_docx_parity_passed': preview_pdf_docx_parity_passed,
        'pdf_gap_headers_clean': pdf_gap_headers_clean_val,
        'pdf_confidence_factor_labels_intact': (
            pdf_confidence_factor_labels_intact),
        'pdf_roadmap_cell_density_valid': pdf_roadmap_cell_density_valid,
        'pdf_kpi_type_column_valid': pdf_kpi_type_column_valid,
        'final_arabic_spacing_pdf_passed': final_arabic_spacing_pdf_passed,
        'pdf_table_layout_profiles_applied': (
            pdf_table_layout_profiles_applied_val),
        'pdf_confidence_factor_layout_valid': (
            pdf_confidence_factor_layout_valid_val),
        'pdf_governance_split_if_wide': pdf_governance_split_if_wide_val,
        'pdf_roadmap_generic_rows_absent': pdf_roadmap_generic_rows_absent_val,
        'pdf_kpi_target_column_valid': pdf_kpi_target_column_valid_val,
        'pdf_table_vertical_stack_warnings': (
            pdf_table_vertical_stack_warnings_val),
        'table_vertical_stack_warnings': _stack_warnings,
        'table_vertical_stack_warning_count': len(_stack_warnings),
        'fallback_applied_by_schema': _stack_eval.get(
            'fallback_applied_by_schema') or {},
        'schemas_with_stack_warnings': _stack_eval.get(
            'schemas_with_warnings') or [],
        'vertical_stack_count_list_consistent': _stack_eval.get(
            'count_list_consistent', True),
        'docx_toc_professional_sections': docx_toc_professional_sections,
        'pdf_confidence_card_labels_readable': (
            pdf_confidence_card_labels_readable_val),
        'pdf_arabic_spacing_final_cleanup_passed': (
            pdf_arabic_spacing_final_cleanup_passed_val),
        'pdf_objectives_readable_layout_applied': (
            pdf_objectives_readable_layout_applied_val),
        'pdf_pillars_no_duplicate_initiative_rendering': (
            pdf_pillars_no_duplicate_initiative_rendering_val),
        'pdf_dense_table_polish_passed': pdf_dense_table_polish_passed_val,
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
        _fb = compute_pdf_export_layout_fallbacks(model, lang)
        stack_eval = evaluate_vertical_stack_gate(model, fallbacks=_fb)
        payload.update(docchecks)
        payload['pdf_final_polish_diag'] = build_pdf_final_polish_diag(
            model, lang, action_taken='pdf_quality_gate_evaluated')
        emit_pdf_final_polish_diag(
            model, lang, action_taken='pdf_quality_gate_evaluated')
        # PR-CY54 — authoritative warnings list; count must equal len(list).
        payload['table_vertical_stack_warnings'] = list(
            docchecks.get('table_vertical_stack_warnings') or [])
        payload['table_vertical_stack_warning_count'] = len(
            payload['table_vertical_stack_warnings'])
        tracker.table_vertical_stack_warnings = list(
            payload['table_vertical_stack_warnings'])

        _count_list_diverged = (
            payload['table_vertical_stack_warning_count']
            != len(payload['table_vertical_stack_warnings']))
        _empty_list_with_count = (
            payload['table_vertical_stack_warning_count'] > 0
            and not payload['table_vertical_stack_warnings'])
        _stack_diag_inconsistent = (
            _count_list_diverged or _empty_list_with_count)
        if _stack_diag_inconsistent:
            try:
                print(
                    '[PDF-VERTICAL-STACK-DIAG] '
                    'pdf_render_failed:diagnostic_inconsistent:'
                    'vertical_stack_count_without_details',
                    flush=True)
            except Exception:  # noqa: BLE001
                pass
            payload['vertical_stack_diagnostic_inconsistent'] = True
            payload['pdf_table_vertical_stack_warnings'] = True
            payload['table_vertical_stack_warning_count'] = len(
                payload['table_vertical_stack_warnings'])

        _gate_blocked = not docchecks.get('docmodel_professional_passed')
        if _stack_diag_inconsistent and _gate_blocked:
            if identify_docmodel_failing_subgate(docchecks) == (
                    'pdf_table_vertical_stack_warnings'):
                _gate_blocked = False
        emit_pdf_vertical_stack_diag(
            stack_eval,
            gate_blocked=_gate_blocked,
            action_taken='pdf_quality_gate_evaluated')

        if not docchecks['docmodel_professional_passed']:
            _subgate = identify_docmodel_failing_subgate(docchecks)
            if (_subgate == 'pdf_table_vertical_stack_warnings'
                    and _stack_diag_inconsistent):
                pass  # PR-CY54 — do not block on empty warning list.
            else:
                _suffix = subgate_to_failure_suffix(_subgate)
                tracker.blockers.append(
                    f'pdf_render_failed:docmodel_professional_quality:'
                    f'{_suffix}')
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
