"""REL3.2 — strict schema-key table binding for strategy tables (RTL-safe)."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

ColumnSpec = Dict[str, Any]

REL32_TABLE_SCHEMAS: Dict[str, Dict[str, Any]] = {
    'strategic_objectives': {
        'table_id': 'strategic_objectives',
        'section_title_ar': 'الرؤية والأهداف الاستراتيجية',
        'columns': (
            {'key': 'row_num', 'label_ar': '#', 'label_en': '#',
             'keywords': ('#', 'م', 'no')},
            {'key': 'objective', 'label_ar': 'الهدف الاستراتيجي',
             'label_en': 'Strategic Objective',
             'keywords': ('الهدف', 'objective', 'goal')},
            {'key': 'target', 'label_ar': 'المستهدف القابل للقياس',
             'label_en': 'Measurable Target',
             'keywords': ('مستهدف', 'target', 'metric')},
            {'key': 'rationale', 'label_ar': 'المبرر', 'label_en': 'Rationale',
             'keywords': ('مبرر', 'justification', 'rationale')},
            {'key': 'timeframe', 'label_ar': 'الإطار الزمني',
             'label_en': 'Timeframe',
             'keywords': ('زمن', 'timeframe', 'period', 'الإطار')},
        ),
    },
    'pillar_initiatives': {
        'table_id': 'pillar_initiatives',
        'section_title_ar': 'الركائز الاستراتيجية',
        'columns': (
            {'key': 'initiative', 'label_ar': 'المبادرة', 'label_en': 'Initiative',
             'keywords': ('مبادرة', 'initiative')},
            {'key': 'description', 'label_ar': 'الوصف', 'label_en': 'Description',
             'keywords': ('وصف', 'description')},
            {'key': 'deliverable', 'label_ar': 'المخرج المتوقع',
             'label_en': 'Expected Deliverable',
             'keywords': ('مخرج', 'deliverable', 'output')},
            {'key': 'owner', 'label_ar': 'المسؤول', 'label_en': 'Owner',
             'keywords': ('مسؤول', 'مالك', 'owner', 'responsible')},
        ),
    },
    'gap_main': {
        'table_id': 'gap_main',
        'section_title_ar': 'تحليل الفجوات',
        'columns': (
            {'key': 'row_num', 'label_ar': '#', 'label_en': '#',
             'keywords': ('#', 'م')},
            {'key': 'gap', 'label_ar': 'الفجوة', 'label_en': 'Gap',
             'keywords': ('فجوة', 'gap')},
            {'key': 'description', 'label_ar': 'الوصف', 'label_en': 'Description',
             'keywords': ('وصف', 'description')},
            {'key': 'priority', 'label_ar': 'الأولوية', 'label_en': 'Priority',
             'keywords': ('أولوية', 'priority')},
            {'key': 'status', 'label_ar': 'الحالة', 'label_en': 'Status',
             'keywords': ('حالة', 'status')},
        ),
    },
    'gap_action': {
        'table_id': 'gap_action',
        'section_title_ar': 'أدلة تطبيق الفجوات',
        'columns': (
            {'key': 'step', 'label_ar': 'الخطوة', 'label_en': 'Step',
             'keywords': ('خطوة', 'step')},
            {'key': 'action', 'label_ar': 'الإجراء', 'label_en': 'Action',
             'keywords': ('إجراء', 'action')},
            {'key': 'owner', 'label_ar': 'المسؤول', 'label_en': 'Owner',
             'keywords': ('مسؤول', 'مالك', 'owner')},
            {'key': 'timeframe', 'label_ar': 'الإطار الزمني',
             'label_en': 'Timeframe',
             'keywords': ('زمن', 'timeframe', 'period', 'الإطار')},
            {'key': 'output', 'label_ar': 'الناتج', 'label_en': 'Output',
             'keywords': ('ناتج', 'output', 'deliverable', 'مخرج')},
        ),
    },
    'roadmap': {
        'table_id': 'roadmap',
        'section_title_ar': 'خارطة الطريق التنفيذية',
        'columns': (
            {'key': 'phase', 'label_ar': 'المرحلة', 'label_en': 'Phase',
             'keywords': ('مرحلة', 'phase')},
            {'key': 'period', 'label_ar': 'الفترة', 'label_en': 'Period',
             'keywords': ('فترة', 'زمن', 'period', 'timeframe', 'الإطار الزمني')},
            {'key': 'initiative', 'label_ar': 'المبادرة', 'label_en': 'Initiative',
             'keywords': ('مبادرة', 'initiative', 'نشاط', 'activity')},
            {'key': 'owner', 'label_ar': 'المسؤول', 'label_en': 'Owner',
             'keywords': ('مسؤول', 'مالك', 'owner')},
            {'key': 'deliverable', 'label_ar': 'المخرج المتوقع',
             'label_en': 'Expected Deliverable',
             'keywords': ('مخرج', 'deliverable', 'output', 'ناتج')},
            {'key': 'framework', 'label_ar': 'الإطار المرتبط',
             'label_en': 'Linked Framework',
             'keywords': ('إطار', 'framework', 'مرتبط')},
        ),
    },
    'kpi_main': {
        'table_id': 'kpi_main',
        'section_title_ar': 'مؤشرات الأداء الرئيسية',
        'columns': (
            {'key': 'row_num', 'label_ar': '#', 'label_en': '#',
             'keywords': ('#', 'م')},
            {'key': 'indicator', 'label_ar': 'وصف المؤشر', 'label_en': 'Indicator',
             'keywords': ('وصف المؤشر', 'المؤشر', 'indicator', 'kpi', 'metric')},
            {'key': 'type', 'label_ar': 'النوع', 'label_en': 'Type',
             'keywords': ('النوع', 'type', 'kpi/kri')},
            {'key': 'target', 'label_ar': 'القيمة المستهدفة', 'label_en': 'Target',
             'keywords': ('مستهدف', 'target', 'القيمة')},
            {'key': 'formula', 'label_ar': 'صيغة الاحتساب', 'label_en': 'Formula',
             'keywords': ('صيغة', 'formula', 'احتساب')},
            {'key': 'source', 'label_ar': 'مصدر', 'label_en': 'Source',
             'keywords': ('مصدر', 'source', 'البيانات')},
            {'key': 'frequency', 'label_ar': 'التكرار', 'label_en': 'Frequency',
             'keywords': ('تكرار', 'frequency', 'تواتر', 'دورية')},
            {'key': 'owner', 'label_ar': 'المالك', 'label_en': 'Owner',
             'keywords': ('المالك', 'owner', 'مسؤول')},
        ),
    },
    'kpi_formula': {
        'table_id': 'kpi_formula',
        'section_title_ar': 'صيغة الاحتساب',
        'columns': (
            {'key': 'row_num', 'label_ar': '#', 'label_en': '#',
             'keywords': ('#', 'م')},
            {'key': 'indicator', 'label_ar': 'المؤشر', 'label_en': 'Indicator',
             'keywords': ('المؤشر', 'indicator', 'kpi')},
            {'key': 'formula', 'label_ar': 'صيغة الاحتساب', 'label_en': 'Formula',
             'keywords': ('صيغة', 'formula')},
            {'key': 'source', 'label_ar': 'مصدر البيانات', 'label_en': 'Data Source',
             'keywords': ('مصدر', 'source')},
        ),
    },
    'kpi_assessment': {
        'table_id': 'kpi_assessment',
        'section_title_ar': 'أدلة تقييم مؤشرات الأداء',
        'columns': (
            {'key': 'indicator', 'label_ar': 'المؤشر', 'label_en': 'Indicator',
             'keywords': ('المؤشر', 'indicator', 'kpi')},
            {'key': 'method', 'label_ar': 'طريقة التقييم',
             'label_en': 'Assessment Method',
             'keywords': ('طريقة', 'method', 'تقييم')},
            {'key': 'formula', 'label_ar': 'صيغة الاحتساب', 'label_en': 'Formula',
             'keywords': ('صيغة', 'formula')},
            {'key': 'source', 'label_ar': 'مصدر البيانات', 'label_en': 'Data Source',
             'keywords': ('مصدر', 'source')},
            {'key': 'frequency', 'label_ar': 'دورية القياس', 'label_en': 'Frequency',
             'keywords': ('دورية', 'تكرار', 'frequency')},
            {'key': 'owner', 'label_ar': 'المالك', 'label_en': 'Owner',
             'keywords': ('المالك', 'owner')},
            {'key': 'threshold', 'label_ar': 'الحد المستهدف', 'label_en': 'Threshold',
             'keywords': ('حد', 'threshold', 'مستهدف')},
            {'key': 'acceptance', 'label_ar': 'دليل القبول',
             'label_en': 'Acceptance Evidence',
             'keywords': ('قبول', 'acceptance')},
            {'key': 'interpretation', 'label_ar': 'تفسير النتيجة',
             'label_en': 'Interpretation',
             'keywords': ('تفسير', 'interpret')},
        ),
    },
    'conf_factor': {
        'table_id': 'conf_factor',
        'section_title_ar': 'تقييم الثقة والمخاطر',
        'columns': (
            {'key': 'factor', 'label_ar': 'العامل', 'label_en': 'Factor',
             'keywords': ('عامل', 'factor')},
            {'key': 'weight', 'label_ar': 'الوزن', 'label_en': 'Weight',
             'keywords': ('وزن', 'weight')},
            {'key': 'score', 'label_ar': 'الدرجة', 'label_en': 'Score',
             'keywords': ('درجة', 'score')},
            {'key': 'contribution', 'label_ar': 'المساهمة',
             'label_en': 'Contribution',
             'keywords': ('مساهمة', 'contribution')},
        ),
    },
    'risk_register': {
        'table_id': 'risk_register',
        'section_title_ar': 'سجل المخاطر',
        'columns': (
            {'key': 'row_num', 'label_ar': '#', 'label_en': '#',
             'keywords': ('#', 'م')},
            {'key': 'risk', 'label_ar': 'المخاطر', 'label_en': 'Risk',
             'keywords': ('مخاطر', 'risk')},
            {'key': 'likelihood', 'label_ar': 'الاحتمالية', 'label_en': 'Likelihood',
             'keywords': ('احتمال', 'likelihood')},
            {'key': 'impact', 'label_ar': 'التأثير', 'label_en': 'Impact',
             'keywords': ('تأثير', 'impact')},
            {'key': 'treatment', 'label_ar': 'خطة المعالجة',
             'label_en': 'Treatment Plan',
             'keywords': ('معالجة', 'treatment', 'mitigation')},
            {'key': 'owner', 'label_ar': 'المالك', 'label_en': 'Owner',
             'keywords': ('المالك', 'owner', 'مسؤول')},
        ),
    },
    'governance': {
        'table_id': 'governance',
        'section_title_ar': 'نموذج الحوكمة والمسؤوليات',
        'columns': (
            {'key': 'role', 'label_ar': 'الدور', 'label_en': 'Role',
             'keywords': ('دور', 'role')},
            {'key': 'responsibilities', 'label_ar': 'نطاق المسؤولية',
             'label_en': 'Responsibilities',
             'keywords': ('مسؤولية', 'responsibilit', 'نطاق')},
            {'key': 'accountability', 'label_ar': 'المساءلة',
             'label_en': 'Accountability',
             'keywords': ('مساءلة', 'accountab')},
            {'key': 'escalation', 'label_ar': 'التقارير / التصعيد',
             'label_en': 'Reporting / Escalation',
             'keywords': ('تصعيد', 'تقارير', 'escalat', 'report')},
            {'key': 'framework', 'label_ar': 'الإطار المرتبط',
             'label_en': 'Linked Framework',
             'keywords': ('إطار', 'framework')},
        ),
    },
    'trace_fw_gap': {
        'table_id': 'trace_fw_gap',
        'section_title_ar': 'مصفوفة تتبع الأطر المرجعية',
        'columns': (
            {'key': 'framework', 'label_ar': 'الإطار المرجعي',
             'label_en': 'Framework',
             'keywords': ('إطار', 'framework', 'nca')},
            {'key': 'capability', 'label_ar': 'مجال القدرة',
             'label_en': 'Capability',
             'keywords': ('قدرة', 'capability', 'مجال')},
            {'key': 'gap', 'label_ar': 'الفجوة', 'label_en': 'Gap',
             'keywords': ('فجوة', 'gap')},
        ),
    },
    'trace_fw_init': {
        'table_id': 'trace_fw_init',
        'section_title_ar': 'مصفوفة تتبع الأطر المرجعية',
        'columns': (
            {'key': 'framework', 'label_ar': 'الإطار', 'label_en': 'Framework',
             'keywords': ('إطار', 'framework')},
            {'key': 'initiative', 'label_ar': 'المبادرة', 'label_en': 'Initiative',
             'keywords': ('مبادرة', 'initiative')},
            {'key': 'metric', 'label_ar': 'المؤشر', 'label_en': 'Metric',
             'keywords': ('مؤشر', 'metric', 'kpi')},
            {'key': 'risk', 'label_ar': 'المخاطر', 'label_en': 'Risk',
             'keywords': ('مخاطر', 'risk')},
        ),
    },
}

_SCHEMA_ALIASES = {
    'gap_table': 'gap_main',
    'kpi_summary': 'kpi_main',
    'kpi_details': 'kpi_formula',
    'environment': 'gap_main',
    'traceability': 'trace_fw_gap',
}

_KPI_TYPE_RE = re.compile(r'^(kpi|kri|مؤشر|kpi/kri)$', re.I)
_FREQ_TOKENS = ('شهري', 'ربع', 'سنوي', 'يومي', 'أسبوعي', 'daily', 'weekly',
                'monthly', 'quarter', 'annual', 'تواتر', 'تكرار')


def _col_index(header: Sequence[str], keywords: Tuple[str, ...]) -> int:
    for i, h in enumerate(header or []):
        blob = str(h).strip().lower()
        for k in keywords:
            kl = k.lower()
            if kl in ('#', 'م', 'no', 'no.'):
                if blob in ('#', 'م', 'no', 'no.'):
                    return i
                continue
            if kl in blob:
                return i
    return -1


def _header_index_for_column(
        header: Sequence[str], col: ColumnSpec, lang: str = 'ar') -> int:
    label = str(
        col.get('label_ar') if lang == 'ar' else col.get('label_en') or ''
    ).strip().lower()
    for i, h in enumerate(header or []):
        hb = str(h).strip().lower()
        if hb == label or (label and label in hb):
            return i
    return _col_index(header, tuple(col.get('keywords') or ()))


def _repair_kpi_row_dict(row: Dict[str, str]) -> Dict[str, str]:
    """Fix common KPI column shifts after key binding."""
    out = dict(row)
    typ = (out.get('type') or '').strip()
    target = (out.get('target') or '').strip()
    formula = (out.get('formula') or '').strip()
    freq = (out.get('frequency') or '').strip()
    owner = (out.get('owner') or '').strip()
    if _KPI_TYPE_RE.match(target) and not _KPI_TYPE_RE.match(typ):
        out['type'], out['target'] = target, typ
        typ, target = out['type'], out['target']
    if _is_freq_token(owner) and not _is_freq_token(freq):
        out['frequency'], out['owner'] = owner, freq
    if (_is_percent_target(formula) and not _is_percent_target(target)
            and re.search(r'[/÷×*+\-]', target)):
        out['formula'], out['target'] = target, formula
    return out


def _cell(row: Sequence[str], idx: int, default: str = '—') -> str:
    if idx < 0 or idx >= len(row):
        return default
    v = str(row[idx]).strip()
    return v if v and v not in ('-', '--') else default


def resolve_schema_id(schema: str) -> str:
    s = (schema or '').strip()
    return _SCHEMA_ALIASES.get(s, s)


def schema_header_labels(schema_id: str, lang: str = 'ar') -> List[str]:
    spec = REL32_TABLE_SCHEMAS.get(resolve_schema_id(schema_id)) or {}
    cols = spec.get('columns') or ()
    if lang == 'ar':
        return [str(c.get('label_ar') or c['key']) for c in cols]
    return [str(c.get('label_en') or c['key']) for c in cols]


def schema_keys(schema_id: str) -> List[str]:
    spec = REL32_TABLE_SCHEMAS.get(resolve_schema_id(schema_id)) or {}
    return [str(c['key']) for c in (spec.get('columns') or ())]


def row_dict_to_cells(row_dict: Dict[str, str], schema_id: str) -> List[str]:
    return [str(row_dict.get(k) or '—') for k in schema_keys(schema_id)]


def _is_freq_token(val: str) -> bool:
    s = (val or '').strip().lower()
    if not s or s == '—':
        return False
    return any(t in s for t in _FREQ_TOKENS)


def _is_percent_target(val: str) -> bool:
    s = (val or '').strip()
    return bool(re.search(r'\d+\s*%', s) or re.search(r'[<>≤≥]', s))


def _validate_row_semantics(
        schema_id: str, row: Dict[str, str], row_index: int) -> List[str]:
    issues: List[str] = []
    sid = resolve_schema_id(schema_id)
    if sid == 'kpi_main':
        typ = (row.get('type') or '').strip()
        target = (row.get('target') or '').strip()
        formula = (row.get('formula') or '').strip()
        freq = (row.get('frequency') or '').strip()
        owner = (row.get('owner') or '').strip()
        indicator = (row.get('indicator') or '').strip()
        row_num = (row.get('row_num') or '').strip()
        if _KPI_TYPE_RE.match(target):
            issues.append(f'row{row_index}:kpi_type_under_target')
        if _is_percent_target(formula) and not re.search(
                r'[/÷×*+\-]', formula):
            issues.append(f'row{row_index}:target_under_formula')
        if _is_freq_token(owner) and not _is_freq_token(freq):
            issues.append(f'row{row_index}:frequency_under_owner')
        if row_num and indicator == row_num:
            issues.append(f'row{row_index}:row_num_duplicated_in_indicator')
        if typ and _KPI_TYPE_RE.match(indicator):
            issues.append(f'row{row_index}:type_under_indicator')
    return issues


def bind_table_row(
        header: Sequence[str],
        row: Sequence[str],
        schema_id: str,
        *,
        row_index: int = 1,
        lang: str = 'ar',
) -> Tuple[Dict[str, str], List[str]]:
    """Map a positional row to schema-keyed dict; return missing keys."""
    sid = resolve_schema_id(schema_id)
    spec = REL32_TABLE_SCHEMAS.get(sid)
    if not spec:
        return {}, [f'unknown_schema:{schema_id}']
    out: Dict[str, str] = {}
    missing: List[str] = []
    for col in spec.get('columns') or ():
        key = str(col['key'])
        idx = _header_index_for_column(header, col, lang=lang)
        if idx < 0:
            if key == 'row_num' and row_index:
                out[key] = str(row_index)
            else:
                missing.append(key)
                out[key] = '—'
        else:
            out[key] = _cell(row, idx)
    if out.get('row_num', '—') == '—' and row_index:
        out['row_num'] = str(row_index)
    return out, missing


def rebind_table_spec(
        table_spec: Optional[Dict[str, Any]],
        *,
        lang: str = 'ar',
        schema_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Rebind header/rows to canonical schema keys (never positional-only)."""
    if not table_spec:
        return table_spec
    tbl = dict(table_spec)
    sid = resolve_schema_id(schema_id or tbl.get('schema') or '')
    if sid not in REL32_TABLE_SCHEMAS:
        return tbl
    header = list(tbl.get('header') or [])
    rows_in = list(tbl.get('rows') or [])
    bound_rows: List[Dict[str, str]] = []
    new_rows: List[List[str]] = []
    all_missing: List[str] = []
    mismatched: List[str] = []
    for ri, r in enumerate(rows_in, 1):
        row_dict, missing = bind_table_row(
            header, list(r), sid, row_index=ri, lang=lang)
        if sid == 'kpi_main':
            row_dict = _repair_kpi_row_dict(row_dict)
        all_missing.extend(missing)
        mismatched.extend(_validate_row_semantics(sid, row_dict, ri))
        bound_rows.append(row_dict)
        new_rows.append(row_dict_to_cells(row_dict, sid))
    labels = schema_header_labels(sid, lang)
    tbl['header'] = labels
    tbl['rows'] = new_rows
    tbl['schema'] = sid
    tbl['schema_keys'] = schema_keys(sid)
    tbl['bound_rows'] = bound_rows
    tbl['_schema_binding'] = evaluate_table_schema_binding_check(
        tbl, lang=lang, rtl_reversal_applied=False)
    return tbl


def evaluate_table_schema_binding_check(
        table_spec: Optional[Dict[str, Any]],
        *,
        lang: str = 'ar',
        rtl_reversal_applied: bool = False,
) -> Dict[str, Any]:
    sid = resolve_schema_id((table_spec or {}).get('schema') or '')
    spec = REL32_TABLE_SCHEMAS.get(sid) or {}
    header = list((table_spec or {}).get('header') or [])
    rows = list((table_spec or {}).get('rows') or [])
    keys = schema_keys(sid) if sid else []
    labels = schema_header_labels(sid, lang) if sid else header
    mismatched: List[str] = []
    missing_keys: List[str] = []
    extra_positional = 0
    if sid and header:
        for col in spec.get('columns') or ():
            if _col_index(header, tuple(col.get('keywords') or ())) < 0:
                if col['key'] not in (table_spec or {}).get('schema_keys', keys):
                    missing_keys.append(str(col['key']))
        for ri, r in enumerate(rows, 1):
            if isinstance(r, dict):
                row_dict = r
            elif (table_spec or {}).get('bound_rows'):
                br = (table_spec or {}).get('bound_rows') or []
                row_dict = br[ri - 1] if ri - 1 < len(br) else {}
            else:
                row_dict, miss = bind_table_row(header, list(r), sid, row_index=ri)
                missing_keys.extend(miss)
            mismatched.extend(_validate_row_semantics(sid, row_dict, ri))
            if len(r) > len(keys):
                extra_positional += len(r) - len(keys)
    blocking: List[str] = []
    if sid and rows:
        if missing_keys:
            blocking.append(f'rel32_table_missing_keys:{sid}')
        if mismatched:
            blocking.append(f'rel32_table_mismatched_cells:{sid}')
        if rtl_reversal_applied:
            blocking.append(f'rel32_table_rtl_value_reversal:{sid}')
    passed = not blocking
    return {
        'table_id': sid or (table_spec or {}).get('schema', ''),
        'section_title': spec.get('section_title_ar', ''),
        'schema_keys': keys,
        'header_labels': labels,
        'row_count': len(rows),
        'mismatched_cells': list(dict.fromkeys(mismatched)),
        'missing_required_keys': list(dict.fromkeys(missing_keys)),
        'extra_positional_cells': extra_positional,
        'rtl_reversal_applied': bool(rtl_reversal_applied),
        'schema_binding_passed': passed,
        'blocking_errors': blocking,
    }


def emit_rel32_table_schema_binding_diag(diag: Dict[str, Any]) -> None:
    try:
        print(
            '[REL32-TABLE-SCHEMA-BINDING-CHECK] '
            + json.dumps(diag, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass


def apply_rel32_schema_binding_to_blocks(
        blocks: Dict[str, Any],
        *,
        lang: str = 'ar',
) -> Dict[str, Any]:
    """Walk professional blocks and rebind every known strategy table."""
    out = dict(blocks or {})
    all_diags: List[Dict[str, Any]] = []

    def _rebind_list(tables: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        rebound: List[Dict[str, Any]] = []
        for tbl in tables or []:
            if not isinstance(tbl, dict):
                continue
            rt = rebind_table_spec(tbl, lang=lang)
            if rt:
                diag = rt.pop('_schema_binding', None) or (
                    evaluate_table_schema_binding_check(rt, lang=lang))
                emit_rel32_table_schema_binding_diag(diag)
                all_diags.append(diag)
                rebound.append(rt)
        return rebound

    for key in ('vision_objectives', 'environment_context', 'gap_analysis',
                'roadmap', 'kpi_kri_framework', 'confidence_risk_register'):
        blk = dict(out.get(key) or {})
        if blk.get('tables'):
            blk['tables'] = _rebind_list(blk['tables'])
            out[key] = blk

    pil = dict(out.get('strategic_pillars') or {})
    pblocks = []
    for pb in pil.get('pillar_blocks') or []:
        pb = dict(pb)
        if pb.get('table'):
            pb['table'] = rebind_table_spec(
                pb['table'], lang=lang, schema_id='pillar_initiatives')
            if pb['table']:
                diag = evaluate_table_schema_binding_check(
                    pb['table'], lang=lang)
                emit_rel32_table_schema_binding_diag(diag)
                all_diags.append(diag)
        pblocks.append(pb)
    if pblocks:
        pil['pillar_blocks'] = pblocks
        out['strategic_pillars'] = pil

    gov = dict(out.get('governance_ownership') or {})
    if gov.get('rows'):
        tbl = {
            'schema': 'governance',
            'header': list(gov.get('header') or schema_header_labels(
                'governance', lang)),
            'rows': gov['rows'],
        }
        tbl = rebind_table_spec(tbl, lang=lang, schema_id='governance')
        if tbl:
            gov['header'] = tbl['header']
            gov['rows'] = tbl['rows']
            gov['schema'] = 'governance'
            gov['bound_rows'] = tbl.get('bound_rows')
            diag = evaluate_table_schema_binding_check(tbl, lang=lang)
            emit_rel32_table_schema_binding_diag(diag)
            all_diags.append(diag)
        out['governance_ownership'] = gov

    trace = dict(out.get('traceability_matrix') or {})
    if trace.get('split_tables'):
        trace['split_tables'] = _rebind_list(trace['split_tables'])
        out['traceability_matrix'] = trace

    out['_rel32_table_schema_binding'] = {
        'checks': all_diags,
        'all_passed': all(c.get('schema_binding_passed') for c in all_diags),
        'blocking_errors': [
            e for c in all_diags for e in (c.get('blocking_errors') or [])],
    }
    return out
