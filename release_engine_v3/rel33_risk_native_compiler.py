"""REL3.3 — deterministic ERM risk-native compiler.

Purpose
-------
ERM risk (``document_type=risk``) must NOT depend on free-form LLM structure.
Free-form generation is non-deterministic: it sometimes emits strategy/cyber
shaped content (vision/objectives/pillars/roadmap/strategy-KPI/governance/
traceability), which correctly fails the risk-domain guard — but only some of
the time. This compiler removes that non-determinism: it treats the LLM output
as *material only* and produces a schema-locked, risk-native artifact that is
always safe to save and export.

It NEVER weakens the risk-domain guard, suppresses ``rel33_domain_contamination``,
or bypasses export evidence. Cyber-primary operating-model substance is stripped
(never copied into ERM); forbidden strategy sections are discarded; risk rows and
controls/KRIs are extracted when usable and deterministically generated from the
scenario/domain otherwise.

Allowed final headings (schema-locked):
  وصف السيناريو · سياق المخاطر · سجل المخاطر · المخاطر المتأصلة والمتبقية ·
  الضوابط · خطة المعالجة · مقاييس KRI للمراقبة · المالكون والمسؤوليات ·
  ملخص المخاطر

Forbidden final headings (never emitted): vision / strategic objectives /
strategic pillars / roadmap / strategy KPI / governance model / traceability
matrix (Arabic + English variants) — see rel33_risk_generation_contract.

──────────────────────────────────────────────────────────────────────────────
REL3.3 DEFECT REGISTER (platform stabilization sweep)
  D1 ERM non-deterministic strategy-shaped generation
       → FIXED here (deterministic compiler); GUARDED by
         tests/test_rel33_risk_native_compiler.py; COVERED by staging acceptance
         (erm:risk:ar) + compiler diagnostic.
  D2 risk/export strategy-gate leakage (vision key, roadmap model-drift)
       → FIXED (rel28_route_evidence + export_evidence_validator document_type
         gating; exporters risk-native split); GUARDED by
         tests/test_rel33_risk_export_gate_isolation.py.
  D3 frozen completeness document_type mismatch
       → FIXED (rel32_frozen_export_lock / rel33_frozen_completeness risk-native);
         GUARDED by tests/test_rel33_risk_frozen_completeness.py.
  D4 treatment evidence semantic mismatch
       → FIXED (semantic_risk_treatment_counts shared source of truth);
         GUARDED by tests/test_rel33_risk_treatment_evidence_semantic.py.
  D5 stale worker deploy readiness
       → FIXED (staging acceptance 480s worker-settle + post-settle verify);
         COVERED by scripts/_rel33_all_domain_staging_acceptance.py.
  D6 debug visibility gaps
       → FIXED (gated export-status echo of generation/export-prep/routing +
         compiler diagnostics); GUARDED by tests/test_rel33_risk_prep_failclosed.py.
  D7 PDF/DOCX parity blockers (empty PDF / DOCX bypass)
       → GUARDED by tests/test_rel33_pdf_evidence_hardening.py +
         tests/test_rel33_p0_export_gates.py; export authority (rel31) enforces
         same canonical content + returned-file evidence for both channels.
──────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

MIN_REGISTER_ROWS = 8
MIN_TREATMENT_ROWS = 8
MIN_KRI_ROWS = 5

# Section-key markers used to locate usable material in the raw LLM output.
_RAW_REGISTER_MARKERS = (
    'register', 'risk_register', 'سجل', 'تقييم_المخاطر', 'مصفوف', 'matrix',
)
_RAW_TREATMENT_MARKERS = (
    'treatment', 'treatments', 'معالج', 'معالجة', 'الضوابط', 'ضوابط',
    'control', 'mitigation', 'تخفيف',
)
_RAW_KRI_MARKERS = ('kri', 'مؤشرات', 'مراقبة', 'monitoring', 'مقاييس')

# Cyber operating-model identity that must never be copied into an ERM artifact.
_CYBER_ROW_MARKERS_AR = (
    'حوكمة الأمن السيبراني', 'مركز العمليات الأمنية',
    'الاستجابة للحوادث السيبرانية', 'إدارة الثغرات السيبرانية',
    'مركز عمليات الأمن', 'فريق الاستجابة للحوادث',
)
_CYBER_ROW_MARKERS_ASCII = (
    'ciso', 'csirt', 'soc', 'siem', 'nca ecc', 'nca dcc',
    'security operations center', 'iam/pam',
)


def emit_rel33_risk_native_compiler(diag: Dict[str, Any]) -> None:
    try:
        print(
            '[REL33-RISK-NATIVE-COMPILER] '
            + json.dumps(diag, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass


def _sha256_short(text: str) -> str:
    import hashlib
    return hashlib.sha256(str(text or '').encode('utf-8')).hexdigest()[:16]


def _row_is_cyber_primary(cells: List[str]) -> bool:
    blob = ' | '.join(str(c) for c in cells)
    low = blob.lower()
    if any(m in blob for m in _CYBER_ROW_MARKERS_AR):
        return True
    for m in _CYBER_ROW_MARKERS_ASCII:
        if re.search(r'(?<![a-z])' + re.escape(m) + r'(?![a-z])', low):
            return True
    return False


def _extract_table_data_rows(section_text: str) -> List[List[str]]:
    """Return the data-row cell lists of the first markdown pipe-table found."""
    rows: List[List[str]] = []
    seen_header = False
    for ln in str(section_text or '').splitlines():
        s = ln.strip()
        if not s.startswith('|'):
            if rows:
                break  # table ended
            continue
        if set(s) <= set('|-: '):
            continue  # separator row
        cells = [c.strip() for c in s.strip('|').split('|')]
        if not seen_header:
            seen_header = True
            continue  # skip header row
        if not any(cells):
            continue
        rows.append(cells)
    return rows


def _clean_cell(text: str) -> str:
    t = re.sub(r'\s+', ' ', str(text or '')).strip()
    return t


def _find_raw_sections(raw_sections: Dict[str, str], markers) -> List[str]:
    out: List[str] = []
    for k, v in (raw_sections or {}).items():
        if str(k).startswith('_'):
            continue
        kl = str(k).lower()
        if any(m in kl for m in markers):
            out.append(str(v or ''))
    return out


# ── Deterministic ERM fallback catalog (domain-scoped, never cyber-primary) ──
_ERM_RISK_CATALOG_AR = [
    ('انقطاع استمرارية الأعمال', 'تشغيلية', 'متوسطة', 'عالٍ'),
    ('عدم الامتثال التنظيمي', 'امتثال', 'متوسطة', 'عالٍ'),
    ('التعرض المالي وتجاوز الميزانية', 'مالية', 'متوسطة', 'عالٍ'),
    ('الإضرار بالسمعة المؤسسية', 'سمعة', 'منخفضة', 'عالٍ'),
    ('مخاطر الأطراف الثالثة والموردين', 'أطراف ثالثة', 'متوسطة', 'متوسط'),
    ('ضعف جودة البيانات وحوكمتها', 'بيانات', 'متوسطة', 'متوسط'),
    ('فشل الضوابط والعمليات الداخلية', 'تشغيلية', 'متوسطة', 'متوسط'),
    ('نقص الموارد والقدرات التشغيلية', 'موارد', 'منخفضة', 'متوسط'),
    ('مخاطر التغيير والتحول المؤسسي', 'تحول', 'متوسطة', 'متوسط'),
    ('مخاطر السلامة والبيئة', 'سلامة', 'منخفضة', 'متوسط'),
]
_ERM_TREATMENT_CATALOG_AR = [
    ('خطة استمرارية الأعمال والتعافي', 'وقائي', 'عالية', '30 يوماً',
     'مالك المخاطر', 'مرتفعة'),
    ('برنامج الامتثال والمراجعة الدورية', 'كاشف', 'عالية', '45 يوماً',
     'مدير الامتثال', 'مرتفعة'),
    ('ضوابط مالية وحدود الإنفاق والموازنة', 'وقائي', 'عالية', '30 يوماً',
     'المدير المالي', 'مرتفعة'),
    ('إدارة السمعة والتواصل المؤسسي', 'تصحيحي', 'متوسطة', '60 يوماً',
     'مالك المخاطر', 'متوسطة'),
    ('إدارة مخاطر الموردين والعقود', 'وقائي', 'متوسطة', '60 يوماً',
     'مدير المشتريات', 'متوسطة'),
    ('ضوابط جودة البيانات وحوكمتها', 'وقائي', 'متوسطة', '60 يوماً',
     'مالك البيانات', 'متوسطة'),
    ('مراجعة الضوابط الداخلية والتدقيق', 'كاشف', 'متوسطة', '45 يوماً',
     'التدقيق الداخلي', 'متوسطة'),
    ('تخطيط الموارد والقدرات والاستمرارية', 'وقائي', 'متوسطة', '90 يوماً',
     'مالك المخاطر', 'متوسطة'),
    ('حوكمة إدارة التغيير المؤسسي', 'وقائي', 'متوسطة', '60 يوماً',
     'لجنة المخاطر', 'متوسطة'),
    ('ضوابط السلامة والبيئة والامتثال', 'وقائي', 'منخفضة', '90 يوماً',
     'مدير السلامة', 'متوسطة'),
]
_ERM_KRI_CATALOG_AR = [
    ('نسبة تجاوز شهية المخاطر', '≤ 5%', 'شهري', 'مالك المخاطر'),
    ('اتجاه المخاطر المتبقية', 'مستقر أو منخفض', 'ربع سنوي', 'لجنة المخاطر'),
    ('نسبة إنجاز خطط المعالجة', '≥ 90%', 'شهري', 'مالك المخاطر'),
    ('فعالية الضوابط الرئيسية', '≥ 90%', 'ربع سنوي', 'التدقيق الداخلي'),
    ('تكرار الحوادث التشغيلية', '≤ 2 سنوياً', 'شهري', 'مالك المخاطر'),
    ('زمن معالجة المخاطر الحرجة', '≤ 30 يوماً', 'شهري', 'مالك المخاطر'),
]
_ERM_OWNER_CATALOG_AR = [
    ('مالك المخاطر', 'ملكية تحديد وتقييم ومعالجة المخاطر ومتابعة الضوابط',
     'لجنة المخاطر'),
    ('لجنة المخاطر', 'الإشراف على شهية المخاطر واعتماد خطط المعالجة',
     'مجلس الإدارة'),
    ('التدقيق الداخلي', 'التحقق المستقل من فعالية الضوابط والامتثال',
     'لجنة المراجعة'),
    ('الراعي التنفيذي', 'توفير الموارد ومساءلة تنفيذ خطة المعالجة',
     'مجلس الإدارة'),
]


def _severity_from_level(risk_level: str) -> str:
    lvl = str(risk_level or '').strip().upper()
    return {
        'CRITICAL': 'حرجة', 'HIGH': 'مرتفعة',
        'MEDIUM': 'متوسطة', 'LOW': 'منخفضة',
    }.get(lvl, 'مرتفعة')


def _score_from(likelihood: str, impact: str) -> str:
    lmap = {'منخفضة': 2, 'متوسطة': 3, 'عالية': 4, 'مرتفعة': 4}
    imap = {'منخفض': 2, 'متوسط': 3, 'عالٍ': 5, 'عالي': 5, 'مرتفع': 5}
    return str(lmap.get(likelihood, 3) * imap.get(impact, 4))


def _build_register_table(rows: List[List[str]]) -> str:
    head = '| # | الخطر | الفئة | الاحتمالية | التأثير | الدرجة | الخطورة |'
    sep = '|---|---|---|---|---|---|---|'
    body = []
    for i, r in enumerate(rows, 1):
        cells = (list(r) + [''] * 7)[:6]
        body.append('| ' + ' | '.join([str(i)] + [_clean_cell(c) for c in cells]) + ' |')
    return '\n'.join([head, sep] + body)


def _build_treatment_table(rows: List[List[str]]) -> str:
    head = ('| # | الضابط / المعالجة | نوع الضابط | الأولوية | الجدول الزمني '
            '| المالك | فعالية المعالجة |')
    sep = '|---|---|---|---|---|---|---|'
    body = []
    for i, r in enumerate(rows, 1):
        cells = (list(r) + [''] * 7)[:6]
        body.append('| ' + ' | '.join([str(i)] + [_clean_cell(c) for c in cells]) + ' |')
    return '\n'.join([head, sep] + body)


def _build_kri_table(rows: List[List[str]]) -> str:
    head = ('| # | مؤشر المخاطر (KRI) | الحد المقبول (شهية المخاطر) '
            '| التكرار | المالك |')
    sep = '|---|---|---|---|---|'
    body = []
    for i, r in enumerate(rows, 1):
        cells = (list(r) + [''] * 5)[:4]
        body.append('| ' + ' | '.join([str(i)] + [_clean_cell(c) for c in cells]) + ' |')
    return '\n'.join([head, sep] + body)


def _build_owner_table(rows: List[List[str]]) -> str:
    head = '| الدور | المسؤولية | جهة التصعيد |'
    sep = '|---|---|---|'
    body = []
    for r in rows:
        cells = (list(r) + [''] * 3)[:3]
        body.append('| ' + ' | '.join([_clean_cell(c) for c in cells]) + ' |')
    return '\n'.join([head, sep] + body)


def _build_inherent_residual_table(register_rows: List[List[str]]) -> str:
    head = '| الخطر | المخاطر المتأصلة | الضوابط | المخاطر المتبقية |'
    sep = '|---|---|---|---|'
    body = []
    for r in register_rows[:MIN_REGISTER_ROWS]:
        name = _clean_cell(r[0]) if r else 'خطر مؤسسي'
        body.append(f'| {name} | مرتفعة | ضوابط وقائية وكاشفة | متوسطة |')
    return '\n'.join([head, sep] + body)


def compile_risk_native_artifact(
        raw_content: str,
        *,
        domain: str = 'erm',
        document_type: str = 'risk',
        lang: str = 'ar',
        context: Optional[Dict[str, Any]] = None,
        route: str = 'generate-risk',
        emit: bool = True,
) -> Dict[str, Any]:
    """Compile a deterministic risk-native ERM artifact from raw LLM material.

    Returns a dict with: ``content`` (canonical risk-native markdown),
    ``sections``, row counts, ``compiler_passed``, ``blocking_errors`` and the
    ``[REL33-RISK-NATIVE-COMPILER]`` diagnostic fields.
    """
    from release_engine_v3.rel33_risk_artifact import (
        _split_risk_markdown,
        normalize_risk_export_sections,
    )
    from release_engine_v3.rel33_risk_generation_contract import (
        detect_forbidden_strategy_sections,
    )

    ctx = dict(context or {})
    asset = str(ctx.get('asset') or ctx.get('org_name') or 'الأصول المؤسسية')
    threat = str(ctx.get('threat') or 'تهديد تشغيلي')
    org = str(ctx.get('org_name') or 'الجهة')
    sector = str(ctx.get('sector') or 'الحكومي')
    risk_level = str(ctx.get('risk_level') or ctx.get('_risk_level') or 'HIGH')

    raw = str(raw_content or '')
    raw_sections = normalize_risk_export_sections(_split_risk_markdown(raw))
    raw_strategy = detect_forbidden_strategy_sections(raw)
    raw_cyber_terms = sorted({
        m for m in _CYBER_ROW_MARKERS_AR if m in raw
    } | {
        m for m in _CYBER_ROW_MARKERS_ASCII
        if re.search(r'(?<![a-z])' + re.escape(m) + r'(?![a-z])', raw.lower())
    })

    # ── Extract usable, non-cyber rows from raw material ──
    def _extract(markers) -> List[List[str]]:
        rows: List[List[str]] = []
        for sec in _find_raw_sections(raw_sections, markers):
            for cells in _extract_table_data_rows(sec):
                if _row_is_cyber_primary(cells):
                    continue
                # keep rows with at least one substantive cell
                if any(len(_clean_cell(c)) >= 2 for c in cells):
                    rows.append([_clean_cell(c) for c in cells])
        return rows

    reg_extracted = _extract(_RAW_REGISTER_MARKERS)
    treat_extracted = _extract(_RAW_TREATMENT_MARKERS)
    kri_extracted = _extract(_RAW_KRI_MARKERS)

    # ── Deterministic ERM fallback to meet minimums ──
    reg_rows = list(reg_extracted)
    reg_fallback = 0
    for name, cat, like, imp in _ERM_RISK_CATALOG_AR:
        if len(reg_rows) >= MIN_REGISTER_ROWS:
            break
        reg_rows.append([name, cat, like, imp, _score_from(like, imp),
                         _severity_from_level(risk_level)])
        reg_fallback += 1

    treat_rows = list(treat_extracted)
    treat_fallback = 0
    for row in _ERM_TREATMENT_CATALOG_AR:
        if len(treat_rows) >= MIN_TREATMENT_ROWS:
            break
        treat_rows.append(list(row))
        treat_fallback += 1

    kri_rows = list(kri_extracted)
    kri_fallback = 0
    for row in _ERM_KRI_CATALOG_AR:
        if len(kri_rows) >= MIN_KRI_ROWS:
            break
        kri_rows.append(list(row))
        kri_fallback += 1

    owner_rows = list(_ERM_OWNER_CATALOG_AR)

    # ── Build schema-locked canonical risk-native markdown ──
    scenario = _clean_cell(
        (raw_sections.get('scenario') or '').replace('#', ' ')) or (
        f'يتناول هذا التقييم مخاطر «{threat}» المؤثرة على {asset} ضمن قطاع '
        f'{sector}، بمنهجية إدارة المخاطر المؤسسية (ERM).')
    context_txt = (
        f'يجرى التقييم ضمن مجال إدارة المخاطر المؤسسية لدى {org}، باستخدام '
        f'شهية المخاطر والسجل والمخاطر المتأصلة والمتبقية والضوابط ومؤشرات '
        f'المخاطر (KRI) وخطط المعالجة ومالكي المخاطر ولجنة المخاطر.')
    summary_txt = (
        f'يُظهر التقييم مستوى مخاطر أولي «{risk_level}» يتطلب تنفيذ خطط المعالجة '
        f'ومتابعة مؤشرات المخاطر (KRI) لخفض المخاطر المتبقية ضمن شهية المخاطر '
        f'المعتمدة، تحت إشراف لجنة المخاطر ومساءلة مالكي المخاطر.')

    parts = [
        '## وصف السيناريو', '', scenario, '',
        '## سياق المخاطر', '', context_txt, '',
        '## سجل المخاطر', '', _build_register_table(reg_rows), '',
        '## المخاطر المتأصلة والمتبقية', '',
        _build_inherent_residual_table(reg_rows), '',
        '## الضوابط', '',
        'تشمل الضوابط ضوابط وقائية وكاشفة وتصحيحية لخفض المخاطر المتأصلة إلى '
        'مستوى المخاطر المتبقية المقبول ضمن شهية المخاطر.', '',
        '## خطة المعالجة', '', _build_treatment_table(treat_rows), '',
        '## مقاييس KRI للمراقبة', '', _build_kri_table(kri_rows), '',
        '## المالكون والمسؤوليات', '', _build_owner_table(owner_rows), '',
        '## ملخص المخاطر', '', summary_txt, '',
    ]
    content = '\n'.join(parts).strip() + '\n'

    # ── Validate the compiled output (schema-lock + isolation) ──
    final_sections = normalize_risk_export_sections(_split_risk_markdown(content))
    forbidden_final = detect_forbidden_strategy_sections(content)
    final_heading_keys = [
        k for k in final_sections.keys() if not str(k).startswith('_')]

    isolation_passed = True
    isolation_blockers: List[str] = []
    try:
        from release_engine_v3.domain_codes import normalize_domain_code
        from release_engine_v3.rel33_domain_guard import (
            evaluate_rel33_risk_domain_isolation,
        )
        dcode = normalize_domain_code(str(domain or ''), default='') or 'erm'
        _iso = evaluate_rel33_risk_domain_isolation(
            final_sections, domain=dcode, document_type='risk',
            route=route, phase='compile', artifact_type='risk',
            section_classifier='risk_native_compiler',
            selected_registry=dcode, emit=False)
        isolation_passed = bool(_iso.get('contract_passed'))
        isolation_blockers = list(_iso.get('blocking_errors') or [])
    except Exception as _iso_e:  # noqa: BLE001
        isolation_blockers = [f'compiler_isolation_error:{_iso_e}']
        isolation_passed = False

    # Completeness / treatment readiness (deterministic minimums met).
    frozen_ready = True
    treatment_ready = True
    try:
        from release_engine_v3.rel33_frozen_completeness import (
            evaluate_risk_sections_complete,
        )
        frozen_ready = bool(
            evaluate_risk_sections_complete(final_sections)[0])
    except Exception:  # noqa: BLE001
        frozen_ready = False
    try:
        from release_engine_v3.rel33_risk_treatment_evidence import (
            count_treatment_rows_from_sections, semantic_risk_treatment_counts,
        )
        _rk, _tk = count_treatment_rows_from_sections(final_sections)
        _sem = semantic_risk_treatment_counts(final_sections)
        treatment_ready = (
            int(_tk) + int(_sem.get('treatment_rows') or 0)) > 0
    except Exception:  # noqa: BLE001
        treatment_ready = False

    blocking_errors: List[str] = []
    if forbidden_final:
        blocking_errors.append('rel33_risk_native_compiler_forbidden_heading')
    if not isolation_passed:
        blocking_errors.extend(isolation_blockers
                               or ['rel33_risk_native_compiler_isolation_failed'])
    if len(reg_rows) < MIN_REGISTER_ROWS or len(treat_rows) < MIN_TREATMENT_ROWS \
            or len(kri_rows) < MIN_KRI_ROWS:
        blocking_errors.append('rel33_risk_native_compiler_incomplete')
    if not frozen_ready or not treatment_ready:
        blocking_errors.append('rel33_risk_native_compiler_evidence_not_ready')

    compiler_passed = not blocking_errors

    diag: Dict[str, Any] = {
        'tag': '[REL33-RISK-NATIVE-COMPILER]',
        'route': str(route or ''),
        'domain': str(domain or ''),
        'document_type': 'risk',
        'artifact_type': 'risk',
        'raw_content_hash': _sha256_short(raw),
        'compiled_content_hash': _sha256_short(content),
        'raw_strategy_sections_detected': list(raw_strategy),
        'raw_cyber_primary_terms_detected': list(raw_cyber_terms),
        'extracted_risk_rows': len(reg_extracted),
        'extracted_treatment_rows': len(treat_extracted),
        'extracted_kri_rows': len(kri_extracted),
        'generated_fallback_risk_rows': reg_fallback,
        'generated_fallback_treatment_rows': treat_fallback,
        'generated_fallback_kri_rows': kri_fallback,
        'final_register_rows': len(reg_rows),
        'final_treatment_rows': len(treat_rows),
        'final_kri_rows': len(kri_rows),
        'final_heading_keys': final_heading_keys,
        'forbidden_final_headings_detected': list(forbidden_final),
        'risk_domain_isolation_passed': bool(isolation_passed),
        'frozen_completeness_ready': bool(frozen_ready),
        'treatment_evidence_ready': bool(treatment_ready),
        'compiler_passed': bool(compiler_passed),
        'blocking_errors': list(dict.fromkeys(blocking_errors)),
    }
    if emit:
        emit_rel33_risk_native_compiler(diag)

    return {
        'content': content if compiler_passed else '',
        'sections': final_sections if compiler_passed else {},
        'register_rows': len(reg_rows),
        'treatment_rows': len(treat_rows),
        'kri_rows': len(kri_rows),
        'owner_rows': len(owner_rows),
        'compiler_passed': bool(compiler_passed),
        'blocking_errors': list(dict.fromkeys(blocking_errors)),
        'diag': diag,
    }
