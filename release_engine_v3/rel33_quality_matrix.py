"""PR-REL3.3 — all-domain document quality matrix runner."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import re
import sys
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]

REL33_TYPE_FIXTURES_AR: Dict[str, Dict[str, str]] = {
    'policy': {
        'purpose': '## الغرض\n\nتوفير إطار حوكمة تنظيمية.\n',
        'scope': '## النطاق\n\nجميع الأنظمة والبيانات.\n',
        'roles': '## الأدوار\n\n| الدور | المسؤولية |\n|---|---|\n| CISO | اعتماد |\n',
        'controls': (
            '## الضوابط\n\n| الضابط | المرجع |\n|---|---|\n'
            '| التحكم بالوصول | NCA ECC |\n| التشفير | NCA DCC |\n'
        ),
        'exceptions': '## الاستثناءات\n\nلا يوجد استثناء دائم.\n',
    },
    'procedure': {
        'purpose': '## الغرض\n\nإجراء تشغيلي موحد.\n',
        'steps': (
            '## الخطوات\n\n| # | الخطوة | المالك |\n|---|---|---|\n'
            '| 1 | التحقق | المحلل |\n| 2 | التنفيذ | المشغل |\n'
        ),
        'roles': '## الأدوار\n\n| الدور | المسؤولية |\n|---|---|\n| المشغل | تنفيذ |\n',
        'inputs': '## المدخلات\n\nطلب معتمد.\n',
        'outputs': '## المخرجات\n\nسجل مكتمل.\n',
    },
    'risk': {
        'register': (
            '## سجل المخاطر\n\n| المخاطرة | التأثير |\n|---|---|\n'
            '| انقطاع الخدمة | عالي |\n'
        ),
        'heatmap': '## خريطة الحرارة\n\nمصفوفة 5×5.\n',
        'appetite': '## شهية المخاطر\n\nمنخفضة للمخاطر التشغيلية.\n',
        'treatments': (
            '## المعالجات\n\n| المخاطرة | المعالجة | المالك |\n|---|---|---|\n'
            '| انقطاع الخدمة | تكرار | مدير العمليات |\n'
        ),
    },
    'audit': {
        'scope': '## نطاق التدقيق\n\nضوابط الأمن السيبراني.\n',
        'findings': (
            '## النتائج\n\n| # | النتيجة | الخطورة |\n|---|---|---|\n'
            '| 1 | ضعف سجل | متوسط |\n'
        ),
        'evidence': (
            '## الأدلة\n\n| النتيجة | الدليل |\n|---|---|\n'
            '| ضعف سجل | عينة سجلات |\n'
        ),
        'recommendations': '## التوصيات\n\nتفعيل SIEM.\n',
    },
    'roadmap': {
        'phases': (
            '## المراحل\n\n| المرحلة | المبادرة | المالك |\n|---|---|---|\n'
            '| Q1 | الأساسيات | CISO |\n'
        ),
        'initiatives': '## المبادرات\n\nقائمة مبادرات معتمدة.\n',
        'owners': '## المالكون\n\n| المبادرة | المالك |\n|---|---|\n| SIEM | CISO |\n',
        'deliverables': '## المخرجات\n\nتقرير شهري.\n',
    },
    'executive_summary': {
        'decision': '## القرار المطلوب\n\nاعتماد البرنامج.\n',
        'priorities': '## الأولويات\n\n1. الحوكمة 2. الامتثال.\n',
        'risks': '## المخاطر\n\nمخاطر التنفيذ محدودة.\n',
        'ask': '## الطلب\n\nتخصيص ميزانية.\n',
    },
    'gap_assessment': {
        'scope': '## النطاق\n\nISO 27001 Annex A.\n',
        'gaps': (
            '## الفجوات\n\n| الفجوة | الأولوية |\n|---|---|\n'
            '| ضعف التحكم | عالية |\n'
        ),
        'guides': '## دليل التطبيق\n\nدليل تطبيق الضوابط.\n',
        'remediation': '## المعالجة\n\nخطة معالجة 90 يوماً.\n',
    },
}


def build_rel33_matrix_cases() -> List[Dict[str, Any]]:
    from release_engine_v3.golden_matrix import GOLDEN_MATRIX

    cases: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for row in GOLDEN_MATRIX:
        if row.get('lang') != 'ar':
            continue
        key = f"{row['domain']}:{row['document_type']}:ar"
        if key in seen:
            continue
        cases.append(dict(row))
        seen.add(key)
    tech = {
        'domain': 'cyber', 'document_type': 'strategy', 'lang': 'ar',
        'doc_subtype': 'technical', 'tier': 'P0',
    }
    if 'cyber:strategy:ar' not in seen:
        cases.insert(0, tech)
    else:
        for i, c in enumerate(cases):
            if c.get('domain') == 'cyber' and c.get('document_type') == 'strategy':
                cases[i] = {**c, 'doc_subtype': 'technical'}
                break
    global_strategy = {
        'domain': 'global', 'document_type': 'strategy', 'lang': 'ar',
        'tier': 'P2',
    }
    if 'global:strategy:ar' not in seen:
        cases.append(global_strategy)
    return cases


def _load_app_module():
    spec = importlib.util.spec_from_file_location('app', ROOT / 'app.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    sys.modules['app'] = mod
    return mod


def _reset_export_state() -> None:
    from release_engine_v3.canonical_document import clear_artifact_registry
    from release_engine_v3.orchestrator import clear_rel3_caches
    from release_engine_v3.rel31_authority import clear_rel3_route_artifact_hashes
    from release_engine_v3.rel32_frozen_export_lock import clear_rel32_frozen_export_lock

    clear_rel3_caches()
    clear_rel3_route_artifact_hashes()
    clear_rel32_frozen_export_lock()
    clear_artifact_registry()


def load_sections_for_case(case: Dict[str, Any]) -> Dict[str, str]:
    domain = case['domain']
    document_type = case['document_type']
    lang = case.get('lang', 'ar')

    if document_type == 'strategy' and domain == 'cyber':
        from release_engine_v3.evidence.docx_text_extractor import (
            extract_docx_visible_text,
        )
        from tests.fixtures.rel31_content_quality.latest_live_fixtures import (
            DOCX_LATEST,
            ensure_latest_live_fixtures,
            sections_from_latest_docx_text,
        )

        ensure_latest_live_fixtures()
        docx_text = extract_docx_visible_text(DOCX_LATEST.read_bytes())
        sections = sections_from_latest_docx_text(docx_text)
        from release_engine.rel31_acceptance_checks import (
            repair_rel31_canonical_sections,
        )

        backend = _load_app_module()._rel31_backend_callables()
        sections, _ = repair_rel31_canonical_sections(
            sections, lang=lang, domain=domain, backend=backend)
        return dict(sections)

    if document_type == 'strategy':
        from domains._registry import get_domain_pack

        pack = get_domain_pack(domain)
        if pack is None:
            return {}
        fx = pack['fixtures_ar'] if lang == 'ar' else pack['fixtures_en']
        return dict(fx.technical_sections())

    if lang == 'ar':
        return dict(REL33_TYPE_FIXTURES_AR.get(document_type) or {})
    return {}


def _extract_schema_table_html(preview_html: str, schema_id: str) -> str:
    blob = preview_html or ''
    pattern = (
        rf'<div[^>]*data-table-id="{re.escape(schema_id)}"[^>]*>'
        r'.*?</table>\s*</div>'
    )
    m = re.search(pattern, blob, re.I | re.S)
    return m.group(0) if m else ''


def evaluate_preview_dom_for_document(
        preview_html: str,
        document_type: str,
        *,
        sections: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    from release_engine_v3.rel32_preview_table_dom import (
        evaluate_preview_dom_binding_check,
        render_preview_table_html,
    )
    from professional_strategy_render import parse_markdown_tables

    dtype = str(document_type or '').strip().lower()
    if dtype != 'strategy':
        return {
            'preview_dom_binding_passed': True,
            'blocking_errors': [],
            'applicable': False,
        }
    results = []
    for schema_id in ('kpi_main', 'kpi_formula'):
        chunk = _extract_schema_table_html(preview_html, schema_id)
        if chunk:
            results.append(
                evaluate_preview_dom_binding_check(chunk, schema_id))
    if not results and sections:
        kpis = sections.get('kpis') or ''
        tables = parse_markdown_tables(kpis)
        if tables and len(tables[0]) >= 2:
            main_hdr, main_row = tables[0][0], tables[0][1]
            html_out = render_preview_table_html(
                main_hdr, [main_row], schema_id='kpi_main', is_rtl=True)
            results.append(
                evaluate_preview_dom_binding_check(html_out, 'kpi_main'))
        if len(tables) >= 2 and len(tables[1]) >= 2:
            form_hdr, form_row = tables[1][0], tables[1][1]
            html_out = render_preview_table_html(
                form_hdr, [form_row], schema_id='kpi_formula', is_rtl=True)
            results.append(
                evaluate_preview_dom_binding_check(html_out, 'kpi_formula'))
    if not results:
        return {
            'preview_dom_binding_passed': False,
            'blocking_errors': ['rel33_preview_schema_tables_missing'],
            'applicable': True,
        }
    blockers: List[str] = []
    for r in results:
        blockers.extend(r.get('blocking_errors') or [])
    passed = all(r.get('preview_dom_binding_passed') for r in results)
    return {
        'preview_dom_binding_passed': passed,
        'blocking_errors': blockers,
        'applicable': True,
        'schema_results': results,
    }


def run_rel33_quality_case(
        case: Dict[str, Any],
        *,
        app_mod: Any = None,
        backend: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Run full REL3.3 quality pipeline for one matrix cell."""
    from release_engine_v3.evidence.docx_text_extractor import (
        extract_docx_visible_text,
    )
    from release_engine_v3.rel31_authority import (
        apply_rel31_authoritative_contract,
        rel3_export_authoritative,
    )
    from release_engine_v3.rel32_complete_strategy_compiler import (
        compile_complete_cyber_ar_technical_strategy,
    )
    from release_engine_v3.rel33_authority import (
        is_rel33_compiler_first,
        is_rel33_domain_authoritative,
        route_key,
    )
    from release_engine_v3.rel33_document_completeness import (
        evaluate_rel33_completeness_gate,
    )
    from release_engine_v3.rel32_frozen_export_lock import (
        emit_rel32_frozen_artifact_export_lock,
    )

    domain = case['domain']
    document_type = case['document_type']
    lang = case.get('lang', 'ar')
    doc_subtype = case.get('doc_subtype', '')
    flags = {'rel3': True, 'rel31': True, 'rel32': True}

    _reset_export_state()
    app_mod = app_mod or _load_app_module()
    backend = backend or app_mod._rel31_backend_callables()
    backend = dict(backend)
    backend['flags'] = dict(flags)
    backend['lang'] = lang
    backend['document_type'] = document_type

    blockers: List[str] = []
    sections = load_sections_for_case(case)
    if not sections:
        return {
            'domain': domain,
            'document_type': document_type,
            'lang': lang,
            'doc_subtype': doc_subtype,
            'compiler_first': False,
            'completeness_gate_passed': False,
            'preview_dom_binding_passed': False,
            'frozen_export_lock_passed': False,
            'docx_returned_file_evidence_passed': False,
            'pdf_returned_file_evidence_passed': False,
            'canonical_hash_equal': False,
            'render_tree_hash_equal': False,
            'staging_smoke_passed': False,
            'legacy_path_used': True,
            'accepted': False,
            'blockers': ['rel33_sections_unavailable'],
        }

    compiler_first = is_rel33_compiler_first(
        domain=domain, lang=lang, flags=flags, document_type=document_type)
    if compiler_first:
        compiled = compile_complete_cyber_ar_technical_strategy(
            sections,
            request_context={
                'lang': lang,
                'domain': domain,
                'document_type': document_type,
                'flags': flags,
                'backend': backend,
                'maturity_level': 'developing',
                'roadmap_horizon_months': 18,
                'selected_frameworks': (
                    ['NCA ECC', 'NCA DCC'] if domain == 'cyber' else []),
            },
        )
        if compiled.legacy_sections:
            sections = dict(compiled.legacy_sections)
        blockers.extend(compiled.blocking_errors or [])

    completeness = evaluate_rel33_completeness_gate(
        sections, domain=domain, document_type=document_type, lang=lang)

    strategy_id = (
        f'rel33-{domain}-{document_type}-{lang}'
        + (f'-{doc_subtype}' if doc_subtype else ''))
    md = app_mod._prcy65_rebuild_content_from_sections(sections, None)
    art: Dict[str, Any] = {
        'sections': sections,
        'final_markdown': md,
        'domain': domain,
        'document_type': document_type,
        'strategy_id': strategy_id,
        'contract_meta': {
            'lang': lang,
            'domain': domain,
            'document_type': document_type,
            'doc_subtype': doc_subtype,
        },
    }

    log_buf = io.StringIO()
    with redirect_stdout(log_buf):
        art = apply_rel31_authoritative_contract(
            art, backend=backend, flags=flags)
    contract = art.get('rel31_generation_contract') or {}
    generation_save_allowed = bool(contract.get('generation_save_allowed'))
    if not generation_save_allowed:
        blockers.extend(contract.get('blocking_errors') or [])

    export_kwargs = {
        'filename': f'{domain}_{document_type}.docx',
        'lang': lang,
        'domain': domain,
        'selected_frameworks': (
            ['NCA ECC', 'NCA DCC'] if domain == 'cyber' else []),
    }
    routes: Dict[str, Any] = {}
    evidences: Dict[str, Any] = {}
    for route in ('preview', 'docx', 'pdf'):
        with redirect_stdout(log_buf):
            export, evidence = rel3_export_authoritative(
                route,
                art,
                backend=backend,
                flags=flags,
                export_kwargs=export_kwargs,
            )
        routes[route] = export
        evidences[route] = evidence

    with redirect_stdout(log_buf):
        lock = emit_rel32_frozen_artifact_export_lock(strategy_id)

    preview_html = (
        getattr(evidences.get('preview'), 'preview_html', None)
        or getattr(routes.get('preview'), 'preview_html', None)
        or (evidences.get('preview').preview_text if evidences.get('preview') else '')
        or ''
    )
    dom = evaluate_preview_dom_for_document(
        preview_html, document_type, sections=sections)

    canon = {r: getattr(routes[r], 'canonical_hash', '') for r in routes}
    tree = {r: getattr(routes[r], 'render_tree_hash', '') for r in routes}
    canon_vals = [v for v in canon.values() if v]
    tree_vals = [v for v in tree.values() if v]
    canonical_hash_equal = len(canon_vals) >= 2 and len(set(canon_vals)) == 1
    render_tree_hash_equal = len(tree_vals) >= 2 and len(set(tree_vals)) == 1

    docx_ev = evidences.get('docx')
    pdf_ev = evidences.get('pdf')
    docx_ok = bool(getattr(docx_ev, 'export_return_allowed', False))
    pdf_ok = bool(getattr(pdf_ev, 'export_return_allowed', False))
    if docx_ok and routes.get('docx'):
        docx_bytes = getattr(routes['docx'], 'docx_bytes', None) or b''
        if not docx_bytes:
            docx_ok = False
            blockers.append('rel33_docx_bytes_missing')
        else:
            _ = extract_docx_visible_text(docx_bytes)
    if pdf_ok and routes.get('pdf'):
        pdf_bytes = getattr(routes['pdf'], 'pdf_bytes', None) or b''
        if not pdf_bytes:
            pdf_ok = False
            blockers.append('rel33_pdf_bytes_missing')
    if not docx_ok:
        blockers.extend(list(getattr(docx_ev, 'blocking_errors', None) or []))
    if not pdf_ok:
        blockers.extend(list(getattr(pdf_ev, 'blocking_errors', None) or []))

    lock_ok = bool(lock.get('export_lock_passed'))
    if compiler_first:
        lock_ok = (
            lock_ok
            and lock.get('frozen_artifact_loaded_for_docx')
            and lock.get('frozen_artifact_loaded_for_pdf')
            and not lock.get('docx_rebuilt_from_markdown')
            and not lock.get('pdf_rebuilt_from_markdown')
            and lock.get('blocking_errors') == []
        )
    else:
        lock_ok = not lock.get('docx_rebuilt_from_markdown') and not lock.get(
            'pdf_rebuilt_from_markdown')

    legacy_path_used = bool(
        lock.get('docx_rebuilt_from_markdown')
        or lock.get('pdf_rebuilt_from_markdown')
        or art.get('_legacy_markdown_authority'))

    rel33_authoritative = is_rel33_domain_authoritative(
        domain=domain, lang=lang, flags=flags)
    row = {
        'domain': domain,
        'document_type': document_type,
        'lang': lang,
        'doc_subtype': doc_subtype,
        'route_key': route_key(
            domain=domain, document_type=document_type, lang=lang,
            doc_subtype=doc_subtype),
        'tier': case.get('tier', ''),
        'rel33_authoritative': rel33_authoritative,
        'compiler_first': compiler_first,
        'generation_save_allowed': generation_save_allowed,
        'completeness_gate_passed': completeness.get('completeness_gate_passed'),
        'preview_dom_binding_passed': dom.get('preview_dom_binding_passed'),
        'frozen_export_lock_passed': lock_ok,
        'docx_returned_file_evidence_passed': docx_ok,
        'pdf_returned_file_evidence_passed': pdf_ok,
        'canonical_hash_equal': canonical_hash_equal,
        'render_tree_hash_equal': render_tree_hash_equal,
        'staging_smoke_passed': False,
        'legacy_path_used': legacy_path_used,
        'accepted': False,
        'blockers': list(dict.fromkeys(
            blockers
            + (completeness.get('blocking_errors') or [])
            + (dom.get('blocking_errors') or [])
            + (lock.get('blocking_errors') or []))),
        'canonical_hash_by_route': canon,
        'render_tree_hash_by_route': tree,
        'rel32_frozen_lock': lock,
    }
    authority_ok = (
        compiler_first if document_type == 'strategy' else rel33_authoritative)
    row['accepted'] = (
        authority_ok
        and row['generation_save_allowed']
        and row['completeness_gate_passed']
        and row['preview_dom_binding_passed']
        and row['frozen_export_lock_passed']
        and row['docx_returned_file_evidence_passed']
        and row['pdf_returned_file_evidence_passed']
        and row['canonical_hash_equal']
        and row['render_tree_hash_equal']
        and not row['legacy_path_used']
    )
    if not row['accepted'] and not row['blockers']:
        row['blockers'] = ['rel33_acceptance_check_failed']
    return row


def run_rel33_quality_matrix(
        *,
        cases: Optional[List[Dict[str, Any]]] = None,
        app_mod: Any = None,
) -> Dict[str, Any]:
    from release_engine_v3.rel33_authority import REL33_P1_ROUTES, route_key

    cases = cases or build_rel33_matrix_cases()
    rows = [run_rel33_quality_case(c, app_mod=app_mod) for c in cases]
    p1_keys = {
        route_key(
            domain=r['domain'], document_type=r['document_type'],
            lang=r.get('lang', 'ar'), doc_subtype=r.get('doc_subtype', ''))
        for r in rows if r.get('tier') == 'P1'
    }

    for p1 in REL33_P1_ROUTES:
        p1_keys.add(route_key(
            domain=p1['domain'], document_type=p1['document_type'],
            lang=p1['lang'], doc_subtype=p1.get('doc_subtype', '')))
    p1_rows = [
        r for r in rows
        if r.get('route_key') in p1_keys
        or (
            r.get('domain'), r.get('document_type'), r.get('lang'),
            r.get('doc_subtype', ''),
        ) in {
            (p['domain'], p['document_type'], p['lang'], p.get('doc_subtype', ''))
            for p in REL33_P1_ROUTES
        }
    ]
    report = {
        'tag': 'REL33-ALL-DOMAIN-DOCUMENT-QUALITY-MATRIX',
        'matrix_size': len(rows),
        'p1_size': len(p1_rows),
        'accepted_count': sum(1 for r in rows if r.get('accepted')),
        'p1_accepted_count': sum(1 for r in p1_rows if r.get('accepted')),
        'all_p1_accepted': all(r.get('accepted') for r in p1_rows) if p1_rows else False,
        'rows': rows,
    }
    return report


def emit_rel33_matrix_report(report: Dict[str, Any]) -> None:
    print('[REL33-ALL-DOMAIN-DOCUMENT-QUALITY-MATRIX]')
    print(json.dumps(report, ensure_ascii=False, indent=2, default=str))


def ensure_test_env() -> None:
    tmp = tempfile.mkdtemp(prefix='rel33_matrix_')
    os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
    os.environ.setdefault('SECRET_KEY', 'test-secret-key')
    os.environ.setdefault(
        'DATABASE_URL', 'sqlite:///' + os.path.join(tmp, 'test.db'))
    os.environ.setdefault('OPENAI_API_KEY', '')
    os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
