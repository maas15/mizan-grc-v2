#!/usr/bin/env python3
"""Generate REL35 fidelity sample DOCX/PDF exports for local inspection."""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault(
    'DATABASE_URL',
    'sqlite:///' + os.path.join(tempfile.mkdtemp(prefix='rel35_samples_'), 't.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

from release_engine_v3.evidence.docx_text_extractor import extract_docx_visible_text
from release_engine_v3.rel31_authority import (
    apply_rel31_authoritative_contract,
    rel3_export_authoritative,
)
from release_engine_v3.rel32_complete_strategy_compiler import (
    compile_complete_cyber_ar_technical_strategy,
)
from release_engine_v3.rel33_quality_matrix import (
    _load_app_module,
    _reset_export_state,
    ensure_test_env,
    load_sections_for_case,
)
from release_engine_v3.rel35_domain_framework_fidelity import (
    detect_forbidden_domain_terms,
    detect_visible_frameworks,
    dga_interoperability_covered,
    emit_rel35_domain_framework_fidelity,
    repair_sections_for_fidelity,
)

OUT = ROOT / 'qa_outputs' / 'rel35_samples'
CASES = (
    ('cyber', ['NCA ECC', 'NCA DCC'], ('NCA ECC', 'NCA DCC')),
    ('data', ['NDMO', 'PDPL'], ()),
    ('ai', ['SDAIA'], ()),
    ('dt', ['DGA'], ()),
)
FORBIDDEN = (
    'NCA ECC', 'NCA DCC', 'CISO', 'SIEM', 'SOAR', 'SOC/SIEM', 'CSIRT',
    'فريق الأمن السيبراني', 'NIST AI RMF',
)


def _pdf_text(pdf_bytes: bytes) -> str:
    try:
        from release_engine_v3.rel32_kpi_main_schema_evidence import (
            extract_pdf_text,
        )
        return extract_pdf_text(pdf_bytes) or ''
    except Exception:
        try:
            from PyPDF2 import PdfReader
            import io
            reader = PdfReader(io.BytesIO(pdf_bytes))
            return '\n'.join((p.extract_text() or '') for p in reader.pages)
        except Exception:
            return ''


def main() -> int:
    ensure_test_env()
    OUT.mkdir(parents=True, exist_ok=True)
    app_mod = _load_app_module()
    backend = app_mod._rel31_backend_callables()
    report = []
    for domain, selected, allowed_extra in CASES:
        _reset_export_state()
        sections = load_sections_for_case({
            'domain': domain, 'document_type': 'strategy', 'lang': 'ar',
            'doc_subtype': 'technical' if domain == 'cyber' else '',
        })
        compiled = compile_complete_cyber_ar_technical_strategy(
            sections,
            request_context={
                'lang': 'ar', 'domain': domain, 'document_type': 'strategy',
                'flags': {'rel3': True, 'rel31': True},
                'backend': backend,
                'maturity_level': 'developing',
                'roadmap_horizon_months': 18,
                'selected_frameworks': selected,
            },
        )
        if compiled.legacy_sections:
            sections = dict(compiled.legacy_sections)
        sections, diag = repair_sections_for_fidelity(
            sections, domain=domain, document_type='strategy',
            selected_frameworks=selected, lang='ar')
        emit_rel35_domain_framework_fidelity(diag)
        md = app_mod._prcy65_rebuild_content_from_sections(sections, None)
        art = {
            'sections': sections,
            'final_markdown': md,
            'domain': domain,
            'document_type': 'strategy',
            'strategy_id': f'rel35-{domain}-fidelity',
            'artifact_id': f'rel35-{domain}-fidelity',
            'contract_meta': {
                'lang': 'ar', 'domain': domain, 'document_type': 'strategy',
            },
        }
        flags = {'rel3': True, 'rel31': True}
        art = apply_rel31_authoritative_contract(art, backend=backend, flags=flags)
        kwargs = {
            'filename': f'rel35_{domain}_strategy.docx',
            'lang': 'ar',
            'domain': domain,
            'document_type': 'strategy',
            'doc_type': 'Strategy Document',
            'selected_frameworks': selected,
        }
        docx, docx_ev = rel3_export_authoritative(
            'docx', art, backend=backend, flags=flags, export_kwargs=kwargs)
        pdf, pdf_ev = rel3_export_authoritative(
            'pdf', art, backend=backend, flags=flags,
            export_kwargs={**kwargs, 'filename': f'rel35_{domain}_strategy.pdf'})
        docx_path = OUT / f'{domain}_strategy.docx'
        pdf_path = OUT / f'{domain}_strategy.pdf'
        docx_path.write_bytes(getattr(docx, 'docx_bytes', None) or b'')
        pdf_path.write_bytes(getattr(pdf, 'pdf_bytes', None) or b'')
        docx_text = extract_docx_visible_text(docx_path.read_bytes())
        pdf_text = _pdf_text(pdf_path.read_bytes())
        visible = docx_text + '\n' + pdf_text
        allowed_here = set(selected) | set(allowed_extra)
        if domain == 'cyber':
            allowed_here.update({
                'CISO', 'SIEM', 'SOAR', 'SOC/SIEM', 'CSIRT',
                'فريق الأمن السيبراني',
            })
        forbidden = [
            t for t in FORBIDDEN
            if t in visible and t not in allowed_here]
        row = {
            'domain': domain,
            'selected_frameworks': selected,
            'docx': str(docx_path),
            'pdf': str(pdf_path),
            'docx_bytes': docx_path.stat().st_size,
            'pdf_bytes': pdf_path.stat().st_size,
            'docx_allowed': bool(getattr(docx_ev, 'export_return_allowed', False)),
            'pdf_allowed': bool(getattr(pdf_ev, 'export_return_allowed', False)),
            'visible_frameworks': detect_visible_frameworks(visible),
            'forbidden_detected': forbidden,
            'dga_interop': dga_interoperability_covered(sections),
            'has_roadmap': 'خارطة' in visible or 'المرحلة' in visible,
            'has_kpi': 'مؤشر' in visible,
            'has_appendix_c': 'ملحق ج' in visible or 'Appendix C' in visible,
            'diag': diag,
        }
        report.append(row)
        print(json.dumps(row, ensure_ascii=False, default=str))
    out_json = OUT / 'inspection.json'
    out_json.write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str),
                        encoding='utf-8')
    print('REL35_SAMPLES=' + str(OUT))
    return 0 if all(
        r['docx_allowed'] and r['pdf_allowed'] and not r['forbidden_detected']
        and (r['dga_interop'] if r['domain'] == 'dt' else True)
        for r in report) else 1


if __name__ == '__main__':
    raise SystemExit(main())
