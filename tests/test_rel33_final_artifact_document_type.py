"""REL3.3 — final-artifact strategy fallback gated by document_type.

Live staging @ c60e69f proved the ERM compiler + save + export-prep all produce
clean risk-native content, yet the export authority still blocked ERM because
build_final_document_artifact synthesized a strategy document (## الرؤية والأهداف
الاستراتيجية) via build_strategy_document when legacy_sections arrived empty —
regardless of document_type. These tests pin the fix: risk/risk_assessment never
call the strategy fallback; the compiled risk markdown propagates into the final
artifact; strategy documents keep their fallback.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_TMP = tempfile.mkdtemp(prefix='test_rel33_final_artifact_dtype_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from release_engine_v3 import canonical_document as _cd
from release_engine_v3.canonical_document import (
    _fa_forbidden_headings_in,
    build_final_document_artifact,
)
from release_engine_v3.contracts import RenderTree
from release_engine_v3.domain_codes import normalize_domain_code
from release_engine_v3.exporters.docx_exporter import export_docx
from release_engine_v3.exporters.pdf_exporter import export_pdf
from release_engine_v3.rel33_domain_guard import (
    evaluate_pre_export_bytes_domain_guard,
)
from release_engine_v3.rel33_frozen_completeness import (
    evaluate_risk_sections_complete,
)
from release_engine_v3.rel33_risk_native_compiler import (
    compile_risk_native_artifact,
)
from release_engine_v3.rel33_risk_treatment_evidence import (
    count_treatment_rows_from_sections,
    semantic_risk_treatment_counts,
)

_RAW = ('## الرؤية والأهداف الاستراتيجية\nحوكمة الأمن السيبراني ومركز العمليات '
        'الأمنية.\n## جدول تقييم المخاطر\n| خطر | متوسطة | عالٍ |\n')
_COMPILED = compile_risk_native_artifact(
    _RAW, domain='erm', document_type='risk', lang='ar',
    context={'asset': 'x', 'threat': 'y', 'risk_level': 'HIGH'},
    emit=False)['content']

_RISK_META = {'lang': 'ar', 'domain': 'erm', 'document_type': 'risk'}


def _risk_art(sections=None, final_markdown=''):
    return {
        'sections': sections or {},
        'final_markdown': final_markdown,
        'domain': 'erm', 'document_type': 'risk', 'artifact_type': 'risk',
        'contract_meta': dict(_RISK_META),
    }


def _render_tree(md):
    return RenderTree(artifact_id='r1', canonical_hash='c' * 16,
                      render_tree_hash='r' * 16, nodes=[], markdown_view=md)


def _docx_backend():
    return {'build_docx_bytes': lambda content, filename, lang, **kw: b'PK-docx',
            'split_sections': lambda _c: {}, 'document_type': 'risk'}


def _pdf_backend():
    return {'build_pdf_bytes': lambda content, **kw: b'%PDF-bytes',
            'split_sections': lambda _c: {}, 'document_type': 'risk'}


class StrategyFallbackGatingTests(unittest.TestCase):

    def test_risk_never_calls_strategy_markdown_fallback(self):
        # The md_view strategy fallback (strategy_document_to_markdown) must
        # never run for risk. (build_strategy_document is still used at line 205
        # to derive canonical structure for all types — that maps risk sections
        # and creates no synthetic strategy sections.)
        with mock.patch.object(_cd, 'strategy_document_to_markdown') as _sdm:
            build_final_document_artifact(
                _risk_art(sections={}, final_markdown=_COMPILED))
            _sdm.assert_not_called()

    def test_risk_empty_and_no_compiled_never_calls_strategy_markdown(self):
        with mock.patch.object(_cd, 'strategy_document_to_markdown') as _sdm:
            art = build_final_document_artifact(_risk_art({}, ''))
            _sdm.assert_not_called()
        self.assertIn('rel33_risk_artifact_empty_sections', art.blocking_errors)

    def test_risk_never_emits_vision_heading(self):
        art = build_final_document_artifact(_risk_art({}, _COMPILED))
        self.assertNotIn('الرؤية والأهداف الاستراتيجية', art.final_markdown_view)
        self.assertEqual(_fa_forbidden_headings_in(art.final_markdown_view), [])

    def test_risk_uses_compiled_markdown_when_sections_empty(self):
        art = build_final_document_artifact(_risk_art({}, _COMPILED))
        self.assertTrue(art.final_markdown_view.strip())
        # Compiled markdown used directly → the register table is preserved.
        self.assertIn('سجل المخاطر', art.final_markdown_view)
        self.assertEqual(art.final_markdown_view.strip(), _COMPILED.strip())

    def test_risk_builds_from_risk_sections_when_markdown_empty(self):
        secs = {
            'register': '| # | خطر |\n|---|---|\n| 1 | توقف الخدمة |\n',
            'treatments': '| # | ضابط | المالك |\n|---|---|---|\n'
                          '| 1 | خطة استمرارية | مالك المخاطر |\n',
        }
        art = build_final_document_artifact(_risk_art(secs, ''))
        self.assertEqual(_fa_forbidden_headings_in(art.final_markdown_view), [])
        self.assertIn('توقف الخدمة', art.final_markdown_view)

    def test_risk_empty_fails_closed(self):
        art = build_final_document_artifact(_risk_art({}, ''))
        self.assertIn('rel33_risk_artifact_empty_sections', art.blocking_errors)
        self.assertFalse(art.final_markdown_view.strip())

    def test_final_risk_markdown_no_forbidden_headings(self):
        art = build_final_document_artifact(_risk_art({}, _COMPILED))
        self.assertEqual(_fa_forbidden_headings_in(art.final_markdown_view), [])

    def test_strategy_still_uses_strategy_fallback(self):
        with mock.patch.object(
                _cd, 'build_strategy_document',
                wraps=_cd.build_strategy_document) as _bsd:
            art = build_final_document_artifact({
                'sections': {}, 'domain': 'cyber', 'document_type': 'strategy',
                'contract_meta': {'lang': 'ar', 'domain': 'cyber',
                                  'document_type': 'strategy'}})
            _bsd.assert_called()
        self.assertTrue(art.final_markdown_view.strip())


class FinalRiskGatePassTests(unittest.TestCase):
    """Final risk markdown passes isolation / completeness / treatment ev."""

    def setUp(self):
        self.art = build_final_document_artifact(_risk_art({}, _COMPILED))
        from release_engine_v3.rel33_risk_artifact import (
            _split_risk_markdown, normalize_risk_export_sections,
        )
        self.secs = normalize_risk_export_sections(
            _split_risk_markdown(self.art.final_markdown_view))

    def test_passes_risk_domain_isolation(self):
        blk = evaluate_pre_export_bytes_domain_guard(
            self.secs, domain='erm', route='docx', document_type='risk')
        self.assertEqual(blk, [], blk)

    def test_passes_frozen_completeness(self):
        ok, present, missing = evaluate_risk_sections_complete(self.secs)
        self.assertTrue(ok, missing)

    def test_passes_treatment_evidence(self):
        rk, tk = count_treatment_rows_from_sections(self.secs)
        sem = semantic_risk_treatment_counts(self.secs)
        self.assertGreater(int(tk) + int(sem.get('treatment_rows') or 0), 0)


class FinalRiskExportTests(unittest.TestCase):

    def setUp(self):
        self.md = build_final_document_artifact(
            _risk_art({}, _COMPILED)).final_markdown_view

    def test_docx_export_passes(self):
        res = export_docx(_render_tree(self.md), backend=_docx_backend(),
                          domain='erm', document_type='risk')
        self.assertEqual(res.blocking_errors, [], res.blocking_errors)
        self.assertEqual(res.bytes_data, b'PK-docx')
        for b in res.blocking_errors:
            self.assertNotIn(':vision:', b)
            self.assertNotIn('الرؤية', b)

    def test_pdf_export_passes(self):
        res = export_pdf(_render_tree(self.md), backend=_pdf_backend(),
                         domain='erm', document_type='risk')
        self.assertEqual(res.blocking_errors, [], res.blocking_errors)
        self.assertEqual(res.bytes_data, b'%PDF-bytes')

    def test_no_roadmap_model_drift_for_risk(self):
        from release_engine.export_evidence_validator import (
            validate_actual_export_evidence,
        )
        from release_engine_v3.rel33_risk_artifact import (
            _split_risk_markdown, normalize_risk_export_sections,
        )
        secs = normalize_risk_export_sections(_split_risk_markdown(self.md))
        out = validate_actual_export_evidence(
            docx_text=self.md, domain='erm', lang='ar', document_type='risk',
            route_name='docx', canonical_sections=secs)
        blk = out.get('blocking_errors') or []
        self.assertFalse(any('roadmap_visible_row_count' in b for b in blk), blk)
        self.assertFalse(any(':vision:' in b for b in blk), blk)


class DiagnosticTests(unittest.TestCase):

    def test_diag_emitted_for_risk(self):
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            build_final_document_artifact(_risk_art({}, _COMPILED))
        out = buf.getvalue()
        self.assertIn('[REL33-FINAL-ARTIFACT-DOCUMENT-TYPE-DIAG]', out)
        self.assertIn('document_type_risk', out)
        self.assertIn('"strategy_fallback_applied": false', out)


if __name__ == '__main__':
    unittest.main()
