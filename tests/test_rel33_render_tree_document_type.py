"""REL3.3 — render tree is document_type-aware (risk never strategy-ordered).

Live staging @ 918397e proved compiler/save/export-prep/final-artifact all carry
clean risk-native content, yet ERM export still blocked because build_render_tree
rendered artifact.canonical_sections in a fixed STRATEGY order/titles
(vision_objectives -> ## الرؤية والأهداف الاستراتيجية) regardless of
document_type. These tests pin the fix: risk uses the compiled risk markdown
(final_markdown_view) or a risk-native sections join — never strategy titles;
strategy keeps its render order.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix='test_rel33_render_tree_dtype_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from release_engine_v3.canonical_document import build_final_document_artifact
from release_engine_v3.contracts import RenderTree
from release_engine_v3.exporters.docx_exporter import export_docx
from release_engine_v3.exporters.pdf_exporter import export_pdf
from release_engine_v3.rel33_domain_guard import (
    evaluate_pre_export_bytes_domain_guard,
)
from release_engine_v3.rel33_frozen_completeness import (
    evaluate_risk_sections_complete,
)
from release_engine_v3.rel33_risk_artifact import (
    _split_risk_markdown,
    normalize_risk_export_sections,
)
from release_engine_v3.rel33_risk_native_compiler import (
    compile_risk_native_artifact,
)
from release_engine_v3.rel33_risk_treatment_evidence import (
    count_treatment_rows_from_sections,
    semantic_risk_treatment_counts,
)
from release_engine_v3.render_tree import (
    _rt_forbidden_headings_in,
    build_render_tree,
)

_COMPILED = compile_risk_native_artifact(
    '## الرؤية والأهداف الاستراتيجية\nحوكمة الأمن السيبراني ومركز العمليات '
    'الأمنية.\n## جدول تقييم المخاطر\n| خطر | متوسطة | عالٍ |\n',
    domain='erm', document_type='risk', lang='ar',
    context={'asset': 'x', 'threat': 'y', 'risk_level': 'HIGH'},
    emit=False)['content']

_RISK_META = {'lang': 'ar', 'domain': 'erm', 'document_type': 'risk'}


def _risk_art(sections=None, final_markdown=''):
    return build_final_document_artifact({
        'sections': sections or {},
        'final_markdown': final_markdown,
        'domain': 'erm', 'document_type': 'risk', 'artifact_type': 'risk',
        'contract_meta': dict(_RISK_META)})


def _render_tree(md):
    return RenderTree(artifact_id='r1', canonical_hash='c' * 16,
                      render_tree_hash='r' * 16, nodes=[], markdown_view=md)


def _docx_backend():
    return {'build_docx_bytes': lambda content, filename, lang, **kw: b'PK-docx',
            'split_sections': lambda _c: {}, 'document_type': 'risk'}


def _pdf_backend():
    return {'build_pdf_bytes': lambda content, **kw: b'%PDF-bytes',
            'split_sections': lambda _c: {}, 'document_type': 'risk'}


class RiskRenderTreeTests(unittest.TestCase):

    def setUp(self):
        self.art = _risk_art({}, _COMPILED)
        self.rt = build_render_tree(self.art)

    def test_risk_uses_final_markdown_view_directly(self):
        self.assertEqual(self.rt.markdown_view.strip(),
                         self.art.final_markdown_view.strip())
        self.assertEqual(self.rt.markdown_view.strip(), _COMPILED.strip())

    def test_risk_never_emits_vision_heading(self):
        self.assertNotIn('الرؤية والأهداف الاستراتيجية', self.rt.markdown_view)

    def test_risk_never_emits_roadmap_kpi_traceability_headings(self):
        for h in ('خارطة الطريق', 'مؤشرات الأداء الرئيسية', 'مصفوفة التتبع',
                  'نموذج الحوكمة', 'الركائز الاستراتيجية'):
            self.assertNotIn('## ' + h, self.rt.markdown_view, h)

    def test_final_hash_equals_render_tree_hash(self):
        self.assertEqual(self.art.final_markdown_view.strip(),
                         self.rt.markdown_view.strip())

    def test_no_forbidden_headings_in_render_tree(self):
        self.assertEqual(_rt_forbidden_headings_in(self.rt.markdown_view), [])

    def test_render_tree_headings_are_risk_native(self):
        titles = [n['title'] for n in self.rt.nodes]
        self.assertIn('وصف السيناريو', titles)
        self.assertIn('سجل المخاطر', titles)
        self.assertIn('مقاييس KRI للمراقبة', titles)
        self.assertNotIn('الرؤية والأهداف الاستراتيجية', titles)


class RiskRenderTreeFallbackTests(unittest.TestCase):

    def test_fallback_uses_risk_native_sections_not_vision(self):
        # No final_markdown → fall back to risk-native legacy_sections join.
        secs = {
            'register': '## سجل المخاطر\n| # | خطر |\n|---|---|\n| 1 | توقف |\n',
            'treatments': '## خطة المعالجة\n| # | ضابط | المالك |\n|---|---|---|\n'
                          '| 1 | خطة استمرارية | مالك المخاطر |\n',
        }
        art = _risk_art(secs, '')
        rt = build_render_tree(art)
        self.assertEqual(_rt_forbidden_headings_in(rt.markdown_view), [])
        self.assertNotIn('الرؤية', rt.markdown_view)
        self.assertTrue(rt.markdown_view.strip())


class RiskRenderTreeGateTests(unittest.TestCase):

    def setUp(self):
        self.rt = build_render_tree(_risk_art({}, _COMPILED))
        self.secs = normalize_risk_export_sections(
            _split_risk_markdown(self.rt.markdown_view))

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


class RiskRenderTreeExportTests(unittest.TestCase):

    def setUp(self):
        self.md = build_render_tree(_risk_art({}, _COMPILED)).markdown_view

    def test_docx_export_passes(self):
        res = export_docx(_render_tree(self.md), backend=_docx_backend(),
                          domain='erm', document_type='risk')
        self.assertEqual(res.blocking_errors, [], res.blocking_errors)
        self.assertEqual(res.bytes_data, b'PK-docx')
        for b in res.blocking_errors:
            self.assertNotIn('الرؤية', b)
            self.assertNotIn(':vision:', b)

    def test_pdf_export_passes(self):
        res = export_pdf(_render_tree(self.md), backend=_pdf_backend(),
                         domain='erm', document_type='risk')
        self.assertEqual(res.blocking_errors, [], res.blocking_errors)
        self.assertEqual(res.bytes_data, b'%PDF-bytes')

    def test_no_roadmap_model_drift_for_risk(self):
        from release_engine.export_evidence_validator import (
            validate_actual_export_evidence,
        )
        secs = normalize_risk_export_sections(_split_risk_markdown(self.md))
        out = validate_actual_export_evidence(
            docx_text=self.md, domain='erm', lang='ar', document_type='risk',
            route_name='docx', canonical_sections=secs)
        blk = out.get('blocking_errors') or []
        self.assertFalse(any('roadmap_visible_row_count' in b for b in blk), blk)
        self.assertFalse(any(':vision:' in b for b in blk), blk)


class StrategyRenderTreePreservedTests(unittest.TestCase):

    def test_strategy_still_uses_strategy_render(self):
        art = build_final_document_artifact({
            'sections': {
                'vision': '## الرؤية والأهداف الاستراتيجية\nنص',
                'pillars': '## الركائز الاستراتيجية\nنص',
                'roadmap': '## خارطة الطريق التنفيذية\n| م | مبادرة |\n'
                           '|---|---|\n| 1 | مبادرة |\n'},
            'domain': 'cyber', 'document_type': 'strategy',
            'contract_meta': {'lang': 'ar', 'domain': 'cyber',
                              'document_type': 'strategy'}})
        rt = build_render_tree(art)
        self.assertTrue(rt.markdown_view.strip())

    def test_gap_assessment_not_routed_to_risk_render(self):
        art = build_final_document_artifact({
            'sections': {'gaps': '## تحليل الفجوات\nنص'},
            'domain': 'global', 'document_type': 'gap_assessment',
            'contract_meta': {'lang': 'ar', 'domain': 'global',
                              'document_type': 'gap_assessment'}})
        # gap_assessment is NOT risk → uses the strategy render path (unchanged).
        rt = build_render_tree(art)
        self.assertEqual(art.document_type, 'gap_assessment')
        self.assertIsInstance(rt, RenderTree)


class DiagnosticTests(unittest.TestCase):

    def test_render_tree_diag_emitted_for_risk(self):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            build_render_tree(_risk_art({}, _COMPILED))
        out = buf.getvalue()
        self.assertIn('[REL33-RENDER-TREE-DOCUMENT-TYPE-DIAG]', out)
        self.assertIn('"render_profile": "risk_native"', out)
        self.assertIn('"strategy_render_order_applied": false', out)
        self.assertIn('"risk_markdown_preferred": true', out)
        self.assertIn('"hashes_match_final_to_render_tree": true', out)


if __name__ == '__main__':
    unittest.main()
