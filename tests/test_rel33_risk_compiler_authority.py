"""REL3.3 — document-type compiler authority for risk exports.

Regression cover for the live staging blocker where an ERM risk artifact was
compiled through the REL32 *strategy* compiler (synthesizing vision/pillars/
environment/roadmap/kpis) and then blocked by the domain guard on the compiled
strategy sections. Risk artifacts must be compiled/frozen/rendered from their
risk-native sections only; the strategy compiler must fail closed if ever
reached with a risk document_type.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix='test_rel33_risk_compiler_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from release_engine_v3.canonical_document import (  # noqa: E402
    _legacy_to_canonical_sections,
    build_final_document_artifact,
)
from release_engine_v3.rel32_compiler import (  # noqa: E402
    compile_canonical_strategy_document,
)
from release_engine_v3.rel33_domain_guard import select_rel33_compiler  # noqa: E402

# Risk-native section set (register + treatments), no strategy sections.
_RISK_SECTIONS = {
    'register': (
        '## سجل المخاطر\n\n| المخاطرة | الاحتمالية | التأثير | المالك |\n'
        '|---|---|---|---|\n'
        '| الوصول غير المصرح به | متوسطة | عالٍ | مدير المخاطر |\n'),
    'treatments': (
        '## خطة المعالجة\n\n| الضابط | النوع | المالك |\n|---|---|---|\n'
        '| مراجعة الصلاحيات | وقائي | مدير المخاطر |\n'),
}

_STRATEGY_SECTIONS = {
    'vision': '## الرؤية\n\nرؤية استراتيجية.\n',
    'pillars': '## الركائز\n\nركائز.\n',
}

_BACKEND = {'flags': {'rel3': True, 'rel31': True, 'rel32': True}}


class CompilerSelectionTests(unittest.TestCase):
    """#1/#11/#12 — compiler authority is selected by document_type."""

    def test_risk_selects_risk_native(self):
        self.assertEqual(select_rel33_compiler('risk'), 'risk_native')
        self.assertEqual(select_rel33_compiler('risk_assessment'), 'risk_native')

    def test_strategy_selects_strategy(self):
        self.assertEqual(select_rel33_compiler('strategy'), 'strategy')
        self.assertEqual(select_rel33_compiler(''), 'strategy')

    def test_gap_selects_gap_native(self):
        self.assertEqual(select_rel33_compiler('gap_assessment'), 'gap_native')


class RiskNeverCompiledAsStrategyTests(unittest.TestCase):
    """#1/#8 — risk canonical build never runs the strategy compiler."""

    def test_risk_canonical_build_skips_strategy_compiler(self):
        canon, legacy, authority_blockers = _legacy_to_canonical_sections(
            dict(_RISK_SECTIONS), lang='ar', domain='erm',
            backend=dict(_BACKEND), document_type='risk')
        # No wrong-compiler block on the normal risk path.
        self.assertEqual(authority_blockers, [])
        # Sections are NOT replaced by synthesized strategy registry content.
        self.assertIn('register', legacy)
        self.assertIn('سجل المخاطر', legacy['register'])
        # No synthesized strategy substance (e.g., ISO 31000 vision lede).
        self.assertNotIn('ISO 31000', legacy.get('vision', ''))

    def test_strategy_canonical_build_still_runs_compiler(self):
        # Preserve strategy behavior: the compiler runs for strategy (cyber).
        canon, legacy, authority_blockers = _legacy_to_canonical_sections(
            dict(_STRATEGY_SECTIONS), lang='ar', domain='cyber',
            backend=dict(_BACKEND), document_type='strategy')
        self.assertEqual(authority_blockers, [])
        # Compiler synthesized the full strategy taxonomy.
        self.assertTrue(
            any(k in legacy for k in ('roadmap', 'kpis', 'governance')))


class StrategyCompilerFailsClosedForRiskTests(unittest.TestCase):
    """#2/#9 — strategy compiler blocks on a risk document_type."""

    def test_compile_canonical_strategy_document_blocks_risk(self):
        res = compile_canonical_strategy_document(
            dict(_RISK_SECTIONS),
            request_context={
                'lang': 'ar', 'domain': 'erm', 'document_type': 'risk',
                'backend': dict(_BACKEND)},
        )
        self.assertFalse(res.passed)
        self.assertIn(
            'rel33_wrong_compiler_for_document_type:risk',
            res.blocking_errors)
        # It must NOT synthesize strategy sections.
        self.assertNotIn('vision', res.legacy_sections)

    def test_compile_via_backend_document_type_blocks_risk(self):
        res = compile_canonical_strategy_document(
            dict(_RISK_SECTIONS),
            request_context={
                'lang': 'ar', 'domain': 'erm',
                'backend': {**_BACKEND, 'document_type': 'risk_assessment'}},
        )
        self.assertFalse(res.passed)
        self.assertIn(
            'rel33_wrong_compiler_for_document_type:risk_assessment',
            res.blocking_errors)


class DocumentTypePreservedTests(unittest.TestCase):
    """#3/#4/#5 — document_type=risk preserved; no Strategy Document fallback."""

    def test_build_final_artifact_preserves_risk_document_type(self):
        art = build_final_document_artifact(
            {
                'sections': dict(_RISK_SECTIONS),
                'domain': 'erm',
                'language': 'ar',
                'document_type': 'risk',
                'contract_meta': {
                    'lang': 'ar', 'domain': 'erm', 'document_type': 'risk'},
                '_rel32_backend': dict(_BACKEND),
            },
            strategy_id='risk-1',
        )
        self.assertEqual(art.document_type, 'risk')
        # Risk-native content preserved (not overwritten by strategy synthesis).
        self.assertIn('register', art.legacy_sections)

    def test_repair_canonical_before_freeze_skips_strategy_for_risk(self):
        from release_engine_v3.rel31_authority import (
            repair_canonical_before_freeze,
        )
        art = {
            'sections': dict(_RISK_SECTIONS),
            'domain': 'erm',
            'document_type': 'risk',
            'contract_meta': {'lang': 'ar', 'domain': 'erm',
                              'document_type': 'risk'},
        }
        out, repairs = repair_canonical_before_freeze(
            art, backend={'lang': 'ar', 'domain': 'erm',
                          'document_type': 'risk',
                          'flags': _BACKEND['flags']})
        # Strategy compiler markers must not appear for a risk artifact.
        self.assertNotIn('_rel32_compiled', out)


class RiskExportEndToEndTests(unittest.TestCase):
    """#6/#7/#8 — DOCX/PDF export of risk uses risk-native sections."""

    def _export(self, route):
        import app
        art = {
            'sections': dict(_RISK_SECTIONS),
            'final_markdown': (
                _RISK_SECTIONS['register'] + '\n\n'
                + _RISK_SECTIONS['treatments']),
            'domain': 'erm',
            'artifact_type': 'risk',
            'document_type': 'risk',
            'strategy_id': '1',
            'artifact_id': '1',
            'contract_meta': {
                'lang': 'ar', 'domain': 'erm',
                'selected_frameworks': ['ISO 31000'],
                'document_type': 'risk'},
        }
        be = app._rel31_backend_callables()
        return app._rel31_authoritative_export_route(
            route, artifact_dict=art, domain='erm', lang='ar', backend=be)

    def test_docx_risk_export_allowed(self):
        res = self._export('docx')
        self.assertIsNotNone(res)
        _export, ev = res
        self.assertTrue(
            ev.export_return_allowed,
            f'docx blockers={ev.blocking_errors}')

    def test_pdf_risk_export_allowed(self):
        res = self._export('pdf')
        self.assertIsNotNone(res)
        _export, ev = res
        self.assertTrue(
            ev.export_return_allowed,
            f'pdf blockers={ev.blocking_errors}')


class GapAssessmentPreservedTests(unittest.TestCase):
    """#10 — gap_assessment keeps document_type and is not risk-native."""

    def test_gap_document_type_preserved(self):
        art = build_final_document_artifact(
            {
                'sections': {'gaps': '## تحليل الفجوات\n\nفجوات.\n'},
                'domain': 'global',
                'language': 'ar',
                'document_type': 'gap_assessment',
                'contract_meta': {
                    'lang': 'ar', 'domain': 'global',
                    'document_type': 'gap_assessment'},
                '_rel32_backend': dict(_BACKEND),
            },
            strategy_id='gap-1',
        )
        # No Strategy Document fallback: document_type is preserved.
        self.assertEqual(art.document_type, 'gap_assessment')


if __name__ == '__main__':
    unittest.main()
