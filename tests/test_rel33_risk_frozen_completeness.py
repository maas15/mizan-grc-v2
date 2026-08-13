"""REL3.3 — risk PDF frozen completeness is document-type aware.

Regression cover for the live staging blocker where an ERM risk PDF export was
blocked with ``rel32_incomplete_frozen_artifact`` because the frozen-lock
resolved the artifact as a strategy (the PDF export dict omitted
``document_type``). Risk artifacts must use a risk-native completeness profile,
fail closed with ``rel33_incomplete_risk_frozen_artifact`` (never the strategy
code), and render non-empty bytes; strategy behavior is unchanged.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix='test_rel33_risk_frozen_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import app  # noqa: E402
from release_engine_v3.rel32_frozen_export_lock import (  # noqa: E402
    resolve_frozen_artifact_for_export,
)
from release_engine_v3.rel33_frozen_completeness import (  # noqa: E402
    evaluate_risk_sections_complete,
)

_FLAGS = {'rel3': True, 'rel31': True}

_RISK_REGISTER = (
    '## سجل المخاطر\n\n| المخاطرة | الاحتمالية | التأثير | المالك |\n'
    '|---|---|---|---|\n'
    '| الوصول غير المصرح به | متوسطة | عالٍ | مدير المخاطر |\n')
_RISK_TREATMENTS = (
    '## خطة المعالجة\n\n| الضابط | النوع | المالك |\n|---|---|---|\n'
    '| مراجعة الصلاحيات الدورية | وقائي | مدير المخاطر |\n')
_RISK_SECTIONS = {'register': _RISK_REGISTER, 'treatments': _RISK_TREATMENTS}
_RISK_MARKDOWN = _RISK_REGISTER + '\n\n' + _RISK_TREATMENTS


def _risk_art(sections, *, artifact_id='1'):
    return {
        'sections': dict(sections),
        'final_markdown': _RISK_MARKDOWN,
        'domain': 'erm',
        'artifact_type': 'risk',
        'document_type': 'risk',
        'strategy_id': artifact_id,
        'artifact_id': artifact_id,
        'final_hash': 'hash-' + artifact_id,
        'contract_meta': {
            'lang': 'ar', 'domain': 'erm', 'document_type': 'risk',
            'selected_frameworks': ['ISO 31000']},
    }


class RiskNativeFrozenCompletenessTests(unittest.TestCase):
    """#1/#2/#3/#5 — risk uses risk-native completeness, not strategy fields."""

    def test_complete_risk_passes_clean(self):
        be = app._rel31_backend_callables()
        _frozen, meta = resolve_frozen_artifact_for_export(
            _risk_art(_RISK_SECTIONS), backend=be, route='pdf', flags=_FLAGS)
        self.assertEqual(meta.get('completeness_profile'), 'risk_native')
        self.assertEqual(meta.get('blocking_errors'), [])
        self.assertTrue(meta.get('frozen_artifact_complete'))

    def test_no_rel32_incomplete_for_complete_risk(self):
        for route in ('docx', 'pdf'):
            be = app._rel31_backend_callables()
            _f, meta = resolve_frozen_artifact_for_export(
                _risk_art(_RISK_SECTIONS), backend=be, route=route,
                flags=_FLAGS)
            self.assertNotIn(
                'rel32_incomplete_frozen_artifact',
                meta.get('blocking_errors') or [], f'route={route}')

    def test_valid_risk_sections_complete(self):
        complete, present, missing = evaluate_risk_sections_complete(
            _RISK_SECTIONS, final_hash='h')
        self.assertTrue(complete, f'missing={missing}')
        self.assertIn('treatment_rows', present)
        self.assertIn('risk_register_rows', present)

    def test_semantic_control_section_counts_as_treatment(self):
        # Slugified Arabic control/mitigation section (الضوابط / التخفيف) must be
        # recognized as treatment rows even though it is not keyed 'treatments'.
        secs = {
            'register': _RISK_REGISTER,
            '4_1_الضوابط_الأولية_التخفيف_الفوري': (
                '## 4.1 الضوابط الأولية — التخفيف الفوري\n'
                '| الضابط | المالك |\n|---|---|\n'
                '| مراجعة الصلاحيات | مدير المخاطر |\n'
                '| فصل المهام | لجنة المخاطر |\n'),
        }
        complete, present, missing = evaluate_risk_sections_complete(
            secs, final_hash='h')
        self.assertIn('treatment_rows', present, f'missing={missing}')
        self.assertTrue(complete, f'missing={missing}')


class RiskFailClosedTests(unittest.TestCase):
    """#4 — incomplete risk fails with the risk-specific code, not strategy."""

    def test_incomplete_risk_uses_risk_error(self):
        be = app._rel31_backend_callables()
        _f, meta = resolve_frozen_artifact_for_export(
            _risk_art({'register': _RISK_REGISTER}, artifact_id='2'),
            backend=be, route='pdf', flags=_FLAGS)
        self.assertIn('rel33_incomplete_risk_frozen_artifact',
                      meta.get('blocking_errors') or [])
        self.assertNotIn('rel32_incomplete_frozen_artifact',
                         meta.get('blocking_errors') or [])


class RiskExportEndToEndTests(unittest.TestCase):
    """#6/#11/#12 — risk DOCX/PDF export allowed with non-empty bytes."""

    def _export(self, route):
        be = app._rel31_backend_callables()
        return app._rel31_authoritative_export_route(
            route, artifact_dict=_risk_art(_RISK_SECTIONS),
            domain='erm', lang='ar', backend=be)

    def test_pdf_export_allowed_non_empty(self):
        res = self._export('pdf')
        self.assertIsNotNone(res)
        export, ev = res
        self.assertTrue(ev.export_return_allowed, f'blk={ev.blocking_errors}')
        pdf_bytes = (getattr(export, 'pdf_bytes', b'')
                     or getattr(export, 'bytes_data', b'') or b'')
        self.assertGreater(len(pdf_bytes), 100)
        self.assertNotIn('rel32_incomplete_frozen_artifact',
                         ev.blocking_errors or [])

    def test_docx_export_allowed_non_empty(self):
        res = self._export('docx')
        self.assertIsNotNone(res)
        export, ev = res
        self.assertTrue(ev.export_return_allowed, f'blk={ev.blocking_errors}')
        docx_bytes = (getattr(export, 'docx_bytes', b'')
                      or getattr(export, 'bytes_data', b'') or b'')
        self.assertGreater(len(docx_bytes), 100)


class StrategyBehaviorPreservedTests(unittest.TestCase):
    """#7 — strategy artifacts still use the strategy frozen code path."""

    def test_strategy_incomplete_uses_rel32_not_risk(self):
        be = app._rel31_backend_callables()
        be['_rel32_incomplete_frozen_artifact'] = True
        art = {
            'sections': {'vision': 'x'},
            'final_markdown': '## الرؤية\nx',
            'domain': 'cyber',
            'artifact_type': 'strategy',
            'document_type': 'strategy',
            'strategy_id': 'strat-x',
            'artifact_id': 'strat-x',
            'final_hash': 'h',
            'contract_meta': {'lang': 'ar', 'domain': 'cyber',
                              'document_type': 'strategy'},
        }
        _f, meta = resolve_frozen_artifact_for_export(
            art, backend=be, route='pdf', flags=_FLAGS)
        self.assertIn('rel32_incomplete_frozen_artifact',
                      meta.get('blocking_errors') or [])
        self.assertNotIn('rel33_incomplete_risk_frozen_artifact',
                         meta.get('blocking_errors') or [])
        # Strategy never uses the risk-native profile.
        self.assertNotEqual(meta.get('completeness_profile'), 'risk_native')


if __name__ == '__main__':
    unittest.main()
