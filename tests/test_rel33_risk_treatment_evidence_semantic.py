"""REL3.3 — ERM risk export evidence recognizes semantic treatment/controls.

Aligns the export evidence gate (evaluate_erm_risk_treatment_evidence) with the
frozen-completeness semantic treatment/control row counting: control/mitigation
sections with slugified Arabic keys (الضوابط / التخفيف / معالجة, controls,
mitigation) count as treatment rows, so `empty_risk_treatment` is not falsely
raised — while remaining fail-closed for genuinely treatment-less risk.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix='test_rel33_risk_tx_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from release_engine_v3.rel33_frozen_completeness import (  # noqa: E402
    evaluate_risk_sections_complete,
)
from release_engine_v3.rel33_risk_treatment_evidence import (  # noqa: E402
    evaluate_erm_risk_treatment_evidence,
    risk_treatment_defects_for_channel,
    semantic_risk_treatment_counts,
)

_CONTROLS_AR = {
    '4_1_الضوابط_الأولية_التخفيف_الفوري': (
        '## 4.1 الضوابط الأولية — التخفيف الفوري\n'
        '| الضابط | المالك | الأولوية |\n|---|---|---|\n'
        '| مراجعة الصلاحيات | مدير المخاطر | عالية |\n'
        '| فصل المهام | لجنة المخاطر | متوسطة |\n'),
}
_MITIGATION_AR = {
    'اجراءات_التخفيف': (
        '## إجراءات التخفيف\n| الإجراء | المالك |\n|---|---|\n'
        '| تحديث السياسات | مدير المخاطر |\n'),
}
_CONTROLS_EN = {
    '4_controls_and_mitigation': (
        '## 4. Controls and mitigation\n| Control | Owner | Priority |\n'
        '|---|---|---|\n| Access review | Risk Manager | High |\n'),
}
_REGISTER = ('## سجل المخاطر\n| المخاطرة | المالك |\n|---|---|\n'
             '| الوصول غير المصرح | مدير المخاطر |\n')


class SemanticTreatmentCountingTests(unittest.TestCase):
    """#1/#2/#3 — Arabic/English control/mitigation sections count."""

    def test_arabic_controls_counted(self):
        c = semantic_risk_treatment_counts(_CONTROLS_AR)
        self.assertGreaterEqual(c['treatment_rows'], 2)

    def test_arabic_mitigation_counted(self):
        c = semantic_risk_treatment_counts(_MITIGATION_AR)
        self.assertGreaterEqual(c['treatment_rows'], 1)

    def test_english_controls_counted(self):
        c = semantic_risk_treatment_counts(_CONTROLS_EN)
        self.assertGreaterEqual(c['treatment_rows'], 1)


class EvidenceGateSemanticTests(unittest.TestCase):
    """#4/#5 — evidence gate does not emit empty_risk_treatment for controls."""

    def _secs(self):
        s = dict(_CONTROLS_AR)
        s['register'] = _REGISTER
        return s

    def test_docx_no_empty_treatment(self):
        diag = evaluate_erm_risk_treatment_evidence(
            '', route='docx', canonical_sections=self._secs())
        self.assertFalse(diag['empty_risk_treatment_triggered'])
        self.assertTrue(diag['passed'])
        self.assertEqual(diag['treatment_rows_literal'], 0)
        self.assertGreaterEqual(diag['treatment_rows_semantic'], 2)
        self.assertEqual(diag['treatment_row_detection_method'],
                         'semantic_control_sections')

    def test_pdf_no_empty_treatment(self):
        defects = risk_treatment_defects_for_channel(
            '', route='pdf', document_type='risk',
            canonical_sections=self._secs())
        self.assertNotIn('empty_risk_treatment', defects)


class FailClosedTests(unittest.TestCase):
    """#6/#7/#8 — headings/narrative-only don't count; treatment-less fails."""

    def test_headings_only_not_counted(self):
        c = semantic_risk_treatment_counts(
            {'4_1_الضوابط': '## 4.1 الضوابط الأولية\n'})
        self.assertEqual(c['treatment_rows'], 0)

    def test_narrative_only_not_counted(self):
        c = semantic_risk_treatment_counts(
            {'4_1_الضوابط': ('## الضوابط\n\nتصف هذه الفقرة الضوابط بشكل عام '
                             'دون جدول إجراءات فعلي.\n')})
        self.assertEqual(c['treatment_rows'], 0)

    def test_treatment_less_risk_fails_closed(self):
        diag = evaluate_erm_risk_treatment_evidence(
            '', route='docx',
            canonical_sections={'register': _REGISTER})
        self.assertTrue(diag['empty_risk_treatment_triggered'])
        self.assertIn('empty_risk_treatment', diag['blocking_errors'])


class ConsistencyTests(unittest.TestCase):
    """#9/#10 — frozen completeness and export evidence agree; complete risk."""

    def test_frozen_and_evidence_consistent(self):
        secs = dict(_CONTROLS_AR)
        secs['register'] = _REGISTER
        _reg, _treat = (
            semantic_risk_treatment_counts(secs)['register_rows'],
            semantic_risk_treatment_counts(secs)['treatment_rows'])
        ev = evaluate_erm_risk_treatment_evidence(
            '', route='docx', canonical_sections=secs)
        self.assertEqual(ev['treatment_rows_semantic'], _treat)
        complete, present, missing = evaluate_risk_sections_complete(
            secs, final_hash='h')
        self.assertIn('treatment_rows', present)
        self.assertTrue(complete, missing)

    def test_complete_risk_no_blockers_either_gate(self):
        secs = dict(_CONTROLS_AR)
        secs['register'] = _REGISTER
        complete, _p, missing = evaluate_risk_sections_complete(
            secs, final_hash='h')
        self.assertTrue(complete, missing)
        ev = evaluate_erm_risk_treatment_evidence(
            '', route='pdf', canonical_sections=secs)
        self.assertEqual(ev['blocking_errors'], [])


if __name__ == '__main__':
    unittest.main()
