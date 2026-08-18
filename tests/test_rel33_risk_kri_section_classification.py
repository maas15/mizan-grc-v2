"""REL3.3 — semantic, document-type-aware ERM risk section classification.

Fixes a false-positive where the pre-save risk domain isolation guard blocked a
legitimate ERM KRI/monitoring section (slugified Arabic key
``5_مقاييس_kri_للمراقبة``) as cyber contamination. KRI/control/treatment
sections are now recognized semantically so incidental security-monitoring
terms are allowed, while clearly-primary Cyber substance (CISO owner, NCA
ECC/DCC framework, SOC/SIEM operating-model initiative, CSIRT, AR cyber
governance) is still blocked anywhere.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix='test_rel33_kri_cls_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from release_engine_v3.rel33_domain_guard import (  # noqa: E402
    classify_risk_section,
    evaluate_rel33_risk_domain_isolation,
    find_cyber_primary_risk_markers,
)

_KRI_KEY = '5_مقاييس_kri_للمراقبة'

# Legitimate ERM KRI monitoring section: SOC coverage / MFA activation appear
# only as incidental monitoring metrics / control activation, not as a cyber
# operating model.
_KRI_LEGIT = (
    '## 5. مقاييس KRI للمراقبة\n\n'
    '| المؤشر | المصدر | المالك |\n|---|---|---|\n'
    '| نسبة تغطية مراقبة الوصول | تقارير SOC | مدير المخاطر |\n'
    '| نسبة تفعيل MFA للحسابات الحساسة | سجل IAM | مدير المخاطر |\n')


class SectionClassificationTests(unittest.TestCase):
    """#1/#2/#3 — semantic classification of slugified/Arabic/English keys."""

    def test_slugified_arabic_kri_key(self):
        c = classify_risk_section(_KRI_KEY)
        self.assertEqual(c['section_semantic_class'], 'risk_kri_monitoring')
        self.assertTrue(c['kri_section_detected'])
        self.assertTrue(c['risk_control_section_detected'])

    def test_arabic_control_headings(self):
        for key in ('مؤشرات_المخاطر', 'مقاييس_المراقبة', 'خطة_المعالجة',
                    'الضوابط_التعويضية', 'سجل_المخاطر'):
            c = classify_risk_section(key)
            self.assertTrue(
                c['risk_control_section_detected'], f'{key} -> {c}')

    def test_english_kri_monitoring_headings(self):
        for key in ('5_kri_monitoring', 'control_effectiveness',
                    'treatment_plan', 'risk_register'):
            c = classify_risk_section(key)
            self.assertTrue(
                c['risk_control_section_detected'], f'{key} -> {c}')


class KriFalsePositiveTests(unittest.TestCase):
    """#4 — legitimate KRI monitoring content does not trigger cyber_primary."""

    def test_legit_kri_not_flagged(self):
        self.assertEqual(
            find_cyber_primary_risk_markers(_KRI_LEGIT, section_key=_KRI_KEY),
            [])

    def test_legit_kri_isolation_passes(self):
        diag = evaluate_rel33_risk_domain_isolation(
            {_KRI_KEY: _KRI_LEGIT,
             'register': '## سجل\n| خطر | مدير المخاطر |\n',
             'treatments': '## معالجة\n| ضابط | مدير المخاطر |\n'},
            domain='erm', document_type='risk', route='generate-risk-async',
            phase='pre_save')
        self.assertTrue(diag['contract_passed'], diag['blocking_errors'])
        self.assertTrue(diag['kri_section_detected'])
        self.assertTrue(diag['risk_control_section_detected'])


class KriPrimaryCyberStillBlocksTests(unittest.TestCase):
    """#5/#6/#7 — clearly-primary cyber substance still blocks in KRI."""

    def test_ciso_owner_row_blocks(self):
        blob = ('## مقاييس KRI\n| المبادرة | المالك |\n|---|---|\n'
                '| مراقبة | CISO |\n')
        self.assertIn('ciso',
                      find_cyber_primary_risk_markers(blob, section_key=_KRI_KEY))

    def test_nca_ecc_framework_blocks(self):
        blob = '## KRI\n| مؤشر | الإطار |\n|---|---|\n| x | NCA ECC |\n'
        self.assertIn('nca ecc',
                      find_cyber_primary_risk_markers(blob, section_key='kri'))

    def test_soc_operating_model_initiative_blocks(self):
        blob = '## KRI\n- تأسيس مركز عمليات SOC ضمن نموذج التشغيل\n'
        self.assertIn('soc',
                      find_cyber_primary_risk_markers(blob, section_key='kri'))

    def test_kri_isolation_blocks_primary_cyber(self):
        diag = evaluate_rel33_risk_domain_isolation(
            {_KRI_KEY: '## KRI\n| المبادرة | المالك |\n|---|---|\n| x | CISO |\n'},
            domain='erm', document_type='risk', phase='pre_save')
        self.assertFalse(diag['contract_passed'])
        self.assertTrue(diag['cyber_marker_blocked_as_primary'])
        self.assertIn(f'rel33_domain_contamination:{_KRI_KEY}:cyber_primary',
                      diag['blocking_errors'])


class ControlSectionsPreserveMfaTests(unittest.TestCase):
    """Treatment/control sections still allow generic controls (MFA/IAM)."""

    def test_treatment_mfa_allowed(self):
        blob = ('## المعالجة\n| الضابط | المالك |\n|---|---|\n'
                '| تفعيل MFA | مدير المخاطر |\n| IAM/PAM | لجنة المخاطر |\n')
        self.assertEqual(
            find_cyber_primary_risk_markers(blob, section_key='treatments'),
            [])


class NarrativeSectionsUnchangedTests(unittest.TestCase):
    """Narrative (non-control) sections still block cyber in identity positions."""

    def test_vision_cyber_identity_blocks(self):
        blob = '## حوكمة الأمن السيبراني\n| تأسيس SOC | CISO |\n'
        hits = find_cyber_primary_risk_markers(blob, section_key='vision')
        self.assertTrue(hits)

    def test_vision_incidental_prose_allowed(self):
        blob = ('الرؤية: تعزيز مرونة المؤسسة. تشمل الضوابط العامة المراقبة '
                'وتفعيل المصادقة عند الحاجة.')
        self.assertEqual(
            find_cyber_primary_risk_markers(blob, section_key='vision'), [])


class DiagnosticFieldsTests(unittest.TestCase):
    """Extended [REL33-RISK-DOMAIN-ISOLATION] diagnostic fields present."""

    def test_diag_has_new_fields(self):
        diag = evaluate_rel33_risk_domain_isolation(
            {_KRI_KEY: _KRI_LEGIT}, domain='erm', document_type='risk',
            phase='pre_save')
        for field in ('sections', 'risk_control_section_detected',
                      'kri_section_detected', 'identity_position_detected',
                      'cyber_marker_allowed_as_incidental_control',
                      'cyber_marker_blocked_as_primary', 'blocked_terms',
                      'blocking_errors'):
            self.assertIn(field, diag)
        secrow = next((r for r in diag['sections']
                       if r['raw_section_key'] == _KRI_KEY), None)
        self.assertIsNotNone(secrow)
        self.assertEqual(secrow['section_semantic_class'], 'risk_kri_monitoring')
        self.assertTrue(diag['cyber_marker_allowed_as_incidental_control'])


if __name__ == '__main__':
    unittest.main()
