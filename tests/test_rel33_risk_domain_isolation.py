"""REL3.3 — ERM risk domain isolation on the live export path.

Regression cover for the live staging blocker
``rel33_domain_contamination:vision:cyber_primary`` on ``erm:risk:ar``:

  * ERM risk documents must never receive Cyber-*primary* substance.
  * The risk route must not run strategy-only vision/objective repairers.
  * A section the shared strategy splitter mislabels as ``vision`` must still
    be evaluated as domain=erm/document_type=risk (not the strategy contract).
  * Incidental generic security terms (a prose SOC/CISO mention, MFA/IAM as a
    risk *control*) are allowed; cyber-primary identity substance is blocked.
  * Blank domain/document_type fails closed.
  * The guard runs before DOCX/PDF bytes are returned.
  * Cyber and the other domains (data/ai/dt/global) remain unaffected.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix='test_rel33_risk_iso_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from release_engine_v3.rel33_domain_guard import (  # noqa: E402
    evaluate_domain_isolation_contract,
    evaluate_pre_export_bytes_domain_guard,
    evaluate_rel33_risk_domain_isolation,
    find_cyber_primary_risk_markers,
)

# A realistic ERM risk artifact for an "unauthorized access" scenario. It
# mentions generic security controls (MFA/IAM in the treatment table, a prose
# reference to monitoring) but is NOT cyber-strategy substance.
_ERM_RISK_CLEAN = {
    'register': (
        '## سجل المخاطر\n\n'
        '| المخاطرة | الاحتمالية | التأثير | الخطورة | المالك |\n'
        '|---|---|---|---|---|\n'
        '| الوصول غير المصرح به للنظام | متوسطة | عالي | عالية | مدير المخاطر |\n'
    ),
    'appetite': '## شهية المخاطر\n\nشهية منخفضة للمخاطر التشغيلية الحرجة.\n',
    'treatments': (
        '## خطة المعالجة\n\n'
        '| الضابط | النوع | الأولوية | المالك |\n'
        '|---|---|---|---|\n'
        '| تفعيل المصادقة متعددة العوامل (MFA) | وقائي | عالية | مدير المخاطر |\n'
        '| إدارة الهوية والوصول IAM/PAM | وقائي | متوسطة | لجنة المخاطر |\n'
    ),
}

# A risk intro the shared strategy splitter mislabels as ``vision`` but whose
# only security mention is incidental prose — must be allowed.
_ERM_RISK_VISION_INCIDENTAL = {
    'vision': (
        'الرؤية: تعزيز مرونة المؤسسة أمام مخاطر الوصول غير المصرح به عبر إطار '
        'إدارة مخاطر مؤسسية متكامل. تشمل الضوابط العامة المراقبة المستمرة '
        'وتفعيل المصادقة متعددة العوامل عند الحاجة.'
    ),
    'register': _ERM_RISK_CLEAN['register'],
    'treatments': _ERM_RISK_CLEAN['treatments'],
}

# A risk doc whose ``vision`` section carries cyber-strategy identity substance
# (cyber-governance heading + CISO as a table owner) — must be blocked.
_ERM_RISK_VISION_CYBER_PRIMARY = {
    'vision': (
        '## حوكمة الأمن السيبراني\n\n'
        '| المبادرة | المالك |\n'
        '|---|---|\n'
        '| تأسيس مركز العمليات الأمنية SOC | CISO |\n'
    ),
    'register': _ERM_RISK_CLEAN['register'],
}


class ErmRiskVisionRegistryTests(unittest.TestCase):
    """#2/#3 — mislabeled 'vision' evaluated as erm/risk, not strategy."""

    def test_mislabeled_vision_uses_risk_rules_not_strategy(self):
        # Under the strategy contract, incidental terms in a narrative 'vision'
        # can trip the 2-hit rule; under the risk isolation they must pass.
        risk = evaluate_rel33_risk_domain_isolation(
            _ERM_RISK_VISION_INCIDENTAL,
            domain='erm', document_type='risk', route='pdf',
            phase='pre_export:pdf')
        self.assertTrue(risk['contract_passed'], risk['blocking_errors'])
        self.assertEqual(risk['resolved_document_type'], 'risk')
        self.assertEqual(risk['selected_registry'], 'erm')
        self.assertFalse(risk['strategy_repairer_invoked'])

    def test_strategy_vision_injection_is_caught_as_risk_contamination(self):
        # Proxy for "risk route must not run strategy vision repairers": if a
        # strategy repairer HAD injected cyber vision substance, the risk
        # isolation blocks it before export.
        risk = evaluate_rel33_risk_domain_isolation(
            _ERM_RISK_VISION_CYBER_PRIMARY,
            domain='erm', document_type='risk', route='pdf',
            phase='pre_export:pdf')
        self.assertFalse(risk['contract_passed'])
        self.assertIn('vision', risk['section'])
        self.assertTrue(risk['cyber_substance_detected'])


class ErmRiskPreSaveGuardTests(unittest.TestCase):
    """#3 — pre-save guard blocks cyber-primary content in any section."""

    def test_presave_blocks_cyber_primary_any_section(self):
        diag = evaluate_rel33_risk_domain_isolation(
            {'register': 'يتناول السجل إدارة الثغرات السيبرانية كأولوية عليا.'},
            domain='erm', document_type='risk', route='api_generate_strategy',
            phase='pre_save')
        self.assertFalse(diag['pre_save_guard_passed'])
        self.assertIn('rel33_domain_contamination:register:cyber_primary',
                      diag['blocking_errors'])

    def test_presave_passes_clean_erm_risk(self):
        diag = evaluate_rel33_risk_domain_isolation(
            _ERM_RISK_CLEAN, domain='erm', document_type='risk',
            phase='pre_save')
        self.assertTrue(diag['pre_save_guard_passed'], diag['blocking_errors'])
        self.assertEqual(diag['blocked_terms'], [])


class ErmRiskPreExportGuardTests(unittest.TestCase):
    """#4/#7 — pre-export bytes guard, document_type-aware, before bytes."""

    def test_preexport_blocks_cyber_primary_in_vision(self):
        blockers = evaluate_pre_export_bytes_domain_guard(
            _ERM_RISK_VISION_CYBER_PRIMARY,
            domain='erm', route='pdf', document_type='risk')
        self.assertIn('rel33_domain_contamination:vision:cyber_primary',
                      blockers)

    def test_preexport_allows_incidental_vision_terms(self):
        blockers = evaluate_pre_export_bytes_domain_guard(
            _ERM_RISK_VISION_INCIDENTAL,
            domain='erm', route='pdf', document_type='risk')
        self.assertEqual(blockers, [])

    def test_preexport_routes_risk_via_document_type_in_sections(self):
        # document_type carried inside sections (_document_type) is honored
        # even when the explicit kwarg is absent.
        secs = dict(_ERM_RISK_VISION_INCIDENTAL)
        secs['_document_type'] = 'risk'
        blockers = evaluate_pre_export_bytes_domain_guard(
            secs, domain='erm', route='docx')
        self.assertEqual(blockers, [])


class ErmRiskValidExportTests(unittest.TestCase):
    """#5 — valid ERM risk content is allowed for DOCX and PDF."""

    def test_valid_erm_risk_docx_and_pdf_allowed(self):
        for route in ('docx', 'pdf'):
            self.assertEqual(
                evaluate_pre_export_bytes_domain_guard(
                    _ERM_RISK_CLEAN, domain='erm', route=route,
                    document_type='risk'),
                [], f'route={route}')

    def test_mfa_iam_controls_in_treatment_are_allowed(self):
        # Generic security controls in a treatment/register section are ERM
        # substance, not cyber contamination (#6).
        self.assertEqual(
            find_cyber_primary_risk_markers(
                _ERM_RISK_CLEAN['treatments'], section_key='treatments'),
            [])


class ErmRiskDocumentTypePreservationTests(unittest.TestCase):
    """#6 — document_type stays 'risk' through preview/DOCX/PDF."""

    def test_export_document_type_helper_preserves_risk(self):
        import app
        self.assertEqual(app._rel33_export_document_type('risk'), 'risk')
        self.assertEqual(
            app._rel33_normalize_export_artifact_type(
                {'document_type': 'risk'}), 'risk')
        self.assertEqual(
            app._rel33_normalize_export_artifact_type(
                {'artifact_type': 'risk'}), 'risk')

    def test_risk_prompt_is_domain_scoped_for_erm(self):
        import app
        prompt = app._build_risk_prompt({
            'language': 'ar', 'domain': 'Enterprise Risk Management',
            'frameworks': ['ISO 27001', 'NIST CSF']})
        # ERM prompt must carry an explicit scope rule that forbids defaulting
        # to the cyber governance stack (the only NCA ECC/CISO mention allowed
        # is inside that negative instruction).
        self.assertIn('إدارة المخاطر المؤسسية', prompt)
        self.assertIn('لا تُدخل حوكمة الأمن السيبراني', prompt)
        self.assertIn('Enterprise Risk Management', prompt)

    def test_risk_prompt_allows_cyber_substance_for_cyber_domain(self):
        import app
        prompt = app._build_risk_prompt({
            'language': 'ar', 'domain': 'Cyber Security'})
        # Cyber risk keeps the generic risk template without the ERM-only
        # scope restriction.
        self.assertNotIn('لا تُدخل حوكمة الأمن السيبراني', prompt)


class FailClosedTests(unittest.TestCase):
    """#8 — blank domain/document_type fails closed."""

    def test_blank_domain_fails_closed(self):
        diag = evaluate_rel33_risk_domain_isolation(
            _ERM_RISK_CLEAN, domain='', document_type='risk')
        self.assertFalse(diag['contract_passed'])
        self.assertIn('rel33_risk_domain_missing', diag['blocking_errors'])

    def test_blank_document_type_fails_closed(self):
        diag = evaluate_rel33_risk_domain_isolation(
            _ERM_RISK_CLEAN, domain='erm', document_type='')
        self.assertFalse(diag['contract_passed'])
        self.assertIn('rel33_risk_document_type_missing',
                      diag['blocking_errors'])

    def test_preexport_blank_domain_fails_closed(self):
        blockers = evaluate_pre_export_bytes_domain_guard(
            _ERM_RISK_CLEAN, domain='', route='pdf', document_type='risk')
        self.assertTrue(any('rel33_export_domain_missing' in b
                            for b in blockers))


class OtherDomainsUnaffectedTests(unittest.TestCase):
    """#7/#8/#9 — cyber, data/ai/dt, and global gap remain correct."""

    def test_cyber_risk_may_contain_cyber_substance(self):
        diag = evaluate_rel33_risk_domain_isolation(
            _ERM_RISK_VISION_CYBER_PRIMARY, domain='cyber',
            document_type='risk')
        self.assertTrue(diag['contract_passed'], diag['blocking_errors'])

    def test_cyber_strategy_still_allowed(self):
        # Strategy path is unchanged: a cyber strategy passes its own contract.
        blockers = evaluate_pre_export_bytes_domain_guard(
            {'vision': '## الرؤية الاستراتيجية\nحوكمة الأمن السيبراني وSOC.'},
            domain='cyber', route='pdf', document_type='strategy')
        self.assertEqual(blockers, [])

    def test_data_strategy_still_isolated(self):
        # A data STRATEGY with cyber-primary substance still blocks via the
        # strategy contract (risk routing must not weaken strategy isolation).
        diag = evaluate_domain_isolation_contract(
            {'pillars': '## الركائز\nحوكمة الأمن السيبراني ومركز العمليات الأمنية.'},
            domain='data', document_type='strategy', phase='pre_export:pdf')
        self.assertFalse(diag['contract_passed'])

    def test_global_gap_assessment_clean_passes(self):
        # gap_assessment continues to use the strategy contract; a clean
        # global gap passes.
        blockers = evaluate_pre_export_bytes_domain_guard(
            {'gaps': '## تحليل الفجوات\nفجوات الامتثال للمعايير الدولية.'},
            domain='global', route='pdf', document_type='gap_assessment')
        self.assertEqual(blockers, [])


if __name__ == '__main__':
    unittest.main()
