"""PR-CY2 — ECC/CSCC capability registry completion.

Pins the ECC and CSCC capability families added to
``_FRAMEWORK_COVERAGE_REQUIREMENTS`` so the
``_compute_missing_selected_framework_coverage`` validator can emit
``selected_framework_coverage_missing:<FW>:<family>`` for every
required family from the Cyber diagnostic spec:

  * ECC adds  ``vulnerability_management``
  * CSCC adds ``monitoring``, ``resilience``, ``incident_response``

Scope: Cyber Security only. TCC / DCC / NDMO / PDPL / and the
Data / AI / DT / ERM domains must remain unaffected. The change is
registry-only: no deterministic strategy rows are inserted, no
validator is weakened, no auth/DB/export/PDF code is touched.

Run:
    python -m pytest \
        tests/test_cyber_ecc_cscc_registry_completion_prcy2.py -q
"""
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_prcy2_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault(
    'DATABASE_URL',
    'sqlite:///' + os.path.join(_TMP_DB_DIR, 'test.db'),
)
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('ANTHROPIC_API_KEY', '')
os.environ.setdefault('GOOGLE_API_KEY', '')


_APP = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    _spec = importlib.util.spec_from_file_location(
        'app', os.path.join(os.path.dirname(__file__), '..', 'app.py')
    )
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
except (ImportError, ModuleNotFoundError) as _e:  # pragma: no cover
    print(f'[WARN] Could not import app.py: {_e}')
    _APP = None


def _fam_dict(spec):
    """Return ``{family_id: (ar_keywords, en_keywords)}`` for a registry
    entry's capability list."""
    out = {}
    for fam_id, ar_kws, en_kws in (spec.get('capabilities') or []):
        out[fam_id] = (tuple(ar_kws or ()), tuple(en_kws or ()))
    return out


@unittest.skipIf(_APP is None, 'app.py could not be imported')
class EccVulnerabilityManagementRegistry(unittest.TestCase):
    """1–5: ECC vulnerability_management family is registered with the
    required AR/EN keywords and is enforced by the coverage validator."""

    def setUp(self):
        self.spec = _APP._FRAMEWORK_COVERAGE_REQUIREMENTS['ECC']
        self.fams = _fam_dict(self.spec)

    def test_01_ecc_includes_vulnerability_management(self):
        self.assertIn('vulnerability_management', self.fams,
                      'ECC capability family vulnerability_management '
                      'must be registered (PR-CY2).')

    def test_02_ecc_vuln_mgmt_accepts_arabic_idarat_althagharat(self):
        ar_kws, _ = self.fams['vulnerability_management']
        self.assertIn('إدارة الثغرات', ar_kws)

    def test_03_ecc_vuln_mgmt_accepts_english_vulnerability_management(self):
        _, en_kws = self.fams['vulnerability_management']
        self.assertIn('vulnerability management', en_kws)

    def test_04_ecc_body_missing_vuln_mgmt_emits_defect(self):
        # ECC body that covers governance / IAM / SOC / incident response
        # but says nothing about vulnerability/patch management must
        # cause the validator to emit
        # ``selected_framework_coverage_missing:ECC:vulnerability_management``.
        body = (
            'Cybersecurity governance and policies are established. '
            'Identity and access management (IAM, PAM) is enforced. '
            'A 24/7 SOC with SIEM provides security monitoring. '
            'Incident response and CSIRT procedures are documented.'
        )
        missing = _APP._compute_missing_selected_framework_coverage(
            body, ['ECC'], domain='Cyber Security', lang='en')
        # Triples are (fw_key, family_id, section_key).
        fams = {fam for (fw, fam, _sk) in missing if fw == 'ECC'}
        self.assertIn('vulnerability_management', fams,
                      'ECC body without vulnerability/patch wording must '
                      'emit selected_framework_coverage_missing:ECC:'
                      'vulnerability_management. Got missing=%r' % (
                          sorted(fams),))

    def test_05_ecc_body_with_vuln_mgmt_passes_family(self):
        body = (
            'Cybersecurity governance and policies are established. '
            'Identity and access management (IAM, PAM) is enforced. '
            'A 24/7 SOC with SIEM provides security monitoring. '
            'Incident response and CSIRT procedures are documented. '
            'A vulnerability management programme performs '
            'vulnerability scanning and patch management on a '
            'continuous basis.'
        )
        missing = _APP._compute_missing_selected_framework_coverage(
            body, ['ECC'], domain='Cyber Security', lang='en')
        fams = {fam for (fw, fam, _sk) in missing if fw == 'ECC'}
        self.assertNotIn('vulnerability_management', fams,
                         'ECC body that names vulnerability management '
                         'must not be flagged. Got missing=%r' % (
                             sorted(fams),))


@unittest.skipIf(_APP is None, 'app.py could not be imported')
class CsccCapabilityRegistry(unittest.TestCase):
    """6–10: CSCC monitoring / resilience / incident_response are
    registered and enforced by the coverage validator."""

    def setUp(self):
        self.spec = _APP._FRAMEWORK_COVERAGE_REQUIREMENTS['CSCC']
        self.fams = _fam_dict(self.spec)

    def test_06_cscc_includes_monitoring(self):
        self.assertIn('monitoring', self.fams)
        ar_kws, en_kws = self.fams['monitoring']
        self.assertIn('المراقبة الأمنية', ar_kws)
        self.assertIn('security monitoring', en_kws)

    def test_07_cscc_includes_resilience(self):
        self.assertIn('resilience', self.fams)
        ar_kws, en_kws = self.fams['resilience']
        self.assertIn('المرونة السيبرانية', ar_kws)
        self.assertIn('business continuity', en_kws)

    def test_08_cscc_includes_incident_response(self):
        self.assertIn('incident_response', self.fams)
        ar_kws, en_kws = self.fams['incident_response']
        self.assertIn('الاستجابة للحوادث', ar_kws)
        self.assertIn('incident response', en_kws)

    def test_09_cscc_body_missing_new_families_emits_defects(self):
        # Body satisfies the two pre-existing CSCC families
        # (critical_assets, privileged_access) but says nothing about
        # monitoring, resilience, or incident response — all three new
        # families must be emitted as defects.
        body = (
            'Critical systems and critical infrastructure are inventoried. '
            'Privileged access management (PAM) and MFA are enforced.'
        )
        missing = _APP._compute_missing_selected_framework_coverage(
            body, ['CSCC'], domain='Cyber Security', lang='en')
        fams = {fam for (fw, fam, _sk) in missing if fw == 'CSCC'}
        for required in ('monitoring', 'resilience', 'incident_response'):
            self.assertIn(required, fams,
                          'CSCC body missing %s must be flagged. '
                          'Got missing=%r' % (required, sorted(fams)))

    def test_10_cscc_body_with_new_families_passes(self):
        body = (
            'Critical systems and critical infrastructure are inventoried. '
            'Privileged access management (PAM) and MFA are enforced. '
            'Critical systems monitoring runs continuously with '
            'monitoring logs reviewed daily. '
            'Cyber resilience is sustained through business continuity '
            'and disaster recovery plans (BCM / DRP). '
            'An incident response plan and CSIRT handle cyber incidents.'
        )
        missing = _APP._compute_missing_selected_framework_coverage(
            body, ['CSCC'], domain='Cyber Security', lang='en')
        fams = {fam for (fw, fam, _sk) in missing if fw == 'CSCC'}
        for required in ('monitoring', 'resilience', 'incident_response'):
            self.assertNotIn(required, fams,
                             'CSCC body covering %s must not be flagged. '
                             'Got missing=%r' % (required, sorted(fams)))


@unittest.skipIf(_APP is None, 'app.py could not be imported')
class UnrelatedRegistriesUnchanged(unittest.TestCase):
    """11–12: TCC, DCC, and the non-Cyber framework registries
    (NDMO, PDPL) preserve their pre-PR-CY2 capability family sets so
    other domains and the existing repair contracts continue to hold."""

    def test_11_tcc_dcc_family_sets_preserved(self):
        tcc_fams = set(_fam_dict(
            _APP._FRAMEWORK_COVERAGE_REQUIREMENTS['TCC']).keys())
        # TCC families predate PR-CY2 and must remain exactly five.
        self.assertEqual(tcc_fams, {
            'remote_access', 'vpn_ztna', 'mfa', 'endpoint',
            'data_protection_remote',
        }, 'TCC capability families must not change in PR-CY2.')

        dcc_fams = set(_fam_dict(
            _APP._FRAMEWORK_COVERAGE_REQUIREMENTS['DCC']).keys())
        # DCC families (post PR-5B.9M) must remain exactly five.
        self.assertEqual(dcc_fams, {
            'data_classification', 'encryption', 'dlp',
            'sensitive_data_handling', 'data_protection',
        }, 'DCC capability families must not change in PR-CY2.')

    def test_12_data_ai_dt_erm_framework_families_preserved(self):
        ndmo_fams = set(_fam_dict(
            _APP._FRAMEWORK_COVERAGE_REQUIREMENTS['NDMO']).keys())
        # NDMO (PR-5B.9Q widening) must remain its five Data families.
        self.assertEqual(ndmo_fams, {
            'data_governance', 'data_quality', 'data_catalog',
            'data_stewardship', 'data_lifecycle',
        }, 'NDMO capability families must not change in PR-CY2.')

        pdpl_spec = _APP._FRAMEWORK_COVERAGE_REQUIREMENTS.get('PDPL')
        self.assertIsNotNone(pdpl_spec, 'PDPL registry must remain.')
        pdpl_fams = set(_fam_dict(pdpl_spec).keys())
        for required in ('privacy_governance', 'consent_management',
                         'data_subject_rights', 'breach_notification'):
            self.assertIn(required, pdpl_fams,
                          'PDPL family %s must not be removed.' % required)


@unittest.skipIf(_APP is None, 'app.py could not be imported')
class NoValidatorWeakeningOrDeterministicRows(unittest.TestCase):
    """13–15: PR-CY2 is registry-only — no validator is weakened, no
    deterministic strategy rows are inserted, and no auth/DB/export
    code path is touched."""

    def test_13_validator_still_emits_defects(self):
        # If the validator had been weakened (e.g. returned [] for ECC
        # bodies missing vulnerability_management), this would silently
        # pass. We assert the validator still flags BOTH the new ECC
        # family and the three new CSCC families when bodies are empty.
        missing_ecc = _APP._compute_missing_selected_framework_coverage(
            '', ['ECC'], domain='Cyber Security', lang='en')
        ecc_fams = {fam for (fw, fam, _sk) in missing_ecc if fw == 'ECC'}
        # All four pre-existing + new vulnerability_management family
        # must be emitted on an empty body.
        for required in ('governance', 'identity_access', 'monitoring',
                         'incident_response', 'vulnerability_management'):
            self.assertIn(required, ecc_fams,
                          'Validator must still flag ECC family %s on '
                          'empty body (validator not weakened).' % required)

        missing_cscc = _APP._compute_missing_selected_framework_coverage(
            '', ['CSCC'], domain='Cyber Security', lang='en')
        cscc_fams = {fam for (fw, fam, _sk) in missing_cscc if fw == 'CSCC'}
        for required in ('critical_assets', 'privileged_access',
                         'monitoring', 'resilience', 'incident_response'):
            self.assertIn(required, cscc_fams,
                          'Validator must still flag CSCC family %s on '
                          'empty body (validator not weakened).' % required)

    def test_14_no_deterministic_strategy_rows_inserted(self):
        # PR-CY2 only adds detection keywords. The registry entries for
        # ECC and CSCC must not carry any deterministic strategy-row
        # template field; the registry exposes ``capabilities``,
        # ``required_sections``, ``repair_targets``, ``display``, and
        # ``aliases`` — no fields named like *_template / *_rows /
        # *_inject / *_synth must appear.
        for fw_key in ('ECC', 'CSCC'):
            spec = _APP._FRAMEWORK_COVERAGE_REQUIREMENTS[fw_key]
            for field_name in spec.keys():
                lower = field_name.lower()
                self.assertFalse(
                    any(token in lower for token in (
                        'template', 'inject', 'synth', 'rows',
                        'rendered', 'preset',
                    )),
                    '%s registry must not carry a deterministic-row '
                    'template field; found %r.' % (fw_key, field_name))

    def test_15_no_auth_db_export_modules_touched(self):
        # PR-CY2 is registry-only. The capability-family registry edit
        # must not have moved app constants used by auth / DB / export.
        # We assert the expected helpers and constants are still
        # importable from the module — a smoke test that the edit did
        # not accidentally delete or reorder unrelated public symbols.
        for name in (
            '_FRAMEWORK_COVERAGE_REQUIREMENTS',
            '_compute_missing_selected_framework_coverage',
            '_resolve_selected_frameworks',
        ):
            self.assertTrue(hasattr(_APP, name),
                            'Expected attribute %s missing from app '
                            'after PR-CY2 registry edit.' % name)


if __name__ == '__main__':  # pragma: no cover
    unittest.main(verbosity=2)
