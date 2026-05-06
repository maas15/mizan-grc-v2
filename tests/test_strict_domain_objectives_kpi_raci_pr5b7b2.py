"""PR-5B.7B.2 — Strict domain resolution for objectives/KPI/RACI.

Asserts:
  * synthesize_objectives_depth no longer uses ``domain or 'Cyber Security'``
    and on DomainResolutionError raises RepairError(section='vision').
  * synthesize_kpi_depth no longer uses ``domain or 'Cyber Security'``
    and on DomainResolutionError raises RepairError(section='kpis').
  * generate_raci_for_domain uses normalize_domain_strict, accepts
    English/Arabic display names + canonical codes, raises
    DomainResolutionError on unknown input, and never silently falls
    back to Cyber Security.

Run:  python -m pytest tests/test_strict_domain_objectives_kpi_raci_pr5b7b2.py -v
"""
import os
import re
import sys
import unittest
from unittest.mock import patch

os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL',
                      'sqlite:///tmp/test_strict_domain_pr5b7b2.db')
# Disable AI providers so unmocked AI calls fail loudly.
os.environ['OPENAI_API_KEY']    = ''
os.environ['ANTHROPIC_API_KEY'] = ''
os.environ['GOOGLE_API_KEY']    = ''
os.environ['GROQ_API_KEY']      = ''
os.environ['DEEPSEEK_API_KEY']  = ''

_APP = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    import importlib.util
    _spec = importlib.util.spec_from_file_location(
        'app', os.path.join(os.path.dirname(__file__), '..', 'app.py')
    )
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
except Exception:
    _APP = None


@unittest.skipIf(_APP is None, "app.py not importable in this environment")
class StrictDomainResolutionPR5B7B2(unittest.TestCase):
    """Domain resolution must never silently fall back to Cyber Security."""

    # ── Static source guarantees ────────────────────────────────────
    def test_objectives_source_no_cyber_default(self):
        with open(_APP.__file__, encoding='utf-8') as _f:
            src = _f.read()
        # Locate synthesize_objectives_depth body
        m = re.search(
            r'def synthesize_objectives_depth\(.*?\n(?=def |\Z)',
            src, flags=re.S,
        )
        self.assertIsNotNone(m)
        body = m.group(0)
        self.assertNotIn("domain or 'Cyber Security'", body)
        self.assertNotIn('domain or "Cyber Security"', body)
        # Must still strict-resolve via get_strategy_domain_context(domain, ...)
        self.assertIn('get_strategy_domain_context(', body)

    def test_kpi_source_no_cyber_default(self):
        with open(_APP.__file__, encoding='utf-8') as _f:
            src = _f.read()
        m = re.search(
            r'def synthesize_kpi_depth\(.*?\n(?=def |\Z)',
            src, flags=re.S,
        )
        self.assertIsNotNone(m)
        body = m.group(0)
        self.assertNotIn("domain or 'Cyber Security'", body)
        self.assertNotIn('domain or "Cyber Security"', body)
        self.assertIn('get_strategy_domain_context(', body)

    def test_raci_source_no_silent_default(self):
        with open(_APP.__file__, encoding='utf-8') as _f:
            src = _f.read()
        m = re.search(
            r'def generate_raci_for_domain\(.*?\n(?=def |\Z)',
            src, flags=re.S,
        )
        self.assertIsNotNone(m)
        body = m.group(0)
        self.assertNotIn("RACI_MAP['Cyber Security']", body)
        self.assertNotIn('RACI_MAP["Cyber Security"]', body)
        self.assertIn('normalize_domain_strict', body)

    # ── synthesize_objectives_depth runtime behaviour ───────────────
    def _force_obj_failure(self, bad_domain):
        sections = {'vision': ''}  # below SO floor → triggers AI repair path
        with patch.object(_APP, 'ai_repair_strategy_section') as _mock_ai:
            with self.assertRaises(_APP.RepairError) as cm:
                _APP.synthesize_objectives_depth(
                    sections, 'en',
                    domain=bad_domain,
                    fw_short='NCA ECC',
                    org_name='Test Co',
                    sector='Banking',
                )
            _mock_ai.assert_not_called()
        return cm.exception

    def test_objectives_empty_domain_raises_repair_error_vision(self):
        err = self._force_obj_failure('')
        self.assertEqual(getattr(err, 'section', None), 'vision')

    def test_objectives_none_domain_raises_repair_error_vision(self):
        err = self._force_obj_failure(None)
        self.assertEqual(getattr(err, 'section', None), 'vision')

    def test_objectives_unknown_domain_raises_repair_error_vision(self):
        err = self._force_obj_failure('Quantum Soup')
        self.assertEqual(getattr(err, 'section', None), 'vision')

    def test_objectives_empty_domain_leaves_sections_untouched(self):
        sections = {'vision': 'untouched original'}
        with patch.object(_APP, 'ai_repair_strategy_section') as _mock_ai:
            with self.assertRaises(_APP.RepairError):
                _APP.synthesize_objectives_depth(
                    sections, 'en', domain='', fw_short='NCA ECC',
                )
            _mock_ai.assert_not_called()
        self.assertEqual(sections['vision'], 'untouched original')

    # ── synthesize_kpi_depth runtime behaviour ──────────────────────
    def _force_kpi_failure(self, bad_domain):
        sections = {'kpis': ''}  # below floor → triggers AI repair path
        with patch.object(_APP, 'ai_repair_strategy_section') as _mock_ai:
            with self.assertRaises(_APP.RepairError) as cm:
                _APP.synthesize_kpi_depth(
                    sections, 'en',
                    domain=bad_domain,
                    fw_short='NCA ECC',
                    generation_mode='consulting',
                    org_name='Test Co',
                    sector='Banking',
                )
            _mock_ai.assert_not_called()
        return cm.exception

    def test_kpi_empty_domain_raises_repair_error_kpis(self):
        err = self._force_kpi_failure('')
        self.assertEqual(getattr(err, 'section', None), 'kpis')

    def test_kpi_none_domain_raises_repair_error_kpis(self):
        err = self._force_kpi_failure(None)
        self.assertEqual(getattr(err, 'section', None), 'kpis')

    def test_kpi_unknown_domain_raises_repair_error_kpis(self):
        err = self._force_kpi_failure('Quantum Soup')
        self.assertEqual(getattr(err, 'section', None), 'kpis')

    def test_kpi_empty_domain_leaves_sections_untouched(self):
        sections = {'kpis': 'untouched original'}
        with patch.object(_APP, 'ai_repair_strategy_section') as _mock_ai:
            with self.assertRaises(_APP.RepairError):
                _APP.synthesize_kpi_depth(
                    sections, 'en', domain='', fw_short='NCA ECC',
                    generation_mode='consulting',
                )
            _mock_ai.assert_not_called()
        self.assertEqual(sections['kpis'], 'untouched original')

    # ── generate_raci_for_domain ────────────────────────────────────
    def test_raci_english_display_resolves(self):
        out = _APP.generate_raci_for_domain('Cyber Security')
        self.assertIn('DOMAIN RACI (Cyber Security):', out)
        self.assertIn('CISO', out)

    def test_raci_canonical_code_resolves_data_not_cyber(self):
        out = _APP.generate_raci_for_domain('data')
        self.assertIn('DOMAIN RACI (Data Management):', out)
        # Cyber-specific accountable role must NOT appear
        self.assertNotIn('Primary Accountable: CISO', out)
        # Data-specific accountable role MUST appear
        self.assertIn('Chief Data Officer', out)

    def test_raci_canonical_code_ai(self):
        out = _APP.generate_raci_for_domain('ai')
        self.assertIn('DOMAIN RACI (Artificial Intelligence):', out)
        self.assertIn('CAIO', out)

    def test_raci_canonical_code_dt(self):
        out = _APP.generate_raci_for_domain('dt')
        self.assertIn('DOMAIN RACI (Digital Transformation):', out)

    def test_raci_canonical_code_erm(self):
        out = _APP.generate_raci_for_domain('erm')
        self.assertIn('DOMAIN RACI (Enterprise Risk Management):', out)
        self.assertIn('CRO', out)

    def test_raci_canonical_code_global(self):
        out = _APP.generate_raci_for_domain('global')
        self.assertIn('DOMAIN RACI (Global Standards):', out)

    def test_raci_arabic_display_resolves_cyber(self):
        out = _APP.generate_raci_for_domain('الأمن السيبراني')
        self.assertIn('DOMAIN RACI (Cyber Security):', out)

    def test_raci_arabic_display_resolves_data(self):
        out = _APP.generate_raci_for_domain('إدارة البيانات')
        self.assertIn('DOMAIN RACI (Data Management):', out)
        self.assertNotIn('Primary Accountable: CISO', out)

    def test_raci_unknown_domain_raises(self):
        with self.assertRaises(_APP.DomainResolutionError):
            _APP.generate_raci_for_domain('Quantum Soup')

    def test_raci_empty_domain_raises(self):
        with self.assertRaises(_APP.DomainResolutionError):
            _APP.generate_raci_for_domain('')

    def test_raci_none_domain_raises(self):
        with self.assertRaises(_APP.DomainResolutionError):
            _APP.generate_raci_for_domain(None)

    def test_raci_does_not_echo_unknown_raw_domain(self):
        # Even if the lookup somehow returned a value, the prompt block
        # must echo only the canonical English display name.
        with self.assertRaises(_APP.DomainResolutionError):
            _APP.generate_raci_for_domain('totally-bogus-xyz')


if __name__ == '__main__':
    unittest.main()
