"""Tests for the domain-isolation layer (Phase 1, 2, 4 of the
Mizan domain-contamination fix).

Covers:
  1. ``normalize_domain_strict`` raises ``DomainResolutionError`` for
     missing/empty/unknown domain input.
  2. ``get_strategy_domain_context`` returns the canonical bundle for each
     supported domain code (cyber/data/ai/dt/erm/global) with the right
     forbidden-term, capability and role lists.
  3. ``validate_domain_isolation`` flags cyber-only terms (NCA ECC, MFA,
     SIEM, MTTD, MTTR, phishing, CISO) when they appear in non-cyber
     strategy sections (Data, AI, ERM, Digital).
  4. ``validate_domain_isolation`` does NOT flag those terms when the
     selected_frameworks legitimately include the matching framework.
  5. ``resolve_export_domain`` returns the canonical English display name
     for valid input and raises for missing strategy-export domain.
  6. The cyber-specific deterministic banks
     (``repair_kpi_section_if_missing_frequency``,
     ``repair_confidence_risk_section``) are gated by domain — for non-cyber
     domains they leave the section unchanged when AI repair is unavailable
     (rather than injecting cyber rows).

Run:  python -m pytest tests/test_domain_isolation.py -v
"""
import os
import sys
import unittest

os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///tmp/test_domain_iso.db')
# Force AI providers OFF so ai_repair_strategy_section() raises RepairError
# immediately (no real network calls). This is exactly the behaviour we want
# to assert: when no AI provider is configured, non-cyber repair must NOT
# substitute cyber defaults — it must leave the section unchanged.
os.environ['OPENAI_API_KEY']    = ''
os.environ['ANTHROPIC_API_KEY'] = ''
os.environ['GOOGLE_API_KEY']    = ''
os.environ['GROQ_API_KEY']      = ''
os.environ['DEEPSEEK_API_KEY']  = ''

_APP = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        'app', os.path.join(os.path.dirname(__file__), '..', 'app.py')
    )
    _APP = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(_APP)
except Exception:
    _APP = None


def _skip_if_no_app(fn):
    import functools

    @functools.wraps(fn)
    def wrapper(self, *args, **kwargs):
        if _APP is None:
            self.skipTest('app.py could not be imported')
        return fn(self, *args, **kwargs)
    return wrapper


class TestNormalizeDomainStrict(unittest.TestCase):
    @_skip_if_no_app
    def test_known_english_display_resolves_to_canonical_code(self):
        self.assertEqual(_APP.normalize_domain_strict('Cyber Security'), 'cyber')
        self.assertEqual(_APP.normalize_domain_strict('Data Management'), 'data')
        self.assertEqual(_APP.normalize_domain_strict('Artificial Intelligence'), 'ai')
        self.assertEqual(_APP.normalize_domain_strict('Digital Transformation'), 'dt')
        self.assertEqual(_APP.normalize_domain_strict('Enterprise Risk Management'), 'erm')
        self.assertEqual(_APP.normalize_domain_strict('Global Standards'), 'global')

    @_skip_if_no_app
    def test_canonical_code_is_passthrough(self):
        for code in ('cyber', 'data', 'ai', 'dt', 'erm', 'global'):
            self.assertEqual(_APP.normalize_domain_strict(code), code)

    @_skip_if_no_app
    def test_empty_or_none_raises(self):
        with self.assertRaises(_APP.DomainResolutionError):
            _APP.normalize_domain_strict(None)
        with self.assertRaises(_APP.DomainResolutionError):
            _APP.normalize_domain_strict('')
        with self.assertRaises(_APP.DomainResolutionError):
            _APP.normalize_domain_strict('   ')

    @_skip_if_no_app
    def test_unknown_raises(self):
        with self.assertRaises(_APP.DomainResolutionError):
            _APP.normalize_domain_strict('Quantum Computing')
        with self.assertRaises(_APP.DomainResolutionError):
            _APP.normalize_domain_strict('not a domain')


class TestGetStrategyDomainContext(unittest.TestCase):
    @_skip_if_no_app
    def test_cyber_context_basics(self):
        ctx = _APP.get_strategy_domain_context('Cyber Security', 'en')
        self.assertEqual(ctx['code'], 'cyber')
        self.assertEqual(ctx['display'], 'Cyber Security')
        self.assertEqual(ctx['lang'], 'en')
        self.assertIn('SOC operations', ctx['allowed_capabilities'])
        self.assertIn('CISO', ctx['role_vocab'])
        # Cyber domain forbids the OTHER domains' primary owner bodies but
        # NOT NCA ECC / MFA / SIEM (those are legitimately cyber-domain).
        self.assertNotIn('NCA ECC', ctx['forbidden_terms'])

    @_skip_if_no_app
    def test_data_context_forbids_cyber_terms(self):
        ctx = _APP.get_strategy_domain_context('Data Management', 'en')
        self.assertEqual(ctx['code'], 'data')
        self.assertIn('Chief Data Officer', ctx['role_vocab'])
        self.assertIn('data governance', ctx['allowed_capabilities'])
        # Cyber-specific terms must be forbidden for a Data strategy.
        forbidden_lc = ' '.join(ctx['forbidden_terms']).lower()
        self.assertIn('nca ecc', forbidden_lc)
        self.assertIn('siem', forbidden_lc)
        self.assertIn('mfa', forbidden_lc)

    @_skip_if_no_app
    def test_arabic_display(self):
        ctx = _APP.get_strategy_domain_context('Data Management', 'ar')
        self.assertEqual(ctx['lang'], 'ar')
        # Arabic display string must not be the English one.
        self.assertNotEqual(ctx['display'], 'Data Management')
        self.assertEqual(ctx['display'], ctx['display_ar'])

    @_skip_if_no_app
    def test_selected_framework_suppresses_matching_forbidden_term(self):
        # An ERM strategy that legitimately scopes cyber risk via NCA ECC
        # should not have NCA ECC in its forbidden list.
        ctx = _APP.get_strategy_domain_context(
            'Enterprise Risk Management', 'en',
            selected_frameworks=['NCA ECC'])
        forbidden_lc = ' '.join(ctx['forbidden_terms']).lower()
        self.assertNotIn('nca ecc', forbidden_lc)

    @_skip_if_no_app
    def test_unknown_domain_raises(self):
        with self.assertRaises(_APP.DomainResolutionError):
            _APP.get_strategy_domain_context('not a domain', 'en')


class TestValidateDomainIsolation(unittest.TestCase):
    @_skip_if_no_app
    def test_data_strategy_with_cyber_terms_is_flagged(self):
        ctx = _APP.get_strategy_domain_context('Data Management', 'en')
        sections = {
            'kpis': (
                "## 6. Key Performance Indicators\n"
                "| # | Metric | Owner |\n|---|---|---|\n"
                "| 1 | NCA ECC compliance rate | CISO |\n"
                "| 2 | MFA enrolment | SOC Manager |\n"
            ),
        }
        contamination = _APP.validate_domain_isolation(sections, ctx)
        self.assertTrue(contamination, "expected contamination but got none")
        rec = contamination[0]
        self.assertEqual(rec['section'], 'kpis')
        self.assertEqual(rec['domain'], 'data')
        found_lc = ' '.join(rec['found_terms']).lower()
        self.assertIn('nca ecc', found_lc)

    @_skip_if_no_app
    def test_ai_strategy_with_cyber_terms_is_flagged(self):
        ctx = _APP.get_strategy_domain_context('Artificial Intelligence', 'en')
        sections = {
            'confidence': (
                "## 7. Confidence & Risk Assessment\n"
                "Risk: phishing of AI engineers via SIEM bypass.\n"
            ),
        }
        contamination = _APP.validate_domain_isolation(sections, ctx)
        self.assertTrue(contamination)
        self.assertEqual(contamination[0]['domain'], 'ai')

    @_skip_if_no_app
    def test_digital_strategy_with_cyber_terms_is_flagged(self):
        ctx = _APP.get_strategy_domain_context('Digital Transformation', 'en')
        sections = {
            'roadmap': (
                "## 5. Implementation Roadmap\n"
                "Phase 1: Deploy SIEM and EDR/XDR. Reduce MTTD < 30min.\n"
            ),
        }
        contamination = _APP.validate_domain_isolation(sections, ctx)
        self.assertTrue(contamination)

    @_skip_if_no_app
    def test_erm_strategy_with_cyber_terms_is_flagged(self):
        ctx = _APP.get_strategy_domain_context('Enterprise Risk Management', 'en')
        sections = {
            'kpis': (
                "## 6. KPIs\n"
                "| # | Metric | Owner |\n|---|---|---|\n"
                "| 1 | NCA ECC controls implemented | SOC |\n"
            ),
        }
        contamination = _APP.validate_domain_isolation(sections, ctx)
        self.assertTrue(contamination)

    @_skip_if_no_app
    def test_clean_data_strategy_passes(self):
        ctx = _APP.get_strategy_domain_context('Data Management', 'en')
        sections = {
            'kpis': (
                "## 6. KPIs\n"
                "| # | Metric | Owner |\n|---|---|---|\n"
                "| 1 | Data quality score | Chief Data Officer |\n"
                "| 2 | Catalog coverage | Data Steward |\n"
            ),
        }
        self.assertEqual(_APP.validate_domain_isolation(sections, ctx), [])

    @_skip_if_no_app
    def test_cyber_strategy_with_cyber_terms_passes(self):
        ctx = _APP.get_strategy_domain_context('Cyber Security', 'en')
        sections = {
            'kpis': (
                "## 6. KPIs\n"
                "| # | Metric | Owner |\n|---|---|---|\n"
                "| 1 | NCA ECC compliance | CISO |\n"
                "| 2 | MFA adoption | SOC Manager |\n"
            ),
        }
        self.assertEqual(_APP.validate_domain_isolation(sections, ctx), [])

    @_skip_if_no_app
    def test_user_selected_framework_suppresses_match(self):
        # ERM strategy with NCA ECC in selected_frameworks should NOT flag
        # NCA ECC even though it appears in the section.
        ctx = _APP.get_strategy_domain_context(
            'Enterprise Risk Management', 'en',
            selected_frameworks=['NCA ECC'])
        sections = {
            'kpis': (
                "## 6. KPIs\n"
                "| # | Metric | Owner |\n|---|---|---|\n"
                "| 1 | NCA ECC controls implemented | CRO |\n"
            ),
        }
        # NCA ECC should now be removed from forbidden — but SIEM/SOC are
        # still forbidden because the user did not select those frameworks.
        contamination = _APP.validate_domain_isolation(sections, ctx)
        for rec in contamination:
            self.assertNotIn('NCA ECC',
                             [t.strip() for t in rec['found_terms']])


class TestResolveExportDomain(unittest.TestCase):
    @_skip_if_no_app
    def test_strategy_artifact_resolves_canonical_display(self):
        self.assertEqual(
            _APP.resolve_export_domain('data', 'strategy'),
            'Data Management',
        )
        self.assertEqual(
            _APP.resolve_export_domain('Cyber Security', 'strategy'),
            'Cyber Security',
        )

    @_skip_if_no_app
    def test_strategy_artifact_missing_domain_raises(self):
        with self.assertRaises(_APP.DomainResolutionError):
            _APP.resolve_export_domain('', 'strategy')
        with self.assertRaises(_APP.DomainResolutionError):
            _APP.resolve_export_domain(None, 'strategy')

    @_skip_if_no_app
    def test_non_strategy_artifact_passes_through_unchanged(self):
        # Policies / gap remediation / podcast etc. must NOT be force-validated.
        self.assertEqual(
            _APP.resolve_export_domain('anything', 'policy'),
            'anything',
        )
        self.assertEqual(
            _APP.resolve_export_domain('', 'policy'),
            '',
        )


class TestNonCyberRepairLeavesSectionAlone(unittest.TestCase):
    """When AI is unavailable and the domain is non-cyber, the deterministic
    cyber repair functions must NOT inject cyber rows. They should leave
    the section unchanged."""

    @_skip_if_no_app
    def test_kpi_repair_no_cyber_injection_for_data_domain(self):
        sections = {
            'kpis': (
                "## 6. Key Performance Indicators\n"
                "| # | Metric | Owner |\n|---|---|---|\n"
                "| 1 | Data quality | CDO |\n"
            )
        }
        original = sections['kpis']
        _APP.repair_kpi_section_if_missing_frequency(
            sections, lang='en',
            domain='Data Management',
            org_name='TestOrg', sector='Government',
            frameworks=[],
        )
        # AI provider not configured in test env → ai_repair raises RepairError,
        # the function returns 0 and the section is unchanged. Critically: no
        # NCA ECC / MFA / SIEM rows are injected.
        self.assertNotIn('NCA ECC', sections['kpis'])
        self.assertNotIn('MFA', sections['kpis'])
        self.assertNotIn('SIEM', sections['kpis'])
        self.assertEqual(sections['kpis'], original)

    @_skip_if_no_app
    def test_confidence_repair_no_cyber_injection_for_ai_domain(self):
        sections = {
            'confidence': (
                "## 7. Confidence Assessment\n"
                "**Confidence Score:** 60%\n"
            )
        }
        _APP.repair_confidence_risk_section(
            sections, lang='en',
            domain='Artificial Intelligence',
            org_name='TestOrg', sector='Government',
            frameworks=[],
        )
        # No cyber risk rows must appear (no SOC, SIEM, IAM/PAM/MFA, DR test,
        # phishing). AI provider unavailable → no AI replacement either; the
        # section is left unchanged.
        text = sections['confidence']
        for term in ('SOC', 'SIEM', 'PAM', 'MFA', 'phishing', 'IAM'):
            self.assertNotIn(term, text,
                             f"unexpected cyber term {term!r} in AI strategy")

    @_skip_if_no_app
    def test_cyber_domain_still_uses_deterministic_bank(self):
        """For domain == cyber the deterministic bank still fires (baseline
        behavior preserved for test backwards compatibility)."""
        sections = {
            'kpis': (
                "## 6. Key Performance Indicators\n"
                "| # | Metric | Owner |\n|---|---|---|\n"
                "| 1 | something | someone |\n"
            )
        }
        n = _APP.repair_kpi_section_if_missing_frequency(
            sections, lang='en',
            domain='Cyber Security',
            org_name='TestOrg', sector='Government',
            frameworks=['NCA ECC'],
        )
        # Should have replaced the section with the canonical 9-col table.
        self.assertGreater(n, 0)
        self.assertIn('Frequency', sections['kpis'])


if __name__ == '__main__':
    unittest.main()
