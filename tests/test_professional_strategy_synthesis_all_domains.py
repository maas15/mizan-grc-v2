"""Domain-agnostic Professional Strategy Synthesis Layer tests.

Verifies that the same professional strategy-document synthesis approach
applies to ALL supported domains:

  * Cyber Security
  * Data Management
  * Artificial Intelligence
  * Digital Transformation
  * Enterprise Risk Management
  * Global Standards

Targets:
  * ``_DOMAIN_STRATEGY_PROFILES`` — per-domain profile dict
  * ``compose_professional_strategy_narrative_ai`` — generic composer

These tests exercise pure helpers — no AI calls, no DB writes.

Run:
    python -m pytest tests/test_professional_strategy_synthesis_all_domains.py -q
"""
import importlib.util
import os
import sys
import tempfile
import unittest

# ── Boot env required by ``app`` ─────────────────────────────────────────
_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_synthesis_all_domains_')
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


def _skip_if_no_app(fn):
    import functools

    @functools.wraps(fn)
    def _wrapped(self, *a, **kw):
        if _APP is None:
            self.skipTest('app.py could not be imported')
        return fn(self, *a, **kw)
    return _wrapped


# ── Per-domain section fixtures ──────────────────────────────────────────
# Each fixture is a minimal but realistic strategy markdown that uses ONLY
# the vocabulary appropriate for its domain. Fixtures are intentionally
# short — only the domain vocabulary matters for the contamination /
# coverage assertions.

CYBER_SECTIONS = {
    'vision': (
        '## 1. Vision and Strategic Objectives\n\n'
        'Vision: build cybersecurity capabilities aligned to NCA ECC '
        'and NCA TCC and protect information assets through governance '
        'and incident response.\n\n'
        '| # | Objective | Metric | Rationale | Timeframe |\n'
        '|---|-----------|--------|-----------|----------|\n'
        '| 1 | Strengthen IAM and PAM | 100% privileged accounts under PAM | Reduce insider risk | 12 months |\n'
        '| 2 | Establish SOC monitoring (SIEM) | MTTD < 30 min | Threat detection | 18 months |\n'
    ),
    'pillars': (
        '## 2. Strategic Pillars\n\n'
        '| # | Pillar | Initiative | Owner |\n'
        '|---|--------|-----------|-------|\n'
        '| 1 | Governance | Cybersecurity policy framework | CISO |\n'
        '| 2 | Identity & Access | Deploy IAM and PAM | SOC Manager |\n'
        '| 3 | Monitoring | Stand up SOC and SIEM | SOC Manager |\n'
        '| 4 | Incident Response | CSIRT capability | CISO |\n'
    ),
    'environment': (
        '## 3. Environment\n\n'
        'Regulatory environment includes NCA ECC and NCA TCC (telework). '
        'Sector-specific cyber threats considered.\n'
    ),
    'gaps': (
        '## 4. Gap Analysis\n\n'
        '| # | Gap | Severity | Remediation |\n'
        '|---|-----|----------|-------------|\n'
        '| 1 | No formal SOC monitoring | High | Stand up SIEM and SOC |\n'
        '| 2 | Privileged access not managed | High | Implement PAM |\n'
        '| 3 | No incident response runbook | Medium | Establish CSIRT |\n'
    ),
    'roadmap': (
        '## 5. Roadmap\n\n'
        '| Phase | Initiative | Months |\n'
        '|-------|-----------|--------|\n'
        '| Short-term | Governance & policies | 0-6 months |\n'
        '| Medium-term | SOC, IAM, PAM build-out | 6-18 months |\n'
        '| Long-term | CSIRT maturity, threat intel | 18-36 months |\n'
    ),
    'kpis': (
        '## 6. KPIs\n\n'
        '| # | Metric | Type | Target | Owner | Frequency |\n'
        '|---|--------|------|--------|-------|-----------|\n'
        '| 1 | MTTD | KPI | < 30 min | SOC Manager | Monthly |\n'
        '| 2 | MTTR | KPI | < 4 hr | SOC Manager | Monthly |\n'
        '| 3 | Patch SLA compliance | KPI | > 95% | Cybersecurity Governance Lead | Monthly |\n'
        '| 4 | Phishing simulation failure rate | KRI | < 5% | CISO | Quarterly |\n'
    ),
    'confidence': (
        '## 7. Confidence and Risk\n\n'
        '| # | Risk | Likelihood | Impact | Mitigation |\n'
        '|---|------|-----------|--------|------------|\n'
        '| 1 | External cyber threat | High | High | Threat intel + SOC |\n'
        '| 2 | Insider threat | Medium | High | PAM + monitoring |\n'
        '| 3 | Third-party risk | Medium | Medium | Vendor reviews |\n'
    ),
}

DATA_SECTIONS = {
    'vision': (
        '## 1. Vision and Strategic Objectives\n\n'
        'Vision: establish enterprise data governance, ownership and '
        'stewardship aligned to NDMO with high data quality and complete '
        'metadata across the data lifecycle.\n\n'
        '| # | Objective | Metric | Rationale | Timeframe |\n'
        '|---|-----------|--------|-----------|----------|\n'
        '| 1 | Implement data governance | DG framework approved | Foundation | 6 months |\n'
        '| 2 | Define data ownership and stewardship | 100% domains owned | Accountability | 12 months |\n'
    ),
    'pillars': (
        '## 2. Strategic Pillars\n\n'
        '| # | Pillar | Initiative | Owner |\n'
        '|---|--------|-----------|-------|\n'
        '| 1 | Data Governance | Establish Data Governance Committee | Chief Data Officer |\n'
        '| 2 | Data Quality | Quality measurement programme | Data Steward |\n'
        '| 3 | Metadata & Catalog | Data catalog deployment | Chief Data Officer |\n'
        '| 4 | Privacy & Lifecycle | Retention and privacy controls | Data Protection Officer (DPO) |\n'
    ),
    'environment': (
        '## 3. Environment\n\n'
        'Regulatory environment includes NDMO requirements covering data '
        'governance, metadata and data quality.\n'
    ),
    'gaps': (
        '## 4. Gap Analysis\n\n'
        '| # | Gap | Severity | Remediation |\n'
        '|---|-----|----------|-------------|\n'
        '| 1 | No data governance committee | High | Establish DG Committee |\n'
        '| 2 | Data quality not measured | High | Implement quality programme |\n'
        '| 3 | No metadata catalog | Medium | Deploy catalog |\n'
    ),
    'roadmap': (
        '## 5. Roadmap\n\n'
        '| Phase | Initiative | Months |\n'
        '|-------|-----------|--------|\n'
        '| Short-term | Data governance foundations | 0-6 months |\n'
        '| Medium-term | Data quality, catalog, stewardship | 6-18 months |\n'
        '| Long-term | Analytics enablement | 18-36 months |\n'
    ),
    'kpis': (
        '## 6. KPIs\n\n'
        '| # | Metric | Type | Target | Owner | Frequency |\n'
        '|---|--------|------|--------|-------|-----------|\n'
        '| 1 | Data quality score | KPI | > 90% | Data Steward | Monthly |\n'
        '| 2 | Metadata completeness | KPI | > 95% | Chief Data Officer | Quarterly |\n'
        '| 3 | Data steward coverage | KPI | 100% | Data Governance Committee | Quarterly |\n'
    ),
    'confidence': (
        '## 7. Confidence and Risk\n\n'
        '| # | Risk | Likelihood | Impact | Mitigation |\n'
        '|---|------|-----------|--------|------------|\n'
        '| 1 | Data quality risk | High | High | Quality programme |\n'
        '| 2 | Privacy / regulatory risk | Medium | High | DPO oversight |\n'
        '| 3 | Stewardship gap | Medium | Medium | Steward training |\n'
    ),
}

AI_SECTIONS = {
    'vision': (
        '## 1. Vision and Strategic Objectives\n\n'
        'Vision: establish responsible AI governance, model risk '
        'management, explainability, bias and fairness controls, '
        'continuous monitoring and human oversight aligned to the '
        'NIST AI Risk Management Framework.\n\n'
        '| # | Objective | Metric | Rationale | Timeframe |\n'
        '|---|-----------|--------|-----------|----------|\n'
        '| 1 | Establish AI governance | AI policy approved | Foundation | 6 months |\n'
        '| 2 | Implement model risk management | 100% models inventoried | Risk control | 12 months |\n'
    ),
    'pillars': (
        '## 2. Strategic Pillars\n\n'
        '| # | Pillar | Initiative | Owner |\n'
        '|---|--------|-----------|-------|\n'
        '| 1 | AI Governance | AI governance framework | Head of AI Governance |\n'
        '| 2 | Model Risk | Model inventory & validation | Model Risk Manager |\n'
        '| 3 | Explainability | Explainability artefacts | AI Compliance Lead |\n'
        '| 4 | Human Oversight | Human-in-the-loop reviews | AI Ethics Officer |\n'
    ),
    'environment': (
        '## 3. Environment\n\n'
        'Regulatory environment includes NIST AI Risk Management Framework '
        'covering AI governance, trustworthy AI and model risk.\n'
    ),
    'gaps': (
        '## 4. Gap Analysis\n\n'
        '| # | Gap | Severity | Remediation |\n'
        '|---|-----|----------|-------------|\n'
        '| 1 | No AI governance | High | Establish AI governance |\n'
        '| 2 | No bias / fairness testing | High | Implement bias tests |\n'
        '| 3 | No model monitoring | Medium | Continuous monitoring |\n'
    ),
    'roadmap': (
        '## 5. Roadmap\n\n'
        '| Phase | Initiative | Months |\n'
        '|-------|-----------|--------|\n'
        '| Short-term | AI governance & inventory | 0-6 months |\n'
        '| Medium-term | Model risk, fairness, explainability | 6-18 months |\n'
        '| Long-term | Continuous monitoring & oversight | 18-36 months |\n'
    ),
    'kpis': (
        '## 6. KPIs\n\n'
        '| # | Metric | Type | Target | Owner | Frequency |\n'
        '|---|--------|------|--------|-------|-----------|\n'
        '| 1 | Model inventory completeness | KPI | 100% | Model Risk Manager | Quarterly |\n'
        '| 2 | Models with bias tests | KPI | > 95% | AI Ethics Officer | Quarterly |\n'
        '| 3 | Models with explainability artefacts | KPI | > 90% | AI Compliance Lead | Quarterly |\n'
        '| 4 | Human oversight coverage | KPI | 100% | Head of AI Governance | Quarterly |\n'
    ),
    'confidence': (
        '## 7. Confidence and Risk\n\n'
        '| # | Risk | Likelihood | Impact | Mitigation |\n'
        '|---|------|-----------|--------|------------|\n'
        '| 1 | Model performance risk | High | High | Continuous monitoring |\n'
        '| 2 | Bias / fairness risk | Medium | High | Bias testing |\n'
        '| 3 | Explainability risk | Medium | Medium | Explainability artefacts |\n'
    ),
}

DT_SECTIONS = {
    'vision': (
        '## 1. Vision and Strategic Objectives\n\n'
        'Vision: accelerate digital transformation through service '
        'digitisation, integration, automation, adoption and a modern '
        'operating model aligned to DGA.\n\n'
        '| # | Objective | Metric | Rationale | Timeframe |\n'
        '|---|-----------|--------|-----------|----------|\n'
        '| 1 | Digitise priority services | 80% services online | User experience | 12 months |\n'
        '| 2 | Build integration layer (APIs) | 100% systems integrated | Interoperability | 18 months |\n'
    ),
    'pillars': (
        '## 2. Strategic Pillars\n\n'
        '| # | Pillar | Initiative | Owner |\n'
        '|---|--------|-----------|-------|\n'
        '| 1 | Service digitisation | Digital services platform | Chief Digital Officer |\n'
        '| 2 | Integration & APIs | API & integration layer | Digital Transformation Office |\n'
        '| 3 | Automation | Process automation programme | Innovation Lead |\n'
        '| 4 | Change management | Adoption & change programme | Chief Digital Officer |\n'
    ),
    'environment': (
        '## 3. Environment\n\n'
        'Regulatory environment includes the DGA Digital Government '
        'framework covering digital services and interoperability.\n'
    ),
    'gaps': (
        '## 4. Gap Analysis\n\n'
        '| # | Gap | Severity | Remediation |\n'
        '|---|-----|----------|-------------|\n'
        '| 1 | Limited service digitisation | High | Digital services rollout |\n'
        '| 2 | Weak integration / APIs | High | Integration layer |\n'
        '| 3 | Low automation coverage | Medium | Automation programme |\n'
    ),
    'roadmap': (
        '## 5. Roadmap\n\n'
        '| Phase | Initiative | Months |\n'
        '|-------|-----------|--------|\n'
        '| Short-term | Quick-win digital services | 0-6 months |\n'
        '| Medium-term | Operating model & integration | 6-18 months |\n'
        '| Long-term | Automation & adoption maturity | 18-36 months |\n'
    ),
    'kpis': (
        '## 6. KPIs\n\n'
        '| # | Metric | Type | Target | Owner | Frequency |\n'
        '|---|--------|------|--------|-------|-----------|\n'
        '| 1 | Digital service adoption rate | KPI | > 70% | Chief Digital Officer | Monthly |\n'
        '| 2 | Service availability / uptime | KPI | > 99.5% | Digital Transformation Office | Monthly |\n'
        '| 3 | Integration coverage (APIs) | KPI | > 90% | Innovation Lead | Quarterly |\n'
        '| 4 | User satisfaction (CSAT) | KPI | > 4.0/5 | Chief Digital Officer | Quarterly |\n'
    ),
    'confidence': (
        '## 7. Confidence and Risk\n\n'
        '| # | Risk | Likelihood | Impact | Mitigation |\n'
        '|---|------|-----------|--------|------------|\n'
        '| 1 | Adoption risk | High | High | Change management |\n'
        '| 2 | Integration risk | Medium | High | API governance |\n'
        '| 3 | Vendor / platform risk | Medium | Medium | Vendor management |\n'
    ),
}

ERM_SECTIONS = {
    'vision': (
        '## 1. Vision and Strategic Objectives\n\n'
        'Vision: implement an integrated enterprise risk management '
        'programme covering risk taxonomy, appetite, assessment, KRIs, '
        'treatment and reporting / escalation aligned to ISO 22301.\n\n'
        '| # | Objective | Metric | Rationale | Timeframe |\n'
        '|---|-----------|--------|-----------|----------|\n'
        '| 1 | Establish risk taxonomy and appetite | Approved by board | Foundation | 6 months |\n'
        '| 2 | Implement KRIs and reporting | KRI dashboard live | Visibility | 12 months |\n'
    ),
    'pillars': (
        '## 2. Strategic Pillars\n\n'
        '| # | Pillar | Initiative | Owner |\n'
        '|---|--------|-----------|-------|\n'
        '| 1 | Risk taxonomy & appetite | Define taxonomy & appetite | Chief Risk Officer (CRO) |\n'
        '| 2 | Risk assessment | Assessment methodology | Risk Analyst |\n'
        '| 3 | KRIs & reporting | KRI framework | Risk Management Committee |\n'
        '| 4 | Treatment & escalation | Treatment plans + escalation | Risk Owner |\n'
    ),
    'environment': (
        '## 3. Environment\n\n'
        'Regulatory environment includes ISO 22301 business continuity '
        'aligned with the enterprise risk management programme.\n'
    ),
    'gaps': (
        '## 4. Gap Analysis\n\n'
        '| # | Gap | Severity | Remediation |\n'
        '|---|-----|----------|-------------|\n'
        '| 1 | No formal risk taxonomy | High | Define taxonomy |\n'
        '| 2 | No risk appetite statement | High | Board-approved appetite |\n'
        '| 3 | No KRI reporting | Medium | KRI framework + dashboard |\n'
    ),
    'roadmap': (
        '## 5. Roadmap\n\n'
        '| Phase | Initiative | Months |\n'
        '|-------|-----------|--------|\n'
        '| Short-term | Taxonomy, appetite, governance | 0-6 months |\n'
        '| Medium-term | Assessment, KRIs, treatment plans | 6-18 months |\n'
        '| Long-term | Integrated reporting & culture | 18-36 months |\n'
    ),
    'kpis': (
        '## 6. KPIs\n\n'
        '| # | Metric | Type | Target | Owner | Frequency |\n'
        '|---|--------|------|--------|-------|-----------|\n'
        '| 1 | Risk register completeness | KPI | 100% | Risk Analyst | Monthly |\n'
        '| 2 | Risk appetite breaches | KRI | 0 | Chief Risk Officer (CRO) | Monthly |\n'
        '| 3 | KRI reporting cadence | KPI | Monthly | Risk Management Committee | Monthly |\n'
        '| 4 | Mitigation plan closure rate | KPI | > 90% | Risk Owner | Quarterly |\n'
    ),
    'confidence': (
        '## 7. Confidence and Risk\n\n'
        '| # | Risk | Likelihood | Impact | Mitigation |\n'
        '|---|------|-----------|--------|------------|\n'
        '| 1 | Strategic risk | High | High | Risk appetite & monitoring |\n'
        '| 2 | Operational risk | Medium | High | Treatment plans |\n'
        '| 3 | Compliance / regulatory risk | Medium | Medium | Compliance programme |\n'
    ),
}

GLOBAL_SECTIONS = {
    'vision': (
        '## 1. Vision and Strategic Objectives\n\n'
        'Vision: achieve standards conformance, certification readiness, '
        'audit findings closure and complete documentation aligned to '
        'ISO/IEC 27001 and the NIST Cybersecurity Framework.\n\n'
        '| # | Objective | Metric | Rationale | Timeframe |\n'
        '|---|-----------|--------|-----------|----------|\n'
        '| 1 | Reach ISO 27001 certification readiness | Stage-2 audit pass | Conformance | 18 months |\n'
        '| 2 | Close audit findings | 100% closure | Continuous improvement | 12 months |\n'
    ),
    'pillars': (
        '## 2. Strategic Pillars\n\n'
        '| # | Pillar | Initiative | Owner |\n'
        '|---|--------|-----------|-------|\n'
        '| 1 | Standards conformance | ISMS implementation | Chief Compliance Officer (CCO) |\n'
        '| 2 | Control coverage | Annex A controls + SoA | Standards Liaison |\n'
        '| 3 | Audit & documentation | Internal audit programme | Audit Coordinator |\n'
        '| 4 | Training & competence | Awareness & competence | Standards Liaison |\n'
    ),
    'environment': (
        '## 3. Environment\n\n'
        'Regulatory environment includes ISO/IEC 27001 (ISMS), the NIST '
        'Cybersecurity Framework and ISO 22301 business continuity.\n'
    ),
    'gaps': (
        '## 4. Gap Analysis\n\n'
        '| # | Gap | Severity | Remediation |\n'
        '|---|-----|----------|-------------|\n'
        '| 1 | Limited standards conformance | High | Conformance programme |\n'
        '| 2 | Audit findings open | High | Closure programme |\n'
        '| 3 | Documentation gaps | Medium | Documentation refresh |\n'
    ),
    'roadmap': (
        '## 5. Roadmap\n\n'
        '| Phase | Initiative | Months |\n'
        '|-------|-----------|--------|\n'
        '| Short-term | Readiness assessment & gap closure | 0-6 months |\n'
        '| Medium-term | Control implementation & documentation | 6-18 months |\n'
        '| Long-term | Certification & continuous improvement | 18-36 months |\n'
    ),
    'kpis': (
        '## 6. KPIs\n\n'
        '| # | Metric | Type | Target | Owner | Frequency |\n'
        '|---|--------|------|--------|-------|-----------|\n'
        '| 1 | Standards conformance rate | KPI | > 95% | Chief Compliance Officer (CCO) | Quarterly |\n'
        '| 2 | Control coverage | KPI | > 95% | Standards Liaison | Quarterly |\n'
        '| 3 | Audit findings closure rate | KPI | > 90% | Audit Coordinator | Monthly |\n'
        '| 4 | Documentation completeness | KPI | > 95% | Standards Liaison | Quarterly |\n'
    ),
    'confidence': (
        '## 7. Confidence and Risk\n\n'
        '| # | Risk | Likelihood | Impact | Mitigation |\n'
        '|---|------|-----------|--------|------------|\n'
        '| 1 | Non-conformance risk | High | High | Conformance programme |\n'
        '| 2 | Certification delay risk | Medium | High | Phased plan |\n'
        '| 3 | Audit-finding recurrence | Medium | Medium | Root-cause analysis |\n'
    ),
}


# Cyber-only contamination terms that must NOT appear in non-cyber outputs
# unless the user explicitly selected the matching framework. We sample a
# small but unambiguous set: SOC, CSIRT, TCC, NCA ECC.
_CYBER_LEAK_TERMS = ['SOC', 'CSIRT', 'TCC', 'NCA ECC']


# ── Tests ────────────────────────────────────────────────────────────────
class TestDomainProfileRegistry(unittest.TestCase):
    """Sanity tests for the per-domain profile registry."""

    @_skip_if_no_app
    def test_all_six_profiles_present(self):
        profiles = _APP._DOMAIN_STRATEGY_PROFILES
        for code in ('cyber', 'data', 'ai', 'dt', 'erm', 'global'):
            self.assertIn(code, profiles, f'missing profile: {code}')

    @_skip_if_no_app
    def test_each_profile_defines_required_keys(self):
        required = {
            'code', 'display_en', 'display_ar', 'strategy_structure',
            'mandatory_themes', 'framework_coverage_keys',
            'gap_categories', 'roadmap_categories',
            'kpi_kri_expectations', 'risk_categories',
            'governance_roles', 'traceability_columns', 'quality_gates',
        }
        for code, prof in _APP._DOMAIN_STRATEGY_PROFILES.items():
            missing = required - set(prof.keys())
            self.assertFalse(
                missing, f'profile {code!r} missing keys: {missing}'
            )

    @_skip_if_no_app
    def test_strategy_structure_is_common_across_domains(self):
        ref = _APP._DOMAIN_STRATEGY_PROFILES['cyber']['strategy_structure']
        for code, prof in _APP._DOMAIN_STRATEGY_PROFILES.items():
            self.assertEqual(
                prof['strategy_structure'], ref,
                f'profile {code!r} has a divergent strategy_structure'
            )
        # Required canonical sections must be present in the structure.
        for required_block in (
            'cover', 'doc_control', 'toc', 'executive_summary',
            'scope_frameworks', 'methodology', 'current_state',
            'vision_objectives', 'strategic_pillars', 'environment_context',
            'gap_analysis', 'roadmap', 'kpi_kri_framework',
            'confidence_risk_register', 'governance_ownership',
            'traceability_matrix', 'appendices',
        ):
            self.assertIn(required_block, ref)


# Helper to invoke the composer.
def _compose(domain, sections, frameworks):
    return _APP.compose_professional_strategy_narrative_ai(
        domain=domain,
        sections=sections,
        metadata={'org_name': 'Test Org', 'sector': 'Government'},
        selected_frameworks=frameworks,
        diagnostic_context='Diagnostic baseline established.',
        obligations=[],
        language='en',
    )


class TestComposerUsesDomainProfile(unittest.TestCase):
    """Each domain must end up using its own profile."""

    @_skip_if_no_app
    def test_cyber_uses_cyber_profile(self):
        m = _compose('Cyber Security', CYBER_SECTIONS, ['ECC', 'TCC'])
        self.assertEqual(m['domain'], 'cyber')
        self.assertEqual(m['profile']['code'], 'cyber')
        self.assertEqual(
            m['profile']['display_en'], 'Cyber Security'
        )

    @_skip_if_no_app
    def test_data_uses_data_profile(self):
        m = _compose('Data Management', DATA_SECTIONS, ['NDMO'])
        self.assertEqual(m['domain'], 'data')
        self.assertEqual(m['profile']['code'], 'data')
        self.assertEqual(m['profile']['display_en'], 'Data Management')

    @_skip_if_no_app
    def test_ai_uses_ai_profile(self):
        m = _compose('Artificial Intelligence', AI_SECTIONS, ['NIST AI RMF'])
        self.assertEqual(m['domain'], 'ai')
        self.assertEqual(m['profile']['code'], 'ai')
        self.assertEqual(m['profile']['display_en'],
                         'Artificial Intelligence')

    @_skip_if_no_app
    def test_dt_uses_dt_profile(self):
        m = _compose('Digital Transformation', DT_SECTIONS, ['DGA'])
        self.assertEqual(m['domain'], 'dt')
        self.assertEqual(m['profile']['code'], 'dt')
        self.assertEqual(m['profile']['display_en'],
                         'Digital Transformation')

    @_skip_if_no_app
    def test_erm_uses_erm_profile(self):
        m = _compose('Enterprise Risk Management', ERM_SECTIONS,
                     ['ISO22301'])
        self.assertEqual(m['domain'], 'erm')
        self.assertEqual(m['profile']['code'], 'erm')
        self.assertEqual(m['profile']['display_en'],
                         'Enterprise Risk Management')

    @_skip_if_no_app
    def test_global_uses_global_profile(self):
        m = _compose('Global Standards', GLOBAL_SECTIONS,
                     ['ISO27001', 'NIST_CSF'])
        self.assertEqual(m['domain'], 'global')
        self.assertEqual(m['profile']['code'], 'global')
        self.assertEqual(m['profile']['display_en'], 'Global Standards')


class TestNoCyberContamination(unittest.TestCase):
    """Non-cyber domains must not be contaminated with SOC/CSIRT/TCC/NCA
    ECC unless explicitly selected and applicable.
    """

    @_skip_if_no_app
    def test_data_strategy_not_contaminated(self):
        m = _compose('Data Management', DATA_SECTIONS, ['NDMO'])
        for blk_key in ('vision_objectives', 'strategic_pillars',
                        'gap_analysis', 'roadmap',
                        'kpi_kri_framework', 'confidence_risk_register'):
            text = (m['blocks'].get(blk_key) or {}).get('content') or ''
            for term in _CYBER_LEAK_TERMS:
                self.assertNotIn(
                    term, text,
                    f'data {blk_key!r} contaminated with {term!r}'
                )

    @_skip_if_no_app
    def test_ai_strategy_not_contaminated(self):
        m = _compose('Artificial Intelligence', AI_SECTIONS,
                     ['NIST AI RMF'])
        for blk_key in ('vision_objectives', 'strategic_pillars',
                        'gap_analysis', 'roadmap',
                        'kpi_kri_framework', 'confidence_risk_register'):
            text = (m['blocks'].get(blk_key) or {}).get('content') or ''
            for term in _CYBER_LEAK_TERMS:
                self.assertNotIn(
                    term, text,
                    f'AI {blk_key!r} contaminated with {term!r}'
                )

    @_skip_if_no_app
    def test_dt_strategy_not_contaminated(self):
        m = _compose('Digital Transformation', DT_SECTIONS, ['DGA'])
        for blk_key in ('vision_objectives', 'strategic_pillars',
                        'gap_analysis', 'roadmap',
                        'kpi_kri_framework', 'confidence_risk_register'):
            text = (m['blocks'].get(blk_key) or {}).get('content') or ''
            for term in _CYBER_LEAK_TERMS:
                self.assertNotIn(
                    term, text,
                    f'DT {blk_key!r} contaminated with {term!r}'
                )

    @_skip_if_no_app
    def test_erm_strategy_not_contaminated(self):
        m = _compose('Enterprise Risk Management', ERM_SECTIONS,
                     ['ISO22301'])
        for blk_key in ('vision_objectives', 'strategic_pillars',
                        'gap_analysis', 'roadmap',
                        'kpi_kri_framework', 'confidence_risk_register'):
            text = (m['blocks'].get(blk_key) or {}).get('content') or ''
            for term in _CYBER_LEAK_TERMS:
                self.assertNotIn(
                    term, text,
                    f'ERM {blk_key!r} contaminated with {term!r}'
                )

    @_skip_if_no_app
    def test_non_cyber_rejects_cyber_only_frameworks(self):
        # Pass a stray cyber framework (TCC) to a Data Management
        # composer — it must be rejected (not retained).
        m = _APP.compose_professional_strategy_narrative_ai(
            domain='Data Management',
            sections=DATA_SECTIONS,
            metadata={'org_name': 'Test Org', 'sector': 'Government'},
            selected_frameworks=['TCC', 'NDMO'],
            diagnostic_context='', obligations=None, language='en',
        )
        self.assertNotIn('TCC', m['selected_frameworks'])
        self.assertIn('NDMO', m['selected_frameworks'])


class TestSelectedFrameworkCoverage(unittest.TestCase):
    """Selected frameworks must be reflected in scope, objectives,
    pillars, gaps, roadmap, KPIs, risks and the traceability matrix.
    """

    def _assert_coverage(self, model, fw_key, anchors):
        cov = model['selected_framework_coverage']
        self.assertIn(fw_key, cov, f'no coverage entry for {fw_key!r}')
        for anchor in anchors:
            self.assertTrue(
                cov[fw_key].get(anchor),
                f'{fw_key!r} missing coverage anchor {anchor!r} in '
                f'{model["domain"]!r}: cov={cov[fw_key]}'
            )

    @_skip_if_no_app
    def test_cyber_ecc_coverage(self):
        m = _compose('Cyber Security', CYBER_SECTIONS, ['ECC', 'TCC'])
        # ECC families (governance, IAM, monitoring, incident response)
        # are present across every cross-section anchor in the fixture,
        # AND the framework appears in scope and the traceability matrix.
        self._assert_coverage(m, 'ECC', [
            'scope', 'objectives', 'pillars', 'gaps', 'roadmap',
            'kpis', 'risks', 'traceability_matrix',
        ])

    @_skip_if_no_app
    def test_data_ndmo_coverage(self):
        m = _compose('Data Management', DATA_SECTIONS, ['NDMO'])
        self._assert_coverage(m, 'NDMO', [
            'scope', 'objectives', 'pillars', 'gaps', 'roadmap',
            'kpis', 'traceability_matrix',
        ])

    @_skip_if_no_app
    def test_ai_nist_ai_rmf_coverage(self):
        m = _compose('Artificial Intelligence', AI_SECTIONS,
                     ['NIST AI RMF'])
        self._assert_coverage(m, 'NIST_AI_RMF', [
            'scope', 'objectives', 'pillars', 'gaps', 'roadmap',
            'kpis', 'traceability_matrix',
        ])

    @_skip_if_no_app
    def test_dt_dga_coverage(self):
        m = _compose('Digital Transformation', DT_SECTIONS, ['DGA'])
        self._assert_coverage(m, 'DGA', [
            'scope', 'objectives', 'pillars', 'gaps', 'roadmap',
            'kpis', 'traceability_matrix',
        ])

    @_skip_if_no_app
    def test_erm_iso22301_coverage(self):
        m = _compose('Enterprise Risk Management', ERM_SECTIONS,
                     ['ISO22301'])
        # ISO22301 must at least be present in scope and the framework
        # traceability matrix for an ERM strategy that selected it.
        self._assert_coverage(m, 'ISO22301', [
            'scope', 'traceability_matrix',
        ])
        # Verify the environment block reflects the framework number.
        env = (m['blocks'].get('environment_context') or {}).get(
            'content') or ''
        self.assertIn('22301', env)

    @_skip_if_no_app
    def test_global_iso27001_coverage(self):
        m = _compose('Global Standards', GLOBAL_SECTIONS,
                     ['ISO27001', 'NIST_CSF'])
        self._assert_coverage(m, 'ISO27001', [
            'scope', 'traceability_matrix',
        ])


class TestNonGenericExecutiveSummary(unittest.TestCase):
    """The professional composer must produce a non-generic executive
    summary for every domain — each summary mentions both the domain
    name and the domain-specific mandatory themes.
    """

    def _exec_text(self, model):
        paras = (model['blocks'].get('executive_summary') or {}).get(
            'paragraphs') or []
        return '\n'.join(p for p in paras if isinstance(p, str))

    @_skip_if_no_app
    def test_each_domain_executive_summary_is_unique_and_specific(self):
        cases = [
            ('Cyber Security', CYBER_SECTIONS, ['ECC'], 'Cyber Security',
             ['governance', 'incident', 'monitoring']),
            ('Data Management', DATA_SECTIONS, ['NDMO'], 'Data Management',
             ['data governance', 'stewardship', 'data quality']),
            ('Artificial Intelligence', AI_SECTIONS, ['NIST AI RMF'],
             'Artificial Intelligence',
             ['AI governance', 'model risk', 'explainability']),
            ('Digital Transformation', DT_SECTIONS, ['DGA'],
             'Digital Transformation',
             ['service digitisation', 'integration', 'automation']),
            ('Enterprise Risk Management', ERM_SECTIONS, ['ISO22301'],
             'Enterprise Risk Management',
             ['risk taxonomy', 'appetite', 'KRI']),
            ('Global Standards', GLOBAL_SECTIONS, ['ISO27001'],
             'Global Standards',
             ['standards conformance', 'certification', 'audit']),
        ]
        seen_summaries = set()
        for domain, sections, fws, label, must_terms in cases:
            m = _compose(domain, sections, fws)
            text = self._exec_text(m)
            self.assertTrue(text, f'empty executive summary for {domain!r}')
            self.assertIn(
                label, text,
                f'executive summary for {domain!r} does not mention '
                f'the canonical domain label'
            )
            for term in must_terms:
                self.assertIn(
                    term, text,
                    f'executive summary for {domain!r} missing '
                    f'mandatory theme {term!r}'
                )
            # Non-generic ⇒ each domain produces a different summary.
            self.assertNotIn(
                text, seen_summaries,
                f'executive summary for {domain!r} matches another domain '
                f'(generic)'
            )
            seen_summaries.add(text)


class TestNoDeterministicStrategyRows(unittest.TestCase):
    """The composer is a synthesis layer — it must NEVER invent strategy
    rows (objectives / gaps / KPIs / risks). When called with empty
    sections it must produce empty per-section blocks.
    """

    @_skip_if_no_app
    def test_empty_sections_produce_empty_section_blocks(self):
        m = _APP.compose_professional_strategy_narrative_ai(
            domain='Data Management',
            sections={},  # nothing — no AI to fall back to
            metadata={'org_name': 'Test Org', 'sector': 'Government'},
            selected_frameworks=['NDMO'],
            diagnostic_context='', obligations=None, language='en',
        )
        for blk_key in ('vision_objectives', 'strategic_pillars',
                        'environment_context', 'gap_analysis',
                        'roadmap', 'kpi_kri_framework',
                        'confidence_risk_register'):
            blk = m['blocks'].get(blk_key) or {}
            self.assertEqual(
                blk.get('content', ''), '',
                f'block {blk_key!r} invented content from empty input'
            )
            # Empty content ⇒ no markdown table rows ('|') were invented.
            self.assertNotIn('|', blk.get('content', ''))


class TestPreviewPathUnchanged(unittest.TestCase):
    """The new composer must not be wired into the preview path. Verify
    the preview-rendering helper does not reference it.
    """

    @_skip_if_no_app
    def test_preview_does_not_invoke_new_composer(self):
        import inspect
        # Locate the preview-render helper. We accept any helper whose
        # name contains 'preview' and is module-level.
        new_composer_name = 'compose_professional_strategy_narrative_ai'
        for name, obj in vars(_APP).items():
            if not callable(obj):
                continue
            if 'preview' not in name.lower():
                continue
            try:
                src = inspect.getsource(obj)
            except (OSError, TypeError):
                continue
            self.assertNotIn(
                new_composer_name, src,
                f'preview helper {name!r} unexpectedly invokes the new '
                f'professional composer'
            )


class TestExportFollowsProfessionalStructure(unittest.TestCase):
    """The composer model MUST follow the canonical professional document
    structure regardless of domain — same ordered blocks, no domain may
    drop or reorder sections.
    """

    EXPECTED_ORDER = [
        'cover', 'doc_control', 'toc', 'executive_summary',
        'scope_frameworks', 'methodology', 'current_state',
        'vision_objectives', 'strategic_pillars', 'environment_context',
        'gap_analysis', 'roadmap', 'kpi_kri_framework',
        'confidence_risk_register', 'governance_ownership',
        'traceability_matrix', 'appendices',
    ]

    @_skip_if_no_app
    def test_every_domain_emits_canonical_order(self):
        cases = [
            ('Cyber Security', CYBER_SECTIONS, ['ECC']),
            ('Data Management', DATA_SECTIONS, ['NDMO']),
            ('Artificial Intelligence', AI_SECTIONS, ['NIST AI RMF']),
            ('Digital Transformation', DT_SECTIONS, ['DGA']),
            ('Enterprise Risk Management', ERM_SECTIONS, ['ISO22301']),
            ('Global Standards', GLOBAL_SECTIONS, ['ISO27001']),
        ]
        for domain, sections, fws in cases:
            m = _compose(domain, sections, fws)
            self.assertEqual(
                m['order'], self.EXPECTED_ORDER,
                f'domain {domain!r} did not emit the canonical professional '
                f'order; got {m["order"]}'
            )
            for blk in self.EXPECTED_ORDER:
                self.assertIn(
                    blk, m['blocks'],
                    f'domain {domain!r} missing block {blk!r}'
                )


if __name__ == '__main__':
    unittest.main()
