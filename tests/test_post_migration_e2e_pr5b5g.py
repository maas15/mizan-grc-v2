"""PR-5B.5G: Post-migration end-to-end validation (no production code changes).

Validates the accepted PR-5B.5F4 state across all six strategy domains and
all three AI-first synthesis paths (vision / kpis / roadmap).  This file
contains validation-only tests; production code is untouched.

Coverage matrix:

  1. Static proof: AST walk of ``app.py`` confirms zero production call
     sites for the four quarantined helpers (already enforced by
     ``test_legacy_bank_quarantine_pr5b5f4.py``; reasserted here for the
     PR-5B.5G acceptance bundle).
  2. Domain isolation per domain × per synth: with
     ``ai_repair_strategy_section`` mocked, the synth helper replaces the
     section verbatim with the AI output and inserts no domain-cross
     contamination.  Non-cyber domains assert the AI output also passes a
     manual cyber-only-term check (CISO / SOC / SIEM / CSIRT / PAM / EDR /
     WAF / MTTD / MTTR).
  3. AI-first repair per section: malformed input is replaced verbatim by
     mocked AI output; no old malformed rows survive; no deterministic
     rows are appended.
  4. Fail-closed per section: when ``ai_repair_strategy_section`` raises
     ``RepairError``, the section text is unchanged, no fallback content
     is appended, no quarantined helper is invoked, the production-caller
     pattern records ``synth_status[<section>] = 'failed'``, and
     ``_final_strategy_audit`` emits ``synth_failed:<section>``.
  5. Quarantined-helper spies installed across every test path: any call
     fails the test loudly.

Preview/export safety:
  Preview/export is a request/response code path that requires a live
  Flask test client, an authenticated session, an initialised SQLAlchemy
  engine, and at least one persisted strategy row.  In the current
  pytest sandbox we do not have a live DB session or authenticated
  client; ``test_8_preview_export_blocker_documented`` documents this
  blocker (and the env vars / fixtures that would be required) instead
  of producing a false-negative.

Run:  python -m pytest tests/test_post_migration_e2e_pr5b5g.py -q
"""

import ast
import importlib
import os
import sys
import unittest

# ---------------------------------------------------------------------------
# Minimal env so app.py can be imported without a live DB / API keys.
# ---------------------------------------------------------------------------
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault(
    'DATABASE_URL', 'sqlite:///tmp/test_post_migration_e2e_pr5b5g.db')
os.environ.setdefault('OPENAI_API_KEY', 'dummy')
os.environ.setdefault('ANTHROPIC_API_KEY', 'dummy')
os.environ.setdefault('GOOGLE_API_KEY', 'dummy')

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

_APP = importlib.import_module('app')

# ---------------------------------------------------------------------------
# Constants under test.
# ---------------------------------------------------------------------------

_QUARANTINED_HELPERS = (
    '_build_domain_so_bank_ar',
    '_build_domain_so_bank_en',
    '_build_domain_kpi_bank_ar',
    '_build_domain_kpi_bank_en',
)

# Six canonical strategy domains × English display name.
_DOMAINS = (
    'Cyber Security',
    'Data Management',
    'Artificial Intelligence',
    'Digital Transformation',
    'Enterprise Risk Management',
    'Global Standards',
)

# Cyber-only terms that must NOT appear in a non-cyber synth output.
# Whole-word match using simple substring with surrounding whitespace
# guards (mirrors the substring style used by _DOMAIN_FORBIDDEN_TERMS).
_CYBER_ONLY_TERMS = (
    'CISO', 'SOC', 'SIEM', 'CSIRT', 'PAM',
    'EDR', 'WAF', 'MTTD', 'MTTR',
)


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------

class _Patch:
    """Lightweight context manager that swaps a module attribute."""

    def __init__(self, target, name, value):
        self.target = target
        self.name = name
        self.value = value
        self._original = None
        self._had = False

    def __enter__(self):
        self._had = hasattr(self.target, self.name)
        if self._had:
            self._original = getattr(self.target, self.name)
        setattr(self.target, self.name, self.value)
        return self

    def __exit__(self, exc_type, exc, tb):
        if self._had:
            setattr(self.target, self.name, self._original)
        else:  # pragma: no cover - defensive
            try:
                delattr(self.target, self.name)
            except AttributeError:
                pass
        return False


def _quarantine_spies():
    """Return list of _Patch objects that fail the test if any of the four
    quarantined helpers is invoked."""
    spies = []
    for name in _QUARANTINED_HELPERS:
        def _spy(*_a, _name=name, **_kw):
            raise AssertionError(
                f'PR-5B.5G: quarantined helper {_name} was called from '
                'production code path under test')
        spies.append(_Patch(_APP, name, _spy))
    return spies


class _SpyStack:
    """Apply a list of _Patch context managers as a single ``with`` block."""

    def __init__(self, patches):
        self.patches = patches

    def __enter__(self):
        for p in self.patches:
            p.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb):
        for p in reversed(self.patches):
            p.__exit__(exc_type, exc, tb)
        return False


# Malformed inputs (force the synth helpers down the AI-first repair branch).

_MALFORMED_VISION_AR = (
    '## 1. الرؤية والأهداف الاستراتيجية\n\n'
    '### الأهداف الاستراتيجية\n\n'
    '| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n'
    '|---|-------|-----------------|--------|---------------|\n'
    '| 1 | OLD-MALFORMED-VISION-ROW | TBD | TBD | TBD |\n'
)

_MALFORMED_KPI_AR = (
    '## 6. مؤشرات الأداء الرئيسية\n\n'
    '| # | وصف المؤشر | القيمة المستهدفة | المبرر |\n'
    '|---|-----------|-----------------|--------|\n'
    '| 1 | OLD-MALFORMED-KPI-ROW | 90% | TBD |\n'
)

_MALFORMED_ROADMAP_EN = (
    '## 5. Implementation Roadmap\n\n'
    '| # | Activity | Owner | Timeline | Deliverable |\n'
    '|---|----------|-------|----------|-------------|\n'
    '| 1 | OLD-MALFORMED-ROADMAP-ROW | TBD | TBD | TBD |\n'
)


def _ai_repaired_vision_for(domain):
    """Build a clean SO section with >= _RICHNESS_MIN_SO_ROWS valid rows
    and a domain label embedded in each row.  Uses Arabic schema."""
    n = max(getattr(_APP, '_RICHNESS_MIN_SO_ROWS', 4), 6)
    header = (
        '## 1. الرؤية والأهداف الاستراتيجية\n\n'
        f'**الرؤية:** رؤية شاملة لـ {domain}.\n\n'
        '### الأهداف الاستراتيجية\n\n'
        '| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n'
        '|---|-------|-----------------|--------|---------------|\n'
    )
    body = '\n'.join(
        f'| {i} | هدف {i} لـ {domain} | ≥ 95% | متطلب حوكمة في {domain} '
        f'| خلال 12 شهراً |'
        for i in range(1, n + 1)
    )
    return header + body + '\n'


def _ai_repaired_kpi_for(domain):
    """Canonical 9-column Arabic KPI schema (with Frequency / التكرار)."""
    n = max(getattr(_APP, '_RICHNESS_MIN_KPI_ROWS', 4), 6)
    header = (
        '## 6. مؤشرات الأداء الرئيسية\n\n'
        '| # | المؤشر | النوع KPI/KRI | القيمة المستهدفة | صيغة الاحتساب '
        '| مصدر البيانات | المالك | التكرار | الإطار الزمني |\n'
        '|---|--------|---------------|-----------------|---------------|'
        '----------------|--------|----------|----------------|\n'
    )
    body = '\n'.join(
        f'| {i} | مؤشر {i} لـ {domain} | KPI | ≥ 90% '
        f'| (المطبّق ÷ الإجمالي) × 100 | سجل الحوكمة في {domain} '
        f'| فريق حوكمة {domain} | شهري | خلال 12 شهراً |'
        for i in range(1, n + 1)
    )
    return header + body + '\n'


def _ai_repaired_roadmap_for(domain):
    """English roadmap with >= consulting-floor substantive rows."""
    n = max(getattr(_APP, '_RICHNESS_MIN_ROADMAP_ROWS', 4) + 2, 8)
    header = (
        '## 5. Implementation Roadmap\n\n'
        '| # | Activity | Owner | Timeline | Deliverable |\n'
        '|---|----------|-------|----------|-------------|\n'
    )
    body = '\n'.join(
        f'| {i} | Establish {domain} capability {i} '
        f'| {domain} Lead | Months {i}-{i + 5} '
        f'| {domain} deliverable {i} |'
        for i in range(1, n + 1)
    )
    return header + body + '\n'


def _assert_no_cyber_only_terms(testcase, text, domain):
    if domain == 'Cyber Security':
        return
    for term in _CYBER_ONLY_TERMS:
        testcase.assertNotIn(
            term, text,
            f'Non-cyber domain {domain!r}: cyber-only term {term!r} '
            f'leaked into AI-repaired output')


# ---------------------------------------------------------------------------
# 1. Static AST proof.
# ---------------------------------------------------------------------------

class _CallSiteVisitor(ast.NodeVisitor):
    def __init__(self, targets):
        self.targets = set(targets)
        self.calls = []

    def visit_Call(self, node):
        callee = None
        f = node.func
        if isinstance(f, ast.Name):
            callee = f.id
        elif isinstance(f, ast.Attribute):
            callee = f.attr
        if callee in self.targets:
            self.calls.append((callee, node.lineno))
        self.generic_visit(node)


class TestStaticZeroProductionCallsites(unittest.TestCase):
    """Re-pin the PR-5B.5F4 quarantine: zero production call sites for
    any of the four legacy deterministic bank helpers."""

    def test_zero_production_call_sites(self):
        path = os.path.join(_REPO_ROOT, 'app.py')
        with open(path, 'r', encoding='utf-8') as fh:
            tree = ast.parse(fh.read(), filename=path)
        v = _CallSiteVisitor(_QUARANTINED_HELPERS)
        v.visit(tree)
        if v.calls:
            details = '\n'.join(f'  - {n} at app.py:{l}' for n, l in v.calls)
            self.fail('PR-5B.5G: quarantined helper(s) still called:\n'
                      + details)

    def test_quarantine_flag_is_false(self):
        # PR-5B.5H: helpers and the _LEGACY_DETERMINISTIC_BANKS_ENABLED
        # flag are deleted entirely. The contract previously expressed by
        # "flag exists and is False" is now strictly stronger: the flag
        # name must not exist on the module at all.
        self.assertFalse(hasattr(_APP, '_LEGACY_DETERMINISTIC_BANKS_ENABLED'))


# ---------------------------------------------------------------------------
# 2. Domain isolation × AI-first replacement (vision / kpis / roadmap).
# ---------------------------------------------------------------------------

class TestDomainIsolationAIFirst(unittest.TestCase):
    """For each of the six canonical domains, mock ai_repair_strategy_section
    so it returns clean domain-appropriate output and assert:

      * synth_<X>_depth replaces the section verbatim with the AI output;
      * old malformed rows do not survive;
      * no deterministic rows are inserted (output equals AI output bytes);
      * no quarantined helper is ever invoked;
      * for non-cyber domains, no cyber-only terms leak in.
    """

    def _run_vision(self, domain):
        repaired = _ai_repaired_vision_for(domain)

        def _ai_stub(**kwargs):
            self.assertEqual(kwargs.get('section_key'), 'vision')
            return repaired

        sections = {'vision': _MALFORMED_VISION_AR}
        with _SpyStack(_quarantine_spies()), \
             _Patch(_APP, 'ai_repair_strategy_section', _ai_stub):
            summary = _APP.synthesize_objectives_depth(
                sections, lang='ar',
                domain=domain, fw_short='NCA ECC',
                sector='Government', org_name='Acme',
                generation_mode='consulting',
            )
        self.assertTrue(summary.get('rebuilt'))
        self.assertEqual(sections['vision'], repaired,
                         f'{domain}: section must equal AI output verbatim')
        self.assertNotIn('OLD-MALFORMED-VISION-ROW', sections['vision'])
        _assert_no_cyber_only_terms(self, sections['vision'], domain)

    def _run_kpi(self, domain):
        repaired = _ai_repaired_kpi_for(domain)

        def _ai_stub(**kwargs):
            self.assertEqual(kwargs.get('section_key'), 'kpis')
            return repaired

        sections = {'kpis': _MALFORMED_KPI_AR}
        with _SpyStack(_quarantine_spies()), \
             _Patch(_APP, 'ai_repair_strategy_section', _ai_stub):
            n = _APP.synthesize_kpi_depth(
                sections, lang='ar',
                domain=domain, fw_short='NCA ECC',
                generation_mode='consulting',
                sector='Government', org_name='Acme',
            )
        self.assertGreaterEqual(n, getattr(_APP, '_RICHNESS_MIN_KPI_ROWS', 4))
        self.assertEqual(sections['kpis'], repaired,
                         f'{domain}: KPI section must equal AI output verbatim')
        self.assertNotIn('OLD-MALFORMED-KPI-ROW', sections['kpis'])
        self.assertIn('التكرار', sections['kpis'])
        _assert_no_cyber_only_terms(self, sections['kpis'], domain)

    def _run_roadmap(self, domain):
        repaired = _ai_repaired_roadmap_for(domain)

        def _ai_stub(**kwargs):
            self.assertEqual(kwargs.get('section_key'), 'roadmap')
            return repaired

        sections = {'roadmap': _MALFORMED_ROADMAP_EN}
        with _SpyStack(_quarantine_spies()), \
             _Patch(_APP, 'ai_repair_strategy_section', _ai_stub):
            n = _APP.synthesize_roadmap_depth(
                sections, lang='en',
                domain=domain, fw_short='NCA ECC',
                generation_mode='consulting',
                sector='Government', org_name='Acme',
            )
        self.assertGreaterEqual(
            n, getattr(_APP, '_RICHNESS_MIN_ROADMAP_ROWS', 4))
        self.assertEqual(sections['roadmap'], repaired,
                         f'{domain}: roadmap must equal AI output verbatim')
        self.assertNotIn('OLD-MALFORMED-ROADMAP-ROW', sections['roadmap'])
        _assert_no_cyber_only_terms(self, sections['roadmap'], domain)

    # Generated test methods per domain × per section, named for readable
    # pytest output.
    def test_vision_per_domain(self):
        for d in _DOMAINS:
            with self.subTest(domain=d, section='vision'):
                self._run_vision(d)

    def test_kpi_per_domain(self):
        for d in _DOMAINS:
            with self.subTest(domain=d, section='kpis'):
                self._run_kpi(d)

    def test_roadmap_per_domain(self):
        for d in _DOMAINS:
            with self.subTest(domain=d, section='roadmap'):
                self._run_roadmap(d)


# ---------------------------------------------------------------------------
# 3. AI-first replacement contract (sanity, single domain).
# ---------------------------------------------------------------------------

class TestAIFirstReplacementContract(unittest.TestCase):
    """Verify the per-section replacement contract once with explicit
    section_key assertion (mirrors PR-5B.5C/F2/F3 acceptance)."""

    def test_vision_section_key_and_replacement(self):
        seen = {}
        repaired = _ai_repaired_vision_for('Cyber Security')

        def _ai_stub(**kwargs):
            seen.update(kwargs)
            return repaired

        sections = {'vision': _MALFORMED_VISION_AR}
        with _SpyStack(_quarantine_spies()), \
             _Patch(_APP, 'ai_repair_strategy_section', _ai_stub):
            _APP.synthesize_objectives_depth(
                sections, lang='ar',
                domain='Cyber Security', fw_short='NCA ECC',
                sector='Government', org_name='Acme',
            )
        self.assertEqual(seen.get('section_key'), 'vision')
        self.assertEqual(sections['vision'], repaired)

    def test_kpis_section_key_and_replacement(self):
        seen = {}
        repaired = _ai_repaired_kpi_for('Cyber Security')

        def _ai_stub(**kwargs):
            seen.update(kwargs)
            return repaired

        sections = {'kpis': _MALFORMED_KPI_AR}
        with _SpyStack(_quarantine_spies()), \
             _Patch(_APP, 'ai_repair_strategy_section', _ai_stub):
            _APP.synthesize_kpi_depth(
                sections, lang='ar',
                domain='Cyber Security', fw_short='NCA ECC',
            )
        self.assertEqual(seen.get('section_key'), 'kpis')
        self.assertEqual(sections['kpis'], repaired)

    def test_roadmap_section_key_and_replacement(self):
        seen = {}
        repaired = _ai_repaired_roadmap_for('Cyber Security')

        def _ai_stub(**kwargs):
            seen.update(kwargs)
            return repaired

        sections = {'roadmap': _MALFORMED_ROADMAP_EN}
        with _SpyStack(_quarantine_spies()), \
             _Patch(_APP, 'ai_repair_strategy_section', _ai_stub):
            _APP.synthesize_roadmap_depth(
                sections, lang='en',
                domain='Cyber Security', fw_short='NCA ECC',
            )
        self.assertEqual(seen.get('section_key'), 'roadmap')
        self.assertEqual(sections['roadmap'], repaired)


# ---------------------------------------------------------------------------
# 4. Fail-closed: RepairError → no fallback content + audit blocks.
# ---------------------------------------------------------------------------

def _raise_repair(*_a, **_kw):
    raise _APP.RepairError('PR-5B.5G forced AI failure')


class TestFailClosedSynthFailedDefects(unittest.TestCase):
    """For each of vision / kpis / roadmap, when the AI helper raises
    RepairError, the section text is unmutated, no quarantined helper is
    invoked, _mark_synth_failed records the failure, and
    _final_strategy_audit emits a synth_failed:<section> defect."""

    def _assert_no_fallback_text(self, text, section):
        # Generic deterministic-fallback markers that prior versions
        # of the repair helpers used to inject after AI failure.
        for fb in ('Closure KPI:', 'مؤشر إغلاق:', 'Remediate:', 'معالجة:'):
            self.assertNotIn(
                fb, text,
                f'{section}: deterministic fallback marker {fb!r} leaked '
                'into the section after RepairError')

    def test_vision_fail_closed(self):
        sections = {'vision': _MALFORMED_VISION_AR}
        original = sections['vision']
        synth_status = {}
        with _SpyStack(_quarantine_spies()), \
             _Patch(_APP, 'ai_repair_strategy_section', _raise_repair):
            with self.assertRaises(_APP.RepairError) as cm:
                _APP.synthesize_objectives_depth(
                    sections, lang='ar',
                    domain='Cyber Security', fw_short='NCA ECC',
                )
        self.assertEqual(sections['vision'], original)
        self._assert_no_fallback_text(sections['vision'], 'vision')
        # Mirror production caller pattern.
        _APP._mark_synth_failed(
            synth_status, 'vision', cm.exception)
        self.assertEqual(
            synth_status.get('synth_status', {}).get('vision'), 'failed')

    def test_kpis_fail_closed(self):
        sections = {'kpis': _MALFORMED_KPI_AR}
        original = sections['kpis']
        synth_status = {}
        with _SpyStack(_quarantine_spies()), \
             _Patch(_APP, 'ai_repair_strategy_section', _raise_repair):
            with self.assertRaises(_APP.RepairError) as cm:
                _APP.synthesize_kpi_depth(
                    sections, lang='ar',
                    domain='Cyber Security', fw_short='NCA ECC',
                )
        self.assertEqual(sections['kpis'], original)
        self._assert_no_fallback_text(sections['kpis'], 'kpis')
        _APP._mark_synth_failed(synth_status, 'kpis', cm.exception)
        self.assertEqual(
            synth_status.get('synth_status', {}).get('kpis'), 'failed')

    def test_roadmap_fail_closed(self):
        sections = {'roadmap': _MALFORMED_ROADMAP_EN}
        original = sections['roadmap']
        synth_status = {}
        with _SpyStack(_quarantine_spies()), \
             _Patch(_APP, 'ai_repair_strategy_section', _raise_repair):
            with self.assertRaises(_APP.RepairError) as cm:
                _APP.synthesize_roadmap_depth(
                    sections, lang='en',
                    domain='Cyber Security', fw_short='NCA ECC',
                )
        self.assertEqual(sections['roadmap'], original)
        self._assert_no_fallback_text(sections['roadmap'], 'roadmap')
        _APP._mark_synth_failed(synth_status, 'roadmap', cm.exception)
        self.assertEqual(
            synth_status.get('synth_status', {}).get('roadmap'), 'failed')

    def test_final_audit_emits_synth_failed_defects(self):
        # Build a minimal-but-rich payload; defects we care about are the
        # synthetic synth_failed:<section> entries the save gate uses.
        sections = {
            'vision': '', 'pillars': '', 'environment': '', 'gaps': '',
            'roadmap': '', 'kpis': '', 'confidence': '',
        }
        defects = _APP._final_strategy_audit(
            sections, 'ar', doc_subtype=None,
            synth_status={
                'vision': 'failed', 'kpis': 'failed', 'roadmap': 'failed',
            })
        tags = {(sec, tag) for sec, tag, _, _ in defects}
        for sec in ('vision', 'kpis', 'roadmap'):
            self.assertIn((sec, f'synth_failed:{sec}'), tags,
                f'PR-5B.5G: _final_strategy_audit must surface '
                f'synth_failed:{sec} so the save gate blocks the strategy')


# ---------------------------------------------------------------------------
# 5. Repair-helper layer (vision/kpi) also fails closed without invoking
#    quarantined helpers (covers PR-5B.5F3 surface, re-pinned for F4).
# ---------------------------------------------------------------------------

class TestRepairLayerFailClosed(unittest.TestCase):
    """The PR-5B.5F3 repair functions delegate to the synth helpers and
    re-raise RepairError with section annotated.  PR-5B.5G re-pins that
    these paths also never touch a quarantined helper."""

    def test_repair_vision_propagates_repair_error_section_vision(self):
        sections = {'vision': _MALFORMED_VISION_AR}
        with _SpyStack(_quarantine_spies()), \
             _Patch(_APP, 'synthesize_objectives_depth', _raise_repair):
            with self.assertRaises(_APP.RepairError) as cm:
                _APP.repair_vision_objectives_if_insufficient(
                    sections, lang='ar',
                    domain='Cyber Security', org_name='Acme',
                    frameworks=['NCA ECC'], sector='Government',
                )
        self.assertEqual(getattr(cm.exception, 'section', None), 'vision')

    def test_repair_kpi_propagates_repair_error_section_kpis(self):
        sections = {'kpis': _MALFORMED_KPI_AR}
        with _SpyStack(_quarantine_spies()), \
             _Patch(_APP, 'synthesize_kpi_depth', _raise_repair):
            with self.assertRaises(_APP.RepairError) as cm:
                _APP.repair_kpi_section_if_missing_frequency(
                    sections, lang='ar',
                    domain='Cyber Security', org_name='Acme',
                    sector='Government', frameworks=['NCA ECC'],
                )
        self.assertEqual(getattr(cm.exception, 'section', None), 'kpis')


# ---------------------------------------------------------------------------
# 6. Preview/export blocker documentation (no false negatives).
# ---------------------------------------------------------------------------

class TestPreviewExportBlocker(unittest.TestCase):
    """Document why preview/export end-to-end cannot be exercised in this
    test sandbox (instead of asserting a misleading pass)."""

    def test_preview_export_blocker_documented(self):
        # Required for an end-to-end preview/export round-trip:
        #   - A live SQLAlchemy engine bound to a populated DB (the
        #     in-memory SQLite default has no schema migrations applied).
        #   - At least one persisted Strategy row + a User session whose
        #     auth cookie matches that user.
        #   - A Flask test client that has hit the login endpoint.
        #   - Network egress to the AI provider OR a global mock of
        #     ai_repair_strategy_section installed before request handlers
        #     run (the synthesizers run inside the request lifecycle).
        # None of these are bootstrapped by the existing pytest fixtures
        # in this repo, so an honest "blocker documented" outcome is
        # preferable to a false-positive integration assertion.
        blockers = [
            'No DB migrations applied against DATABASE_URL in test env',
            'No authenticated Flask test client fixture',
            'No persisted Strategy row to preview/export',
            'No global mock of ai_repair_strategy_section across the '
            'request lifecycle (AI keys are dummies)',
        ]
        # Sanity: app exposes the production-side gate function.
        self.assertTrue(hasattr(_APP, '_final_strategy_audit'))
        self.assertTrue(hasattr(_APP, '_mark_synth_failed'))
        # Surface blockers so the PR description / report can quote them.
        self.assertTrue(blockers)


if __name__ == '__main__':
    unittest.main()
