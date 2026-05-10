"""PR-5B.8I: Runtime save-gate coverage for ``cybersecurity_capabilities_missing``.

These tests exercise the targeted AI repair path that runs at the final save
gate when ``validate_arabic_strategy_semantic_richness`` flags
``cybersecurity_capabilities_missing``.  They also pin the validator's
domain-aware behaviour (cyber-only) and the existing token recognition map.

Run:  python -m pytest tests/test_cybersecurity_capabilities_runtime_pr5b8i.py -q
"""

import os
import sys
import unittest
from unittest import mock

# ---------------------------------------------------------------------------
# Test environment setup (mirrors tests/test_technical_strategy_depth.py).
# ---------------------------------------------------------------------------
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///tmp/test_cyber_caps_pr5b8i.db')
os.environ.setdefault('OPENAI_API_KEY', 'dummy')
os.environ.setdefault('ANTHROPIC_API_KEY', 'dummy')
os.environ.setdefault('GOOGLE_API_KEY', 'dummy')

_USING_REAL_APP = False
_APP = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        'app', os.path.join(os.path.dirname(__file__), '..', 'app.py')
    )
    _APP = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(_APP)
    _USING_REAL_APP = True
except Exception:  # noqa: BLE001 — tests below skip when app cannot import
    pass


def _skip_if_no_app(fn):
    import functools

    @functools.wraps(fn)
    def wrapper(self, *a, **kw):
        if not _USING_REAL_APP:
            self.skipTest('app.py not importable in this environment')
        return fn(self, *a, **kw)
    return wrapper


# A baseline Arabic Cyber Security Technical Strategy that covers ALL 8
# required capability families across multiple sections.  Used as the
# starting point for "passes" and "missing one family" tests.
_FULL_CAPS_SECTIONS_AR = {
    'vision': (
        '## 1. الرؤية والأهداف الاستراتيجية\n\n'
        'تعزيز الأمن السيبراني عبر إدارة الهوية والوصول المميز، والمصادقة '
        'الثنائية، والمراقبة المستمرة.\n\n'
        '### الأهداف الاستراتيجية:\n\n'
        '| # | الهدف | المؤشر | المبرر | الإطار |\n'
        '|---|------|-------|--------|--------|\n'
        '| 1 | إدارة الهوية والصلاحيات | 100% | IAM PAM | 12ش |\n'
        '| 2 | المصادقة الثنائية MFA | 100% | NCA | 12ش |\n'
        '| 3 | المراقبة الأمنية SIEM SOC | 24/7 | NCA | 12ش |\n'
        '| 4 | الاستجابة للحوادث | <4س | NCA | 12ش |\n'
        '| 5 | إدارة الثغرات والتصحيح | 30 يوم | NCA | 12ش |\n'
        '| 6 | حماية البيانات والتشفير | 100% | NCA | 12ش |\n'
    ),
    'pillars': (
        '## 2. الركائز الاستراتيجية\n\n'
        '### الركيزة 1: الحوكمة\n\nمبادرات الحوكمة وإدارة الهوية IAM/PAM.\n\n'
        '### الركيزة 2: المراقبة\n\nبناء SOC مع SIEM ومراقبة مستمرة.\n\n'
        '### الركيزة 3: المرونة\n\nالنسخ الاحتياطي والتعافي من الكوارث (DR).\n'
    ),
    'environment': (
        '## 3. البيئة التنظيمية والتهديدات\n\n'
        'السياق التنظيمي: NCA ECC. التهديدات: phishing وتصيد. الأعمال: '
        'حماية البيانات و DLP.\n\n'
        '- البعد التنظيمي: NCA\n- التهديدات: تصيد\n- الأعمال: التشفير\n'
    ),
    'gaps': (
        '## 4. تحليل الفجوات\n\n'
        '| # | الفجوة | الوصف | الأولوية | الحالة |\n'
        '|---|------|------|---------|--------|\n'
        '| 1 | غياب MFA | المصادقة الثنائية | حرجة | مفتوحة |\n'
        '| 2 | ضعف التوعية | برامج التدريب والتوعية ضد التصيد | عالية | مفتوحة |\n'
    ),
    'roadmap': (
        '## 5. خارطة الطريق\n\n'
        '| # | النشاط | المسؤول | الإطار الزمني | المخرج |\n'
        '|---|------|--------|--------------|--------|\n'
        '| 1 | نشر MFA | CISO | الشهر 1-3 | تفعيل المصادقة |\n'
        '| 2 | بناء SOC + SIEM | SOC | الشهر 3-6 | مراقبة |\n'
        '| 3 | برنامج توعية ضد التصيد | HR | الشهر 4-9 | التدريب |\n'
        '| 4 | تنفيذ النسخ الاحتياطي والتعافي | IT | الشهر 6-12 | استعادة |\n'
    ),
    'kpis': (
        '## 6. مؤشرات الأداء الرئيسية\n\n'
        '| # | المؤشر | النوع | القيمة المستهدفة | صيغة | المصدر | المالك | التكرار | الإطار |\n'
        '|---|------|------|-----------------|------|--------|-------|---------|--------|\n'
        '| 1 | تغطية IAM/PAM | KPI | 100% | x | GRC | CISO | شهري | 12ش |\n'
        '| 2 | تفعيل MFA | KPI | 100% | x | IAM | CISO | شهري | 12ش |\n'
        '| 3 | استجابة SOC | KPI | <4س | x | SIEM | CISO | شهري | 12ش |\n'
        '| 4 | إدارة الثغرات والتصحيح | KPI | 30 يوم | x | VM | CISO | شهري | 12ش |\n'
        '| 5 | اختبار النسخ الاحتياطي والتعافي | KPI | 100% | x | DR | CISO | ربع | 12ش |\n'
        '| 6 | برامج التوعية ضد التصيد | KPI | 100% | x | HR | CISO | ربع | 12ش |\n'
        '| 7 | تشفير البيانات و DLP | KPI | 100% | x | DP | CISO | شهري | 12ش |\n'
    ),
    'confidence': '',
}


# ---------------------------------------------------------------------------
# 1. Validator: full coverage passes; one missing family fails.
# ---------------------------------------------------------------------------
class TestValidatorCapabilityCoverage(unittest.TestCase):

    @_skip_if_no_app
    def test_full_coverage_passes(self):
        defects = _APP.validate_arabic_strategy_semantic_richness(
            _FULL_CAPS_SECTIONS_AR, lang='ar', doc_subtype='technical')
        tags = [t for t, _ in defects]
        self.assertNotIn(
            'cybersecurity_capabilities_missing', tags,
            f'Full-coverage strategy should not flag missing; tags={tags}')

    @_skip_if_no_app
    def test_missing_one_family_fails(self):
        # Strip every token of the Backup/DR family from the assembled text
        # so EXACTLY one family is missing.  Build a fresh sections dict.
        stripped = {}
        for k, v in _FULL_CAPS_SECTIONS_AR.items():
            t = v
            for tok in ('backup', 'نسخ احتياطي', 'تعافي', 'استعادة', 'DR', 'dr'):
                t = t.replace(tok, '___')
            stripped[k] = t
        defects = _APP.validate_arabic_strategy_semantic_richness(
            stripped, lang='ar', doc_subtype='technical')
        tag_to_detail = dict(defects)
        self.assertIn('cybersecurity_capabilities_missing', tag_to_detail)
        self.assertIn('Backup/DR', tag_to_detail['cybersecurity_capabilities_missing'])

    @_skip_if_no_app
    def test_arabic_synonyms_recognised(self):
        # Arabic-only payload that uses ONLY Arabic accepted tokens (no
        # English).  Validator must recognise them and not flag the family.
        sections = {k: '' for k in _FULL_CAPS_SECTIONS_AR}
        sections['pillars'] = (
            'الهوية والوصول المميز، المصادقة الثنائية، مراقبة، استجابة، '
            'حوادث، ثغرات، نسخ احتياطي، تعافي، توعية، تصيد، حماية البيانات، '
            'تشفير.'
        )
        defects = _APP.validate_arabic_strategy_semantic_richness(
            sections, lang='ar', doc_subtype='technical')
        tags = [t for t, _ in defects]
        self.assertNotIn(
            'cybersecurity_capabilities_missing', tags,
            f'Arabic synonyms should be recognised; tags={tags}')


# ---------------------------------------------------------------------------
# 2. _compute_missing_cyber_capabilities helper used by the repair path.
# ---------------------------------------------------------------------------
class TestMissingCapsHelper(unittest.TestCase):

    @_skip_if_no_app
    def test_helper_returns_missing_families_only(self):
        sections = {k: '' for k in _FULL_CAPS_SECTIONS_AR}
        sections['pillars'] = (
            'IAM PAM MFA SIEM SOC incident response vulnerability awareness '
            'data protection'
        )
        # All families covered EXCEPT Backup/DR.
        missing = _APP._compute_missing_cyber_capabilities(sections)
        self.assertEqual(missing, ['Backup/DR'])

    @_skip_if_no_app
    def test_helper_full_text_returns_empty(self):
        self.assertEqual(
            _APP._compute_missing_cyber_capabilities(_FULL_CAPS_SECTIONS_AR),
            [],
        )


# ---------------------------------------------------------------------------
# 3. Domain isolation: non-cyber domains are NOT held to the cyber capability
#    requirement when ``domain`` is supplied.
# ---------------------------------------------------------------------------
class TestNonCyberDomainsUnaffected(unittest.TestCase):

    @_skip_if_no_app
    def test_non_cyber_domain_skips_capability_check(self):
        # Empty strategy, but for a non-cyber domain — must not flag the
        # cyber capability defect when a domain is explicitly supplied.
        sections = {k: '' for k in _FULL_CAPS_SECTIONS_AR}
        for d in ('Data Governance', 'Artificial Intelligence',
                  'Enterprise Risk Management', 'Digital Transformation'):
            defects = _APP.validate_arabic_strategy_semantic_richness(
                sections, lang='ar', doc_subtype='technical', domain=d)
            tags = [t for t, _ in defects]
            self.assertNotIn(
                'cybersecurity_capabilities_missing', tags,
                f'Non-cyber domain {d!r} must not receive cyber capability '
                f'requirement; tags={tags}')

    @_skip_if_no_app
    def test_cyber_domain_still_flags_missing(self):
        sections = {k: '' for k in _FULL_CAPS_SECTIONS_AR}
        defects = _APP.validate_arabic_strategy_semantic_richness(
            sections, lang='ar', doc_subtype='technical',
            domain='Cyber Security')
        tags = [t for t, _ in defects]
        self.assertIn('cybersecurity_capabilities_missing', tags)

    @_skip_if_no_app
    def test_default_domain_none_preserves_legacy_behavior(self):
        # When no domain is supplied (legacy/unit tests), the check still
        # runs.  This pins backward-compatibility.
        sections = {k: '' for k in _FULL_CAPS_SECTIONS_AR}
        defects = _APP.validate_arabic_strategy_semantic_richness(
            sections, lang='ar', doc_subtype='technical')
        tags = [t for t, _ in defects]
        self.assertIn('cybersecurity_capabilities_missing', tags)


# ---------------------------------------------------------------------------
# 4. ai_repair_strategy_section is invoked with a validation_error that
#    NAMES the missing capability families (Option A contract) — verified
#    by spying on the underlying generate_ai_content prompt.
# ---------------------------------------------------------------------------
class TestRepairPromptCarriesMissingFamilies(unittest.TestCase):

    @_skip_if_no_app
    def test_validation_error_lists_missing_families_in_prompt(self):
        # Compose a sections dict missing Backup/DR + Awareness.
        sections = {k: v for k, v in _FULL_CAPS_SECTIONS_AR.items()}
        # Strip Backup/DR + Awareness tokens only.
        for fam_tokens in (('backup', 'نسخ احتياطي', 'تعافي', 'استعادة',
                            'DR', 'dr'),
                           ('awareness', 'توعية', 'phishing', 'تصيد',
                            'التدريب')):
            for kk in list(sections):
                t = sections[kk]
                for tok in fam_tokens:
                    t = t.replace(tok, '___')
                sections[kk] = t
        missing = _APP._compute_missing_cyber_capabilities(sections)
        self.assertIn('Backup/DR', missing)
        self.assertIn('Awareness', missing)

        domain_ctx = _APP.get_strategy_domain_context(
            'Cyber Security', lang='en', selected_frameworks=[])

        ve = (
            'The assembled strategy is missing the following cybersecurity '
            'capability families: ' + ', '.join(missing)
            + '. Each family MUST appear at least once in this section.'
        )

        captured = {'prompt': None}

        def _fake_generate(prompt, language=None, task_type=None,
                           content_type=None):
            captured['prompt'] = prompt
            # Return a stub markdown that carries the heading + every
            # missing-family token so the post-repair domain-isolation /
            # heading checks pass.
            return (
                '## 5. Roadmap\n\nbackup, DR, awareness, phishing, IAM, MFA, '
                'SIEM, incident response, vulnerability, data protection, '
                'encryption.'
            )

        with mock.patch.object(_APP, 'generate_ai_content',
                               side_effect=_fake_generate):
            out = _APP.ai_repair_strategy_section(
                section_key='roadmap', sections=sections, lang='en',
                domain_context=domain_ctx, validation_error=ve)
        self.assertIsNotNone(captured['prompt'])
        # Missing family names must appear inside the prompt the AI sees.
        self.assertIn('Backup/DR', captured['prompt'])
        self.assertIn('Awareness', captured['prompt'])
        # The prompt MUST also contain the cyber capability coverage clause
        # (added in the prior fix), since the section_key is in the cyber
        # set and the resolved domain is cyber.
        self.assertIn('cybersecurity capability coverage',
                      captured['prompt'].lower())
        self.assertTrue(out.strip().startswith('##'))


# ---------------------------------------------------------------------------
# 5. AI-first guarantee: when the AI provider is unavailable, the repair
#    raises RepairError (so the save gate stays fail-closed) and NO
#    deterministic capability rows are inserted.
# ---------------------------------------------------------------------------
class TestRepairFailClosedNoDeterministicRows(unittest.TestCase):

    @_skip_if_no_app
    def test_repair_failure_raises_repair_error(self):
        domain_ctx = _APP.get_strategy_domain_context(
            'Cyber Security', lang='en', selected_frameworks=[])
        sections = {k: v for k, v in _FULL_CAPS_SECTIONS_AR.items()}

        def _boom(*a, **kw):
            raise RuntimeError('no ai provider configured')

        with mock.patch.object(_APP, 'generate_ai_content', side_effect=_boom):
            with self.assertRaises(_APP.RepairError):
                _APP.ai_repair_strategy_section(
                    section_key='pillars', sections=sections, lang='en',
                    domain_context=domain_ctx,
                    validation_error='missing IAM/PAM, MFA')

    @_skip_if_no_app
    def test_no_deterministic_capability_row_helper_exists(self):
        # Guardrail: ensure no helper that injects fixed deterministic
        # capability rows was added under a recognisable name.  This pins
        # the "do not hardcode capability rows" contract.
        forbidden_names = (
            '_inject_capability_rows',
            '_force_inject_cyber_capabilities',
            '_deterministic_cyber_capability_rows',
        )
        for name in forbidden_names:
            self.assertFalse(
                hasattr(_APP, name),
                f'Deterministic capability injector {name!r} must not exist')


# ---------------------------------------------------------------------------
# 6. validator → repair → revalidate contract: helper reflects post-repair
#    state of sections.  Test simulates a successful AI repair by mutating
#    sections in place and confirming the helper now reports zero missing.
# ---------------------------------------------------------------------------
class TestRevalidationAfterRepair(unittest.TestCase):

    @_skip_if_no_app
    def test_post_repair_revalidation_clears_defect(self):
        # Start from missing Backup/DR; "repair" by appending tokens; helper
        # must return [].
        sections = {k: v for k, v in _FULL_CAPS_SECTIONS_AR.items()}
        for tok in ('backup', 'نسخ احتياطي', 'تعافي', 'استعادة', 'DR'):
            for kk in list(sections):
                sections[kk] = sections[kk].replace(tok, '___')
        self.assertEqual(
            _APP._compute_missing_cyber_capabilities(sections),
            ['Backup/DR'])
        sections['roadmap'] += '\n\nنسخ احتياطي وتعافي (DR backup).'
        self.assertEqual(
            _APP._compute_missing_cyber_capabilities(sections), [])


if __name__ == '__main__':
    unittest.main()
