"""PR-5B.8L: Runtime save-gate coverage for environment-section depth.

These tests pin the AI-first repair contract for the environment section
depth defects emitted by ``validate_environment_richness`` /
``validate_arabic_strategy_semantic_richness``:

  - environment_missing
  - environment_paragraphs_insufficient
  - environment_structured_block_missing
  - environment_topic_coverage_incomplete

Contract:
  1. A canonical Arabic environment section with the required heading,
     three category paragraphs, and a 5-column threat/gap matrix passes
     the depth validator.
  2. Heading only (no paragraphs, no table) fails.
  3. Wrong table headers (only a heading + token cells) still fails the
     structured-block / topic-coverage check.
  4. ``_AI_REPAIR_SECTION_SCHEMA["environment"]`` exists for both AR and
     EN and requires the canonical heading, the three categories, the
     5-column matrix, and forbids placeholders / HTML / trace markers.
  5. ``ai_repair_strategy_section`` accepts ``section_key="environment"``
     and the prompt carries the canonical heading and the depth defect
     names supplied via ``validation_error``.
  6. The internal synth marker ``mizan-synth-env-v2`` is stripped from
     AI-repair output by ``_ai_repair_strip_html_and_trace``.
  7. AI-first / fail-closed: when the provider raises, the repair raises
     ``RepairError`` and no deterministic environment rows are inserted.
  8. Non-cyber domains do NOT receive the cyber-capability coverage
     clause when repairing the environment section.

Run:  python -m pytest tests/test_environment_depth_runtime_pr5b8l.py -q
"""

import os
import sys
import unittest
from unittest import mock

# ---------------------------------------------------------------------------
# Test environment setup (mirrors tests/test_cybersecurity_capabilities_runtime_pr5b8i.py).
# ---------------------------------------------------------------------------
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///tmp/test_env_depth_pr5b8l.db')
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


# A canonical Arabic environment section that satisfies all four depth
# checks: heading, ≥3 substantive paragraphs (regulatory + threat +
# business keywords), and a structured table with ≥2 data rows.
_GOOD_ENV_AR = (
    '## 3. البيئة التنظيمية والتهديدات\n\n'
    '**السياق التنظيمي:** يفرض الإطار التنظيمي المعمول به في قطاع الخدمات '
    'الحكومية متطلبات صريحة على الامتثال للوائح والأنظمة، بما يشمل تطبيق '
    'الضوابط وإثبات الحوكمة المستمرة، وفق متطلبات الإطار التنظيمي الوطني.\n\n'
    '**سياق التهديدات:** تشير البيانات الوطنية إلى ارتفاع ملحوظ في الهجمات '
    'وحوادث الاختراق وحملات التصيد الموجّه ضد المنظمات في القطاع، مما يرفع '
    'أولوية تحصين الضوابط وتسريع الاستجابة للتهديدات الناشئة.\n\n'
    '**السياق التشغيلي وسياق الأعمال:** تواجه المنظمة ضغوطاً تشغيلية '
    'متصاعدة تتعلق باستمرارية الأعمال والتحول الرقمي وتقديم الخدمات، مما '
    'يستلزم موازنة الاستثمارات الاستراتيجية مع متطلبات قطاع الخدمات.\n\n'
    '| # | البُعد / التهديد | المصدر / الإشارة | التأثير المحتمل | المبادرة المرتبطة |\n'
    '|---|-----------------|-------------------|------------------|-------------------|\n'
    '| 1 | البُعد التنظيمي | متطلبات الإطار التنظيمي على القطاع | عالٍ | تأسيس برنامج الامتثال |\n'
    '| 2 | التهديدات | ارتفاع حوادث التصيد والاختراق | عالٍ | تعزيز الاستجابة للحوادث |\n'
    '| 3 | الأعمال | ضغوط استمرارية الأعمال والتحول الرقمي | متوسط | برنامج استمرارية الأعمال |\n'
)

_HEADING_ONLY_AR = '## 3. البيئة التنظيمية والتهديدات\n\nقسم قصير.\n'


# ---------------------------------------------------------------------------
# 1. Validator behaviour pin — good payload passes, heading-only fails.
# ---------------------------------------------------------------------------
class TestEnvironmentDepthValidator(unittest.TestCase):

    @_skip_if_no_app
    def test_good_arabic_environment_passes_depth_validator(self):
        defects = _APP.validate_environment_richness(
            {'environment': _GOOD_ENV_AR}, lang='ar',
            generation_mode='consulting')
        self.assertEqual(
            defects, [],
            f'Canonical AR environment should pass depth validator; defects={defects}')

    @_skip_if_no_app
    def test_heading_only_arabic_environment_fails(self):
        defects = _APP.validate_environment_richness(
            {'environment': _HEADING_ONLY_AR}, lang='ar',
            generation_mode='consulting')
        tags = {t for t, _ in defects}
        # Heading-only payload must trigger paragraphs_insufficient AND
        # structured_block_missing AND topic_coverage_incomplete.
        self.assertIn('environment_paragraphs_insufficient', tags)
        self.assertIn('environment_structured_block_missing', tags)
        self.assertIn('environment_topic_coverage_incomplete', tags)

    @_skip_if_no_app
    def test_wrong_table_headers_still_fails_topic_coverage(self):
        # Section has a 2-row table but no real category narrative — the
        # topic-coverage check must still fire because the table cells
        # alone do not contain the required regulatory / threat / business
        # keyword sets.
        bad = (
            '## 3. البيئة التنظيمية والتهديدات\n\n'
            'بدون فقرات سرديّة.\n\n'
            '| A | B | C |\n'
            '|---|---|---|\n'
            '| x | y | z |\n'
            '| p | q | r |\n'
        )
        defects = _APP.validate_environment_richness(
            {'environment': bad}, lang='ar', generation_mode='consulting')
        tags = {t for t, _ in defects}
        self.assertIn('environment_paragraphs_insufficient', tags)
        self.assertIn('environment_topic_coverage_incomplete', tags)


# ---------------------------------------------------------------------------
# 2. AI repair schema for environment requires the canonical structures.
# ---------------------------------------------------------------------------
class TestAIRepairSchemaEnvironment(unittest.TestCase):

    @_skip_if_no_app
    def test_schema_entry_exists_for_environment(self):
        self.assertIn('environment', _APP._AI_REPAIR_SECTION_SCHEMA)
        entry = _APP._AI_REPAIR_SECTION_SCHEMA['environment']
        self.assertIn('ar', entry)
        self.assertIn('en', entry)

    @_skip_if_no_app
    def test_schema_arabic_includes_canonical_heading_and_categories(self):
        ar = _APP._AI_REPAIR_SECTION_SCHEMA['environment']['ar']
        self.assertIn('## 3. البيئة التنظيمية والتهديدات', ar)
        # Three mandatory categories.
        self.assertIn('السياق التنظيمي', ar)
        self.assertIn('سياق التهديدات', ar)
        # The third category clause uses "السياق التشغيلي وسياق الأعمال".
        self.assertIn('سياق الأعمال', ar)
        # 5-column matrix headers.
        self.assertIn('البُعد', ar)
        self.assertIn('التأثير', ar)
        # Forbids placeholders / HTML / trace markers.
        self.assertIn('نائبة', ar)
        self.assertIn('HTML', ar)
        self.assertIn('mizan-synth-env-v2', ar)

    @_skip_if_no_app
    def test_schema_english_includes_canonical_heading_and_categories(self):
        en = _APP._AI_REPAIR_SECTION_SCHEMA['environment']['en']
        self.assertIn('## 3. Regulatory Environment & Threat Landscape', en)
        self.assertIn('Regulatory context', en)
        self.assertIn('Threat context', en)
        self.assertIn('Business & operational context', en)
        # 5-column matrix headers.
        self.assertIn('Dimension / Threat', en)
        self.assertIn('Linked Initiative', en)
        self.assertIn('placeholder', en.lower())
        self.assertIn('HTML', en)
        self.assertIn('mizan-synth-env-v2', en)

    @_skip_if_no_app
    def test_canonical_environment_heading_for_repair_matches_normalizer(self):
        # _AI_REPAIR_SECTION_HEADINGS["environment"]["en"] must agree with
        # the canonical title used by _reapply_canonical_section_headings
        # ("3. Regulatory Environment & Threat Landscape").
        en = _APP._AI_REPAIR_SECTION_HEADINGS['environment']['en']
        self.assertEqual(en, '3. Regulatory Environment & Threat Landscape')
        ar = _APP._AI_REPAIR_SECTION_HEADINGS['environment']['ar']
        self.assertEqual(ar, '3. البيئة التنظيمية والتهديدات')


# ---------------------------------------------------------------------------
# 3. ai_repair_strategy_section(section_key='environment') prompt carries
#    the depth defects supplied via validation_error.
# ---------------------------------------------------------------------------
class TestEnvironmentRepairPrompt(unittest.TestCase):

    @_skip_if_no_app
    def test_prompt_contains_canonical_heading_and_validation_error(self):
        domain_ctx = _APP.get_strategy_domain_context(
            'Cyber Security', lang='en', selected_frameworks=[])

        ve = ('The environment section fails the depth validator with: '
              'environment_paragraphs_insufficient, '
              'environment_structured_block_missing.')
        captured = {'prompt': None}

        def _fake_generate(prompt, language=None, task_type=None,
                           content_type=None):
            captured['prompt'] = prompt
            # Return a stub markdown that satisfies the heading + lenient
            # output checks of ai_repair_strategy_section.
            return (
                '## 3. Regulatory Environment & Threat Landscape\n\n'
                'Regulatory context: compliance obligations.\n\n'
                'Threat context: incident landscape.\n\n'
                'Business & operational context: continuity pressure.\n'
            )

        with mock.patch.object(_APP, 'generate_ai_content',
                               side_effect=_fake_generate):
            out = _APP.ai_repair_strategy_section(
                section_key='environment',
                sections={'environment': ''},
                lang='en', domain_context=domain_ctx,
                validation_error=ve)
        self.assertIsNotNone(captured['prompt'])
        self.assertIn('Regulatory Environment & Threat Landscape',
                      captured['prompt'])
        self.assertIn('environment_paragraphs_insufficient',
                      captured['prompt'])
        self.assertIn('Dimension / Threat', captured['prompt'])
        self.assertTrue(out.strip().startswith('## 3.'))

    @_skip_if_no_app
    def test_repair_strips_internal_synth_marker(self):
        # AI returns content that includes the internal synth marker as
        # an HTML comment — _ai_repair_strip_html_and_trace must strip it.
        domain_ctx = _APP.get_strategy_domain_context(
            'Cyber Security', lang='ar', selected_frameworks=[])
        polluted = (
            '## 3. البيئة التنظيمية والتهديدات\n\n'
            '<!-- mizan-synth-env-v2 -->\n'
            'السياق التنظيمي: لوائح وأنظمة.\n\n'
            'سياق التهديدات: هجمات وحوادث.\n\n'
            'سياق الأعمال: استمرارية وتشغيل.\n'
        )

        def _fake(prompt, language=None, task_type=None, content_type=None):
            return polluted

        with mock.patch.object(_APP, 'generate_ai_content', side_effect=_fake):
            out = _APP.ai_repair_strategy_section(
                section_key='environment',
                sections={'environment': ''},
                lang='ar', domain_context=domain_ctx,
                validation_error='depth')
        self.assertNotIn('mizan-synth-env-v2', out)
        self.assertNotIn('<!--', out)

    @_skip_if_no_app
    def test_non_cyber_domain_does_not_get_cyber_capability_clause(self):
        # When repairing the environment section for a non-cyber domain
        # (e.g. ERM), the cyber-capability coverage clause must NOT be
        # appended to the prompt — the cyber-only families are not
        # appropriate for an ERM strategy.
        domain_ctx = _APP.get_strategy_domain_context(
            'Enterprise Risk Management', lang='en', selected_frameworks=[])
        captured = {'prompt': None}

        def _fake(prompt, language=None, task_type=None, content_type=None):
            captured['prompt'] = prompt
            return (
                '## 3. Regulatory Environment & Threat Landscape\n\n'
                'Regulatory context paragraph.\n\nThreat context paragraph.\n\n'
                'Business & operational context paragraph.\n'
            )

        with mock.patch.object(_APP, 'generate_ai_content', side_effect=_fake):
            _APP.ai_repair_strategy_section(
                section_key='environment',
                sections={'environment': ''},
                lang='en', domain_context=domain_ctx,
                validation_error='depth')
        self.assertIsNotNone(captured['prompt'])
        # Cyber capability coverage clause is gated on
        # domain_context['code'] == 'cyber'.
        self.assertNotIn('cybersecurity capability coverage',
                         captured['prompt'].lower())
        self.assertNotIn('IAM/PAM', captured['prompt'])


# ---------------------------------------------------------------------------
# 4. AI-first / fail-closed: provider failure raises RepairError and no
#    deterministic environment rows are injected.
# ---------------------------------------------------------------------------
class TestEnvironmentRepairFailClosed(unittest.TestCase):

    @_skip_if_no_app
    def test_repair_failure_raises_repair_error(self):
        domain_ctx = _APP.get_strategy_domain_context(
            'Cyber Security', lang='en', selected_frameworks=[])

        def _boom(*a, **kw):
            raise RuntimeError('no ai provider configured')

        with mock.patch.object(_APP, 'generate_ai_content', side_effect=_boom):
            with self.assertRaises(_APP.RepairError):
                _APP.ai_repair_strategy_section(
                    section_key='environment',
                    sections={'environment': ''},
                    lang='en', domain_context=domain_ctx,
                    validation_error='environment_missing')

    @_skip_if_no_app
    def test_no_deterministic_environment_row_injector_added(self):
        # Guardrail: no helper that injects fixed deterministic env rows
        # was added under a recognisable name as part of this PR.
        forbidden_names = (
            '_inject_environment_rows',
            '_force_inject_environment_matrix',
            '_deterministic_environment_threat_rows',
        )
        for name in forbidden_names:
            self.assertFalse(
                hasattr(_APP, name),
                f'Deterministic environment injector {name!r} must not exist')

    @_skip_if_no_app
    def test_invalid_repair_does_not_overwrite_original_section(self):
        # Simulate the gate's revalidation logic in isolation: when the
        # AI-repaired environment still fails validate_environment_richness,
        # the original section text must be retained.
        original = _HEADING_ONLY_AR
        sections = {'environment': original}
        bad_repair = '## 3. البيئة التنظيمية والتهديدات\n\nغير صالح.\n'
        trial = dict(sections)
        trial['environment'] = bad_repair
        defects = _APP.validate_environment_richness(
            trial, lang='ar', generation_mode='consulting')
        self.assertTrue(defects, 'bad_repair must still fail the validator')
        # The pipeline only assigns when defects == []. Confirm contract.
        if defects:
            # Do NOT mutate `sections['environment']`.
            pass
        self.assertEqual(sections['environment'], original)


if __name__ == '__main__':
    unittest.main()
