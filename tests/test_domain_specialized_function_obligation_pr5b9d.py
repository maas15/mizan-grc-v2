"""PR-5B.9D — Cross-domain specialized-function establishment requirement.

When the diagnostic input flags ``org_structure_is_none=True`` the
Technical Strategy MUST explicitly include the recommendation to
ESTABLISH the domain-specific specialized function:

  * Cyber  → Cybersecurity Department / CISO / governance committee
  * Data   → Data Management Office / CDO / data governance committee
  * AI     → AI Governance Office / AI governance committee / model
             risk roles
  * DT     → Digital Transformation Office / Chief Digital Officer /
             digital governance model
  * ERM    → ERM function / CRO / risk committee / risk owners

These tests pin:

  1. The validator emits ``specialized_function_missing`` for every
     non-cyber domain (data/ai/dt/erm) when ``org_structure_is_none=True``
     and the strategy lacks the required concept families.
  2. A strategy that explicitly includes the establishment wording for
     the matching domain passes (no ``specialized_function_missing``
     defect).
  3. When ``org_structure_is_none=False`` the requirement is NOT forced.
  4. The AI repair prompt addendum names the per-domain required
     concept families (department, head officer, committee, roles) for
     gaps/roadmap/confidence/environment sections — without inserting
     deterministic content into ``sections``.
  5. The cyber-only ``cybersecurity_department_establishment_missing``
     defect is preserved (regression guard for PR-5B.8U).

Run:
    python -m pytest tests/test_domain_specialized_function_obligation_pr5b9d.py -q
"""

import importlib.util
import os
import sys
import tempfile
import unittest
import unittest.mock


# ── Boot env required by ``app`` ─────────────────────────────────────────
_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_spec_fn_pr5b9d_')
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


# ── Fixtures ─────────────────────────────────────────────────────────────
# A minimal Arabic strategy skeleton that lacks ANY mention of a
# specialized-function establishment recommendation. All sections carry
# benign domain-neutral wording so that the only defect a domain-aware
# validator should surface is ``specialized_function_missing``.
_BARE_AR = {
    'vision': (
        '## 1. الرؤية والأهداف الاستراتيجية\n\n'
        'تعزيز القدرات التشغيلية للمنظمة.\n\n'
        '### الأهداف الاستراتيجية:\n\n'
        '| # | الهدف | المؤشر | المبرر | الإطار |\n'
        '|---|------|-------|--------|--------|\n'
        '| 1 | تطوير القدرات | 100% | تحسين | 12ش |\n'
    ),
    'pillars': (
        '## 2. الركائز الاستراتيجية\n\n'
        '### الركيزة 1: تطوير القدرات\n\nبرامج تطوير القدرات.\n'
    ),
    'environment': '## 3. البيئة التنظيمية\n\nبيئة عمل تشغيلية.\n',
    'gaps': (
        '## 4. تحليل الفجوات\n\n'
        '| # | الفجوة | الوصف | الأولوية | الحالة |\n'
        '|---|------|------|---------|--------|\n'
        '| 1 | فجوة في القدرات | وصف عام | عالية | مفتوحة |\n'
    ),
    'roadmap': (
        '## 5. خارطة الطريق\n\n'
        '| # | النشاط | المسؤول | الإطار | المخرج |\n'
        '|---|------|--------|------|--------|\n'
        '| 1 | تطوير القدرات | الإدارة | 12ش | تحسن |\n'
    ),
    'kpis': (
        '## 6. مؤشرات الأداء\n\n'
        '| # | المؤشر | النوع | المستهدفة | صيغة | المصدر | المالك | التكرار | الإطار |\n'
        '|---|------|------|----------|------|--------|-------|---------|--------|\n'
        '| 1 | مؤشر | KPI | 100% | x | عام | الإدارة | شهري | 12ش |\n'
    ),
    'confidence': (
        '## 7. تقييم الثقة والمخاطر\n\n**درجة الثقة:** 70%\n\n'
        '| # | الخطر | الاحتمالية | التأثير | خطة التخفيف |\n'
        '|---|------|----------|--------|------------|\n'
        '| 1 | خطر عام | عالية | عالي | متابعة |\n'
    ),
}


# Per-domain "good" sections that satisfy the establishment requirement.
_FULL_BY_DOMAIN = {
    'data': {
        'gaps': (
            '## 4. تحليل الفجوات\n\n'
            'إنشاء مكتب إدارة البيانات وتعيين CDO وتشكيل لجنة حوكمة '
            'البيانات وتعيين أمناء البيانات وتحديد الأدوار والمسؤوليات.\n'
        ),
    },
    'ai': {
        'gaps': (
            '## 4. تحليل الفجوات\n\n'
            'إنشاء مكتب حوكمة الذكاء الاصطناعي وتعيين Chief AI Officer '
            'وتشكيل لجنة حوكمة الذكاء الاصطناعي وتفعيل أدوار مخاطر '
            'النماذج (model risk).\n'
        ),
    },
    'dt': {
        'gaps': (
            '## 4. تحليل الفجوات\n\n'
            'إنشاء مكتب التحول الرقمي وتعيين Chief Digital Officer '
            'وتشكيل لجنة التحول الرقمي واعتماد نموذج تشغيل التحول '
            'الرقمي.\n'
        ),
    },
    'erm': {
        'gaps': (
            '## 4. تحليل الفجوات\n\n'
            'إنشاء إدارة المخاطر المؤسسية وتعيين CRO وتشكيل لجنة '
            'المخاطر وتعيين مالكي المخاطر وتحديد الأدوار '
            'والمسؤوليات.\n'
        ),
    },
}


def _make_sections(extra=None):
    s = {k: v for k, v in _BARE_AR.items()}
    for k, v in (extra or {}).items():
        s[k] = v
    return s


_DOMAIN_NAMES_AR = {
    'data':  'إدارة البيانات',
    'ai':    'الذكاء الاصطناعي',
    'dt':    'التحول الرقمي',
    'erm':   'إدارة المخاطر المؤسسية',
    'cyber': 'الأمن السيبراني',
}


# ── Tests ────────────────────────────────────────────────────────────────
class SpecializedFunctionDetectionTests(unittest.TestCase):
    """``_compute_missing_specialized_function_concepts`` and the
    validator-level ``specialized_function_missing`` defect."""

    @_skip_if_no_app
    def test_helper_exists(self):
        """The cross-domain helper must exist and accept a domain code."""
        self.assertTrue(
            hasattr(_APP, '_compute_missing_specialized_function_concepts'),
            '_compute_missing_specialized_function_concepts helper missing',
        )
        self.assertTrue(
            hasattr(_APP, '_DOMAIN_SPECIALIZED_FUNCTION_CONCEPTS'),
            '_DOMAIN_SPECIALIZED_FUNCTION_CONCEPTS dict missing',
        )

    @_skip_if_no_app
    def test_per_domain_concept_families_present(self):
        """Every non-cyber domain must declare at least 3 concept families."""
        for code in ('data', 'ai', 'dt', 'erm'):
            with self.subTest(domain=code):
                concepts = _APP._DOMAIN_SPECIALIZED_FUNCTION_CONCEPTS.get(code)
                self.assertIsNotNone(
                    concepts, f'concept dict missing for {code}',
                )
                self.assertGreaterEqual(
                    len(concepts), 3,
                    f'{code} must declare ≥ 3 specialized-function concept '
                    f'families',
                )
                # establish_dept family is always required.
                self.assertIn(
                    'establish_dept', concepts,
                    f'{code} concept dict must include establish_dept',
                )

    @_skip_if_no_app
    def test_bare_strategy_misses_all_families(self):
        """Bare strategy must be flagged for every non-cyber domain."""
        for code in ('data', 'ai', 'dt', 'erm'):
            with self.subTest(domain=code):
                missing = _APP._compute_missing_specialized_function_concepts(
                    _make_sections(), code,
                )
                self.assertTrue(
                    missing,
                    f'bare strategy must surface missing concept families '
                    f'for {code}, got empty list',
                )

    @_skip_if_no_app
    def test_validator_emits_specialized_function_missing_per_domain(self):
        """``validate_arabic_strategy_semantic_richness`` emits
        ``specialized_function_missing`` for each non-cyber domain when
        ``org_structure_is_none=True``."""
        for code in ('data', 'ai', 'dt', 'erm'):
            with self.subTest(domain=code):
                defects = _APP.validate_arabic_strategy_semantic_richness(
                    _make_sections(), 'ar',
                    domain=_DOMAIN_NAMES_AR[code],
                    org_structure_is_none=True,
                )
                tags = [t for (t, _d) in defects]
                self.assertIn(
                    'specialized_function_missing', tags,
                    f'expected specialized_function_missing in {tags!r} '
                    f'for {code}',
                )

    @_skip_if_no_app
    def test_validator_skips_when_org_structure_present(self):
        """When ``org_structure_is_none=False`` the new defect must NOT
        fire (preserves existing behaviour for orgs with a defined
        structure)."""
        for code in ('data', 'ai', 'dt', 'erm'):
            with self.subTest(domain=code):
                defects = _APP.validate_arabic_strategy_semantic_richness(
                    _make_sections(), 'ar',
                    domain=_DOMAIN_NAMES_AR[code],
                    org_structure_is_none=False,
                )
                tags = [t for (t, _d) in defects]
                self.assertNotIn('specialized_function_missing', tags)

    @_skip_if_no_app
    def test_per_domain_full_strategy_passes(self):
        """A strategy that explicitly includes the matching domain's
        establishment wording must clear the defect."""
        for code, extra in _FULL_BY_DOMAIN.items():
            with self.subTest(domain=code):
                missing = _APP._compute_missing_specialized_function_concepts(
                    _make_sections(extra), code,
                )
                self.assertEqual(
                    [], missing,
                    f'{code}: expected no missing concept families but got '
                    f'{missing!r}',
                )

    @_skip_if_no_app
    def test_cyber_legacy_defect_preserved(self):
        """Regression guard for PR-5B.8U: the cyber-specific defect tag
        ``cybersecurity_department_establishment_missing`` is still
        emitted on a bare cyber strategy when ``org_structure_is_none``
        is True. The new ``specialized_function_missing`` tag must NOT
        fire on cyber (cyber retains its dedicated check)."""
        defects = _APP.validate_arabic_strategy_semantic_richness(
            _make_sections(), 'ar',
            domain='Cyber Security',
            org_structure_is_none=True,
        )
        tags = [t for (t, _d) in defects]
        self.assertIn('cybersecurity_department_establishment_missing', tags)
        self.assertNotIn('specialized_function_missing', tags)


class SpecializedFunctionRepairPromptTests(unittest.TestCase):
    """Confirm ``ai_repair_strategy_section`` injects per-domain MANDATORY
    clauses naming the required concept families. We monkey-patch the
    AI provider to capture the prompt without making a network call."""

    def _patch_ai(self, captured):
        import functools

        def _fake(prompt, **kw):
            captured['prompt'] = prompt
            captured['kw'] = kw
            # Returning ``None`` triggers ai_repair_strategy_section's
            # "empty content" RepairError; we re-raise as the test only
            # cares about the prompt that was constructed.
            raise RuntimeError('AI mocked')

        return _fake

    @_skip_if_no_app
    def test_data_repair_prompt_names_required_concepts(self):
        captured = {}
        domain_ctx = _APP.get_strategy_domain_context(
            'Data Management', 'ar')
        with unittest.mock.patch.object(
            _APP, 'generate_ai_content',
            side_effect=self._patch_ai(captured),
        ):
            with self.assertRaises(_APP.RepairError):
                _APP.ai_repair_strategy_section(
                    section_key='gaps',
                    sections=_make_sections(),
                    lang='ar',
                    domain_context=domain_ctx,
                    org_structure_is_none=True,
                )
        prompt = captured.get('prompt', '')
        # Must mention the data-specific specialized function concepts.
        self.assertIn('مكتب إدارة البيانات', prompt)
        self.assertIn('CDO', prompt)
        self.assertIn('لجنة حوكمة البيانات', prompt)
        # The data establishment clause must NOT prescribe a CISO; CISO
        # may appear in the data-domain forbidden-terms block, so check
        # the establishment clause body only.
        _est_clause = prompt.split(
            'قاعدة إنشاء وظيفة إدارة البيانات', 1)[-1]
        self.assertNotIn('CISO', _est_clause)

    @_skip_if_no_app
    def test_erm_repair_prompt_names_required_concepts(self):
        captured = {}
        domain_ctx = _APP.get_strategy_domain_context(
            'Enterprise Risk Management', 'ar')
        with unittest.mock.patch.object(
            _APP, 'generate_ai_content',
            side_effect=self._patch_ai(captured),
        ):
            with self.assertRaises(_APP.RepairError):
                _APP.ai_repair_strategy_section(
                    section_key='gaps',
                    sections=_make_sections(),
                    lang='ar',
                    domain_context=domain_ctx,
                    org_structure_is_none=True,
                )
        prompt = captured.get('prompt', '')
        self.assertIn('إدارة المخاطر المؤسسية', prompt)
        self.assertIn('CRO', prompt)
        self.assertIn('لجنة المخاطر', prompt)
        _est_clause = prompt.split(
            'قاعدة إنشاء إدارة المخاطر المؤسسية', 1)[-1]
        self.assertNotIn('CISO', _est_clause)
        self.assertNotIn('CDO', _est_clause)

    @_skip_if_no_app
    def test_ai_domain_repair_prompt_names_required_concepts(self):
        captured = {}
        domain_ctx = _APP.get_strategy_domain_context(
            'Artificial Intelligence', 'ar')
        with unittest.mock.patch.object(
            _APP, 'generate_ai_content',
            side_effect=self._patch_ai(captured),
        ):
            with self.assertRaises(_APP.RepairError):
                _APP.ai_repair_strategy_section(
                    section_key='gaps',
                    sections=_make_sections(),
                    lang='ar',
                    domain_context=domain_ctx,
                    org_structure_is_none=True,
                )
        prompt = captured.get('prompt', '')
        self.assertIn('حوكمة الذكاء الاصطناعي', prompt)
        self.assertIn('Chief AI Officer', prompt)
        self.assertIn('مخاطر النماذج', prompt)
        # The AI establishment clause must NOT prescribe CISO/CRO/CDO as
        # the officer to appoint (those are forbidden cross-domain roles
        # for AI). They may still appear in the forbidden-terms list of
        # the domain isolation block — so we check the establishment
        # clause body only.
        _est_clause = prompt.split(
            'قاعدة إنشاء وظيفة حوكمة الذكاء الاصطناعي', 1)[-1]
        self.assertNotIn('CISO', _est_clause)
        self.assertNotIn('CRO', _est_clause)

    @_skip_if_no_app
    def test_dt_repair_prompt_names_required_concepts(self):
        captured = {}
        domain_ctx = _APP.get_strategy_domain_context(
            'Digital Transformation', 'ar')
        with unittest.mock.patch.object(
            _APP, 'generate_ai_content',
            side_effect=self._patch_ai(captured),
        ):
            with self.assertRaises(_APP.RepairError):
                _APP.ai_repair_strategy_section(
                    section_key='gaps',
                    sections=_make_sections(),
                    lang='ar',
                    domain_context=domain_ctx,
                    org_structure_is_none=True,
                )
        prompt = captured.get('prompt', '')
        self.assertIn('مكتب التحول الرقمي', prompt)
        self.assertIn('Chief Digital Officer', prompt)
        # Must not pollute with cyber/erm wording in the establishment
        # clause body.
        _est_clause = prompt.split(
            'قاعدة إنشاء وظيفة التحول الرقمي', 1)[-1]
        self.assertNotIn('CISO', _est_clause)
        self.assertNotIn('CRO', _est_clause)

    @_skip_if_no_app
    def test_cyber_repair_prompt_unchanged(self):
        """Regression guard: cyber repair prompt continues to name
        CISO + Cybersecurity Department (PR-5B.8U preserved verbatim)."""
        captured = {}
        domain_ctx = _APP.get_strategy_domain_context(
            'Cyber Security', 'ar')
        with unittest.mock.patch.object(
            _APP, 'generate_ai_content',
            side_effect=self._patch_ai(captured),
        ):
            with self.assertRaises(_APP.RepairError):
                _APP.ai_repair_strategy_section(
                    section_key='gaps',
                    sections=_make_sections(),
                    lang='ar',
                    domain_context=domain_ctx,
                    org_structure_is_none=True,
                )
        prompt = captured.get('prompt', '')
        self.assertIn('إدارة الأمن السيبراني', prompt)
        self.assertIn('CISO', prompt)


class CoexistObjectivesTests(unittest.TestCase):
    """Part D — Vision/Objectives must include BOTH the framework
    compliance objective AND the specialized-function objective; one
    repair must not overwrite the other."""

    @_skip_if_no_app
    def test_specialized_function_objective_helper_exists(self):
        self.assertTrue(
            hasattr(_APP, '_compute_missing_specialized_function_objective'),
        )

    @_skip_if_no_app
    def test_missing_specialized_function_objective_per_domain(self):
        """When the SO table lacks the establishment objective row, the
        helper returns True for every domain — independent of compliance
        objective coverage."""
        for code in ('cyber', 'data', 'ai', 'dt', 'erm'):
            with self.subTest(domain=code):
                missing = _APP._compute_missing_specialized_function_objective(
                    _make_sections(),
                    domain=_DOMAIN_NAMES_AR[code],
                    lang='ar',
                    org_structure_is_none=True,
                )
                self.assertTrue(
                    missing,
                    f'{code}: expected missing-objective True on bare SO '
                    f'table, got False',
                )

    @_skip_if_no_app
    def test_specialized_function_objective_helper_no_op_when_org_present(self):
        """Helper must short-circuit to False when org_structure_is_none
        is False (no enforcement)."""
        missing = _APP._compute_missing_specialized_function_objective(
            _make_sections(), domain='Data Management', lang='ar',
            org_structure_is_none=False,
        )
        self.assertFalse(missing)

    @_skip_if_no_app
    def test_audit_emits_specialized_function_objective_missing(self):
        """``_final_strategy_audit`` must emit the
        ``specialized_function_objective_missing`` defect on the vision
        section when ``org_structure_is_none=True`` and the SO table
        lacks the establishment row."""
        defects = _APP._final_strategy_audit(
            _make_sections(), 'ar',
            selected_frameworks=None,
            domain='Data Management',
            org_structure_is_none=True,
        )
        tagstr = ';'.join(
            f'{sec}:{tag}' for (sec, tag, _c, _f) in defects
        )
        self.assertIn('specialized_function_objective_missing', tagstr)
        self.assertIn('vision:', tagstr)

    @_skip_if_no_app
    def test_vision_repair_prompt_requires_both_objectives_to_coexist(self):
        """Vision-section AI repair prompt must explicitly state that
        the specialized-function objective row is ADDITIONAL TO the
        compliance objective row (one must not replace the other)."""
        captured = {}
        domain_ctx = _APP.get_strategy_domain_context(
            'Data Management', 'ar')

        def _fake(prompt, **kw):
            captured['prompt'] = prompt
            raise RuntimeError('AI mocked')

        with unittest.mock.patch.object(
            _APP, 'generate_ai_content', side_effect=_fake,
        ):
            with self.assertRaises(_APP.RepairError):
                _APP.ai_repair_strategy_section(
                    section_key='vision',
                    sections=_make_sections(),
                    lang='ar',
                    domain_context=domain_ctx,
                    org_structure_is_none=True,
                )
        prompt = captured.get('prompt', '')
        self.assertIn('مكتب إدارة البيانات', prompt)
        self.assertIn('CDO', prompt)
        # Must explicitly assert coexistence wording.
        self.assertIn('إضافي', prompt)


# Unittest / pytest entrypoint

if __name__ == '__main__':
    unittest.main()
