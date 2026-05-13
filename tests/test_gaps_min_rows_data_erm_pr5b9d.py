"""PR-5B.9D — Gaps row-count alignment for Data and ERM domains.

Pins the contract that consulting/assurance gap analysis MUST contain
at least 5 substantive rows. The validator threshold is NOT lowered;
the AI repair contract is strengthened so the model returns at least
5 valid rows.

These tests assert:

  1. ``synthesize_gaps_depth(domain='Data Management', generation_mode=
     'consulting', ...)`` invokes ``ai_repair_strategy_section`` with
     ``min_rows >= 5``.
  2. Same for ``Enterprise Risk Management``.
  3. ``org_structure_is_none=True`` also forces ``min_rows >= 5`` even
     in drafting mode.
  4. The gaps prompt for Data names the expected gap categories
     (data office / data quality / catalog / PDPL / consents).
  5. The gaps prompt for ERM names the expected gap categories
     (ERM dept / CRO / risk appetite / register / KRIs / treatment).
  6. When ``org_structure_is_none=True`` for Data/ERM, the prompt also
     names the missing specialized function as a required gap row.
  7. If the AI returns fewer than 5 valid rows after repair, the
     synthesizer raises ``RepairError(section='gaps')`` and the original
     gaps text is preserved (fail-closed).
  8. If the AI returns ≥ 5 valid rows + per-row guides, the synthesizer
     replaces ``sections['gaps']`` with the AI output.

Run:
    python -m pytest tests/test_gaps_min_rows_data_erm_pr5b9d.py -q
"""

import importlib.util
import os
import sys
import tempfile
import unittest
import unittest.mock


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_gaps_min_pr5b9d_')
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
# A gaps section with only 2 rows — below the 5-row consulting floor —
# forcing synthesize_gaps_depth to invoke AI repair.
_THIN_GAPS_AR = (
    '## 4. تحليل الفجوات\n\n'
    '| # | الفجوة | الوصف | الأولوية | الحالة |\n'
    '|---|------|------|---------|--------|\n'
    '| 1 | فجوة 1 | وصف 1 | عالية | مفتوحة |\n'
    '| 2 | فجوة 2 | وصف 2 | عالية | مفتوحة |\n'
)


def _sections_with_thin_gaps():
    return {'gaps': _THIN_GAPS_AR}


def _build_repaired_gaps(n_rows=5):
    """Build a syntactically valid AR gaps section with N substantive
    rows + N per-row implementation guides."""
    rows = [
        '| # | الفجوة | الوصف | الأولوية | الحالة |',
        '|---|------|------|---------|--------|',
    ]
    for i in range(1, n_rows + 1):
        rows.append(
            f'| {i} | فجوة جوهرية رقم {i} | وصف جوهري للفجوة رقم {i} '
            f'يتناول حالة محددة قابلة للقياس | عالية | مفتوحة |'
        )
    guides = []
    for i in range(1, n_rows + 1):
        guides.append(
            f'\n#### دليل تنفيذ الفجوة رقم {i}: فجوة جوهرية رقم {i}\n'
            f'| الخطوة | الإجراء | المسؤول | الإطار الزمني | الناتج |\n'
            f'|--------|---------|---------|----------------|--------|\n'
            f'| 1 | إجراء أ | فريق الحوكمة | الشهر 1 | مخرج أ |\n'
            f'| 2 | إجراء ب | فريق الحوكمة | الشهر 2 | مخرج ب |\n'
            f'| 3 | إجراء ج | فريق الحوكمة | الشهر 3 | مخرج ج |\n'
            f'| 4 | إجراء د | فريق الحوكمة | الشهر 4 | مخرج د |\n'
        )
    return '## 4. تحليل الفجوات\n\n' + '\n'.join(rows) + '\n' + ''.join(guides)


# ── Tests ────────────────────────────────────────────────────────────────
class GapsMinRowsContractTests(unittest.TestCase):
    """min_rows contract — Data and ERM in consulting/assurance MUST
    request at least 5 rows from the AI."""

    @_skip_if_no_app
    def test_01_data_consulting_requests_min_5_rows(self):
        captured = {}

        def _fake_repair(section_key, sections, lang, domain_context,
                         **kwargs):
            captured['section_key'] = section_key
            captured['min_rows'] = kwargs.get('min_rows')
            captured['org_structure_is_none'] = kwargs.get(
                'org_structure_is_none')
            return _build_repaired_gaps(n_rows=5)

        sections = _sections_with_thin_gaps()
        with unittest.mock.patch.object(
            _APP, 'ai_repair_strategy_section', side_effect=_fake_repair,
        ):
            _APP.synthesize_gaps_depth(
                sections, lang='ar', domain='Data Management',
                generation_mode='consulting',
            )
        self.assertEqual('gaps', captured.get('section_key'))
        self.assertGreaterEqual(
            captured.get('min_rows') or 0, 5,
            'data + consulting must request ≥ 5 gap rows',
        )

    @_skip_if_no_app
    def test_02_erm_consulting_requests_min_5_rows(self):
        captured = {}

        def _fake_repair(section_key, sections, lang, domain_context,
                         **kwargs):
            captured['min_rows'] = kwargs.get('min_rows')
            return _build_repaired_gaps(n_rows=5)

        sections = _sections_with_thin_gaps()
        with unittest.mock.patch.object(
            _APP, 'ai_repair_strategy_section', side_effect=_fake_repair,
        ):
            _APP.synthesize_gaps_depth(
                sections, lang='ar',
                domain='Enterprise Risk Management',
                generation_mode='consulting',
            )
        self.assertGreaterEqual(
            captured.get('min_rows') or 0, 5,
            'erm + consulting must request ≥ 5 gap rows',
        )

    @_skip_if_no_app
    def test_03_org_structure_none_forces_min_5_rows_in_drafting(self):
        """``org_structure_is_none=True`` raises the floor to 5 even in
        drafting mode."""
        captured = {}

        def _fake_repair(section_key, sections, lang, domain_context,
                         **kwargs):
            captured['min_rows'] = kwargs.get('min_rows')
            return _build_repaired_gaps(n_rows=5)

        sections = _sections_with_thin_gaps()
        with unittest.mock.patch.object(
            _APP, 'ai_repair_strategy_section', side_effect=_fake_repair,
        ):
            _APP.synthesize_gaps_depth(
                sections, lang='ar', domain='Data Management',
                generation_mode='drafting',
                org_structure_is_none=True,
            )
        self.assertGreaterEqual(
            captured.get('min_rows') or 0, 5,
            'org_structure_is_none must force ≥ 5 gap rows even in drafting',
        )


class GapsRepairPromptCategoriesTests(unittest.TestCase):
    """The gaps repair prompt must name the expected gap categories per
    domain (and the specialized-function row when org_structure_is_none).
    We invoke ``ai_repair_strategy_section`` directly with a mocked AI
    provider to capture the prompt text."""

    def _patch_ai(self, captured):
        def _fake(prompt, **kw):
            captured['prompt'] = prompt
            raise RuntimeError('AI mocked')

        return _fake

    @_skip_if_no_app
    def test_04_data_gaps_prompt_names_required_categories(self):
        captured = {}
        ctx = _APP.get_strategy_domain_context('Data Management', 'ar')
        with unittest.mock.patch.object(
            _APP, 'generate_ai_content',
            side_effect=self._patch_ai(captured),
        ):
            with self.assertRaises(_APP.RepairError):
                _APP.ai_repair_strategy_section(
                    section_key='gaps',
                    sections=_sections_with_thin_gaps(),
                    lang='ar',
                    domain_context=ctx,
                    org_structure_is_none=False,
                )
        prompt = captured.get('prompt', '')
        # Required categories from problem statement Part C.
        self.assertIn('مكتب إدارة البيانات', prompt)
        self.assertIn('جودة البيانات', prompt)
        self.assertIn('كتالوج البيانات', prompt)
        self.assertIn('PDPL', prompt)
        # consents — fifth required Data category per docstring
        self.assertIn('إدارة الموافقات', prompt)

    @_skip_if_no_app
    def test_05_erm_gaps_prompt_names_required_categories(self):
        captured = {}
        ctx = _APP.get_strategy_domain_context(
            'Enterprise Risk Management', 'ar')
        with unittest.mock.patch.object(
            _APP, 'generate_ai_content',
            side_effect=self._patch_ai(captured),
        ):
            with self.assertRaises(_APP.RepairError):
                _APP.ai_repair_strategy_section(
                    section_key='gaps',
                    sections=_sections_with_thin_gaps(),
                    lang='ar',
                    domain_context=ctx,
                    org_structure_is_none=False,
                )
        prompt = captured.get('prompt', '')
        # Required categories from problem statement Part C.
        self.assertIn('إدارة المخاطر المؤسسية', prompt)
        self.assertIn('CRO', prompt)
        self.assertIn('شهية المخاطر', prompt)
        self.assertIn('سجل المخاطر', prompt)
        self.assertIn('KRIs', prompt)
        # treatment — sixth required ERM category per docstring
        self.assertIn('خطط المعالجة', prompt)

    @_skip_if_no_app
    def test_06_data_org_none_prompt_names_specialized_function(self):
        """When org_structure_is_none=True for Data, the gaps prompt
        also names the missing specialized function (CDO / data office
        / data governance committee) so one of the gap rows surfaces it.
        """
        captured = {}
        ctx = _APP.get_strategy_domain_context('Data Management', 'ar')
        with unittest.mock.patch.object(
            _APP, 'generate_ai_content',
            side_effect=self._patch_ai(captured),
        ):
            with self.assertRaises(_APP.RepairError):
                _APP.ai_repair_strategy_section(
                    section_key='gaps',
                    sections=_sections_with_thin_gaps(),
                    lang='ar',
                    domain_context=ctx,
                    org_structure_is_none=True,
                )
        prompt = captured.get('prompt', '')
        self.assertIn('مكتب إدارة البيانات', prompt)
        self.assertIn('CDO', prompt)
        self.assertIn('لجنة حوكمة البيانات', prompt)

    @_skip_if_no_app
    def test_07_erm_org_none_prompt_names_specialized_function(self):
        captured = {}
        ctx = _APP.get_strategy_domain_context(
            'Enterprise Risk Management', 'ar')
        with unittest.mock.patch.object(
            _APP, 'generate_ai_content',
            side_effect=self._patch_ai(captured),
        ):
            with self.assertRaises(_APP.RepairError):
                _APP.ai_repair_strategy_section(
                    section_key='gaps',
                    sections=_sections_with_thin_gaps(),
                    lang='ar',
                    domain_context=ctx,
                    org_structure_is_none=True,
                )
        prompt = captured.get('prompt', '')
        self.assertIn('إدارة المخاطر المؤسسية', prompt)
        self.assertIn('CRO', prompt)
        self.assertIn('لجنة المخاطر', prompt)


class GapsRepairFailureClosesTests(unittest.TestCase):
    """When the AI returns < 5 valid rows the synthesizer must raise
    ``RepairError(section='gaps')`` and the original gaps text must be
    preserved (fail-closed)."""

    @_skip_if_no_app
    def test_08_insufficient_repair_raises_repair_error_section_gaps(self):
        # Mock returns only 3 rows — below the 5-row floor.
        def _fake_repair(section_key, sections, lang, domain_context,
                         **kwargs):
            return _build_repaired_gaps(n_rows=3)

        sections = _sections_with_thin_gaps()
        original_gaps = sections['gaps']
        with unittest.mock.patch.object(
            _APP, 'ai_repair_strategy_section', side_effect=_fake_repair,
        ):
            with self.assertRaises(_APP.RepairError) as cm:
                _APP.synthesize_gaps_depth(
                    sections, lang='ar', domain='Data Management',
                    generation_mode='consulting',
                )
        self.assertEqual(getattr(cm.exception, 'section', None), 'gaps')
        # Fail-closed: original text preserved.
        self.assertEqual(original_gaps, sections['gaps'])

    @_skip_if_no_app
    def test_09_sufficient_repair_replaces_section(self):
        def _fake_repair(section_key, sections, lang, domain_context,
                         **kwargs):
            return _build_repaired_gaps(n_rows=5)

        sections = _sections_with_thin_gaps()
        with unittest.mock.patch.object(
            _APP, 'ai_repair_strategy_section', side_effect=_fake_repair,
        ):
            result = _APP.synthesize_gaps_depth(
                sections, lang='ar', domain='Data Management',
                generation_mode='consulting',
            )
        self.assertTrue(result.get('rebuilt'))
        # Repaired text replaced the thin original.
        self.assertGreaterEqual(
            _APP.count_substantive_gaps(sections['gaps']), 5,
        )


if __name__ == '__main__':
    unittest.main()
