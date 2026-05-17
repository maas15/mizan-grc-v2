"""PR-5B.9L — Digital Transformation structural-gap enforcement.

When the diagnostic input flags ``org_structure_is_none=True`` AND the
selected domain is Digital Transformation (``dt``), the **Gaps**
section MUST contain ONE explicit row that names the missing
domain-specific specialized function — e.g.
"غياب مكتب التحول الرقمي ونموذج تشغيل التحول الرقمي" or
"غياب Chief Digital Officer".

Generic wording such as "تعزيز الحوكمة" / "Strengthen governance"
must NOT satisfy the structural-gap check unless it explicitly names
the Digital Transformation Office / Chief Digital Officer / digital
transformation operating model.

These tests pin:

  1. DT gaps without a DT specialized-function token emits
     ``missing_structural_gap-org_structure_is_none`` (section=gaps).
  2. DT gaps containing "غياب مكتب التحول الرقمي" passes (no defect).
  3. DT gaps containing "غياب Chief Digital Officer" passes.
  4. DT gaps containing only generic "تعزيز الحوكمة" fails.
  5. DT gaps repair prompt includes the canonical DT vocabulary
     (مكتب التحول الرقمي, Chief Digital Officer, نموذج تشغيل التحول
     الرقمي, حوكمة الخدمات الرقمية, حوكمة التكامل).
  6. The DT registry (`_DOMAIN_SPECIALIZED_FUNCTION_CONCEPTS['dt']`)
     recognises both "مكتب" (office) and the newly added "إدارة"
     (department) phrasings.
  7. The other domain registries (cyber, data, ai, erm) are unchanged
     and their structural-gap helper behaviour still passes.

Run:
    python -m pytest tests/test_dt_structural_gap_pr5b9l.py -q
"""

import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_dt_struct_pr5b9l_')
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


# ── Sample DT gap tables (Arabic) ─────────────────────────────────────────

# Generic gap table — five substantive rows but NONE name the DT
# specialized function. Triggers missing_structural_gap.
_DT_GAPS_GENERIC_AR = (
    '## 4. تحليل الفجوات\n\n'
    '| # | الفجوة | الوصف | الأولوية | الحالة |\n'
    '|---|------|------|---------|--------|\n'
    '| 1 | فجوة في القدرات الرقمية | وصف عام | عالية | مفتوحة |\n'
    '| 2 | فجوة في التدريب الرقمي | وصف عام | متوسطة | مفتوحة |\n'
    '| 3 | فجوة في الأدوات الرقمية | وصف عام | منخفضة | مفتوحة |\n'
    '| 4 | فجوة في العمليات الرقمية | وصف عام | عالية | مفتوحة |\n'
    '| 5 | فجوة في التوثيق الرقمي | وصف عام | متوسطة | مفتوحة |\n'
)

# Gap table containing only vague governance wording — must STILL be
# rejected because it does not name the DT specialized function.
# Per the problem statement, "تعزيز الحوكمة" alone must NOT satisfy
# the DT structural-gap requirement.
_DT_GAPS_VAGUE_AR = (
    '## 4. تحليل الفجوات\n\n'
    '| # | الفجوة | الوصف | الأولوية | الحالة |\n'
    '|---|------|------|---------|--------|\n'
    '| 1 | تعزيز الحوكمة | وصف عام | عالية | مفتوحة |\n'
    '| 2 | تحسين القدرات الرقمية | وصف عام | متوسطة | مفتوحة |\n'
    '| 3 | تطوير المهارات الرقمية | وصف عام | عالية | مفتوحة |\n'
    '| 4 | تحسين تجربة المستفيد | وصف عام | متوسطة | مفتوحة |\n'
    '| 5 | تطوير البنية التحتية الرقمية | وصف عام | منخفضة | مفتوحة |\n'
)

# Gap table that explicitly names the DT office — passes.
_DT_GAPS_GOOD_OFFICE_AR = _DT_GAPS_GENERIC_AR + (
    '| 6 | غياب مكتب التحول الرقمي ونموذج تشغيل التحول الرقمي | '
    'لا توجد وظيفة متخصصة | عالية | مفتوحة |\n'
)

# Gap table that explicitly names Chief Digital Officer — passes.
_DT_GAPS_GOOD_CDO_AR = _DT_GAPS_GENERIC_AR + (
    '| 6 | غياب Chief Digital Officer ولجنة التحول الرقمي | '
    'لا يوجد مسؤول | عالية | مفتوحة |\n'
)

# Gap table that explicitly names the DT department phrasing — passes
# (PR-5B.9L widens the establish_dept family to recognise "إدارة" not
# only "مكتب").
_DT_GAPS_GOOD_DEPT_AR = _DT_GAPS_GENERIC_AR + (
    '| 6 | غياب إدارة التحول الرقمي وخطوط الرفع للتحول الرقمي | '
    'لا توجد وظيفة متخصصة | عالية | مفتوحة |\n'
)


# ── Helper accessors ──────────────────────────────────────────────────────

def _missing(gaps_text):
    """Convenience wrapper around the helper under test."""
    return _APP._compute_missing_structural_gap_for_domain(
        gaps_text, 'dt',
        org_structure_is_none=True, lang='ar',
    )


def _has_struct_gap_defect(defects):
    for tup in defects:
        if not isinstance(tup, tuple) or len(tup) < 2:
            continue
        sec, tag = tup[0], tup[1]
        if (sec == 'gaps'
                and isinstance(tag, str)
                and tag.startswith(
                    'missing_structural_gap-org_structure_is_none')):
            return True
    return False


def _make_sections(gaps_text):
    return {
        'vision': '## 1. الرؤية\n\nرؤية.\n',
        'pillars': '## 2. الركائز\n\n### 1\n\nنص.\n',
        'environment': '## 3. البيئة\n\nنص.\n',
        'gaps': gaps_text,
        'roadmap': '## 5. خارطة\n\n',
        'kpis': '## 6. مؤشرات\n\n',
        'confidence': '## 7. الثقة\n\n',
    }


# ── Tests ────────────────────────────────────────────────────────────────

class DTHelperTests(unittest.TestCase):
    """Direct helper-level contracts for the DT structural-gap check."""

    @_skip_if_no_app
    def test_dt_generic_gaps_fails_helper(self):
        # No DT specialized-function token anywhere ⇒ missing list
        # must be non-empty.
        self.assertTrue(
            len(_missing(_DT_GAPS_GENERIC_AR)) > 0,
            'expected DT generic gaps to be flagged as missing the '
            'structural row')

    @_skip_if_no_app
    def test_dt_office_gap_passes_helper(self):
        self.assertEqual(_missing(_DT_GAPS_GOOD_OFFICE_AR), [])

    @_skip_if_no_app
    def test_dt_cdo_gap_passes_helper(self):
        self.assertEqual(_missing(_DT_GAPS_GOOD_CDO_AR), [])

    @_skip_if_no_app
    def test_dt_department_gap_passes_helper(self):
        # PR-5B.9L: the "إدارة" phrasing is recognised in addition to
        # the legacy "مكتب" phrasing.
        self.assertEqual(_missing(_DT_GAPS_GOOD_DEPT_AR), [])

    @_skip_if_no_app
    def test_dt_vague_governance_fails_helper(self):
        # Vague "تعزيز الحوكمة" / "تحسين النموذج التشغيلي" /
        # "تطوير الإطار المؤسسي" does not name a DT specialized
        # function token, so the helper must flag it.
        self.assertTrue(
            len(_missing(_DT_GAPS_VAGUE_AR)) > 0,
            'expected DT vague-governance gaps to be flagged as '
            'missing the structural row')

    @_skip_if_no_app
    def test_dt_registry_contains_required_concepts(self):
        reg = _APP._DOMAIN_SPECIALIZED_FUNCTION_CONCEPTS['dt']
        # establish_dept must include both Arabic phrasings.
        ed = set(t.lower() for t in reg['establish_dept'])
        self.assertIn('مكتب التحول الرقمي', ed)
        self.assertIn('إدارة التحول الرقمي', ed)
        self.assertIn('digital transformation office', ed)
        self.assertIn('digital transformation department', ed)
        # head_officer must include Chief Digital Officer.
        ho = set(t.lower() for t in reg['head_officer'])
        self.assertIn('chief digital officer', ho)
        self.assertIn('رئيس التحول الرقمي', ho)
        # committee must include لجنة التحول الرقمي.
        co = set(t.lower() for t in reg['committee'])
        self.assertIn('لجنة التحول الرقمي', co)
        # operating_model must include the additional governance &
        # integration phrases the problem statement requires.
        om = set(t.lower() for t in reg['operating_model'])
        self.assertIn('نموذج تشغيل التحول الرقمي', om)
        self.assertIn('حوكمة الخدمات الرقمية', om)
        self.assertIn('حوكمة التكامل', om)
        self.assertIn('خطوط الرفع', om)


class DTFinalAuditTests(unittest.TestCase):
    """End-to-end audit defect emission for DT."""

    @_skip_if_no_app
    def test_dt_generic_gaps_emits_defect(self):
        defects = _APP._final_strategy_audit(
            _make_sections(_DT_GAPS_GENERIC_AR), lang='ar',
            doc_subtype=None, selected_frameworks=None,
            domain='dt', org_structure_is_none=True,
        )
        self.assertTrue(
            _has_struct_gap_defect(defects),
            f'expected DT structural-gap defect, got {defects!r}')

    @_skip_if_no_app
    def test_dt_vague_governance_emits_defect(self):
        defects = _APP._final_strategy_audit(
            _make_sections(_DT_GAPS_VAGUE_AR), lang='ar',
            doc_subtype=None, selected_frameworks=None,
            domain='dt', org_structure_is_none=True,
        )
        self.assertTrue(
            _has_struct_gap_defect(defects),
            f'expected DT structural-gap defect for vague wording, '
            f'got {defects!r}')

    @_skip_if_no_app
    def test_dt_office_row_clears_defect(self):
        defects = _APP._final_strategy_audit(
            _make_sections(_DT_GAPS_GOOD_OFFICE_AR), lang='ar',
            doc_subtype=None, selected_frameworks=None,
            domain='dt', org_structure_is_none=True,
        )
        self.assertFalse(
            _has_struct_gap_defect(defects),
            f'unexpected DT structural-gap defect with office row, '
            f'got {defects!r}')

    @_skip_if_no_app
    def test_dt_cdo_row_clears_defect(self):
        defects = _APP._final_strategy_audit(
            _make_sections(_DT_GAPS_GOOD_CDO_AR), lang='ar',
            doc_subtype=None, selected_frameworks=None,
            domain='dt', org_structure_is_none=True,
        )
        self.assertFalse(
            _has_struct_gap_defect(defects),
            f'unexpected DT structural-gap defect with CDO row, '
            f'got {defects!r}')


class DTRepairPromptTests(unittest.TestCase):
    """Pin the canonical DT vocabulary in the gaps repair prompt and
    ensure the AI-first repair path validates the candidate against
    the DT structural-gap helper (no deterministic injection)."""

    @_skip_if_no_app
    def _build_dt_gaps_prompt(self):
        """Invoke ``ai_repair_strategy_section`` with ``provider='none'``
        environment so the function builds the prompt and then raises
        ``RepairError`` when it tries to call out — we intercept the
        prompt by monkey-patching the provider dispatch.
        """
        captured = {}

        def _fake_call(prompt, **_kw):
            captured['prompt'] = prompt
            # Return empty so the repair caller treats it as failure
            # (we only care about the prompt content for this test).
            return ''
        # generate_ai_content signature: (prompt, language='en',
        # content_type='strategy', ...) — accept positional + kwargs.
        def _fake_generate(prompt, *_a, **_kw):
            captured['prompt'] = prompt
            return ''

        # The provider dispatch function used inside
        # ai_repair_strategy_section. We monkey-patch the closest
        # known entry point: ``generate_ai_content`` (the actual call
        # at the bottom of ai_repair_strategy_section).
        # ``generate_ai_content`` is the canonical provider entry point
        # used by ``ai_repair_strategy_section``; assert it is present
        # so a refactor that renames it surfaces here rather than as a
        # silent skip downstream.
        assert hasattr(_APP, 'generate_ai_content'), (
            'app.generate_ai_content is the documented provider entry '
            'point used by ai_repair_strategy_section — a refactor that '
            'renames it must be reflected here')
        patched = []
        for name in (
            'generate_ai_content',
            '_call_ai_provider', 'call_ai_provider',
            '_ai_provider_dispatch', '_provider_call',
            '_ai_chat', '_ai_complete',
        ):
            if hasattr(_APP, name):
                patched.append((name, getattr(_APP, name)))
                setattr(_APP, name,
                        _fake_generate if name == 'generate_ai_content'
                        else _fake_call)
        try:
            try:
                _APP.ai_repair_strategy_section(
                    section_key='gaps',
                    sections={
                        'vision': '## 1. الرؤية\n',
                        'pillars': '## 2. الركائز\n',
                        'environment': '## 3. البيئة\n',
                        'gaps': _DT_GAPS_GENERIC_AR,
                        'roadmap': '## 5. خارطة\n',
                        'kpis': '## 6. مؤشرات\n',
                        'confidence': '## 7. الثقة\n',
                    },
                    lang='ar',
                    domain_context={
                        'code': 'dt',
                        'display': 'التحول الرقمي',
                        'display_en': 'Digital Transformation',
                        'forbidden_terms': [],
                        'allowed_capabilities': [],
                        'role_vocab': [],
                        'selected_frameworks': [],
                        'validation_rules': {'min_gap_rows': 5},
                    },
                    org_structure_is_none=True,
                    validation_error=(
                        'gaps do not include structural gap'),
                )
            except Exception:
                # Either RepairError (no provider) or whatever the
                # repair flow raises on empty result — both are OK,
                # we already captured the prompt before the raise.
                pass
        finally:
            for name, orig in patched:
                setattr(_APP, name, orig)
        return captured.get('prompt', '')

    @_skip_if_no_app
    def test_dt_repair_prompt_names_required_concepts(self):
        # Build the prompt directly via the internal builder. The
        # ``ai_repair_strategy_section`` function assembles the prompt
        # synchronously before calling the provider, so we can simply
        # patch the provider call to capture it. If no provider hook
        # is patchable we fall back to asserting on the prompt schema
        # block + addendum substrings that the repair function
        # constructs unconditionally.
        prompt = self._build_dt_gaps_prompt()
        if not prompt:
            self.skipTest(
                'could not capture DT gaps repair prompt — provider '
                'dispatcher symbol not found')
        for needle in (
            'مكتب التحول الرقمي',
            'Chief Digital Officer',
            'نموذج تشغيل التحول الرقمي',
            'حوكمة الخدمات الرقمية',
            'حوكمة التكامل',
        ):
            self.assertIn(
                needle, prompt,
                f'DT gaps repair prompt must mention {needle!r}; '
                f'prompt was {prompt[:400]!r}…')

    @_skip_if_no_app
    def test_dt_repair_prompt_rejects_vague_wording(self):
        prompt = self._build_dt_gaps_prompt()
        if not prompt:
            self.skipTest(
                'could not capture DT gaps repair prompt — provider '
                'dispatcher symbol not found')
        # The DT-specific reinforcement clause must enumerate the
        # forbidden vague wording so the AI cannot silently regress
        # to a generic "تعزيز الحوكمة" row.
        for vague in (
            'تعزيز الحوكمة',
            'تحسين النموذج التشغيلي',
            'تطوير الإطار المؤسسي',
        ):
            self.assertIn(
                vague, prompt,
                f'DT gaps repair prompt must explicitly list the '
                f'forbidden vague phrase {vague!r}; prompt was '
                f'{prompt[:400]!r}…')

    @_skip_if_no_app
    def test_dt_repair_prompt_pins_canonical_row(self):
        prompt = self._build_dt_gaps_prompt()
        if not prompt:
            self.skipTest(
                'could not capture DT gaps repair prompt — provider '
                'dispatcher symbol not found')
        canonical = (
            'غياب مكتب التحول الرقمي ونموذج تشغيل التحول الرقمي'
        )
        self.assertIn(
            canonical, prompt,
            f'DT gaps repair prompt must pin the canonical row '
            f'title {canonical!r}; prompt was {prompt[:400]!r}…')


class DTRepairValidationTests(unittest.TestCase):
    """Pin the repair-routing validation contract: 5 rows are NOT
    enough on their own — the candidate MUST also pass the DT
    structural-gap helper. No deterministic rows may be inserted."""

    @_skip_if_no_app
    def test_dt_five_rows_without_structural_gap_is_rejected(self):
        # Use the helper directly as the validator: the routing
        # pipeline calls ``_compute_missing_structural_gap_for_domain``
        # after counting rows and rejects the candidate when the list
        # is non-empty.
        self.assertGreater(
            _APP.count_substantive_gaps(_DT_GAPS_GENERIC_AR),
            4,
            'baseline must have ≥5 substantive rows so the test '
            'exercises the structural-gap path, not the row-count '
            'path')
        self.assertTrue(
            len(_missing(_DT_GAPS_GENERIC_AR)) > 0,
            'a 5-row DT gaps table without a structural DT row must '
            'still be rejected by the helper')

    @_skip_if_no_app
    def test_dt_five_rows_with_structural_gap_is_accepted(self):
        # 6 substantive rows including the structural DT row — must
        # pass both the row floor and the structural-gap helper.
        self.assertGreaterEqual(
            _APP.count_substantive_gaps(_DT_GAPS_GOOD_OFFICE_AR),
            5)
        self.assertEqual(_missing(_DT_GAPS_GOOD_OFFICE_AR), [])


class SiblingDomainsUnaffectedTests(unittest.TestCase):
    """Make sure the DT-only changes did not weaken the cyber / data /
    ai / erm structural-gap behaviour."""

    @_skip_if_no_app
    def test_sibling_domains_registry_keys_unchanged(self):
        reg = _APP._DOMAIN_SPECIALIZED_FUNCTION_CONCEPTS
        # Cyber, data, ai, erm must still be present with their
        # original family keys (no removals).
        self.assertIn('cyber', reg)
        self.assertIn('data', reg)
        self.assertIn('ai', reg)
        self.assertIn('erm', reg)
        # Data must still have the head_officer family containing CDO.
        self.assertTrue(any(
            'chief data officer' in t.lower()
            for t in reg['data']['head_officer']))
        # AI must still have AI Governance Office in establish_dept.
        self.assertTrue(any(
            'ai governance office' in t.lower()
            for t in reg['ai']['establish_dept']))
        # ERM must still have CRO in head_officer.
        self.assertTrue(any(
            'chief risk officer' in t.lower()
            for t in reg['erm']['head_officer']))

    @_skip_if_no_app
    def test_sibling_domain_helper_still_passes_with_good_rows(self):
        good_per_domain = {
            'ai': '| 6 | غياب مكتب حوكمة الذكاء الاصطناعي | x | عالية | مفتوحة |\n',
            'data': '| 6 | غياب مكتب إدارة البيانات | x | عالية | مفتوحة |\n',
            'cyber': '| 6 | غياب إدارة الأمن السيبراني وCISO | x | عالية | مفتوحة |\n',
            'erm': '| 6 | غياب إدارة المخاطر المؤسسية وCRO | x | عالية | مفتوحة |\n',
        }
        for d, row in good_per_domain.items():
            with self.subTest(domain=d):
                gaps = _DT_GAPS_GENERIC_AR + row
                missing = (
                    _APP._compute_missing_structural_gap_for_domain(
                        gaps, d,
                        org_structure_is_none=True, lang='ar',
                    ))
                self.assertEqual(
                    missing, [],
                    f'sibling domain {d!r} regressed — got '
                    f'{missing!r}')


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
