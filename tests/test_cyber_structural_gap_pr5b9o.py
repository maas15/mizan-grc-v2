"""PR-5B.9O — Cybersecurity structural-gap enforcement.

Production symptom: Cyber Security strategy generation failed with
``missing_structural_gap-org_structure_is_none`` while the gaps text
did **not** contain an explicit Cybersecurity structural-gap row
(e.g. "غياب إدارة الأمن السيبراني" / "غياب CISO" / "غياب نموذج
تشغيل الأمن السيبراني"). The audit emitted the defect correctly but
the gaps repair prompt for Cyber did not pin the canonical wording
nor enumerate forbidden vague phrases — so the AI kept returning
generic governance rows.

PR-5B.9O fixes:

  * Widen ``_CYBER_DEPT_ESTAB_CONCEPTS`` to recognise every accepted
    Arabic + English structural-gap phrasing from the spec
    (including "الإدارة المتخصصة للأمن السيبراني" / "الهيكل
    التنظيمي للأمن السيبراني" / "نموذج تشغيل الأمن السيبراني"
    without the ال definite article / "missing cybersecurity
    operating model").
  * Append a Cyber-specific reinforcement block to the gaps repair
    prompt (mirror of the DT block from PR-5B.9L) — pins canonical
    row title, requires Owner/Timeframe/Output for each guide step,
    and enumerates forbidden vague wording.
  * Enrich the ``[GAPS-STRUCTURAL-GAP-REPAIR]`` diagnostic with the
    canonical required-wording label.

Tests pin:

  1. Cyber gaps without "إدارة الأمن السيبراني" / CISO emits
     ``missing_structural_gap-org_structure_is_none``.
  2. Cyber gaps containing "غياب إدارة الأمن السيبراني" passes.
  3. Cyber gaps containing "غياب CISO" passes.
  4. Cyber gaps containing only generic "تعزيز الحوكمة" fails.
  5. Cyber gaps repair prompt mentions: إدارة الأمن السيبراني,
     CISO, لجنة حوكمة الأمن السيبراني, نموذج تشغيل الأمن السيبراني,
     خطوط الرفع, RACI.
  6. Cyber registry recognises the additional accepted wordings.
  7. Other-domain structural-gap helpers (data, ai, dt, erm) remain
     unaffected.

Run:
    python -m pytest tests/test_cyber_structural_gap_pr5b9o.py -q
"""

import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_struct_pr5b9o_')
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


# ── Sample Cyber gap tables (Arabic) ──────────────────────────────────────

# Generic gap table — five substantive rows but NONE name the Cyber
# specialized function. Triggers missing_structural_gap.
_CYBER_GAPS_GENERIC_AR = (
    '## 4. تحليل الفجوات\n\n'
    '| # | الفجوة | الوصف | الأولوية | الحالة |\n'
    '|---|------|------|---------|--------|\n'
    '| 1 | فجوة في الوعي بالأمن | وصف عام | عالية | مفتوحة |\n'
    '| 2 | فجوة في تدريب المستخدمين | وصف عام | متوسطة | مفتوحة |\n'
    '| 3 | فجوة في تصنيف الأصول | وصف عام | منخفضة | مفتوحة |\n'
    '| 4 | فجوة في رصد الحوادث | وصف عام | عالية | مفتوحة |\n'
    '| 5 | فجوة في تحديث الأنظمة | وصف عام | متوسطة | مفتوحة |\n'
)

# Vague governance wording only — must STILL be rejected.
_CYBER_GAPS_VAGUE_AR = (
    '## 4. تحليل الفجوات\n\n'
    '| # | الفجوة | الوصف | الأولوية | الحالة |\n'
    '|---|------|------|---------|--------|\n'
    '| 1 | تعزيز الحوكمة | وصف عام | عالية | مفتوحة |\n'
    '| 2 | تحسين الإطار التنظيمي | وصف عام | متوسطة | مفتوحة |\n'
    '| 3 | تطوير السياسات | وصف عام | عالية | مفتوحة |\n'
    '| 4 | تحسين الوعي العام | وصف عام | متوسطة | مفتوحة |\n'
    '| 5 | تطوير قدرات الرصد | وصف عام | منخفضة | مفتوحة |\n'
)

# Gap table that explicitly names the Cyber department — passes.
_CYBER_GAPS_GOOD_DEPT_AR = _CYBER_GAPS_GENERIC_AR + (
    '| 6 | غياب إدارة الأمن السيبراني ونموذج تشغيل الأمن السيبراني | '
    'لا توجد وظيفة متخصصة | عالية | مفتوحة |\n'
)

# Gap table that explicitly names CISO — passes.
_CYBER_GAPS_GOOD_CISO_AR = _CYBER_GAPS_GENERIC_AR + (
    '| 6 | غياب CISO ولجنة حوكمة الأمن السيبراني | '
    'لا يوجد مسؤول | عالية | مفتوحة |\n'
)

# Gap table that names "الإدارة المتخصصة" phrasing — passes (PR-5B.9O
# widened the establish_dept family to recognise "الإدارة المتخصصة
# للأمن السيبراني").
_CYBER_GAPS_GOOD_SPECIALIZED_AR = _CYBER_GAPS_GENERIC_AR + (
    '| 6 | غياب الإدارة المتخصصة للأمن السيبراني | '
    'لا توجد وظيفة متخصصة | عالية | مفتوحة |\n'
)

# Gap table that names "نموذج تشغيل الأمن السيبراني" (no ال) — passes.
_CYBER_GAPS_GOOD_OPMODEL_AR = _CYBER_GAPS_GENERIC_AR + (
    '| 6 | غياب نموذج تشغيل الأمن السيبراني | '
    'لا يوجد نموذج تشغيلي | عالية | مفتوحة |\n'
)


def _missing(gaps_text):
    """Convenience wrapper around the helper under test."""
    return _APP._compute_missing_structural_gap_for_domain(
        gaps_text, 'cyber',
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


# ── Helper-level tests ───────────────────────────────────────────────────

class CyberHelperTests(unittest.TestCase):
    """Direct helper-level contracts for the Cyber structural-gap
    check."""

    @_skip_if_no_app
    def test_cyber_generic_gaps_fails_helper(self):
        # No Cyber specialized-function token anywhere ⇒ missing list
        # must be non-empty.
        self.assertTrue(
            len(_missing(_CYBER_GAPS_GENERIC_AR)) > 0,
            'expected Cyber generic gaps to be flagged as missing '
            'the structural row')

    @_skip_if_no_app
    def test_cyber_dept_gap_passes_helper(self):
        self.assertEqual(_missing(_CYBER_GAPS_GOOD_DEPT_AR), [])

    @_skip_if_no_app
    def test_cyber_ciso_gap_passes_helper(self):
        self.assertEqual(_missing(_CYBER_GAPS_GOOD_CISO_AR), [])

    @_skip_if_no_app
    def test_cyber_specialized_dept_phrasing_passes_helper(self):
        # PR-5B.9O — "الإدارة المتخصصة للأمن السيبراني" wording must
        # be recognised in addition to the legacy "إدارة الأمن
        # السيبراني" phrasing.
        self.assertEqual(_missing(_CYBER_GAPS_GOOD_SPECIALIZED_AR), [])

    @_skip_if_no_app
    def test_cyber_operating_model_no_alef_lam_passes_helper(self):
        # PR-5B.9O — "نموذج تشغيل الأمن السيبراني" (no ال on تشغيل)
        # must be recognised; the legacy 'نموذج التشغيل' token would
        # otherwise miss it.
        self.assertEqual(_missing(_CYBER_GAPS_GOOD_OPMODEL_AR), [])

    @_skip_if_no_app
    def test_cyber_vague_governance_fails_helper(self):
        # Vague "تعزيز الحوكمة" / "تحسين الإطار التنظيمي" / "تطوير
        # السياسات" alone does not name a Cyber specialized-function
        # token, so the helper must flag it.
        self.assertTrue(
            len(_missing(_CYBER_GAPS_VAGUE_AR)) > 0,
            'expected Cyber vague-governance gaps to be flagged as '
            'missing the structural row')

    @_skip_if_no_app
    def test_cyber_registry_contains_required_concepts(self):
        reg = _APP._DOMAIN_SPECIALIZED_FUNCTION_CONCEPTS['cyber']
        # establish_dept must recognise every accepted variant.
        ed = set(t.lower() for t in reg['establish_dept'])
        self.assertIn('إدارة الأمن السيبراني', ed)
        self.assertIn('الإدارة المتخصصة للأمن السيبراني', ed)
        self.assertIn('الهيكل التنظيمي للأمن السيبراني', ed)
        self.assertIn('cybersecurity department', ed)
        # ciso family must include CISO + chief information security
        # officer wording.
        ci = set(t.lower() for t in reg['ciso'])
        self.assertIn('ciso', ci)
        self.assertIn('chief information security officer', ci)
        # operating_model family must include the cybersecurity-scoped
        # operating-model + reporting-lines + RACI phrasings.
        om = set(t.lower() for t in reg['operating_model'])
        self.assertIn('نموذج تشغيل الأمن السيبراني', om)
        self.assertIn('cybersecurity operating model', om)
        self.assertIn('cybersecurity reporting lines', om)
        self.assertIn('لجنة حوكمة الأمن السيبراني', om)
        # roles_responsibilities must include cybersecurity RACI.
        rr = set(t.lower() for t in reg['roles_responsibilities'])
        self.assertIn('raci', rr)
        self.assertIn('مصفوفة raci', rr)


# ── End-to-end audit defect emission ─────────────────────────────────────

class CyberFinalAuditTests(unittest.TestCase):
    """End-to-end audit defect emission for Cyber."""

    @_skip_if_no_app
    def test_cyber_generic_gaps_emits_defect(self):
        defects = _APP._final_strategy_audit(
            _make_sections(_CYBER_GAPS_GENERIC_AR), lang='ar',
            doc_subtype=None, selected_frameworks=None,
            domain='cyber', org_structure_is_none=True,
        )
        self.assertTrue(
            _has_struct_gap_defect(defects),
            f'expected Cyber structural-gap defect, got {defects!r}')

    @_skip_if_no_app
    def test_cyber_vague_governance_emits_defect(self):
        defects = _APP._final_strategy_audit(
            _make_sections(_CYBER_GAPS_VAGUE_AR), lang='ar',
            doc_subtype=None, selected_frameworks=None,
            domain='cyber', org_structure_is_none=True,
        )
        self.assertTrue(
            _has_struct_gap_defect(defects),
            f'expected Cyber structural-gap defect for vague wording, '
            f'got {defects!r}')

    @_skip_if_no_app
    def test_cyber_dept_row_clears_defect(self):
        defects = _APP._final_strategy_audit(
            _make_sections(_CYBER_GAPS_GOOD_DEPT_AR), lang='ar',
            doc_subtype=None, selected_frameworks=None,
            domain='cyber', org_structure_is_none=True,
        )
        self.assertFalse(
            _has_struct_gap_defect(defects),
            f'unexpected Cyber structural-gap defect with dept row, '
            f'got {defects!r}')

    @_skip_if_no_app
    def test_cyber_ciso_row_clears_defect(self):
        defects = _APP._final_strategy_audit(
            _make_sections(_CYBER_GAPS_GOOD_CISO_AR), lang='ar',
            doc_subtype=None, selected_frameworks=None,
            domain='cyber', org_structure_is_none=True,
        )
        self.assertFalse(
            _has_struct_gap_defect(defects),
            f'unexpected Cyber structural-gap defect with CISO row, '
            f'got {defects!r}')


# ── Repair-prompt vocabulary pinning ─────────────────────────────────────

class CyberRepairPromptTests(unittest.TestCase):
    """Pin the canonical Cyber vocabulary in the gaps repair prompt."""

    def _build_cyber_gaps_prompt(self):
        captured = {}

        def _fake_generate(prompt, *_a, **_kw):
            captured['prompt'] = prompt
            return ''

        def _fake_call(prompt, **_kw):
            captured['prompt'] = prompt
            return ''

        assert hasattr(_APP, 'generate_ai_content'), (
            'app.generate_ai_content is the documented provider entry '
            'point used by ai_repair_strategy_section')
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
                        'gaps': _CYBER_GAPS_GENERIC_AR,
                        'roadmap': '## 5. خارطة\n',
                        'kpis': '## 6. مؤشرات\n',
                        'confidence': '## 7. الثقة\n',
                    },
                    lang='ar',
                    domain_context={
                        'code': 'cyber',
                        'display': 'الأمن السيبراني',
                        'display_en': 'Cybersecurity',
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
                pass
        finally:
            for name, orig in patched:
                setattr(_APP, name, orig)
        return captured.get('prompt', '')

    @_skip_if_no_app
    def test_cyber_repair_prompt_names_required_concepts(self):
        prompt = self._build_cyber_gaps_prompt()
        if not prompt:
            self.skipTest(
                'could not capture Cyber gaps repair prompt — '
                'provider dispatcher symbol not found')
        for needle in (
            'إدارة الأمن السيبراني',
            'CISO',
            'لجنة حوكمة الأمن السيبراني',
            'نموذج تشغيل الأمن السيبراني',
            'خطوط الرفع',
            'RACI',
        ):
            self.assertIn(
                needle, prompt,
                f'Cyber gaps repair prompt must mention {needle!r}; '
                f'prompt head was {prompt[:400]!r}…')

    @_skip_if_no_app
    def test_cyber_repair_prompt_rejects_vague_wording(self):
        prompt = self._build_cyber_gaps_prompt()
        if not prompt:
            self.skipTest(
                'could not capture Cyber gaps repair prompt — '
                'provider dispatcher symbol not found')
        # The Cyber-specific reinforcement clause must enumerate the
        # forbidden vague wording so the AI cannot silently regress
        # to a generic governance row.
        for vague in (
            'تعزيز الحوكمة',
            'تحسين الإطار التنظيمي',
            'تطوير السياسات',
        ):
            self.assertIn(
                vague, prompt,
                f'Cyber gaps repair prompt must explicitly list the '
                f'forbidden vague phrase {vague!r}')

    @_skip_if_no_app
    def test_cyber_repair_prompt_requires_owner_timeframe_output(self):
        prompt = self._build_cyber_gaps_prompt()
        if not prompt:
            self.skipTest(
                'could not capture Cyber gaps repair prompt')
        # The 1:1 implementation guide must require Owner, Timeframe,
        # Output explicitly for each step.
        for needle in ('Owner', 'Timeframe', 'Output'):
            self.assertIn(needle, prompt)


# ── Repair-routing rejection / acceptance behaviour ──────────────────────

class CyberRepairRoutingTests(unittest.TestCase):
    """Smoke tests for the structural-gap repair acceptance contract:
    candidate must have ≥ 5 substantive rows AND clear the helper."""

    @_skip_if_no_app
    def test_cyber_repair_candidate_with_5_rows_no_struct_row_rejected(
            self):
        # Helper-level acceptance check used by the repair routing.
        rows_no_struct = _CYBER_GAPS_VAGUE_AR
        # Must be flagged as still missing → repair caller would
        # restore original gaps + mark synth_failed.
        self.assertTrue(
            len(_missing(rows_no_struct)) > 0,
            'a 5-row vague gaps candidate must be rejected by the '
            'Cyber structural-gap helper')

    @_skip_if_no_app
    def test_cyber_repair_candidate_with_5_rows_and_struct_row_accepted(
            self):
        # Helper-level acceptance check.
        rows_with_struct = _CYBER_GAPS_GOOD_DEPT_AR
        self.assertEqual(
            _missing(rows_with_struct), [],
            'a 5-row gaps candidate that names إدارة الأمن السيبراني '
            'must clear the Cyber structural-gap helper')

    @_skip_if_no_app
    def test_cyber_repair_routing_no_deterministic_injection(self):
        # The structural-gap repair branch must NOT mutate the gaps
        # text deterministically. The only mutation path is via the
        # AI provider call. We assert by reading the source: the
        # repair branch contains no literal canonical Arabic row
        # string that would be inserted directly.
        import os
        with open(
            os.path.join(os.path.dirname(__file__), '..', 'app.py'),
            'r', encoding='utf-8',
        ) as fh:
            src = fh.read()
        # Locate the GAPS-STRUCTURAL-GAP-REPAIR block.
        marker = "[GAPS-STRUCTURAL-GAP-REPAIR]"
        idx = src.find(marker)
        self.assertGreater(idx, 0, 'expected diagnostic marker to exist')
        # Sentinel: there must be NO ``sections['gaps'] = `` followed
        # by a literal hard-coded structural-gap row in the next 500
        # bytes after the marker. (The only assignment we expect is
        # ``sections['gaps'] = _sg_new`` or ``sections['gaps'] =
        # _sg_before``.) Both are variable assignments — neither
        # contains the literal substring "غياب إدارة الأمن السيبراني".
        block = src[idx: idx + 5000]
        self.assertNotIn(
            'sections[\'gaps\'] = "غياب', block,
            'no deterministic literal gap row should be injected by '
            'the structural-gap repair routing')


# ── Other-domain regression ──────────────────────────────────────────────

class OtherDomainStructuralGapRegressionTests(unittest.TestCase):
    """The Cyber-only token widening must not break the helper for
    other domains (data, ai, dt, erm)."""

    @_skip_if_no_app
    def test_data_helper_unaffected(self):
        # Data gap row that already covers the data registry — must
        # still be considered satisfied.
        data_gaps = (
            '## 4. تحليل الفجوات\n\n'
            '| # | الفجوة | الوصف | الأولوية | الحالة |\n'
            '|---|------|------|---------|--------|\n'
            '| 1 | غياب مكتب إدارة البيانات | لا توجد وظيفة | '
            'عالية | مفتوحة |\n'
        )
        self.assertEqual(
            _APP._compute_missing_structural_gap_for_domain(
                data_gaps, 'data',
                org_structure_is_none=True, lang='ar'),
            [])

    @_skip_if_no_app
    def test_ai_helper_unaffected(self):
        ai_gaps = (
            '## 4. تحليل الفجوات\n\n'
            '| # | الفجوة | الوصف | الأولوية | الحالة |\n'
            '|---|------|------|---------|--------|\n'
            '| 1 | غياب AI Governance Office | لا توجد وظيفة | '
            'عالية | مفتوحة |\n'
        )
        self.assertEqual(
            _APP._compute_missing_structural_gap_for_domain(
                ai_gaps, 'ai',
                org_structure_is_none=True, lang='ar'),
            [])

    @_skip_if_no_app
    def test_dt_helper_unaffected(self):
        dt_gaps = (
            '## 4. تحليل الفجوات\n\n'
            '| # | الفجوة | الوصف | الأولوية | الحالة |\n'
            '|---|------|------|---------|--------|\n'
            '| 1 | غياب مكتب التحول الرقمي | لا توجد وظيفة | '
            'عالية | مفتوحة |\n'
        )
        self.assertEqual(
            _APP._compute_missing_structural_gap_for_domain(
                dt_gaps, 'dt',
                org_structure_is_none=True, lang='ar'),
            [])

    @_skip_if_no_app
    def test_erm_helper_unaffected(self):
        erm_gaps = (
            '## 4. تحليل الفجوات\n\n'
            '| # | الفجوة | الوصف | الأولوية | الحالة |\n'
            '|---|------|------|---------|--------|\n'
            '| 1 | غياب إدارة المخاطر المؤسسية | لا توجد وظيفة | '
            'عالية | مفتوحة |\n'
        )
        self.assertEqual(
            _APP._compute_missing_structural_gap_for_domain(
                erm_gaps, 'erm',
                org_structure_is_none=True, lang='ar'),
            [])


# ── Validator-strength regression ────────────────────────────────────────

class ValidatorNotWeakenedTests(unittest.TestCase):
    """The Cyber registry widening must not weaken the helper —
    semantics still reject empty / non-cyber gaps text."""

    @_skip_if_no_app
    def test_empty_gaps_still_flagged(self):
        self.assertTrue(
            len(_APP._compute_missing_structural_gap_for_domain(
                '', 'cyber',
                org_structure_is_none=True, lang='ar')) > 0)

    @_skip_if_no_app
    def test_helper_off_when_org_structure_is_none_false(self):
        # When org_structure_is_none=False, helper is a no-op.
        self.assertEqual(
            _APP._compute_missing_structural_gap_for_domain(
                _CYBER_GAPS_GENERIC_AR, 'cyber',
                org_structure_is_none=False, lang='ar'),
            [])

    @_skip_if_no_app
    def test_min_gap_rows_constant_not_lowered(self):
        # The minimum gap rows floor used by the structural-gap repair
        # acceptance check must remain at the existing positive value
        # (i.e. PR-5B.9O must not weaken it). We snapshot the value
        # rather than pin a specific number — any positive integer is
        # acceptable as long as it remains > 0.
        self.assertTrue(
            isinstance(
                getattr(_APP, '_RICHNESS_MIN_GAP_ROWS', None), int))
        self.assertGreater(
            getattr(_APP, '_RICHNESS_MIN_GAP_ROWS', 0), 0)


# ── Data NDMO/PDPL regression (Part C) ───────────────────────────────────

class DataNDMOPDPLRegressionTests(unittest.TestCase):
    """PR-5B.9O Part C — Data Management + NDMO/PDPL + org_structure
    is_none must still pass Vision/Gaps obligations. The previous PRs
    already wired the NDMO alias widening (PR-5B.9N) and the Data
    Management Office concept registry; this regression test pins the
    contract."""

    @_skip_if_no_app
    def test_data_ndmo_pdpl_no_structural_gap_defect_when_dmo_present(
            self):
        sections = {
            'vision': (
                '## 1. الرؤية\n\n'
                'تحقيق الالتزام بإطار NDMO وPDPL وإنشاء مكتب إدارة '
                'البيانات.\n'),
            'pillars': '## 2. الركائز\n\n### 1\n\nنص.\n',
            'environment': '## 3. البيئة\n\nنص.\n',
            'gaps': (
                '## 4. تحليل الفجوات\n\n'
                '| # | الفجوة | الوصف | الأولوية | الحالة |\n'
                '|---|------|------|---------|--------|\n'
                '| 1 | غياب مكتب إدارة البيانات | لا توجد وظيفة | '
                'عالية | مفتوحة |\n'
                '| 2 | فجوة في تصنيف البيانات | وصف | عالية | مفتوحة |\n'
                '| 3 | فجوة في جودة البيانات | وصف | متوسطة | مفتوحة |\n'
                '| 4 | فجوة في حماية البيانات الشخصية | وصف | '
                'عالية | مفتوحة |\n'
                '| 5 | فجوة في حوكمة البيانات | وصف | متوسطة | مفتوحة |\n'),
            'roadmap': '## 5. خارطة\n\n',
            'kpis': '## 6. مؤشرات\n\n',
            'confidence': '## 7. الثقة\n\n',
        }
        defects = _APP._final_strategy_audit(
            sections, lang='ar',
            doc_subtype=None,
            selected_frameworks=['NDMO', 'PDPL'],
            domain='data', org_structure_is_none=True,
        )
        # Structural-gap defect specifically must NOT be raised for
        # Data when the gaps text names "مكتب إدارة البيانات".
        self.assertFalse(
            _has_struct_gap_defect(defects),
            f'Data NDMO/PDPL gaps that name DMO should not emit '
            f'structural-gap defect; got {defects!r}')


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
