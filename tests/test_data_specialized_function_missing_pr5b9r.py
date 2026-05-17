"""PR-5B.9R — Data Management ``specialized_function_missing:data`` repair.

PR-5B.9Q tightened ``_DOMAIN_SPECIALIZED_FUNCTION_CONCEPTS['data']`` to
five families (establish_dept, head_officer, committee,
roles_responsibilities including ``ملكية البيانات``/data ownership,
operating_model including ``نموذج تشغيل إدارة البيانات`` and reporting
lines). The cross-section validator
``_compute_missing_specialized_function_concepts`` therefore expects
all five families to surface somewhere across the assembled strategy.
The Data Management runtime previously emitted
``specialized_function_missing`` for plausible AI output that covered
only a subset of the five families, with no targeted AI-first repair
pass routing the missing family list back into the
``ai_repair_strategy_section`` prompt.

PR-5B.9R adds the ``[SPECIALIZED-FUNCTION-REPAIR]`` AI-first pass
(strictly scoped to ``domain == 'data'``) immediately after the cyber
dept-establishment repair and before the environment depth repair.
This module pins:

  1. Detection — bare/partial Data strategies emit the cross-section
     ``specialized_function_missing`` defect tag.
  2. Generic ``حوكمة البيانات`` wording alone still fails.
  3. A strategy that explicitly names all five families passes.
  4. Missing ``operating_model`` and ``roles_responsibilities`` families
     are surfaced in the diagnostic helper output.
  5. The data-domain prompt addendum in ``ai_repair_strategy_section``
     names DMO + CDO + Data Governance Committee + Stewards/Ownership +
     Operating Model + RACI + reporting lines for pillars / gaps /
     roadmap / confidence repair calls.
  6. The Cyber-only ``cybersecurity_department_establishment_missing``
     repair routing is preserved verbatim (regression guard) and the
     cyber/AI/DT/ERM specialized-function helpers continue to behave
     unchanged.
  7. Validators are not weakened: ``_compute_missing_specialized_
     function_concepts`` still uses all-family-match semantics.
  8. No deterministic content is inserted into ``sections``.
  9. Export / PDF / DOCX / auth / DB are untouched (regression guard
     via static file-level search).

Run:
    python -m pytest \
        tests/test_data_specialized_function_missing_pr5b9r.py -q
"""

import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_data_pr5b9r_')
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
def _bare_ar_sections():
    """Minimal Arabic strategy skeleton with no specialized-function
    wording in any section. Used as the starting point for the
    ``specialized_function_missing`` detection tests."""
    return {
        'vision': (
            '## 1. الرؤية والأهداف الاستراتيجية\n\n'
            '### الأهداف الاستراتيجية:\n\n'
            '| # | الهدف | المؤشر | المبرر | الإطار |\n'
            '|---|------|-------|--------|--------|\n'
            '| 1 | تطوير القدرات | 100% | تحسين | NDMO |\n'
            '| 2 | تعزيز الجودة | 90% | تحسين | NDMO |\n'
            '| 3 | تطوير المهارات | 80% | تحسين | NDMO |\n'
            '| 4 | تحسين الكفاءة | 95% | تحسين | NDMO |\n'
        ),
        'pillars': (
            '## 2. الركائز الاستراتيجية\n\n'
            '### الركيزة 1: تطوير القدرات\n\n'
            'برامج تطوير القدرات التشغيلية.\n'
        ),
        'environment': (
            '## 3. البيئة التنظيمية\n\n'
            'فقرة عن البيئة التنظيمية.\n'
        ),
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
            '| 1 | تطوير القدرات | الإدارة | NDMO | تحسن |\n'
        ),
        'kpis': (
            '## 6. مؤشرات الأداء\n\n'
            '| # | المؤشر | النوع | المستهدفة | صيغة | المصدر '
            '| المالك | التكرار | الإطار |\n'
            '|---|------|------|----------|------|--------|'
            '-------|---------|--------|\n'
            '| 1 | مؤشر | KPI | 100% | x | عام | الإدارة | شهري | NDMO |\n'
        ),
        'confidence': (
            '## 7. تقييم الثقة والمخاطر\n\n**درجة الثقة:** 70%\n\n'
            '| # | الخطر | الاحتمالية | التأثير | خطة التخفيف |\n'
            '|---|------|----------|--------|------------|\n'
            '| 1 | خطر عام | عالية | عالي | متابعة |\n'
        ),
    }


def _full_data_sections():
    """Data strategy that explicitly covers ALL five concept families
    (establish_dept, head_officer, committee, roles_responsibilities,
    operating_model) across the assembled sections."""
    s = _bare_ar_sections()
    s['pillars'] = (
        '## 2. الركائز الاستراتيجية\n\n'
        '### الركيزة 1: حوكمة البيانات ومكتب إدارة البيانات ونموذج '
        'التشغيل\n\n'
        'إنشاء مكتب إدارة البيانات وتعيين CDO وتشكيل لجنة حوكمة '
        'البيانات وتعيين أمناء البيانات وتثبيت ملكية البيانات '
        'واعتماد نموذج تشغيل إدارة البيانات وخطوط الرفع وتحديد '
        'الأدوار والمسؤوليات (RACI).\n\n'
        '| # | المبادرة | المخرج | المدة |\n'
        '|---|---------|------|------|\n'
        '| 1 | تأسيس مكتب إدارة البيانات | DMO | 6 أشهر |\n'
        '| 2 | تعيين CDO | منصب | 3 أشهر |\n'
        '| 3 | تفعيل لجنة حوكمة البيانات | لجنة | 3 أشهر |\n'
    )
    s['gaps'] = (
        '## 4. تحليل الفجوات\n\n'
        '| # | الفجوة | الوصف | الأولوية | الحالة |\n'
        '|---|------|------|---------|--------|\n'
        '| 1 | غياب مكتب إدارة البيانات ونموذج تشغيل إدارة البيانات '
        '| لا يوجد DMO ولا CDO ولا لجنة حوكمة البيانات ولا أمناء '
        'البيانات ولا خطوط رفع | عالية | مفتوحة |\n'
    )
    s['roadmap'] = (
        '## 5. خارطة الطريق\n\n'
        '| # | النشاط | المسؤول | الإطار | المخرج |\n'
        '|---|------|--------|------|--------|\n'
        '| 1 | تأسيس مكتب إدارة البيانات وتعيين CDO وتفعيل لجنة '
        'حوكمة البيانات وأمناء البيانات | الإدارة العليا | 6 أشهر '
        '| نموذج تشغيل إدارة البيانات وخطوط الرفع |\n'
    )
    return s


# ── Tests ────────────────────────────────────────────────────────────────
class DataSpecializedFunctionDetectionTests(unittest.TestCase):
    """Cross-section detection — pins the family-based-matching semantics
    introduced by PR-5B.9Q/9R."""

    @_skip_if_no_app
    def test_bare_data_strategy_missing_dmo_emits_defect(self):
        """A Data strategy that mentions NO DMO/CDO/committee must
        surface the ``specialized_function_missing`` defect."""
        defects = _APP.validate_arabic_strategy_semantic_richness(
            _bare_ar_sections(), 'ar',
            domain='Data Management',
            org_structure_is_none=True,
        )
        tags = [t for (t, _d) in defects]
        self.assertIn('specialized_function_missing', tags)

    @_skip_if_no_app
    def test_generic_data_governance_only_still_fails(self):
        """Mentioning only the generic phrase ``حوكمة البيانات`` (with
        no DMO / CDO / committee / stewards / operating-model wording)
        must still emit ``specialized_function_missing``."""
        s = _bare_ar_sections()
        s['pillars'] = (
            '## 2. الركائز الاستراتيجية\n\n'
            '### الركيزة 1: تعزيز حوكمة البيانات\n\n'
            'برنامج عام لتعزيز حوكمة البيانات داخل المنظمة.\n'
        )
        defects = _APP.validate_arabic_strategy_semantic_richness(
            s, 'ar',
            domain='Data Management',
            org_structure_is_none=True,
        )
        tags = [t for (t, _d) in defects]
        self.assertIn('specialized_function_missing', tags)
        # Confirm the helper reports the structural families as missing.
        missing = _APP._compute_missing_specialized_function_concepts(
            s, 'data')
        self.assertTrue(missing,
                        'generic governance must NOT mask missing families')

    @_skip_if_no_app
    def test_full_coverage_passes(self):
        """A strategy with DMO + CDO + committee + stewards/ownership +
        operating model must clear the cross-section helper."""
        missing = _APP._compute_missing_specialized_function_concepts(
            _full_data_sections(), 'data')
        self.assertEqual([], missing,
                         f'expected no missing families, got {missing!r}')

    @_skip_if_no_app
    def test_missing_operating_model_family_reported(self):
        """If every family is covered EXCEPT operating_model, the helper
        surfaces exactly that family (diagnostic precision)."""
        s = _bare_ar_sections()
        s['pillars'] = (
            '## 2. الركائز الاستراتيجية\n\n'
            '### الركيزة 1: حوكمة البيانات\n\n'
            'إنشاء مكتب إدارة البيانات وتعيين CDO وتشكيل لجنة حوكمة '
            'البيانات وتعيين أمناء البيانات وتثبيت ملكية البيانات '
            'وتحديد الأدوار والمسؤوليات.\n'
        )
        missing = _APP._compute_missing_specialized_function_concepts(
            s, 'data')
        self.assertEqual(missing, ['operating_model'])

    @_skip_if_no_app
    def test_missing_ownership_stewards_family_reported(self):
        """If every family is covered EXCEPT roles_responsibilities
        (stewards / ownership / RACI), the helper surfaces exactly
        that family."""
        s = _bare_ar_sections()
        s['pillars'] = (
            '## 2. الركائز الاستراتيجية\n\n'
            '### الركيزة 1: حوكمة البيانات ونموذج التشغيل\n\n'
            'إنشاء مكتب إدارة البيانات وتعيين CDO وتشكيل لجنة حوكمة '
            'البيانات واعتماد نموذج تشغيل إدارة البيانات وخطوط '
            'الرفع.\n'
        )
        missing = _APP._compute_missing_specialized_function_concepts(
            s, 'data')
        self.assertEqual(missing, ['roles_responsibilities'])


class DataSpecializedFunctionRepairPromptTests(unittest.TestCase):
    """Repair-prompt content — the ``ai_repair_strategy_section`` prompt
    (which the new ``[SPECIALIZED-FUNCTION-REPAIR]`` pass invokes) must
    explicitly name every required Data Management concept family for
    pillars / gaps / roadmap / confidence repairs."""

    def _capture_prompt(self, captured):
        def _fake(prompt, **kw):
            captured['prompt'] = prompt
            captured['kw'] = kw
            raise RuntimeError('AI mocked')
        return _fake

    def _invoke(self, section_key, captured):
        import unittest.mock
        dctx = _APP.get_strategy_domain_context('Data Management', 'ar')
        with unittest.mock.patch.object(
                _APP, 'generate_ai_content',
                side_effect=self._capture_prompt(captured)):
            with self.assertRaises(_APP.RepairError):
                _APP.ai_repair_strategy_section(
                    section_key=section_key,
                    sections=_bare_ar_sections(),
                    lang='ar',
                    domain_context=dctx,
                    org_structure_is_none=True,
                )
        return captured.get('prompt', '')

    @_skip_if_no_app
    def test_pillars_prompt_names_required_concepts(self):
        captured = {}
        prompt = self._invoke('pillars', captured)
        self.assertIn('مكتب إدارة البيانات', prompt)
        self.assertIn('CDO', prompt)
        self.assertIn('لجنة حوكمة البيانات', prompt)
        self.assertIn('أمناء البيانات', prompt)
        self.assertIn('RACI', prompt)
        # operating model + reporting lines
        self.assertTrue(
            ('نموذج التشغيل' in prompt)
            or ('نموذج تشغيل إدارة البيانات' in prompt))
        self.assertIn('خطوط الرفع', prompt)

    @_skip_if_no_app
    def test_roadmap_prompt_names_dmo_and_cdo(self):
        captured = {}
        prompt = self._invoke('roadmap', captured)
        self.assertIn('مكتب إدارة البيانات', prompt)
        self.assertIn('CDO', prompt)
        self.assertIn('لجنة حوكمة البيانات', prompt)

    @_skip_if_no_app
    def test_gaps_prompt_names_missing_dmo_and_operating_model(self):
        captured = {}
        prompt = self._invoke('gaps', captured)
        self.assertIn('مكتب إدارة البيانات', prompt)
        # operating-model / reporting-lines wording must appear
        self.assertTrue(
            ('نموذج التشغيل' in prompt)
            or ('نموذج تشغيل إدارة البيانات' in prompt))

    @_skip_if_no_app
    def test_confidence_prompt_names_governance_owners(self):
        captured = {}
        prompt = self._invoke('confidence', captured)
        self.assertIn('CDO', prompt)
        self.assertIn('لجنة حوكمة البيانات', prompt)


class DataSpecializedFunctionRepairRoutingTests(unittest.TestCase):
    """``[SPECIALIZED-FUNCTION-REPAIR]`` AI-first repair routing — gated
    on ``domain == 'data'`` and ``org_structure_is_none=True``."""

    @_skip_if_no_app
    def test_repair_pass_marker_present_in_source(self):
        """Static guard: the new repair pass must exist in app.py and
        be tagged with the ``[SPECIALIZED-FUNCTION-REPAIR]`` log
        marker, gated on the data domain only."""
        with open(os.path.join(
                os.path.dirname(__file__), '..', 'app.py'),
                'r', encoding='utf-8') as f:
            src = f.read()
        self.assertIn('[SPECIALIZED-FUNCTION-REPAIR]', src)
        self.assertIn('[SPECIALIZED-FUNCTION-CHECK]', src)
        self.assertIn("_sf_dcode == 'data'", src)
        # Diagnostic context required by the contract.
        self.assertIn('missing_families=', src)
        self.assertIn('matched_families=', src)
        self.assertIn('sections_scanned=', src)
        self.assertIn('matched_terms=', src)

    @_skip_if_no_app
    def test_repair_pass_routes_required_sections(self):
        """Static guard: pillars / gaps / roadmap / confidence are all
        repaired by the new pass."""
        with open(os.path.join(
                os.path.dirname(__file__), '..', 'app.py'),
                'r', encoding='utf-8') as f:
            src = f.read()
        # Locate the new repair pass.
        marker = '[SPECIALIZED-FUNCTION-REPAIR]'
        start = src.find('# ── PR-5B.9R: targeted AI repair for cross-domain')
        end = src.find('# ── PR-5B.8L: targeted AI repair for environment',
                       start)
        self.assertGreater(start, 0,
                           'PR-5B.9R pass header not found')
        self.assertGreater(end, start,
                           'PR-5B.9R pass terminator not found')
        block = src[start:end]
        self.assertIn(marker, block)
        # Must invoke ai_repair_strategy_section on every required key.
        self.assertIn("'pillars', 'gaps', 'roadmap'", block)
        self.assertIn("'confidence'", block)
        self.assertIn('ai_repair_strategy_section', block)
        # Validation_error must name the missing families explicitly.
        self.assertIn('Uncovered concept families', block)
        # Fail-closed behaviour: restore original + mark synth_failed.
        self.assertIn('_mark_synth_failed', block)
        self.assertIn('specialized_function_missing:', block)

    @_skip_if_no_app
    def test_rejected_candidate_restores_original(self):
        """Static guard: the new pass restores the original section text
        when the AI candidate regresses the cross-section coverage."""
        with open(os.path.join(
                os.path.dirname(__file__), '..', 'app.py'),
                'r', encoding='utf-8') as f:
            src = f.read()
        start = src.find('# ── PR-5B.9R: targeted AI repair for cross-domain')
        end = src.find('# ── PR-5B.8L: targeted AI repair for environment',
                       start)
        block = src[start:end]
        self.assertIn('rejected_regression', block)
        self.assertIn('sections[_sfsec] = _sf_before_text', block)


class CrossDomainRegressionGuards(unittest.TestCase):
    """Confirm Cyber / AI / DT / ERM specialized-function behaviour is
    preserved verbatim."""

    @_skip_if_no_app
    def test_cyber_dept_repair_routing_unchanged(self):
        with open(os.path.join(
                os.path.dirname(__file__), '..', 'app.py'),
                'r', encoding='utf-8') as f:
            src = f.read()
        # Cyber repair tag preserved.
        self.assertIn('cybersecurity_department_establishment_missing',
                      src)
        # Cyber repair body still contains CISO + Cybersecurity Department
        # wording (regression guard for PR-5B.8U).
        self.assertIn('Cybersecurity Department', src)
        self.assertIn('CISO', src)

    @_skip_if_no_app
    def test_ai_dt_erm_concept_families_preserved(self):
        """Detection helpers for ai / dt / erm domains must still flag
        a bare strategy (no behaviour regression from the new
        Data-only repair routing)."""
        for code, label in (
                ('ai', 'Artificial Intelligence'),
                ('dt', 'Digital Transformation'),
                ('erm', 'Enterprise Risk Management')):
            with self.subTest(domain=code):
                missing = _APP._compute_missing_specialized_function_concepts(
                    _bare_ar_sections(), code)
                self.assertTrue(
                    missing,
                    f'{code}: bare strategy must surface missing families')

    @_skip_if_no_app
    def test_cyber_specialized_function_helper_unchanged(self):
        """Cyber must continue to be served by its dedicated cyber-only
        helper (legacy guard from PR-5B.9D)."""
        defects = _APP.validate_arabic_strategy_semantic_richness(
            _bare_ar_sections(), 'ar',
            domain='Cyber Security',
            org_structure_is_none=True,
        )
        tags = [t for (t, _d) in defects]
        self.assertIn('cybersecurity_department_establishment_missing',
                      tags)
        self.assertNotIn('specialized_function_missing', tags)


class StructuralIntegrityGuards(unittest.TestCase):
    """No deterministic rows, validators not weakened, export untouched."""

    @_skip_if_no_app
    def test_specialized_function_helper_strict_semantics_preserved(self):
        """``_compute_missing_specialized_function_concepts`` must
        continue to require coverage of every family — no weakening
        of the validator."""
        s = _bare_ar_sections()
        s['gaps'] = s['gaps'] + '\nمكتب إدارة البيانات فقط.\n'
        # Only establish_dept is covered; the other four families remain
        # missing. The helper MUST report at least 4 missing families
        # (validator strictness preserved).
        missing = _APP._compute_missing_specialized_function_concepts(
            s, 'data')
        self.assertGreaterEqual(
            len(missing), 4,
            'helper must not be weakened: only establish_dept covered')

    @_skip_if_no_app
    def test_data_registry_has_five_required_families(self):
        """PR-5B.9Q invariant: Data registry MUST carry all five
        families. The new repair pass relies on this set."""
        concepts = _APP._DOMAIN_SPECIALIZED_FUNCTION_CONCEPTS['data']
        for fam in ('establish_dept', 'head_officer', 'committee',
                    'roles_responsibilities', 'operating_model'):
            self.assertIn(fam, concepts)

    @_skip_if_no_app
    def test_no_deterministic_data_rows_injected(self):
        """Static guard: the new repair pass MUST NOT inject any
        deterministic Arabic content into ``sections`` (everything
        must be AI-first via ``ai_repair_strategy_section``)."""
        with open(os.path.join(
                os.path.dirname(__file__), '..', 'app.py'),
                'r', encoding='utf-8') as f:
            src = f.read()
        start = src.find('# ── PR-5B.9R: targeted AI repair for cross-domain')
        end = src.find('# ── PR-5B.8L: targeted AI repair for environment',
                       start)
        block = src[start:end]
        # The pass body must NEVER write a deterministic Arabic row
        # into ``sections[<sec>]`` — every assignment to
        # ``sections[_sfsec]`` either calls the AI repair function or
        # restores the original ``_sf_before_text``.
        forbidden_inline_rows = (
            '| 1 | تأسيس مكتب إدارة البيانات',
            'sections[\'pillars\'] = (',
            'sections[\'gaps\'] = (',
            'sections[\'roadmap\'] = (',
        )
        for needle in forbidden_inline_rows:
            self.assertNotIn(needle, block,
                             f'deterministic inline content found: '
                             f'{needle!r}')

    @_skip_if_no_app
    def test_export_pdf_docx_auth_db_untouched(self):
        """Regression guard: the new repair pass must not touch any
        export / PDF / DOCX / auth / DB pipeline. Confirmed by absence
        of the relevant module calls inside the new block."""
        with open(os.path.join(
                os.path.dirname(__file__), '..', 'app.py'),
                'r', encoding='utf-8') as f:
            src = f.read()
        start = src.find('# ── PR-5B.9R: targeted AI repair for cross-domain')
        end = src.find('# ── PR-5B.8L: targeted AI repair for environment',
                       start)
        block = src[start:end]
        # Forbidden module surfaces — the new pass is strategy-text
        # repair only.
        for forbidden in ('reportlab', 'docx.', 'pdf_export',
                          'session[', 'login_required',
                          'db.session', 'sqlalchemy'):
            self.assertNotIn(forbidden, block,
                             f'{forbidden} touched by new pass')


if __name__ == '__main__':
    unittest.main()
