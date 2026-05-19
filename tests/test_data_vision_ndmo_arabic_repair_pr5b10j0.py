"""PR-J0 — Fix Arabic Data NDMO Vision compliance repair.

Runtime root cause exercised here:

  * ``_FRAMEWORK_COVERAGE_REQUIREMENTS['NDMO']['display']`` is the
    English string ``"NDMO Data Management Framework"`` and was being
    interpolated directly into the AR vision-repair prompts (via
    ``_build_vision_composite_repair_contract`` clause (C) and
    ``FW-COMPLIANCE-OBJECTIVE-REPAIR``). The AI then emitted the EN
    label inside the AR Vision body; ``_vision_template_residue_hits``
    rejected the candidate as
    ``vision_contains_en_template_residue:NDMO Data Governance
    Framework`` (the related EN long-name that also routinely leaks).
    ``_AR_TEMPLATE_RESIDUE_MAP`` replacements run AFTER validation, so
    they never got a chance to fix the candidate; both repair attempts
    failed; the original Vision was restored;
    ``_compute_missing_compliance_objective`` kept reporting NDMO
    missing; the post-normalization audit emitted
    ``selected_framework_compliance_objective_missing:NDMO (vision)
    0/1`` and the save was rejected as 422.

This test pins:

  1. ``_compute_missing_compliance_objective`` accepts each of the
     PR-J0 Arabic acceptance phrases for NDMO.
  2. EN ``"NDMO Data Governance Framework"`` is detected as template
     residue when present in a raw AR Vision candidate (template-
     residue detection is NOT weakened globally).
  3. The Data Arabic vision repair prompt produced by
     ``_build_vision_composite_repair_contract`` and
     ``FW-COMPLIANCE-OBJECTIVE-REPAIR`` no longer contains
     ``"NDMO Data Governance Framework"`` /
     ``"NDMO Data Management Framework"`` — it uses the Arabic
     canonical wording instead.
  4. The Data + AR pre-validation normalization replaces the two known
     NDMO EN labels with their Arabic canonical equivalents and the
     resulting candidate is accepted by the vision contract.
  5. The pre-validation normalization is scoped: it does NOT touch
     Cyber / AI / DT / ERM AR Vision candidates and does NOT replace
     other EN framework long-names (e.g. SDAIA, ECC).
  6. No deterministic Strategic Objective rows are inserted by the
     normalization helper.
  7. ``_AR_TEMPLATE_RESIDUE_MAP`` still contains the
     ``"NDMO Data Governance Framework"`` key so the final-audit
     residue detection remains intact.

Run:
    python -m pytest tests/test_data_vision_ndmo_arabic_repair_pr5b10j0.py -q
"""

import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_pr5b10j0_')
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


# ── Vision fixtures ──────────────────────────────────────────────────────


_AR_TABLE_HDR = (
    '| # | الهدف الاستراتيجي | المؤشر | المبرر | الإطار الزمني |\n'
    '|---|------------------|-------|--------|---------------|\n'
)


def _vision_with_objective(objective_text):
    """Build a >=6 row Arabic vision whose row #1 is ``objective_text``."""
    return (
        '## 1. الرؤية والأهداف الاستراتيجية\n\n'
        '**الرؤية:** حوكمة بيانات وطنية ممتثلة.\n\n'
        '### الأهداف الاستراتيجية:\n\n'
        + _AR_TABLE_HDR
        + f'| 1 | {objective_text} | 100% | الامتثال التنظيمي | 12 شهراً |\n'
        + '| 2 | بناء مستودع بيانات | 100% | مركزية البيانات | 18 شهراً |\n'
        + '| 3 | تدريب فرق البيانات | 100% | بناء الكفاءات | 12 شهراً |\n'
        + '| 4 | اعتماد أدوات تحليل | 100% | الكفاءة | 12 شهراً |\n'
        + '| 5 | تطوير لوحات المعلومات | 100% | الشفافية | 12 شهراً |\n'
        + '| 6 | قياس جودة المخرجات | 100% | التحسين | 12 شهراً |\n'
    )


# ── Tests 1-2, 7 — _compute_missing_compliance_objective accepts AR ─────

_AR_ACCEPTANCE_OBJECTIVES = [
    # Required by problem statement Required-fix items 3 & 7
    'تحقيق الالتزام بإطار حوكمة وإدارة البيانات الوطني NDMO',
    'تحقيق الامتثال لضوابط NDMO لحوكمة وإدارة البيانات',
    'الالتزام بإطار NDMO لحوكمة البيانات',
    'الامتثال لمكتب إدارة البيانات الوطنية NDMO',
    'الالتزام بضوابط NDMO لإدارة البيانات',
]


class NDMOArabicComplianceAcceptanceTests(unittest.TestCase):
    """Tests 1, 2, 7 — AR NDMO objective phrases pass compliance check."""

    @_skip_if_no_app
    def test_each_required_ar_phrase_passes_ndmo_compliance(self):
        for phrase in _AR_ACCEPTANCE_OBJECTIVES:
            with self.subTest(phrase=phrase):
                sections = {'vision': _vision_with_objective(phrase)}
                missing = _APP._compute_missing_compliance_objective(
                    sections,
                    selected_frameworks=['grc_ndmo'],
                    domain='Data Management',
                    lang='ar',
                )
                self.assertNotIn(
                    'NDMO', missing,
                    f'NDMO still missing for objective: {phrase!r}',
                )


# ── Tests 3, 11 — Template residue detection still fires for EN label ───


class TemplateResidueNotWeakenedTests(unittest.TestCase):
    """Tests 3 + 11 — EN NDMO long-name is still residue."""

    @_skip_if_no_app
    def test_en_ndmo_governance_label_detected_in_ar_vision(self):
        # An AR Vision body that ACCIDENTALLY contains the EN long-name
        # must still be flagged by the residue detector.
        ar_body = (
            '## 1. الرؤية والأهداف الاستراتيجية\n\n'
            '**الرؤية:** الالتزام بضوابط NDMO Data Governance '
            'Framework.\n'
        )
        hits = _APP._vision_template_residue_hits(ar_body, lang='ar')
        self.assertIn('NDMO Data Governance Framework', hits)

    @_skip_if_no_app
    def test_ar_residue_map_still_contains_ndmo_governance_key(self):
        # The global _AR_TEMPLATE_RESIDUE_MAP must still carry the
        # original NDMO Governance key — the fix did not REMOVE any
        # residue keys.
        self.assertIn(
            'NDMO Data Governance Framework',
            _APP._AR_TEMPLATE_RESIDUE_MAP,
        )

    @_skip_if_no_app
    def test_ar_residue_map_now_also_covers_management_label(self):
        # PR-J0 additionally maps the registry display long-name so
        # ``normalize_final_arabic_sections`` cleans both EN forms.
        self.assertIn(
            'NDMO Data Management Framework',
            _APP._AR_TEMPLATE_RESIDUE_MAP,
        )

    @_skip_if_no_app
    def test_residue_check_unchanged_for_other_en_labels(self):
        # SDAIA EN long-name in an AR vision should still be flagged —
        # the normalization helper does NOT touch SDAIA / other
        # frameworks.
        ar_body = (
            '**الرؤية:** الالتزام بـ SDAIA AI Ethics Framework.\n'
        )
        hits = _APP._vision_template_residue_hits(ar_body, lang='ar')
        self.assertIn('SDAIA AI Ethics Framework', hits)


# ── Tests 4, 5, 6 — Repair prompts use Arabic canonical NDMO wording ────


_AR_CANONICAL_WORDING_TOKENS = (
    'إطار حوكمة وإدارة البيانات الوطني NDMO',
)


class ArabicRepairPromptContentTests(unittest.TestCase):
    """Tests 4, 5, 6 — the AR Data vision repair prompts do not emit
    English NDMO long-names and DO emit the canonical Arabic wording.
    """

    @_skip_if_no_app
    def test_composite_repair_contract_uses_ar_canonical_for_ndmo(self):
        ve_msg, _min_rows = (
            _APP._build_vision_composite_repair_contract(
                domain='Data Management',
                selected_frameworks=['grc_ndmo'],
                org_structure_is_none=False,
                generation_mode='drafting',
                lang='ar',
                existing_vision='',
                existing_valid_rows=0,
                missing_obligations={
                    'compliance_missing': ['NDMO'],
                    'specialized_missing': False,
                },
                attempt=1,
            ))
        # Test 4 — no EN NDMO Governance long-name in the AR prompt
        self.assertNotIn('NDMO Data Governance Framework', ve_msg)
        # Test 5 — no EN NDMO Management long-name in the AR prompt
        self.assertNotIn('NDMO Data Management Framework', ve_msg)
        # Test 6 — Arabic canonical NDMO wording IS in the prompt
        self.assertTrue(
            any(tok in ve_msg for tok in _AR_CANONICAL_WORDING_TOKENS),
            f'AR canonical NDMO wording not found in prompt: {ve_msg!r}',
        )

    @_skip_if_no_app
    def test_repair_display_label_helper_returns_ar_for_ndmo_ar(self):
        label = _APP._framework_repair_display_label('NDMO', 'ar')
        self.assertEqual(label, _APP._NDMO_AR_VISION_REPAIR_LABEL)
        self.assertNotIn('Framework', label)

    @_skip_if_no_app
    def test_repair_display_label_helper_returns_en_for_ndmo_en(self):
        # EN repair prompts continue to use the registry display.
        label = _APP._framework_repair_display_label('NDMO', 'en')
        self.assertEqual(label, 'NDMO Data Management Framework')

    @_skip_if_no_app
    def test_repair_display_label_helper_unchanged_for_non_ndmo(self):
        # Test 13 — Cyber/AI/DT/ERM unchanged. The helper must return
        # the original registry display for non-NDMO frameworks even
        # when lang=='ar'.
        for fw_key, expected in (
                ('ECC', 'NCA ECC (Essential Cybersecurity Controls)'),
                ('TCC', 'NCA TCC (Telework Cybersecurity Controls)'),
                ('NIST_AI_RMF',
                 'NIST AI Risk Management Framework'),
                ('COSO_ERM',
                 'COSO Enterprise Risk Management Framework'),
                ('SDAIA',
                 'SDAIA AI Ethics & Governance Principles'),
                ('PDPL',
                 'Personal Data Protection Law (PDPL)'),
        ):
            with self.subTest(fw=fw_key):
                self.assertEqual(
                    _APP._framework_repair_display_label(fw_key, 'ar'),
                    expected,
                )


# ── Tests 7, 8, 9, 10 — Pre-validation normalization end-to-end ─────────


class DataArVisionNormalizationTests(unittest.TestCase):
    """Tests 7, 8, 9, 10 — Data+AR candidate with EN NDMO label is
    normalized before validation, gets accepted, and clears the
    NDMO compliance missing check.
    """

    @_skip_if_no_app
    def test_normalize_replaces_both_known_ndmo_en_labels(self):
        text = (
            '**الرؤية:** الالتزام بضوابط NDMO Data Governance '
            'Framework وNDMO Data Management Framework.'
        )
        out, n = _APP._normalize_data_ar_vision_framework_labels(text)
        self.assertEqual(n, 2)
        self.assertNotIn('NDMO Data Governance Framework', out)
        self.assertNotIn('NDMO Data Management Framework', out)
        self.assertIn('إطار حوكمة وإدارة البيانات الوطني NDMO', out)
        self.assertIn('إطار إدارة البيانات الوطني NDMO', out)

    @_skip_if_no_app
    def test_normalize_noop_on_empty_or_missing_labels(self):
        out, n = _APP._normalize_data_ar_vision_framework_labels('')
        self.assertEqual((out, n), ('', 0))
        ar_body = '**الرؤية:** حوكمة بيانات وطنية.\n'
        out2, n2 = (
            _APP._normalize_data_ar_vision_framework_labels(ar_body))
        self.assertEqual(out2, ar_body)
        self.assertEqual(n2, 0)

    @_skip_if_no_app
    def test_normalize_does_not_touch_other_en_framework_labels(self):
        # Test 11 — scope of the normalization is strictly the two
        # NDMO long-names; SDAIA / ECC are NOT replaced.
        text = (
            '**الرؤية:** الالتزام بـ SDAIA AI Ethics Framework '
            'و ECC.'
        )
        out, n = _APP._normalize_data_ar_vision_framework_labels(text)
        self.assertEqual(n, 0)
        self.assertEqual(out, text)

    @_skip_if_no_app
    def test_assign_vision_normalizes_ar_data_candidate_then_accepts(self):
        # Tests 7, 8, 9, 10 — the full path. Candidate vision contains
        # the EN NDMO Governance label; ``_assign_vision_if_valid_or_restore``
        # MUST pre-normalize it (only because domain=='data' AND
        # lang=='ar'), the contract MUST accept it, and the assigned
        # vision MUST clear the NDMO compliance missing check.
        candidate = _vision_with_objective(
            'تحقيق الالتزام بـ NDMO Data Governance Framework'
        )
        sections = {'vision': ''}
        report = _APP._assign_vision_if_valid_or_restore(
            sections,
            candidate,
            original_vision='',
            domain='Data Management',
            selected_frameworks=['grc_ndmo'],
            org_structure_is_none=False,
            generation_mode='drafting',
            lang='ar',
            synth_status=None,
            original_valid_rows=0,
            repair_label='pr-j0-test',
        )
        self.assertTrue(
            report.get('assign_allowed'),
            f'AR Data NDMO candidate should have been accepted '
            f'after normalization; errors={report.get("errors")}',
        )
        assigned = sections['vision']
        # The EN long-name must have been replaced before assignment.
        self.assertNotIn('NDMO Data Governance Framework', assigned)
        self.assertIn(
            'إطار حوكمة وإدارة البيانات الوطني NDMO', assigned)
        # NDMO compliance check now clean.
        missing = _APP._compute_missing_compliance_objective(
            sections, ['grc_ndmo'],
            domain='Data Management', lang='ar')
        self.assertNotIn('NDMO', missing)

    @_skip_if_no_app
    def test_assign_vision_does_not_normalize_for_cyber_ar(self):
        # Test 13 — Cyber/AI/DT/ERM unchanged. A Cyber AR Vision
        # candidate that contains the EN NDMO long-name must NOT be
        # silently normalized (it should be REJECTED for residue,
        # exactly as before).
        candidate = (
            '## 1. الرؤية والأهداف الاستراتيجية\n\n'
            '**الرؤية:** الالتزام بـ NDMO Data Governance Framework '
            'وECC.\n\n'
            '### الأهداف الاستراتيجية:\n\n'
            + _AR_TABLE_HDR
            + '| 1 | تحقيق الالتزام بضوابط NCA ECC | 100% | الامتثال '
            '| 12 شهراً |\n'
            + '| 2 | بناء قدرات المراقبة | 100% | الكشف | 18 شهراً |\n'
            + '| 3 | تدريب فرق الأمن | 100% | بناء الكفاءات '
            '| 12 شهراً |\n'
            + '| 4 | اعتماد أدوات الحماية | 100% | الكفاءة '
            '| 12 شهراً |\n'
            + '| 5 | تطوير سياسات الأمن | 100% | الحوكمة | 12 شهراً |\n'
            + '| 6 | قياس النضج الأمني | 100% | التحسين | 12 شهراً |\n'
        )
        sections = {'vision': ''}
        report = _APP._assign_vision_if_valid_or_restore(
            sections,
            candidate,
            original_vision='',
            domain='Cyber Security',
            selected_frameworks=['grc_nca_frameworks'],
            org_structure_is_none=False,
            generation_mode='drafting',
            lang='ar',
            synth_status=None,
            original_valid_rows=0,
            repair_label='pr-j0-test-cyber',
        )
        # The Cyber AR path must still reject the candidate as residue.
        self.assertFalse(report.get('assign_allowed'))
        self.assertTrue(
            any('NDMO Data Governance Framework' in e
                for e in report.get('errors', [])),
            f'Cyber AR candidate should be rejected as residue; '
            f'errors={report.get("errors")}',
        )

    @_skip_if_no_app
    def test_normalization_does_not_add_objective_rows(self):
        # Test 12 — no deterministic objective rows inserted by the
        # normalization helper. Row count before == row count after.
        text = _vision_with_objective(
            'تحقيق الالتزام بـ NDMO Data Governance Framework')
        rows_before = _APP.count_valid_objective_rows(text)
        out, _n = (
            _APP._normalize_data_ar_vision_framework_labels(text))
        rows_after = _APP.count_valid_objective_rows(out)
        self.assertEqual(rows_before, rows_after)


# ── Test 14 — auth/DB/export untouched ──────────────────────────────────


class AuthDBExportUntouchedTests(unittest.TestCase):
    """Test 14 — PR-J0 must not touch auth/DB/export pathways."""

    @_skip_if_no_app
    def test_normalize_final_arabic_sections_still_callable(self):
        # The post-synthesis normalizer is a sibling pathway and must
        # remain importable + callable.
        out = _APP.normalize_final_arabic_sections(
            {'vision': 'NDMO Data Management Framework'}, 'ar')
        # It should now replace the management label too (we added the
        # key in PR-J0) — verifies that the residue map extension does
        # not break the existing post-synth normalizer.
        self.assertIsInstance(out, dict)

    @_skip_if_no_app
    def test_pr_j0_helpers_have_no_export_side_effects(self):
        # The helpers are pure functions; verify by inspection that
        # they do not pull in any export / DB / auth modules.
        import inspect
        for fn in (
                _APP._framework_repair_display_label,
                _APP._normalize_data_ar_vision_framework_labels,
        ):
            src = inspect.getsource(fn)
            for bad in ('flask', 'jinja', 'reportlab', 'sqlite',
                        'sqlalchemy', 'session', 'login_required'):
                with self.subTest(fn=fn.__name__, token=bad):
                    self.assertNotIn(bad, src.lower())


if __name__ == '__main__':
    unittest.main()
