"""PR-CY23 — Cyber strategy final quality gate (executive-grade)
tests on the LAST rendered/export markdown model.

PR-CY18 specialized-objective preservation, PR-CY20 framework-
compliance preservation, and PR-CY22 final export audit are NOT
exercised here and MUST remain untouched by this PR.
"""
import functools
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_final_quality_gate_prcy23_')
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
    @functools.wraps(fn)
    def _wrapped(self, *a, **kw):
        if _APP is None:
            self.skipTest('app.py could not be imported')
        return fn(self, *a, **kw)
    return _wrapped


# ── Defect 1: Arabic word fragment split in vision ─────────────────
class ArabicFragmentRepairTests(unittest.TestCase):

    @_skip_if_no_app
    def test_irsaa_fragment_rejoined(self):
        sections = {'vision': 'تستهدف الاستراتيجية إرس\nاء برنامج للأمن السيبراني.'}
        n = _APP._prcy23_arabic_word_fragment_repair(sections, 'ar')
        self.assertGreaterEqual(n, 1)
        self.assertIn('إرساء برنامج', sections['vision'])
        self.assertNotIn('إرس\nاء', sections['vision'])

    @_skip_if_no_app
    def test_idempotent_when_already_joined(self):
        sections = {'vision': 'إرساء برنامج متكامل'}
        n = _APP._prcy23_arabic_word_fragment_repair(sections, 'ar')
        self.assertEqual(n, 0)

    @_skip_if_no_app
    def test_noop_for_english(self):
        sections = {'vision': 'Establish a programme'}
        n = _APP._prcy23_arabic_word_fragment_repair(sections, 'en')
        self.assertEqual(n, 0)


# ── Defect 2: Roadmap phase timeline validation ────────────────────
class RoadmapPhaseTimelineTests(unittest.TestCase):

    _ROADMAP = (
        '### المرحلة 1\n\n'
        '| # | المبادرة | الشهر | المالك |\n'
        '|---|---|---|---|\n'
        '| 1 | حوكمة | 1-6 | CISO |\n\n'
        '### المرحلة 2\n\n'
        '| # | المبادرة | الشهر | المالك |\n'
        '|---|---|---|---|\n'
        '| 1 | SOC | 7-18 | SOC |\n\n'
        '### المرحلة 3\n\n'
        'نص دون جدول زمني.\n'
    )

    @_skip_if_no_app
    def test_phase_without_timeline_is_dropped(self):
        sections = {'roadmap': self._ROADMAP}
        dropped = _APP._prcy23_roadmap_phase_timeline_validate(
            sections, 'ar')
        self.assertEqual(dropped, 1)
        self.assertIn('المرحلة 1', sections['roadmap'])
        self.assertIn('المرحلة 2', sections['roadmap'])
        self.assertNotIn('المرحلة 3', sections['roadmap'])

    @_skip_if_no_app
    def test_every_phase_with_timeline_is_kept(self):
        text = self._ROADMAP.replace(
            'نص دون جدول زمني.',
            '| # | المبادرة | الشهر | المالك |\n'
            '|---|---|---|---|\n'
            '| 1 | SOAR | 19-24 | SOC |',
        )
        sections = {'roadmap': text}
        dropped = _APP._prcy23_roadmap_phase_timeline_validate(
            sections, 'ar')
        self.assertEqual(dropped, 0)
        self.assertIn('المرحلة 3', sections['roadmap'])


# ── Defect 3: Orphan rows after final phase ─────────────────────────
class OrphanPostPhaseRowsTests(unittest.TestCase):

    _ROADMAP_WITH_ORPHANS = (
        '### المرحلة 1\n\n'
        '| # | المبادرة | الشهر | المالك |\n'
        '|---|---|---|---|\n'
        '| 1 | حوكمة | 1-6 | CISO |\n\n'
        '#### معايير النجاح للمرحلة 1\n- إنشاء اللجنة\n\n'
        '| # | المبادرة | المالك | الإطار الزمني | المخرجات |\n'
        '|---|---|---|---|---|\n'
        '| 1 | تصنيف البيانات | فريق | — | — |\n'
        '| 2 | لجنة حوكمة الأمن السيبراني | فريق | — | — |\n'
        '| 3 | IAM/MFA framework | فريق | — | — |\n'
    )

    @_skip_if_no_app
    def test_orphan_post_phase_rows_dropped(self):
        sections = {'roadmap': self._ROADMAP_WITH_ORPHANS}
        n = _APP._prcy23_strip_orphan_post_phase_rows(sections, 'ar')
        self.assertGreaterEqual(n, 3)
        self.assertNotIn('IAM/MFA framework', sections['roadmap'])
        self.assertNotIn('لجنة حوكمة الأمن السيبراني', sections['roadmap'])


# ── Defect 4: KPI schema enforcement ───────────────────────────────
class KpiSchemaTests(unittest.TestCase):

    @_skip_if_no_app
    def test_dash_only_target_is_marked(self):
        sections = {'kpis': (
            '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساب |'
            ' مصدر البيانات/الأداة | تواتر القياس |\n'
            '|---|---|---|---|---|---|\n'
            '| 1 | زمن الاستجابة | — | (a/b)*100 | SIEM | شهري |\n'
        )}
        diag = _APP._prcy23_kpi_schema_enforce(sections, 'ar')
        self.assertGreaterEqual(diag['dash_only_marked'], 1)
        # PR-CY38 — schema-first composer replaces the marker with a
        # typed cyber target (or a neutral fallback / dash); never a
        # ``[REQUIRES_AI_*]`` marker in user-facing markdown.
        self.assertNotIn('[REQUIRES_AI_TARGET_REPAIR]', sections['kpis'])
        self.assertNotIn('[REQUIRES_AI_', sections['kpis'])

    @_skip_if_no_app
    def test_duplicated_formula_in_target_cleared(self):
        formula = '(a/b)*100'
        sections = {'kpis': (
            '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساب |'
            ' مصدر البيانات/الأداة | تواتر القياس |\n'
            '|---|---|---|---|---|---|\n'
            f'| 1 | زمن الاستجابة | {formula} | {formula} | SIEM | شهري |\n'
        )}
        diag = _APP._prcy23_kpi_schema_enforce(sections, 'ar')
        self.assertGreaterEqual(diag['duplicated_formula_cleared'], 1)
        # Target column should no longer hold the formula verbatim.
        body = sections['kpis']
        lines = [ln for ln in body.split('\n') if ln.startswith('| 1 |')]
        self.assertTrue(lines)
        cells = [c.strip() for c in lines[0].strip('|').split('|')]
        self.assertNotEqual(cells[2], formula)

    @_skip_if_no_app
    def test_malformed_rtl_threshold_normalized(self):
        sections = {'kpis': (
            '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساب |'
            ' مصدر البيانات/الأداة | تواتر القياس |\n'
            '|---|---|---|---|---|---|\n'
            '| 1 | نسبة الترقيع خارج SLA | 5% &gt; | (x/y)*100 |'
            ' إدارة الثغرات | شهري |\n'
        )}
        diag = _APP._prcy23_kpi_schema_enforce(sections, 'ar')
        self.assertGreaterEqual(diag['rtl_threshold_normalized'], 1)
        self.assertNotIn('5% &gt;', sections['kpis'])
        self.assertNotIn('5% >', sections['kpis'])
        self.assertTrue(
            ('أكبر من 5%' in sections['kpis'])
            or ('أقل من 5%' in sections['kpis'])
        )


# ── Defect 5: KRI threshold direction ──────────────────────────────
class KriThresholdDirectionTests(unittest.TestCase):

    _KPI_WITH_KRI = (
        '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساب |'
        ' مصدر البيانات/الأداة | تواتر القياس |\n'
        '|---|---|---|---|---|---|\n'
        '| 1 | x | 95% | f | SIEM | شهري |\n\n'
        '### مؤشرات المخاطر الرئيسية (KRIs)\n\n'
        '| # | مؤشر المخاطر (KRI) | الحد الأعلى المقبول |'
        ' مصدر القياس | الإطار الزمني |\n'
        '|---|---|---|---|---|\n'
        '| 1 | نسبة تغطية التشفير للبيانات الحساسة | ≤ 95% |'
        ' إدارة الأمن السيبراني | ربع سنوي |\n'
        '| 2 | نسبة الأصول المُصنّفة | ≤ 90% | حوكمة البيانات |'
        ' ربع سنوي |\n'
        '| 3 | نسبة الموظفين المُجتازين لاختبار محاكاة التصيد |'
        ' ≤ 90% | الموارد البشرية | ربع سنوي |\n'
        '| 4 | نسبة انعقاد لجنة حوكمة الأمن السيبراني | ≤ 95% |'
        ' مكتب الحوكمة | ربع سنوي |\n'
    )

    @_skip_if_no_app
    def test_coverage_thresholds_flipped_to_ge(self):
        sections = {'kpis': self._KPI_WITH_KRI}
        n = _APP._prcy23_kri_schema_enforce(sections, 'ar')
        self.assertGreaterEqual(n, 4)
        text = sections['kpis']
        # All four KRI rows now use ≥ rather than ≤.
        self.assertIn('≥ 95%', text)
        self.assertIn('≥ 90%', text)
        # And no ≤ thresholds remain on the coverage rows.
        for label in ('تغطية التشفير', 'الأصول المُصنّفة',
                      'محاكاة التصيد', 'لجنة حوكمة'):
            # Find the row and assert it does not contain ≤.
            for ln in text.split('\n'):
                if label in ln:
                    self.assertNotIn('≤', ln, f'row still ≤: {ln}')


# ── Defect 6: Confidence consistency ───────────────────────────────
class ConfidenceConsistencyTests(unittest.TestCase):

    @_skip_if_no_app
    def test_displayed_score_aligned_to_derived(self):
        sections = {'confidence': (
            '**درجة الثقة:** 72%\n\n'
            '#### تفصيل عوامل درجة الثقة\n\n'
            '| العامل | الوزن | الدرجة | المساهمة |\n'
            '|---|---|---|---|\n'
            '| اكتمال المدخلات | 15% | 90 | 13.5 |\n'
            '\n**درجة الثقة المُشتقة من العوامل:** 82%\n'
        )}
        diag = _APP._prcy23_confidence_consistency(sections, 'ar')
        self.assertTrue(diag['fixed'])
        self.assertEqual(diag['derived_score'], 82)
        # The displayed score line is rewritten to match derived.
        self.assertIn('**درجة الثقة:** 82%', sections['confidence'])
        # And the derived line is preserved.
        self.assertIn('المُشتقة من العوامل:** 82%', sections['confidence'])

    @_skip_if_no_app
    def test_noop_when_already_consistent(self):
        sections = {'confidence': (
            '**درجة الثقة:** 82%\n\n'
            '**درجة الثقة المُشتقة من العوامل:** 82%\n'
        )}
        diag = _APP._prcy23_confidence_consistency(sections, 'ar')
        self.assertFalse(diag['fixed'])


# ── Defect 7: Resource consistency ─────────────────────────────────
class ResourceConsistencyTests(unittest.TestCase):

    @_skip_if_no_app
    def test_unsupported_headcount_rewritten_ar(self):
        sections = {
            'pillars': 'يلزم تعيين 15 موظفًا متخصصًا في الأمن السيبراني.',
            'roadmap': '### المرحلة 1\n\n| # | المبادرة | الشهر |\n'
                       '|---|---|---|\n| 1 | x | 1-6 |',
        }
        n = _APP._prcy23_resource_consistency(sections, 'ar')
        self.assertGreaterEqual(n, 1)
        self.assertNotIn('15 موظفًا متخصصًا', sections['pillars'])
        self.assertIn('كادر متخصص متدرّج', sections['pillars'])

    @_skip_if_no_app
    def test_headcount_kept_when_resource_plan_present(self):
        sections = {
            'pillars': 'يلزم تعيين 15 موظفًا متخصصًا.',
            'roadmap': ('### المرحلة 1\n\nخطة الكادر:\n| # | عدد الموظفين |\n'
                        '|---|---|\n| 1 | 15 |'),
        }
        n = _APP._prcy23_resource_consistency(sections, 'ar')
        self.assertEqual(n, 0)
        self.assertIn('15 موظفًا متخصصًا', sections['pillars'])


# ── Defect 8: DCC capability-specific mapping ──────────────────────
class DccCapabilityMappingTests(unittest.TestCase):

    @_skip_if_no_app
    def test_classification_row_gets_classification_phrase(self):
        sections = {'traceability': (
            '| # | القدرة | الوصف |\n'
            '|---|---|---|\n'
            '| 1 | تصنيف البيانات | منع تسرب البيانات |\n'
        )}
        n = _APP._prcy23_dcc_capability_mapping(sections, 'ar')
        self.assertGreaterEqual(n, 1)
        # Row should now include classification-specific wording.
        self.assertIn('سياسة تصنيف البيانات', sections['traceability'])


# ── Final assertions surfaced in diagnostic ────────────────────────
class FinalAssertionsTests(unittest.TestCase):

    @_skip_if_no_app
    def test_assertions_detect_arabic_split(self):
        sections = {'vision': 'إرس\nاء برنامج'}
        issues = _APP._prcy23_final_assertions(sections, 'ar')
        self.assertTrue(any('arabic_word_fragment_split' in s
                            for s in issues))

    @_skip_if_no_app
    def test_assertions_detect_phase_without_timeline(self):
        sections = {'roadmap': '### المرحلة 3\n\nنص بدون جدول.\n'}
        issues = _APP._prcy23_final_assertions(sections, 'ar')
        self.assertTrue(any('roadmap_phase_missing_timeline' in s
                            for s in issues))

    @_skip_if_no_app
    def test_assertions_detect_kpi_dash_target(self):
        sections = {'kpis': (
            '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساب |'
            ' مصدر البيانات/الأداة | تواتر القياس |\n'
            '|---|---|---|---|---|---|\n'
            '| 1 | x | — | f | SIEM | شهري |\n'
        )}
        issues = _APP._prcy23_final_assertions(sections, 'ar')
        self.assertIn('kpi_target_dash_only', issues)


# ── End-to-end: quality gate wires into the final export audit ─────
class QualityGateIntegrationTests(unittest.TestCase):

    _CONTENT_AR = (
        '## 1. الرؤية الاستراتيجية\n\n'
        'تستهدف الاستراتيجية إرس\nاء برنامج للأمن السيبراني خلال 24 شهرًا.\n\n'
        '## 5. خارطة الطريق\n\n'
        '### المرحلة 1\n\n'
        '| # | المبادرة | الشهر | المالك |\n'
        '|---|---|---|---|\n'
        '| 1 | حوكمة | 1-6 | CISO |\n\n'
        '### المرحلة 3\n\n'
        'نص بلا جدول.\n\n'
        '## 6. مؤشرات الأداء الرئيسية\n\n'
        '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساب |'
        ' مصدر البيانات/الأداة | تواتر القياس |\n'
        '|---|---|---|---|---|---|\n'
        '| 1 | تغطية الترقيع | 5% &gt; | (x/y)*100 | إدارة الثغرات | شهري |\n\n'
        '### مؤشرات المخاطر الرئيسية (KRIs)\n\n'
        '| # | مؤشر المخاطر (KRI) | الحد الأعلى المقبول |'
        ' مصدر القياس | الإطار الزمني |\n'
        '|---|---|---|---|---|\n'
        '| 1 | نسبة تغطية التشفير للبيانات الحساسة | ≤ 95% |'
        ' إدارة الأمن السيبراني | ربع سنوي |\n\n'
        '## 7. تقييم الثقة\n\n'
        '**درجة الثقة:** 72%\n\n'
        '**درجة الثقة المُشتقة من العوامل:** 82%\n'
    )

    @_skip_if_no_app
    def test_quality_gate_runs_in_final_export_audit(self):
        new_content, sections, diag = _APP._cyber_final_export_audit(
            self._CONTENT_AR,
            metadata={'domain': 'cyber'},
            selected_frameworks=['ECC', 'DCC'],
            lang='ar',
            domain='cyber',
        )
        self.assertIn('prcy23', diag)
        prcy23 = diag['prcy23']
        # 1. Arabic fragment repair fired.
        self.assertGreaterEqual(
            int(prcy23.get('arabic_word_fragment_repair', 0) or 0), 1)
        self.assertNotIn('إرس\nاء', new_content)
        # 2. Phase 3 without timeline dropped.
        self.assertGreaterEqual(
            int(prcy23.get('roadmap_phase_timeline_dropped', 0) or 0), 1)
        self.assertNotIn('المرحلة 3', new_content)
        # 4. KPI RTL threshold normalised.
        self.assertNotIn('5% &gt;', new_content)
        self.assertNotIn('5% >', new_content)
        # 5. KRI threshold direction flipped to ≥.
        self.assertIn('≥ 95%', new_content)
        # 6. Confidence displayed score aligned to derived (82).
        self.assertIn('**درجة الثقة:** 82%', new_content)

    @_skip_if_no_app
    def test_quality_gate_idempotent(self):
        first, _, _ = _APP._cyber_final_export_audit(
            self._CONTENT_AR,
            metadata={'domain': 'cyber'},
            selected_frameworks=['ECC'],
            lang='ar',
            domain='cyber',
        )
        second, _, diag2 = _APP._cyber_final_export_audit(
            first,
            metadata={'domain': 'cyber'},
            selected_frameworks=['ECC'],
            lang='ar',
            domain='cyber',
        )
        prcy23_2 = diag2.get('prcy23', {})
        self.assertEqual(
            int(prcy23_2.get('arabic_word_fragment_repair', 0) or 0), 0)
        self.assertEqual(
            int(prcy23_2.get('roadmap_phase_timeline_dropped', 0) or 0), 0)
        self.assertEqual(prcy23_2.get('confidence_consistency', {})
                         .get('displayed_rewrites', 0), 0)

    @_skip_if_no_app
    def test_quality_gate_noop_for_non_cyber(self):
        new_content, sections, diag = _APP._cyber_final_export_audit(
            self._CONTENT_AR,
            metadata={'domain': 'data'},
            selected_frameworks=['ECC'],
            lang='ar',
            domain='data',
        )
        # Non-cyber path returns content untouched and empty diag.
        self.assertEqual(new_content, self._CONTENT_AR)
        self.assertEqual(diag, {})

    @_skip_if_no_app
    def test_content_splice_carries_quality_gate_output(self):
        new_content, sections, diag = _APP._cyber_final_export_audit(
            self._CONTENT_AR,
            metadata={'domain': 'cyber'},
            selected_frameworks=['ECC'],
            lang='ar',
            domain='cyber',
        )
        # The audited sections must be present verbatim in the
        # spliced content (PDF/DOCX/Preview share this same content).
        for key in ('vision', 'roadmap', 'kpis', 'confidence'):
            body = (sections.get(key) or '').strip()
            if body:
                self.assertIn(body, new_content)


if __name__ == '__main__':
    unittest.main()
