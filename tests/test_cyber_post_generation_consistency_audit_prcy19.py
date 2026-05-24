"""PR-CY19 — Cyber post-generation consistency audit tests.

Covers:

* roadmap semantic-duplicate removal,
* roadmap dependency ordering (governance before IAM/SOC/VM/DLP),
* executive summary horizon = max(vision, roadmap),
* KPI RTL column mapping repair,
* KRI auto-generation when methodology mentions KRI,
* DCC traceability validation (encryption / DLP cells),
* confidence-score weighted breakdown,
* regression: PR-CY18 specialized-objective row helpers untouched,
* regression: Data domain audit is a no-op (scope == 'cyber').

Tests load ``app.py`` directly via ``importlib`` (mirroring existing
``test_cyber_*`` tests in this repo). No network / DB / OpenAI access
is required.
"""
import functools
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_consistency_audit_prcy19_')
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


def _roadmap_with_duplicates_and_bad_order():
    # Note: row 8 and row 10 are the same initiative + owner + timeframe
    # + output (the production bug reported in the problem statement).
    # Also: IAM (row 1) appears before the governance/CISO row (row 7).
    return (
        '## 5. خارطة الطريق التنفيذية\n\n'
        '| # | المبادرة | المسؤول | الإطار الزمني | المخرجات |\n'
        '|---|---|---|---|---|\n'
        '| 1 | تنفيذ إدارة الهوية والوصول IAM | إدارة تقنية المعلومات | '
        '6 أشهر | منصة IAM |\n'
        '| 2 | بناء مركز العمليات الأمنية SOC | إدارة الأمن السيبراني | '
        '12 شهراً | SOC تشغيلي |\n'
        '| 3 | إدارة الثغرات | إدارة الأمن السيبراني | 6 أشهر | '
        'منصة فحص الثغرات |\n'
        '| 4 | منع تسرب البيانات DLP | إدارة الأمن السيبراني | '
        '9 أشهر | منصة DLP |\n'
        '| 5 | إدارة مخاطر الأطراف الثالثة | إدارة المخاطر | '
        '6 أشهر | برنامج تقييم الموردين |\n'
        '| 6 | تقارير الامتثال للإدارة العليا | إدارة الحوكمة | '
        '3 أشهر | تقارير دورية |\n'
        '| 7 | إنشاء إدارة الأمن السيبراني بقيادة CISO وتعيين '
        'لجنة حوكمة الأمن السيبراني | الإدارة العليا | 3 أشهر | '
        'هيكل إداري معتمد |\n'
        '| 8 | تطبيق ضوابط تصنيف البيانات والتشفير | إدارة الأمن '
        'السيبراني | 9 أشهر | ضوابط تصنيف وتشفير |\n'
        '| 9 | تدريب الموظفين على الوعي الأمني | الموارد البشرية | '
        '4 أشهر | برنامج توعية |\n'
        '| 10 | تطبيق ضوابط تصنيف البيانات والتشفير | إدارة الأمن '
        'السيبراني | 9 أشهر | ضوابط تصنيف وتشفير |\n'
    )


def _vision_with_18_months():
    return (
        '## 1. الرؤية والأهداف الاستراتيجية\n\n'
        '**الرؤية:** قيادة الأمن السيبراني الوطني.\n\n'
        '| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n'
        '|---|---|---|---|---|\n'
        '| 1 | تحقيق الامتثال لإطار ECC | 100% | NCA ECC | 18 شهراً |\n'
        '| 2 | تحقيق الامتثال لإطار DCC | 100% | NCA DCC | 18 شهراً |\n'
    )


def _kpis_with_rtl_defects():
    return (
        '## 6. مؤشرات الأداء الرئيسية\n\n'
        '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساب | '
        'المبرر | الإطار الزمني |\n'
        '|---|---|---|---|---|---|\n'
        '| 1 | معدل الاستجابة للحوادث | KPI | 24 ساعة | '
        'حرج للامتثال | — |\n'
        '| 2 | تغطية الترقيع الأمني | 95% | (مرقّع/إجمالي)×100 | '
        'حرج | شهري |\n'
    )


def _kpis_no_kri_table():
    # KPIs section with a regular KPI table but no KRI table.
    return (
        '## 6. مؤشرات الأداء الرئيسية\n\n'
        '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساب | '
        'المبرر | الإطار الزمني |\n'
        '|---|---|---|---|---|---|\n'
        '| 1 | تغطية الترقيع الأمني | 95% | (مرقّع/إجمالي)×100 | '
        'حرج | شهري |\n'
    )


def _confidence_section_basic():
    return (
        '## 7. درجة الثقة والتحقق\n\n'
        '**درجة الثقة:** 78%\n\n'
        'تعكس الدرجة الحالية نضج المنظمة في الأمن السيبراني.\n'
    )


def _metadata_cyber():
    return {'org_name': 'Acme', 'sector': 'Banking',
            'domain': 'Cyber Security'}


class TestPRCY19RoadmapDedupAndOrder(unittest.TestCase):

    @_skip_if_no_app
    def test_dedup_removes_semantic_duplicate(self):
        sections = {'roadmap': _roadmap_with_duplicates_and_bad_order()}
        diag = _APP._cyber_post_generation_consistency_audit(
            sections, 'ar', 'cyber')
        self.assertGreaterEqual(diag['roadmap_dedup'], 1,
                                'roadmap dedup must remove row 8/10 duplicate')
        # Only one occurrence remains.
        roadmap = sections['roadmap']
        n = roadmap.count('تطبيق ضوابط تصنيف البيانات والتشفير')
        self.assertEqual(n, 1,
                         'semantic-duplicate initiative must appear exactly '
                         'once after audit')

    @_skip_if_no_app
    def test_governance_row_before_dependent_rows(self):
        sections = {'roadmap': _roadmap_with_duplicates_and_bad_order()}
        _APP._cyber_post_generation_consistency_audit(
            sections, 'ar', 'cyber')
        roadmap = sections['roadmap']
        # Find indices of the governance row vs dependent rows.
        gov_pos = roadmap.find('إنشاء إدارة الأمن السيبراني')
        iam_pos = roadmap.find('IAM')
        soc_pos = roadmap.find('SOC')
        dlp_pos = roadmap.find('DLP')
        rep_pos = roadmap.find('تقارير الامتثال')
        self.assertGreater(gov_pos, 0)
        self.assertLess(gov_pos, iam_pos)
        self.assertLess(gov_pos, soc_pos)
        self.assertLess(gov_pos, dlp_pos)
        self.assertLess(gov_pos, rep_pos)


class TestPRCY19Horizon(unittest.TestCase):

    @_skip_if_no_app
    def test_horizon_picks_max_across_objectives_and_roadmap(self):
        sections = {
            'vision': _vision_with_18_months(),
            'roadmap': _roadmap_with_duplicates_and_bad_order(),
        }
        paras = _APP._build_executive_summary_block(
            sections, _metadata_cyber(), ['ECC', 'DCC'], 'ar')
        joined = '\n'.join(paras)
        # Must not display the lower roadmap-only horizon (3 / 6 / 9 / 12)
        # as the "حتى" value when the vision objectives go to 18 months.
        self.assertNotIn('حتى 7 أشهر', joined,
                         'horizon must not be hardcoded to 7 months')
        # Must reflect the 18-month objective.
        self.assertIn('18', joined,
                      'horizon must reflect the 18-month strategic objective')


class TestPRCY19KPIRtl(unittest.TestCase):

    @_skip_if_no_app
    def test_kpi_repair_does_not_leave_KPI_header_in_target(self):
        sections = {'kpis': _kpis_with_rtl_defects()}
        diag = _APP._cyber_post_generation_consistency_audit(
            sections, 'ar', 'cyber')
        self.assertGreaterEqual(diag['kpi_rtl_fix'], 1)
        kpis = sections['kpis']
        # Restrict to the original KPI table portion (the audit may have
        # appended a KRI table later — those rows are tested separately).
        kpi_portion = kpis.split('### مؤشرات المخاطر')[0]
        # Target Value cell should no longer literally be "KPI".
        # Locate row 1 line.
        row1 = [ln for ln in kpi_portion.split('\n')
                if ln.startswith('| 1 |')]
        self.assertEqual(len(row1), 1)
        cells = [c.strip() for c in row1[0].strip('|').split('|')]
        self.assertNotEqual(cells[2], 'KPI',
                            'Target Value must not be literal "KPI"')
        # Formula must not be a bare timeframe.
        formula_last_token = cells[3].split()[-1] if cells[3].split() else ''
        self.assertNotIn('ساعة', formula_last_token)


class TestPRCY19KRI(unittest.TestCase):

    @_skip_if_no_app
    def test_kri_table_added_when_absent(self):
        sections = {'kpis': _kpis_no_kri_table()}
        diag = _APP._cyber_post_generation_consistency_audit(
            sections, 'ar', 'cyber')
        self.assertTrue(diag['kri_table_added'])
        self.assertIn('مؤشر المخاطر', sections['kpis'])

    @_skip_if_no_app
    def test_kri_table_not_added_when_present(self):
        kpis = (_kpis_no_kri_table()
                + '\n\n### مؤشرات المخاطر الرئيسية (KRIs)\n\n'
                  '| # | مؤشر المخاطر | الحد |\n|---|---|---|\n'
                  '| 1 | MTTD | 60 دقيقة |\n')
        sections = {'kpis': kpis}
        diag = _APP._cyber_post_generation_consistency_audit(
            sections, 'ar', 'cyber')
        self.assertFalse(diag['kri_table_added'])


class TestPRCY19DCCTraceability(unittest.TestCase):

    @_skip_if_no_app
    def test_encryption_row_with_awareness_text_is_repaired(self):
        # An encryption row mis-targeted with awareness/phishing content.
        roadmap = (
            '## 5. خارطة الطريق التنفيذية\n\n'
            '| # | المبادرة | المسؤول | الإطار الزمني | المخرجات |\n'
            '|---|---|---|---|---|\n'
            '| 1 | تشفير البيانات عبر برامج توعية الموظفين ضد '
            'التصيد والتوعية الأمنية المستمرة | إدارة الأمن '
            'السيبراني | 9 أشهر | برنامج توعية |\n'
        )
        sections = {'roadmap': roadmap}
        diag = _APP._cyber_post_generation_consistency_audit(
            sections, 'ar', 'cyber')
        self.assertGreaterEqual(diag['dcc_traceability_fix'], 1)
        self.assertIn('التشفير', sections['roadmap'])

    @_skip_if_no_app
    def test_dlp_row_gets_leakage_phrase_if_missing(self):
        roadmap = (
            '## 5. خارطة الطريق التنفيذية\n\n'
            '| # | المبادرة | المسؤول | الإطار الزمني | المخرجات |\n'
            '|---|---|---|---|---|\n'
            '| 1 | نشر منصة DLP المركزية لمراقبة قنوات الخروج | '
            'إدارة الأمن السيبراني | 9 أشهر | منصة |\n'
        )
        sections = {'roadmap': roadmap}
        _APP._cyber_post_generation_consistency_audit(
            sections, 'ar', 'cyber')
        self.assertIn('تسرب', sections['roadmap'])


class TestPRCY19ConfidenceBreakdown(unittest.TestCase):

    @_skip_if_no_app
    def test_confidence_breakdown_appended_with_factors(self):
        sections = {
            'confidence': _confidence_section_basic(),
            'vision': _vision_with_18_months(),
            'roadmap': _roadmap_with_duplicates_and_bad_order(),
            'pillars': 'لجنة حوكمة الأمن السيبراني',
        }
        diag = _APP._cyber_post_generation_consistency_audit(
            sections, 'ar', 'cyber',
            metadata=_metadata_cyber(),
            selected_frameworks=['ECC', 'DCC'])
        self.assertTrue(diag['confidence_breakdown_added'])
        c = sections['confidence']
        for label in ('اكتمال المدخلات',
                      'تغطية الأطر المرجعية',
                      'جدوى خارطة الطريق',
                      'جاهزية الموارد',
                      'نضج الحوكمة',
                      'جاهزية حماية البيانات'):
            self.assertIn(label, c, f'missing factor: {label}')
        self.assertIn('درجة الثقة المُشتقة', c)

    @_skip_if_no_app
    def test_confidence_breakdown_idempotent(self):
        sections = {'confidence': _confidence_section_basic()}
        d1 = _APP._cyber_post_generation_consistency_audit(
            sections, 'ar', 'cyber',
            metadata=_metadata_cyber(),
            selected_frameworks=['ECC'])
        d2 = _APP._cyber_post_generation_consistency_audit(
            sections, 'ar', 'cyber',
            metadata=_metadata_cyber(),
            selected_frameworks=['ECC'])
        self.assertTrue(d1['confidence_breakdown_added'])
        self.assertFalse(d2['confidence_breakdown_added'])


class TestPRCY19DomainScope(unittest.TestCase):

    @_skip_if_no_app
    def test_data_domain_audit_is_noop(self):
        sections = {
            'roadmap': _roadmap_with_duplicates_and_bad_order(),
            'kpis': _kpis_no_kri_table(),
            'confidence': _confidence_section_basic(),
        }
        before = {k: v for k, v in sections.items()}
        diag = _APP._cyber_post_generation_consistency_audit(
            sections, 'ar', 'data')
        self.assertEqual(diag, {}, 'audit must be a no-op for non-cyber')
        for k in before:
            self.assertEqual(sections[k], before[k])


class TestPRCY19PRCY18Untouched(unittest.TestCase):

    @_skip_if_no_app
    def test_prcy18_row_helpers_still_present(self):
        # Sanity check — the PR-CY18 specialized-objective row preservation
        # helpers must still be importable and callable; PR-CY19 must not
        # have replaced or shadowed them.
        for name in ('_extract_cyber_vision_objective_topup_row',
                     '_splice_cyber_vision_objective_topup_row',
                     '_convergence_cyber_specialized_objective_topup_repair'):
            self.assertTrue(hasattr(_APP, name),
                            f'PR-CY18 helper {name} missing — regression!')


# ════════════════════════════════════════════════════════════════════════
# Regression tests required by the revised PR-CY19 specification.
# ════════════════════════════════════════════════════════════════════════


class TestPRCY19KRIDerivedContent(unittest.TestCase):
    """KRI rows must be DERIVED from observable inputs — there are no
    fixed deterministic rows. Changing the inputs must change the
    emitted KRI rows."""

    @_skip_if_no_app
    def test_kri_no_rows_when_no_signals(self):
        # KPIs section is present (so the table COULD be appended) but
        # there are no risks / gaps / frameworks / DLP / encryption /
        # IAM / incident-response / awareness signals anywhere — so no
        # KRI table must be appended (no fixed deterministic fallback).
        sections = {
            'kpis': (
                '## 6. KPIs\n\n'
                '| # | KPI Description | Target Value | Formula | '
                'Rationale | Timeframe |\n'
                '|---|---|---|---|---|---|\n'
                '| 1 | Quarterly board review attendance | ≥ 90% | '
                '(attended/scheduled)×100 | Oversight | Quarterly |\n'
            ),
        }
        diag = _APP._cyber_post_generation_consistency_audit(
            sections, 'en', 'cyber')
        self.assertFalse(diag['kri_table_added'],
                         'no KRI rows must be emitted when no risk / '
                         'gap / framework / data-protection signal is '
                         'present')
        self.assertNotIn('MTTD', sections['kpis'])
        self.assertNotIn('Patching SLA', sections['kpis'])
        self.assertNotIn('DLP incidents', sections['kpis'])

    @_skip_if_no_app
    def test_kri_changes_when_input_risks_and_gaps_change(self):
        # A minimal KPI table that contains no KRI-triggering vocabulary
        # (board attendance only). Shared between both scenarios so the
        # ONLY differing signal is what we inject in gaps / roadmap.
        kpi_table = (
            '## 6. KPIs\n\n'
            '| # | KPI Description | Target Value | Formula | '
            'Rationale | Timeframe |\n'
            '|---|---|---|---|---|---|\n'
            '| 1 | Board oversight cadence | ≥ 90% | '
            '(attended/scheduled)×100 | Oversight | Quarterly |\n'
        )
        # Scenario A: incident-response + patching risks only.
        sections_a = {
            'kpis': kpi_table,
            'gaps': 'Incident response is immature; SOC has no SIEM. '
                    'Vulnerability patching is delayed.',
            'roadmap': 'Build SOC; deploy vulnerability management.',
        }
        diag_a = _APP._cyber_post_generation_consistency_audit(
            sections_a, 'en', 'cyber')
        self.assertTrue(diag_a['kri_table_added'])
        kri_a = sections_a['kpis']
        self.assertIn('MTTD', kri_a)
        self.assertIn('MTTR', kri_a)
        self.assertIn('Patching SLA', kri_a)
        # No DLP / IAM signal → those rows must NOT appear.
        self.assertNotIn('DLP incidents', kri_a)
        self.assertNotIn('Anomalous failed login', kri_a)
        self.assertNotIn('Encryption coverage', kri_a)
        self.assertNotIn('Third-party risk score', kri_a)

        # Scenario B: DLP + encryption + third-party risks only — the
        # derived KRI table must be materially different from A.
        sections_b = {
            'kpis': kpi_table,
            'gaps': 'Data classification controls are missing; '
                    'encryption coverage on sensitive data is partial.',
            'roadmap': 'Deploy DLP; enforce encryption at rest; vendor '
                       'risk programme for third-party suppliers.',
        }
        diag_b = _APP._cyber_post_generation_consistency_audit(
            sections_b, 'en', 'cyber')
        self.assertTrue(diag_b['kri_table_added'])
        kri_b = sections_b['kpis']
        self.assertIn('DLP incidents', kri_b)
        self.assertIn('Encryption coverage', kri_b)
        self.assertIn('Third-party risk score', kri_b)
        # No SOC/SIEM/incident or patching signal → those must NOT appear.
        self.assertNotIn('MTTD', kri_b)
        self.assertNotIn('MTTR', kri_b)
        self.assertNotIn('Patching SLA', kri_b)
        # Content MUST differ between the two scenarios.
        self.assertNotEqual(kri_a, kri_b,
                            'derived KRI rows must change when input '
                            'risks/gaps change')

    @_skip_if_no_app
    def test_kri_derived_from_selected_frameworks(self):
        # No textual signals other than the KPI header — but DCC is a
        # selected framework that mandates data-classification and DLP
        # KRIs. The derived KRIs must reflect that obligation.
        sections = {
            'kpis': (
                '## 6. KPIs\n\n'
                '| # | KPI Description | Target Value | Formula | '
                'Rationale | Timeframe |\n'
                '|---|---|---|---|---|---|\n'
                '| 1 | Quarterly board review | ≥ 90% | '
                '(attended/scheduled)×100 | Oversight | Quarterly |\n'
            ),
        }
        diag = _APP._cyber_post_generation_consistency_audit(
            sections, 'en', 'cyber',
            selected_frameworks=['DCC'])
        self.assertTrue(diag['kri_table_added'])
        self.assertIn('DLP incidents', sections['kpis'])
        self.assertIn('Assets classified', sections['kpis'])

    @_skip_if_no_app
    def test_kri_table_not_duplicated_on_repeated_runs(self):
        sections = {
            'kpis': _kpis_no_kri_table(),
            'gaps': 'Incident response is immature.',
        }
        d1 = _APP._cyber_post_generation_consistency_audit(
            sections, 'ar', 'cyber')
        kpis_after_first = sections['kpis']
        d2 = _APP._cyber_post_generation_consistency_audit(
            sections, 'ar', 'cyber')
        self.assertTrue(d1['kri_table_added'])
        self.assertFalse(d2['kri_table_added'],
                         'KRI table must not be appended again on a '
                         'second audit run')
        self.assertEqual(sections['kpis'], kpis_after_first,
                         'second audit run must leave kpis unchanged')
        # The KRI header should appear exactly once.
        self.assertEqual(sections['kpis'].count('مؤشرات المخاطر الرئيسية'),
                         1, 'KRI heading must appear exactly once')


class TestPRCY19KPIFormulaPreservation(unittest.TestCase):
    """KPI repair must preserve existing recoverable formulas and never
    invent a generic ``Measured per approved methodology`` placeholder."""

    @_skip_if_no_app
    def test_ratio_formula_preserved(self):
        sections = {
            'kpis': (
                '## 6. مؤشرات الأداء الرئيسية\n\n'
                '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساب | '
                'المبرر | الإطار الزمني |\n'
                '|---|---|---|---|---|---|\n'
                '| 1 | تغطية الترقيع الأمني | 95% | '
                '(مرقّع/إجمالي)×100 | حرج | شهري |\n'
            ),
        }
        _APP._cyber_post_generation_consistency_audit(
            sections, 'ar', 'cyber')
        # The ratio formula must still be present, untouched.
        self.assertIn('(مرقّع/إجمالي)×100', sections['kpis'])
        # And it must NOT have been replaced by a generic placeholder.
        self.assertNotIn('يُحتسب وفق المنهجية المعتمدة', sections['kpis'])
        self.assertNotIn('Measured per approved methodology',
                         sections['kpis'])

    @_skip_if_no_app
    def test_average_time_formula_preserved(self):
        sections = {
            'kpis': (
                '## 6. KPIs\n\n'
                '| # | KPI Description | Target Value | Formula | '
                'Rationale | Timeframe |\n'
                '|---|---|---|---|---|---|\n'
                '| 1 | Incident response time | ≤ 4 hours | '
                'Average time from detection to containment | '
                'Critical | Monthly |\n'
            ),
        }
        _APP._cyber_post_generation_consistency_audit(
            sections, 'en', 'cyber')
        self.assertIn('Average time from detection to containment',
                      sections['kpis'])
        self.assertNotIn('Measured per approved methodology',
                         sections['kpis'])
        self.assertNotIn('Elapsed time from event trigger to completion',
                         sections['kpis'])

    @_skip_if_no_app
    def test_count_formula_preserved(self):
        sections = {
            'kpis': (
                '## 6. KPIs\n\n'
                '| # | KPI Description | Target Value | Formula | '
                'Rationale | Timeframe |\n'
                '|---|---|---|---|---|---|\n'
                '| 1 | Critical incidents per quarter | 0 | '
                'Count of incidents classified as critical | '
                'Resilience | Quarterly |\n'
            ),
        }
        _APP._cyber_post_generation_consistency_audit(
            sections, 'en', 'cyber')
        self.assertIn('Count of incidents classified as critical',
                      sections['kpis'])

    @_skip_if_no_app
    def test_formula_reconstructed_from_neighbour_when_leaked(self):
        # Formula leaked into the Target Value cell; formula cell is
        # empty / dash. Repair must move it back, not invent a generic
        # placeholder.
        sections = {
            'kpis': (
                '## 6. KPIs\n\n'
                '| # | KPI Description | Target Value | Formula | '
                'Rationale | Timeframe |\n'
                '|---|---|---|---|---|---|\n'
                '| 1 | Patching coverage | (patched/total)×100 | — | '
                'Critical | Monthly |\n'
            ),
        }
        diag = _APP._cyber_post_generation_consistency_audit(
            sections, 'en', 'cyber')
        self.assertGreaterEqual(diag['kpi_rtl_fix'], 1)
        # The formula must now live in the Formula column, not in Target.
        row1 = [ln for ln in sections['kpis'].split('\n')
                if ln.startswith('| 1 |')][0]
        cells = [c.strip() for c in row1.strip('|').split('|')]
        self.assertEqual(cells[3], '(patched/total)×100',
                         'leaked formula must be moved back to the '
                         'Formula column')
        # No generic invented wording.
        self.assertNotIn('Measured per approved methodology',
                         sections['kpis'])

    @_skip_if_no_app
    def test_unrecoverable_formula_marked_for_ai_repair_not_invented(self):
        # No recoverable formula anywhere in the row; formula cell holds
        # a bare timeframe. PR-CY19 (revised) must mark the row for AI
        # repair, NOT invent a generic measurement string.
        sections = {
            'kpis': (
                '## 6. KPIs\n\n'
                '| # | KPI Description | Target Value | Formula | '
                'Rationale | Timeframe |\n'
                '|---|---|---|---|---|---|\n'
                '| 1 | Incident response | 24 hours | 24 hours | '
                'Critical | — |\n'
            ),
        }
        diag = _APP._cyber_post_generation_consistency_audit(
            sections, 'en', 'cyber')
        self.assertGreaterEqual(diag['kpi_rtl_fix'], 1)
        self.assertNotIn('Measured per approved methodology',
                         sections['kpis'])
        self.assertNotIn('Elapsed time from event trigger to completion',
                         sections['kpis'])
        self.assertIn('REQUIRES_AI_FORMULA_REPAIR', sections['kpis'])


class TestPRCY19RoadmapDistinctRowsPreserved(unittest.TestCase):
    """Roadmap dedup must remove duplicates only, never collapse two
    distinct initiatives into one."""

    @_skip_if_no_app
    def test_distinct_rows_preserved_after_dedup(self):
        sections = {'roadmap': _roadmap_with_duplicates_and_bad_order()}
        _APP._cyber_post_generation_consistency_audit(
            sections, 'ar', 'cyber')
        roadmap = sections['roadmap']
        # Every distinct initiative from the original (apart from the
        # duplicate of row 10) must still be present exactly once.
        distinct_initiatives = [
            'تنفيذ إدارة الهوية والوصول IAM',
            'بناء مركز العمليات الأمنية SOC',
            'إدارة الثغرات',
            'منع تسرب البيانات DLP',
            'إدارة مخاطر الأطراف الثالثة',
            'تقارير الامتثال للإدارة العليا',
            'إنشاء إدارة الأمن السيبراني',
            'تطبيق ضوابط تصنيف البيانات والتشفير',
            'تدريب الموظفين على الوعي الأمني',
        ]
        for init in distinct_initiatives:
            self.assertGreaterEqual(
                roadmap.count(init), 1,
                f'distinct initiative was dropped: {init!r}')
        # The semantic-duplicate phrase must appear exactly once.
        self.assertEqual(
            roadmap.count('تطبيق ضوابط تصنيف البيانات والتشفير'), 1)


if __name__ == '__main__':
    unittest.main()
