"""PR-CY21 — Cyber strategy final-document defect fixes.

Covers the remaining defects observed after PR-CY18/19/20:

* (A) Executive-summary horizon parser now picks the max upper bound
      from phased-roadmap month ranges such as ``31-36``.
* (B) Orphan flat-roadmap tables/rows appended after a phased roadmap
      maturity table are stripped; cross-table semantic dedup removes
      repeated DLP/classification rows.
* (C) KPI rendered-table model is repaired: literal type tokens
      (``KPI`` / ``KRI``) are stripped from value columns, and the
      "المبرر" header is renamed to "مصدر البيانات/الأداة" when its
      cells are populated with source/tool values.
* (D) KRI table is rendered in the kpis section (real table, not just
      glossary/methodology mentions).
* (E) Confidence-score weighted breakdown block is appended once and
      remains idempotent on repeated audit runs.
* (F) DCC traceability rejects rows whose linked cell is only a month
      range such as ``10-12``.
"""
import functools
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_final_doc_audit_prcy21_')
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


def _metadata_cyber():
    return {'org_name': 'Acme', 'sector': 'Banking',
            'domain': 'Cyber Security'}


def _phased_roadmap_with_36_months():
    """Phased roadmap whose ``الشهر`` column contains ranges 1-2, 3-6,
    7-12, 13-18, 19-24, 25-30, 31-36 — phase-3 extends to 36 months."""
    return (
        '## 5. خارطة الطريق التنفيذية\n\n'
        '### المرحلة 1 — التأسيس\n\n'
        '| # | النشاط | المسؤول | الشهر | المخرجات |\n'
        '|---|---|---|---|---|\n'
        '| 1 | إنشاء إدارة الأمن السيبراني بقيادة CISO | الإدارة العليا | '
        '1-2 | هيكل معتمد |\n'
        '| 2 | تطبيق ضوابط تصنيف البيانات والتشفير | إدارة الأمن السيبراني | '
        '7-9 | ضوابط مطبقة |\n'
        '| 3 | نشر منع تسرب البيانات DLP | إدارة الأمن السيبراني | '
        '10-12 | منصة DLP |\n'
        '| 4 | بناء مركز العمليات الأمنية SOC | إدارة الأمن السيبراني | '
        '13-18 | SOC تشغيلي |\n'
        '| 5 | المراجعة والتحسين المستمر للضوابط | إدارة الأمن السيبراني | '
        '31-36 | تقرير النضج |\n'
    )


def _flat_orphan_roadmap_rows():
    """Flat-roadmap orphan rows that the AI sometimes appends after the
    phased table, repeating DLP / classification initiatives."""
    return (
        '\n\n### مؤشرات النضج\n\n'
        '| # | المبادرة | المسؤول | الإطار الزمني | المخرجات |\n'
        '|---|---|---|---|---|\n'
        '| 1 | تطبيق ضوابط تصنيف البيانات والتشفير | إدارة الأمن '
        'السيبراني | 9 أشهر | ضوابط تصنيف وتشفير |\n'
        '| 2 | نشر منع تسرب البيانات DLP | إدارة الأمن السيبراني | '
        '9 أشهر | منصة DLP |\n'
        '| 3 | تطبيق ضوابط تصنيف البيانات والتشفير | إدارة الأمن '
        'السيبراني | 9 أشهر | ضوابط تصنيف وتشفير |\n'
    )


def _kpis_with_type_tokens_and_misnamed_header():
    """KPI table whose column-4 header is "المبرر" but the cells are
    populated with source/tool values (SIEM, IAM, إدارة الأمن
    السيبراني). Also contains rogue ``KPI`` / ``KRI`` tokens in
    value cells — the production defect that shifted columns."""
    return (
        '## 6. مؤشرات الأداء الرئيسية\n\n'
        '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساب | '
        'المبرر | الإطار الزمني |\n'
        '|---|---|---|---|---|---|\n'
        '| 1 | تغطية الترقيع الأمني | 95% | (مرقّع/إجمالي)×100 | '
        'إدارة الثغرات | شهري |\n'
        '| 2 | معدل اكتشاف الحوادث | KPI | (محتشف/إجمالي)×100 | '
        'SIEM/SOC | شهري |\n'
        '| 3 | نسبة الموظفين المُجتازين | 90% | (مجتاز/إجمالي)×100 | '
        'منصة التوعية | ربع سنوي |\n'
        '| 4 | نسبة تغطية MFA | 100% | (مستخدم MFA/إجمالي)×100 | '
        'IAM/PAM | شهري |\n'
    )


# ──────────────────────────────────────────────────────────────────────
# (A) Horizon parser
# ──────────────────────────────────────────────────────────────────────


class TestPRCY21Horizon(unittest.TestCase):

    @_skip_if_no_app
    def test_horizon_picks_max_upper_bound_from_phased_ranges(self):
        sections = {
            'roadmap': _phased_roadmap_with_36_months(),
            # Vision says 18 months (legacy short-horizon statement).
            'vision': (
                '## 1. الرؤية\n\n'
                '| # | الهدف | المقياس | المبرر | الإطار الزمني |\n'
                '|---|---|---|---|---|\n'
                '| 1 | الامتثال لإطار ECC | 100% | NCA | 18 شهراً |\n'
            ),
        }
        paras = _APP._build_executive_summary_block(
            sections, _metadata_cyber(), ['ECC', 'DCC'], 'ar')
        joined = '\n'.join(paras)
        # Horizon must reflect the 36-month phase-3 activity, not 18.
        self.assertIn('36', joined,
                      'horizon must include 36 from phased roadmap')

    @_skip_if_no_app
    def test_horizon_ignores_prose_ranges_outside_roadmap(self):
        # A vision that contains ``10-12 employees`` must not be
        # misread as a 12-month horizon. Roadmap has 18 months only.
        sections = {
            'vision': '## 1.\nWe have 10-12 employees overall.\n',
            'roadmap': (
                '## 5.\n'
                '| # | المبادرة | المسؤول | الإطار الزمني | المخرجات |\n'
                '|---|---|---|---|---|\n'
                '| 1 | x | y | 18 شهراً | z |\n'
            ),
        }
        paras = _APP._build_executive_summary_block(
            sections, _metadata_cyber(), ['ECC'], 'ar')
        joined = '\n'.join(paras)
        self.assertIn('18', joined)


# ──────────────────────────────────────────────────────────────────────
# (B) Roadmap orphan-flat-row sanitizer
# ──────────────────────────────────────────────────────────────────────


class TestPRCY21RoadmapOrphanStrip(unittest.TestCase):

    @_skip_if_no_app
    def test_orphan_flat_table_after_phased_is_dropped(self):
        sections = {
            'roadmap': (_phased_roadmap_with_36_months()
                        + _flat_orphan_roadmap_rows()),
        }
        diag = _APP._cyber_post_generation_consistency_audit(
            sections, 'ar', 'cyber')
        self.assertGreaterEqual(
            diag.get('roadmap_orphan_flat_dropped', 0), 1,
            'orphan flat-roadmap rows must be removed')
        # The phased table is preserved; classification appears once,
        # DLP appears once.
        roadmap = sections['roadmap']
        n_class = roadmap.count('تطبيق ضوابط تصنيف البيانات والتشفير')
        n_dlp = roadmap.count('نشر منع تسرب البيانات DLP')
        self.assertEqual(n_class, 1,
                         'classification row must appear exactly once')
        self.assertEqual(n_dlp, 1,
                         'DLP row must appear exactly once')

    @_skip_if_no_app
    def test_cross_table_dedup_removes_repeated_initiatives(self):
        # Two roadmap blocks, neither tagged as phased; the second
        # repeats DLP/classification verbatim. Cross-table dedup must
        # collapse the duplicates after composition.
        sections = {
            'roadmap': (
                '## 5.\n'
                '| # | المبادرة | المسؤول | الإطار الزمني | المخرجات |\n'
                '|---|---|---|---|---|\n'
                '| 1 | تطبيق ضوابط تصنيف البيانات والتشفير | x | 9 أشهر | y |\n'
                '| 2 | نشر منع تسرب البيانات DLP | x | 9 أشهر | y |\n'
                '\n'
                '### تكميلي\n'
                '| # | المبادرة | المسؤول | الإطار الزمني | المخرجات |\n'
                '|---|---|---|---|---|\n'
                '| 1 | تطبيق ضوابط تصنيف البيانات والتشفير | x | 9 أشهر | y |\n'
                '| 2 | نشر منع تسرب البيانات DLP | x | 9 أشهر | y |\n'
            ),
        }
        diag = _APP._cyber_post_generation_consistency_audit(
            sections, 'ar', 'cyber')
        self.assertGreaterEqual(
            diag.get('roadmap_cross_table_dedup', 0), 2)
        self.assertEqual(
            sections['roadmap'].count(
                'تطبيق ضوابط تصنيف البيانات والتشفير'), 1)
        self.assertEqual(
            sections['roadmap'].count('نشر منع تسرب البيانات DLP'), 1)


# ──────────────────────────────────────────────────────────────────────
# (C) KPI table — strip type tokens + rename misused "المبرر" header
# ──────────────────────────────────────────────────────────────────────


class TestPRCY21KPIRenderedTable(unittest.TestCase):

    @_skip_if_no_app
    def test_literal_kpi_kri_tokens_are_stripped_from_value_cells(self):
        sections = {'kpis': _kpis_with_type_tokens_and_misnamed_header()}
        _APP._cyber_post_generation_consistency_audit(
            sections, 'ar', 'cyber')
        # No data row's value cells (cols 2..5) may equal the literal
        # tokens "KPI" or "KRI" after the audit.
        kpi_portion = sections['kpis'].split('### مؤشرات المخاطر')[0]
        for ln in kpi_portion.split('\n'):
            if not ln.startswith('|') or not ln.endswith('|'):
                continue
            cells = [c.strip() for c in ln.strip('|').split('|')]
            if len(cells) < 6:
                continue
            if not cells[0].isdigit():
                continue
            for col in (2, 3, 4, 5):
                self.assertNotIn(cells[col].lower(),
                                 ('kpi', 'kri', 'وصف المؤشر',
                                  'نوع المؤشر', 'type'),
                                 f'value col {col} carries a literal '
                                 f'type token in row {cells[0]}')

    @_skip_if_no_app
    def test_misnamed_justification_header_is_renamed_to_source(self):
        sections = {'kpis': _kpis_with_type_tokens_and_misnamed_header()}
        _APP._cyber_post_generation_consistency_audit(
            sections, 'ar', 'cyber')
        # Header row of the KPI table now reflects the true semantics
        # of column 4.
        kpis = sections['kpis']
        first_table_lines = [ln for ln in kpis.split('\n')
                             if ln.startswith('|') and ln.endswith('|')]
        self.assertTrue(first_table_lines)
        header = first_table_lines[0]
        self.assertIn('مصدر البيانات', header)
        self.assertNotIn('| المبرر |', header)


# ──────────────────────────────────────────────────────────────────────
# (D) KRI rendering — real table, not just glossary mentions
# ──────────────────────────────────────────────────────────────────────


class TestPRCY21KRIRendering(unittest.TestCase):

    @_skip_if_no_app
    def test_glossary_only_kri_mention_is_not_treated_as_existing_table(self):
        sections = {
            'kpis': (
                '## 6. مؤشرات الأداء الرئيسية\n\n'
                '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساب | '
                'المبرر | الإطار الزمني |\n'
                '|---|---|---|---|---|---|\n'
                '| 1 | تغطية الترقيع | 95% | (مرقّع/إجمالي)×100 | '
                'إدارة الثغرات | شهري |\n'
            ),
            # Methodology and glossary mention KRI but do NOT render
            # a real KRI table.
            'methodology': 'منهجية تشمل مؤشرات الأداء الرئيسية KPIs '
                           'ومؤشرات المخاطر KRIs.',
            'glossary': 'KRI: مؤشر المخاطر الرئيسي.',
            'gaps': 'الاستجابة للحوادث ضعيفة؛ ترقيع الثغرات متأخر.',
        }
        diag = _APP._cyber_post_generation_consistency_audit(
            sections, 'ar', 'cyber')
        self.assertTrue(diag['kri_table_added'],
                        'glossary/methodology mentions must NOT block '
                        'KRI table generation in the kpis section')
        # The rendered kpis section now contains a real KRI table.
        self.assertIn('مؤشر المخاطر', sections['kpis'])
        self.assertIn('### مؤشرات المخاطر', sections['kpis'])


# ──────────────────────────────────────────────────────────────────────
# (E) Confidence breakdown — weights sum to 100, idempotent
# ──────────────────────────────────────────────────────────────────────


class TestPRCY21ConfidenceBreakdown(unittest.TestCase):

    @_skip_if_no_app
    def test_breakdown_weights_sum_to_100(self):
        sections = {
            'confidence': '## 7.\n**درجة الثقة:** 72%\n',
            'roadmap': _phased_roadmap_with_36_months(),
        }
        _APP._cyber_post_generation_consistency_audit(
            sections, 'ar', 'cyber',
            metadata=_metadata_cyber(),
            selected_frameworks=['ECC', 'DCC'])
        import re as _re
        weights = [int(m) for m in _re.findall(
            r'\|\s*(\d{1,3})%\s*\|', sections['confidence'])]
        # Each factor row contributes one weight %; the sum must be 100.
        self.assertGreaterEqual(len(weights), 6)
        # Sum the first 6 (one per factor; trailing % values inside the
        # contribution column will not appear with the same delimiter).
        self.assertEqual(sum(weights[:6]), 100,
                         'breakdown weights must sum to exactly 100%')

    @_skip_if_no_app
    def test_breakdown_idempotent(self):
        sections = {
            'confidence': '## 7.\n**درجة الثقة:** 72%\n',
        }
        d1 = _APP._cyber_post_generation_consistency_audit(
            sections, 'ar', 'cyber',
            metadata=_metadata_cyber(),
            selected_frameworks=['ECC'])
        snapshot = sections['confidence']
        d2 = _APP._cyber_post_generation_consistency_audit(
            sections, 'ar', 'cyber',
            metadata=_metadata_cyber(),
            selected_frameworks=['ECC'])
        self.assertTrue(d1['confidence_breakdown_added'])
        self.assertFalse(d2['confidence_breakdown_added'])
        self.assertEqual(sections['confidence'], snapshot)
        # Heading must appear exactly once.
        self.assertEqual(
            sections['confidence'].count('تفصيل عوامل درجة الثقة'), 1)


# ──────────────────────────────────────────────────────────────────────
# (F) DCC traceability cleanup — reject month-range orphan cells
# ──────────────────────────────────────────────────────────────────────


class TestPRCY21DCCTraceability(unittest.TestCase):

    @_skip_if_no_app
    def test_month_range_label_is_not_used_as_traceability_cell(self):
        # The roadmap leaks a row whose first cell is ``10-12`` (the
        # phased ``الشهر`` column). _build_traceability_matrix's cell
        # picker must reject that label so the rendered DCC
        # traceability row never carries ``10-12`` as its initiative
        # text.
        sections = {
            'roadmap': (
                '## 5.\n'
                '| # | النشاط | المسؤول | الشهر | المخرجات |\n'
                '|---|---|---|---|---|\n'
                '| 1 | معالجة البيانات الحساسة وفق ضوابط الحماية '
                '(processing of classified sensitive data) | إدارة '
                'الأمن السيبراني | 10-12 | تقرير |\n'
            ),
            'gaps': '',
            'kpis': '',
            'pillars': '',
        }
        matrix = _APP._build_traceability_matrix(
            sections, ['DCC'], 'ar', domain_code='cyber')
        # The matrix is a list of rows; verify no rendered cell is the
        # bare "10-12" token.
        import re as _re_mr
        for r in matrix:
            for cell in r:
                self.assertFalse(
                    _re_mr.fullmatch(r'\d+\s*[-–]\s*\d+', str(cell or '').strip()),
                    f'traceability matrix contains a month-range '
                    f'orphan cell: {cell!r}')


if __name__ == '__main__':
    unittest.main()
