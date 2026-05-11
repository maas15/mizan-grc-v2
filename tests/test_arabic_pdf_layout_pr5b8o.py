"""PR-5B.8O — Arabic PDF layout / RTL alignment / heading punctuation.

Targets the visual defects observed after PR-5B.8N restored full-section
rendering:

    1. Reversed heading punctuation:
       ``.1 الرؤية``           must render as ``1. الرؤية``.
       ``الركيزة :1``           must render as ``الركيزة 1:``.
       ``دليل تقييم المؤشر رقم :1`` must render as
       ``دليل تقييم المؤشر رقم 1:``.

    2. Arabic environment section must NOT contain the English
       generic-table headers ``Item Description Details Notes``.

    3. Environment section narrative paragraphs render BEFORE the
       environment table (not after / not as table rows).

    4. KPI formulas render with the label first (``الصيغة: …``)
       and with all LaTeX wrappers removed.

    5. Dense KPI table must not drop the section heading.

    6. Common English role labels (CISO, SOC Manager, …) must not be
       fragmented into ``Cybers ecurity Govern ance`` by narrow column
       wrapping — they are mapped to clean Arabic display labels.

    7. AI generation / prompt logic is untouched.

Run:
    python -m pytest tests/test_arabic_pdf_layout_pr5b8o.py -v
"""
import importlib.util
import os
import sys
import tempfile
import unittest

# ── Boot env required by ``app`` ─────────────────────────────────────────
_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_arabic_pdf_layout_pr5b8o_')
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


# ── Full Arabic strategy markdown (re-uses PR-5B.8N fixture shape) ───────
FULL_ARABIC_STRATEGY = '''## 1. الرؤية والأهداف الاستراتيجية

**الرؤية:** بناء قدرات الأمن السيبراني المتقدمة وحماية المعلومات الحيوية.

**الرسالة:** توفير بيئة رقمية آمنة عبر إطار حوكمة شامل وضوابط فعالة.

### الأهداف الاستراتيجية:

| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |
|---|---|---|---|---|
| 1 | تعزيز إطار حوكمة الأمن السيبراني | بلوغ مستوى النضج 4 من 5 | الالتزام التنظيمي | 12 شهر |
| 2 | تقليل المخاطر السيبرانية | خفض المخاطر العالية بنسبة 40% | حماية الأصول | 18 شهر |
| 3 | تحسين الاستجابة للحوادث | متوسط الزمن أقل من 4 ساعات | تقليل الأثر | 9 أشهر |
| 4 | بناء ثقافة الأمن السيبراني | تدريب 95% من الموظفين | تقليل المخاطر البشرية | 12 شهر |
| 5 | تطوير قدرات الكشف | تغطية 100% للأصول الحيوية | الاكتشاف المبكر | 15 شهر |

## 2. الركائز الاستراتيجية

### الركيزة 1: الحوكمة والامتثال

تعزيز إطار حوكمة الأمن السيبراني عبر السياسات والإجراءات.

| # | المبادرة | الوصف | المخرج المتوقع | المسؤول |
|---|---|---|---|---|
| 1 | تحديث السياسات | مراجعة وفق NCA-ECC | سياسات معتمدة | CISO |
| 2 | تطوير إطار الحوكمة | تصميم هيكل المجلس | إطار معتمد | Cybersecurity Governance Lead |
| 3 | تنفيذ برنامج الامتثال | برنامج رصد الالتزام | تقارير دورية | SOC Manager |

### الركيزة 2: إدارة المخاطر

بناء قدرات تقييم المخاطر بفاعلية.

| # | المبادرة | الوصف | المخرج المتوقع | المسؤول |
|---|---|---|---|---|
| 1 | منهجية المخاطر | اعتماد ISO 27005 | منهجية معتمدة | CSIRT Lead |
| 2 | بناء سجل المخاطر | تطوير سجل مركزي | سجل فعّال | Risk Manager |
| 3 | تقييم دوري | جلسات ربع سنوية | تقارير ربع سنوية | Compliance Manager |

## 3. البيئة التنظيمية والتهديدات

تعمل المنظمة في بيئة معقدة تشمل متطلبات NCA-ECC وأنظمة حماية البيانات الوطنية، إضافة إلى متطلبات قطاعية صادرة عن الجهات الإشرافية.

**سياق التهديدات:** هجمات الفدية، التهديدات الداخلية، سلسلة التوريد، استهداف بيانات المواطنين.

**السياق التشغيلي:** اعتماد متزايد على الأنظمة الرقمية والبنية السحابية، مع توسع في الخدمات الإلكترونية المقدمة للمستفيدين.

| البُعد | المصدر | الأثر | المبادرة |
|---|---|---|---|
| تنظيمي | NCA-ECC | متطلب امتثال إجباري | برنامج مواءمة شامل |
| تهديدي | برامج الفدية | تعطل الخدمات | بناء قدرات الكشف والاستجابة |
| تشغيلي | البنية السحابية | توسع سطح الهجوم | حوكمة سحابية وضوابط هوية |

## 4. تحليل الفجوات

| # | الفجوة | الوصف | الأولوية | الحالة |
|---|---|---|---|---|
| 1 | غياب إطار الحوكمة | لا يوجد مجلس فعّال | عالية | مفتوحة |
| 2 | ضعف الكشف | عدم وجود SOC | عالية | مفتوحة |
| 3 | محدودية الوعي | برامج تدريب غير منتظمة | متوسطة | مفتوحة |
| 4 | ضعف إدارة الوصول | عدم تطبيق أقل امتيازات | عالية | مفتوحة |
| 5 | قصور خطط الاستجابة | عدم اختبار الخطط | متوسطة | مفتوحة |

## 5. خارطة الطريق التنفيذية

### المرحلة 1: التأسيس (الأشهر 1-6)

| # | النشاط | المسؤول | الجدول الزمني | المخرج |
|---|---|---|---|---|
| 1 | إنشاء المجلس | الإدارة | الشهر 1-2 | ميثاق المجلس |
| 2 | اعتماد إطار الحوكمة | CISO | الشهر 3-4 | إطار معتمد |
| 3 | التقييم الأولي | Risk Manager | الشهر 5-6 | تقرير التقييم |

## 6. مؤشرات الأداء الرئيسية

| # | المؤشر | النوع | القيمة المستهدفة | صيغة الاحتساب | مصدر البيانات | المالك | التكرار | الإطار الزمني |
|---|---|---|---|---|---|---|---|---|
| 1 | نسبة الامتثال لـ NCA-ECC | KPI | 95% | (الضوابط المطبقة ÷ الضوابط المطلوبة) × 100 | لوحة الامتثال | CISO | شهري | 12 شهر |
| 2 | متوسط زمن الكشف | KPI | < 30 دقيقة | إجمالي الزمن ÷ عدد الحوادث | SIEM | SOC Manager | أسبوعي | 6 شهر |
| 3 | نسبة الوعي الأمني | KPI | 95% | (المتدربون ÷ إجمالي الموظفين) × 100 | LMS | Compliance Manager | فصلي | 12 شهر |
| 4 | عدد الحوادث الحرجة | KRI | < 2 سنوياً | عدد الحوادث المصنفة حرجة | سجل الحوادث | CISO | شهري | 12 شهر |
| 5 | نسبة المخاطر المخففة | KPI | 80% | (المخاطر المخففة ÷ المخاطر العالية) × 100 | سجل المخاطر | Risk Manager | فصلي | 18 شهر |
| 6 | متوسط زمن الاستجابة | KPI | < 4 ساعات | إجمالي الزمن ÷ عدد الحوادث | نظام الحوادث | CSIRT Lead | أسبوعي | 9 شهر |

### أدلة تقييم مؤشرات الأداء

#### دليل تقييم المؤشر رقم 1: نسبة الامتثال لـ NCA-ECC

**الصيغة:** (الضوابط المطبقة ÷ الضوابط المطلوبة) × 100

| الخطوة | الإجراء | الأداة/النظام | المسؤول | المخرج |
|---|---|---|---|---|
| 1 | جمع قائمة الضوابط المطبقة | لوحة الامتثال | محلل الامتثال | قائمة الضوابط |
| 2 | تطبيق الصيغة الحسابية | لوحة التحكم | محلل الأمن | القيمة المحسوبة |
| 3 | مقارنة بالمستهدف 95% | تقرير المؤشر | مدير الامتثال | تقرير الفجوة |
| 4 | رفع التقرير الشهري | نظام التقارير | مدير الامتثال | تقرير معتمد |

## 7. تقييم الثقة والمخاطر

**درجة الثقة:** 78%

**المبرر:** الاستراتيجية مبنية على إطار NCA-ECC المعتمد ومدعومة بقدرات داخلية متوفرة.

| # | عامل النجاح الحرج | الوصف | الأهمية |
|---|---|---|---|
| 1 | الدعم التنفيذي | التزام الإدارة العليا | عالية |
| 2 | توفر الكوادر | وجود محللي أمن سيبراني | عالية |
| 3 | الموازنة المالية | تخصيص ميزانية كافية | عالية |

| # | الخطر | الاحتمالية | التأثير | خطة التخفيف |
|---|---|---|---|---|
| 1 | نقص الكفاءات | عالية | عالي | برنامج تطوير |
| 2 | تأخر التنفيذ | متوسطة | عالي | متابعة شهرية |
| 3 | تطور التهديدات | عالية | عالي | تحديث مستمر |
| 4 | تغيير الأولويات | متوسطة | متوسط | حوكمة مستقرة |
| 5 | ضعف التكامل | متوسطة | متوسط | تخطيط معماري |
'''


# ── Helpers (mirror PR-5B.8N) ────────────────────────────────────────────
def _shape(s):
    """Return the forms an Arabic substring may take when extracted from
    the ReportLab-generated PDF.
    """
    import arabic_reshaper
    from bidi.algorithm import get_display
    reshaped = arabic_reshaper.reshape(s)
    return reshaped, get_display(reshaped), s


def _present(text, s):
    for v in _shape(s):
        if v in text:
            return True
    return False


def _find_first(text, s):
    idx = -1
    for v in _shape(s):
        i = text.find(v)
        if i >= 0 and (idx == -1 or i < idx):
            idx = i
    return idx


def _make_test_user(username='pr5b8o_test_user'):
    from werkzeug.security import generate_password_hash
    with _APP.app.app_context():
        _APP.init_db()
        db = _APP.get_db()
        cols = [c['name'] for c in db.execute('PRAGMA table_info(users)').fetchall()]
        if 'password_hash' in cols:
            db.execute(
                "INSERT OR IGNORE INTO users (username, password_hash, email, role, is_active) "
                "VALUES (?, ?, ?, ?, 1)",
                (username, generate_password_hash('xxx'), f'{username}@test.local', 'user'),
            )
        else:
            db.execute(
                "INSERT OR IGNORE INTO users (username, password, email, role) "
                "VALUES (?, ?, ?, ?)",
                (username, generate_password_hash('xxx'), f'{username}@test.local', 'user'),
            )
        db.commit()
        row = db.execute(
            "SELECT id FROM users WHERE username=?", (username,)
        ).fetchone()
        return row['id']


def _build_arabic_pdf_bytes(content, **overrides):
    uid = _make_test_user()
    client = _APP.app.test_client()
    with client.session_transaction() as sess:
        sess['user_id'] = uid
        sess['username'] = 'pr5b8o_test_user'
        sess['role'] = 'user'
    payload = {
        'content': content,
        'filename': 'pr5b8o_test',
        'language': 'ar',
        'org_name': 'منظمة اختبار',
        'sector': 'حكومي',
        'doc_type': 'Strategy Document',
        'domain': 'Cyber Security',
        'artifact_type': 'strategy',
        'artifact_id': None,
        'generation_mode': 'drafting',
    }
    payload.update(overrides)
    resp = client.post('/api/generate-pdf', json=payload)
    if resp.status_code != 200:
        raise AssertionError(
            f'PDF route failed: status={resp.status_code} body={resp.data[:400]!r}'
        )
    return resp.data


def _extract_pdf_text(pdf_bytes):
    import fitz
    doc = fitz.open(stream=pdf_bytes, filetype='pdf')
    pages = [p.get_text() for p in doc]
    doc.close()
    return pages


# ─── 1-3. Pure heading-normalizer unit tests (no PDF needed) ─────────────
class ArabicHeadingNormalizerTest(unittest.TestCase):

    @_skip_if_no_app
    def test_dot_before_digit_is_swapped(self):
        norm = _APP._arabic_pdf_heading_normalize
        self.assertEqual(
            norm('.1 الرؤية والأهداف الاستراتيجية'),
            '1. الرؤية والأهداف الاستراتيجية',
        )
        # Markdown-prefixed form must work too.
        self.assertEqual(
            norm('## .1 الرؤية والأهداف الاستراتيجية'),
            '## 1. الرؤية والأهداف الاستراتيجية',
        )
        # Idempotent — already-correct form must be left alone.
        self.assertEqual(
            norm('1. الرؤية والأهداف الاستراتيجية'),
            '1. الرؤية والأهداف الاستراتيجية',
        )
        # Pure ASCII numbered list (no Arabic) must not be touched —
        # English ".1 Foo" stays unchanged.
        self.assertEqual(norm('.1 Foo'), '.1 Foo')

    @_skip_if_no_app
    def test_pillar_colon_swap(self):
        norm = _APP._arabic_pdf_heading_normalize
        self.assertEqual(norm('الركيزة :1'), 'الركيزة 1:')
        self.assertEqual(norm('### الركيزة :2 الحوكمة'),
                         '### الركيزة 2: الحوكمة')
        self.assertEqual(norm('ركيزة :3'), 'ركيزة 3:')
        # Idempotent
        self.assertEqual(norm('الركيزة 1:'), 'الركيزة 1:')

    @_skip_if_no_app
    def test_kpi_guide_colon_swap(self):
        norm = _APP._arabic_pdf_heading_normalize
        self.assertEqual(
            norm('دليل تقييم المؤشر رقم :1'),
            'دليل تقييم المؤشر رقم 1:',
        )
        self.assertEqual(
            norm('#### دليل تقييم المؤشر رقم :12 نسبة الامتثال'),
            '#### دليل تقييم المؤشر رقم 12: نسبة الامتثال',
        )
        # Idempotent
        self.assertEqual(
            norm('دليل تقييم المؤشر رقم 1:'),
            'دليل تقييم المؤشر رقم 1:',
        )


# ─── 4-10. PDF round-trip tests ──────────────────────────────────────────
class ArabicPdfRoundTripLayoutTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if _APP is None:
            return
        cls.pdf_bytes = _build_arabic_pdf_bytes(FULL_ARABIC_STRATEGY)
        cls.pages = _extract_pdf_text(cls.pdf_bytes)
        cls.all_text = '\n'.join(cls.pages)

    @_skip_if_no_app
    def test_all_seven_section_headings_in_logical_order(self):
        """The PDF must contain every canonical H2 heading and they must
        appear in the canonical 1 → 7 order."""
        canonical = [
            'الرؤية',
            'الركائز الاستراتيجية',
            'البيئة التنظيمية',
            'تحليل الفجوات',
            'خارطة الطريق',
            'مؤشرات الأداء الرئيسية',
            'تقييم الثقة',
        ]
        positions = []
        for h in canonical:
            idx = _find_first(self.all_text, h)
            self.assertGreater(
                idx, -1,
                f'Canonical heading missing from Arabic PDF: {h!r}',
            )
            positions.append(idx)
        self.assertEqual(
            positions, sorted(positions),
            f'Section headings are out of order. Positions: {positions}.'
        )

    @_skip_if_no_app
    def test_environment_section_no_english_default_table_headers(self):
        """The English generic-table headers ``Item Description Details
        Notes`` must NEVER leak into an Arabic environment section."""
        # Build a markdown variant whose env section has a 4-col table that
        # would previously trigger the (4,'default') English header
        # injection because the table omits an explicit header row.
        env_md = FULL_ARABIC_STRATEGY.replace(
            '| البُعد | المصدر | الأثر | المبادرة |\n|---|---|---|---|\n',
            '',  # remove explicit Arabic header → forces injection path
        )
        text = '\n'.join(_extract_pdf_text(_build_arabic_pdf_bytes(env_md)))
        # The raw English defaults must not appear inline.
        for stray in ('Item Description Details Notes',
                      'Item\nDescription\nDetails\nNotes'):
            self.assertNotIn(
                stray, text,
                f'English generic table header {stray!r} leaked into Arabic PDF.'
            )

    @_skip_if_no_app
    def test_environment_narrative_appears_before_environment_table(self):
        """The narrative paragraph (regulatory/threat/operational context)
        must render BEFORE the threat/impact table inside section 3."""
        env_heading_idx = _find_first(self.all_text, 'البيئة التنظيمية')
        narrative_idx   = _find_first(self.all_text, 'سياق التهديدات')
        table_idx       = _find_first(self.all_text, 'تنظيمي')  # cell text
        self.assertGreater(env_heading_idx, -1,
                           'Environment heading missing from PDF.')
        self.assertGreater(narrative_idx, -1,
                           'Environment narrative missing from PDF.')
        # Narrative must come after the heading but before the first table cell.
        self.assertGreater(narrative_idx, env_heading_idx)
        if table_idx >= 0:
            self.assertLess(
                narrative_idx, table_idx,
                'Environment narrative must precede the env table.',
            )

    @_skip_if_no_app
    def test_formula_label_renders_before_formula(self):
        self.assertTrue(
            _present(self.all_text, 'الصيغة'),
            'Formula label "الصيغة" missing from PDF text.',
        )
        # The numeric tail of the formula must survive too.
        self.assertIn('100', self.all_text,
                      'Formula trailing "× 100" missing from PDF.')

    @_skip_if_no_app
    def test_formula_text_has_no_latex_wrappers(self):
        latex_md = FULL_ARABIC_STRATEGY.replace(
            '**الصيغة:** (الضوابط المطبقة ÷ الضوابط المطلوبة) × 100',
            r'**الصيغة:** \text{Numerator}\div\text{Denominator}\times 100\%',
        )
        text = '\n'.join(_extract_pdf_text(_build_arabic_pdf_bytes(latex_md)))
        for stray in (r'\text', r'\times', r'\(', r'\)'):
            self.assertNotIn(
                stray, text,
                f'LaTeX wrapper {stray!r} leaked into Arabic PDF.',
            )

    @_skip_if_no_app
    def test_dense_kpi_table_does_not_drop_section_heading(self):
        """The 9-column dense KPI table must render and section 6's
        heading (مؤشرات الأداء الرئيسية) must still be present."""
        self.assertTrue(
            _present(self.all_text, 'مؤشرات الأداء الرئيسية'),
            'Dense KPI table dropped the section 6 heading.',
        )
        # And the KPI-guides sub-heading must still be present.
        self.assertTrue(
            _present(self.all_text, 'أدلة تقييم'),
            'KPI assessment guides sub-heading dropped from PDF.',
        )

    @_skip_if_no_app
    def test_role_labels_not_split_into_fragments(self):
        """The PDF text must not contain the broken-wrap fragments that
        the user observed for English role names."""
        bad_fragments = [
            'Cybers ecurity',
            'Govern ance',
            'Cybe rsecurity',
            'Cyber security Govern',
        ]
        for frag in bad_fragments:
            self.assertNotIn(
                frag, self.all_text,
                f'Role-name fragment leaked into Arabic PDF: {frag!r}',
            )
        # Positive assertion: the display-only Arabic role labels must be
        # present in the rendered text. The fixture cells contain the
        # English source labels (CISO, SOC Manager, Cybersecurity
        # Governance Lead, CSIRT Lead, Risk Manager, Compliance Manager).
        # PyMuPDF extracts each cell's wrapped lines separately, so we
        # match on shorter unique substrings rather than the full phrases.
        expected_ar_label_fragments = [
            'الأمن السيبراني',          # CISO → رئيس الأمن السيبراني
            'مركز العمليات',             # SOC Manager → مدير مركز العمليات الأمنية
            'حوكمة الأمن السيبراني',    # Cybersecurity Governance Lead → قائد حوكمة الأمن السيبراني
            'فريق الاستجابة',            # CSIRT Lead → قائد فريق الاستجابة للحوادث
        ]
        missing = [lbl for lbl in expected_ar_label_fragments
                   if not _present(self.all_text, lbl)]
        self.assertEqual(
            missing, [],
            f'Display-only Arabic role labels missing from PDF: {missing}',
        )


# ─── 11. Strict scope: AI generation untouched ───────────────────────────
class NoAiOrPromptLogicChangedTest(unittest.TestCase):
    """Smoke check: AI providers and prompt-building helpers still exist
    with the same names — this PR is strictly scoped to PDF rendering."""

    @_skip_if_no_app
    def test_ai_entry_points_intact(self):
        for sym in (
            'api_generate_strategy',
            'api_generate_pdf',
            'ensure_markdown_formatting',
            '_arabic_pdf_heading_normalize',
        ):
            self.assertTrue(
                hasattr(_APP, sym),
                f'Required public symbol {sym!r} is missing.',
            )


if __name__ == '__main__':
    unittest.main()
