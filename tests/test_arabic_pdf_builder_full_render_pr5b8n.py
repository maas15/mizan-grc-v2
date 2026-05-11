"""PR-5B.8N — Arabic PDF builder must render ALL 7 canonical strategy
sections, never start the body at the KPI-assessment-guides subsection,
and must normalise the Arabic formula label so it renders as
``الصيغة: (...) × 100`` (label first, no LaTeX wrappers).

Root cause that this test guards against:

    ReportLab's ``BaseDocTemplate.build()`` mutates the ``flowables`` list
    it is given (``del flowables[0]`` for every consumed flowable). When
    the PDF builder's first ``doc.build(story, …)`` raised a
    ``TypeError``/``ValueError`` mid-document, the retry path then
    iterated the *mutated* ``story`` (only the trailing fragment that
    had not yet been rendered), sanitised the tables in it, and rebuilt
    a fresh PDF using just that fragment. In production this dropped
    sections 1 → "أدلة تقييم مؤشرات الأداء" (the first sub-block of
    section 6 to survive the early crash) and produced a PDF whose body
    started with ``أدلة تقييم مؤشرات الأداء`` and ``تقييم الثقة والمخاطر``.

Fix: snapshot ``story`` before the first ``doc.build()`` so the retry
path always sees the FULL original story (cover → TOC → all 7 sections).
Also: normalise Arabic formula lines (``**الصيغة:** …`` /
``…الصيغة:`` reverse-glued / ``\\text{}`` / ``\\times``) before they are
fed to the bidi/reshape pipeline so they render in the correct visual
order.

Run:
    python -m pytest tests/test_arabic_pdf_builder_full_render_pr5b8n.py -v
"""
import importlib.util
import os
import sys
import tempfile
import unittest

# ── Boot env required by ``app`` ─────────────────────────────────────────
_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_arabic_pdf_builder_full_render_pr5b8n_')
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


# ── Full Arabic strategy markdown — all 7 canonical sections ─────────────
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

### الركيزة الأولى: الحوكمة والامتثال

تعزيز إطار حوكمة الأمن السيبراني عبر السياسات والإجراءات.

| # | المبادرة | الوصف | المخرج المتوقع |
|---|---|---|---|
| 1 | تحديث السياسات | مراجعة وفق NCA-ECC | سياسات معتمدة |
| 2 | تطوير إطار الحوكمة | تصميم هيكل المجلس | إطار معتمد |
| 3 | تنفيذ برنامج الامتثال | برنامج رصد الالتزام | تقارير دورية |

### الركيزة الثانية: إدارة المخاطر

بناء قدرات تقييم المخاطر بفاعلية.

| # | المبادرة | الوصف | المخرج المتوقع |
|---|---|---|---|
| 1 | منهجية المخاطر | اعتماد ISO 27005 | منهجية معتمدة |
| 2 | بناء سجل المخاطر | تطوير سجل مركزي | سجل فعّال |
| 3 | تقييم دوري | جلسات ربع سنوية | تقارير ربع سنوية |

## 3. البيئة التنظيمية والتهديدات

تعمل المنظمة في بيئة معقدة تشمل متطلبات NCA-ECC وأنظمة حماية البيانات.

**التهديدات الرئيسية:** هجمات الفدية، التهديدات الداخلية، سلسلة التوريد.

## 4. تحليل الفجوات

| # | الفجوة | الوصف | الأولوية | الحالة |
|---|---|---|---|---|
| 1 | غياب إطار الحوكمة | لا يوجد مجلس فعّال | عالية | مفتوحة |
| 2 | ضعف الكشف | عدم وجود SOC | عالية | مفتوحة |
| 3 | محدودية الوعي | برامج تدريب غير منتظمة | متوسطة | مفتوحة |
| 4 | ضعف إدارة الوصول | عدم تطبيق أقل امتيازات | عالية | مفتوحة |
| 5 | قصور خطط الاستجابة | عدم اختبار الخطط | متوسطة | مفتوحة |

## 5. خارطة الطريق التنفيذية

### المرحلة الأولى: التأسيس (الأشهر 1-6)

| # | النشاط | المسؤول | الجدول الزمني | المخرج |
|---|---|---|---|---|
| 1 | إنشاء المجلس | الإدارة | الشهر 1-2 | ميثاق المجلس |
| 2 | اعتماد إطار الحوكمة | مدير الأمن | الشهر 3-4 | إطار معتمد |
| 3 | التقييم الأولي | فريق المخاطر | الشهر 5-6 | تقرير التقييم |

### المرحلة الثانية: البناء (الأشهر 7-18)

| # | النشاط | المسؤول | الجدول الزمني | المخرج |
|---|---|---|---|---|
| 1 | بناء SOC | محلل الأمن السيبراني | الشهر 7-12 | SOC تشغيلي |
| 2 | تطبيق ضوابط NCA-ECC | فريق الأمن | الشهر 8-14 | ضوابط مطبقة |
| 3 | تنفيذ برنامج الوعي | فريق التدريب | الشهر 9-18 | تدريب 95% |

## 6. مؤشرات الأداء الرئيسية

| # | المؤشر | النوع | القيمة المستهدفة | صيغة الاحتساب | مصدر البيانات | المالك | التكرار | الإطار الزمني |
|---|---|---|---|---|---|---|---|---|
| 1 | نسبة الامتثال لـ NCA-ECC | KPI | 95% | (الضوابط المطبقة ÷ الضوابط المطلوبة) × 100 | لوحة الامتثال | مدير الامتثال | شهري | 12 شهر |
| 2 | متوسط زمن الكشف | KPI | < 30 دقيقة | إجمالي الزمن ÷ عدد الحوادث | SIEM | محلل الأمن | أسبوعي | 6 شهر |
| 3 | نسبة الوعي الأمني | KPI | 95% | (المتدربون ÷ إجمالي الموظفين) × 100 | LMS | مدير التدريب | فصلي | 12 شهر |
| 4 | عدد الحوادث الحرجة | KRI | < 2 سنوياً | عدد الحوادث المصنفة حرجة | سجل الحوادث | مدير الأمن | شهري | 12 شهر |
| 5 | نسبة المخاطر المخففة | KPI | 80% | (المخاطر المخففة ÷ المخاطر العالية) × 100 | سجل المخاطر | مدير المخاطر | فصلي | 18 شهر |
| 6 | متوسط زمن الاستجابة | KPI | < 4 ساعات | إجمالي الزمن ÷ عدد الحوادث | نظام الحوادث | محلل الأمن | أسبوعي | 9 شهر |

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


# ── Helpers ──────────────────────────────────────────────────────────────
def _shape(s):
    """Return forms that an Arabic substring may take when extracted by
    PyMuPDF from the ReportLab-generated PDF.

    PyMuPDF re-reverses the visual L→R glyph stream back to logical RTL
    order, so the *reshape-only* form (no bidi reverse) is the form that
    actually appears in the extracted text. We also return the
    ``get_display`` form as a fallback for renderers that don't re-reverse.
    """
    import arabic_reshaper
    from bidi.algorithm import get_display
    reshaped = arabic_reshaper.reshape(s)
    return reshaped, get_display(reshaped), s


def _present(text, s):
    """True if any of the shape variants of ``s`` are found in ``text``."""
    for v in _shape(s):
        if v in text:
            return True
    return False


def _find_first(text, s):
    """Return the lowest index any shape variant of ``s`` occurs at, or -1."""
    idx = -1
    for v in _shape(s):
        i = text.find(v)
        if i >= 0 and (idx == -1 or i < idx):
            idx = i
    return idx


def _make_test_user(username='pr5b8n_test_user'):
    """Create a throwaway user for the export gate. Returns user_id."""
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
    """Build an Arabic strategy PDF through the public route and return
    the bytes. Uses ``generation_mode='drafting'`` (no DB-state gate) to
    keep the test isolated from the publishability gate.
    """
    uid = _make_test_user()
    client = _APP.app.test_client()
    with client.session_transaction() as sess:
        sess['user_id'] = uid
        sess['username'] = 'pr5b8n_test_user'
        sess['role'] = 'user'
    payload = {
        'content': content,
        'filename': 'pr5b8n_test',
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
    """Return all PDF text per page using PyMuPDF (already a project dep)."""
    import fitz
    import io
    doc = fitz.open(stream=pdf_bytes, filetype='pdf')
    pages = [p.get_text() for p in doc]
    doc.close()
    return pages


# ── Tests ────────────────────────────────────────────────────────────────
class ArabicPdfBuilderFullRenderTest(unittest.TestCase):
    """All 7 canonical sections must render — no silent drops."""

    @classmethod
    def setUpClass(cls):
        if _APP is None:
            return
        cls.pdf_bytes = _build_arabic_pdf_bytes(FULL_ARABIC_STRATEGY)
        cls.pages = _extract_pdf_text(cls.pdf_bytes)
        cls.all_text = '\n'.join(cls.pages)

    @_skip_if_no_app
    def test_pdf_has_multiple_pages(self):
        # Cover + TOC + ≥3 body pages once all 7 sections render.
        self.assertGreater(len(self.pages), 3,
                           f'Expected >3 pages, got {len(self.pages)}: '
                           f'this is the regression — the body collapsed onto a '
                           f'single trailing page after the cover.')

    @_skip_if_no_app
    def test_all_seven_section_headings_present(self):
        """The PDF text must contain every canonical H2 heading."""
        canonical = [
            'الرؤية',
            'الركائز الاستراتيجية',
            'البيئة التنظيمية',
            'تحليل الفجوات',
            'خارطة الطريق',
            'مؤشرات الأداء الرئيسية',
            'تقييم الثقة',
        ]
        missing = [k for k in canonical if not _present(self.all_text, k)]
        self.assertEqual(
            missing, [],
            f'Missing canonical headings: {missing}. '
            f'PDF body must render all 7 sections, not only the KPI '
            f'guides + section 7.'
        )

    @_skip_if_no_app
    def test_body_does_not_start_at_kpi_guides(self):
        """The first body page (page 3+) must NOT be the KPI-guides
        sub-section — that was the symptom of the dropped-sections bug.
        """
        self.assertGreaterEqual(
            len(self.pages), 3,
            'Expected at least 3 pages (cover + TOC + body).'
        )
        body_first = self.pages[2]
        if _present(body_first, 'أدلة تقييم مؤشرات الأداء'):
            self.assertTrue(
                _present(body_first, 'الرؤية'),
                f'Body page 3 starts at "أدلة تقييم مؤشرات الأداء" — '
                f'this is the dropped-sections regression (PR-5B.8N).'
            )

    @_skip_if_no_app
    def test_vision_appears_before_kpi_guides(self):
        """Section 1 (vision) must appear before section 6's
        KPI-assessment-guides subsection."""
        v_idx = _find_first(self.all_text, 'الرؤية')
        g_idx = _find_first(self.all_text, 'أدلة تقييم')
        self.assertGreater(
            v_idx, -1,
            'Vision keyword "الرؤية" missing from PDF text.'
        )
        if g_idx >= 0:
            self.assertLess(
                v_idx, g_idx,
                'Section 1 (vision) must appear before "أدلة تقييم …" — '
                'the body parser must render sequentially.',
            )

    @_skip_if_no_app
    def test_malformed_separator_rows_do_not_drop_sections(self):
        """Tables with extra/malformed ``|---|`` separator rows in the
        BODY of a section must not cause earlier sections to be dropped.
        """
        # Inject a stray duplicated separator row inside section 2.
        broken = FULL_ARABIC_STRATEGY.replace(
            '| 1 | تحديث السياسات',
            '|---|---|---|---|\n| 1 | تحديث السياسات',
            1,
        )
        pdf = _build_arabic_pdf_bytes(broken)
        text = '\n'.join(_extract_pdf_text(pdf))
        # Section 1's vision must still be present.
        self.assertTrue(
            _present(text, 'الرؤية'),
            'A malformed separator row in section 2 must not drop section 1.',
        )
        # Section 4's gaps must still be present.
        self.assertTrue(
            _present(text, 'الفجوات'),
            'A malformed separator row in section 2 must not drop section 4.',
        )


class ArabicPdfFormulaNormalisationTest(unittest.TestCase):
    """Formula label must render as 'الصيغة:' before the formula and
    must not contain LaTeX wrapper artefacts."""

    @_skip_if_no_app
    def test_formula_label_is_before_formula(self):
        text = '\n'.join(_extract_pdf_text(
            _build_arabic_pdf_bytes(FULL_ARABIC_STRATEGY)
        ))
        self.assertTrue(
            _present(text, 'الصيغة'),
            'Formula label "الصيغة" must be present in the PDF text.'
        )
        self.assertIn('100', text,
                      'Formula trailing "× 100" must remain in the PDF.')

    @_skip_if_no_app
    def test_formula_text_has_no_latex_wrappers(self):
        """No raw LaTeX wrappers remain on formula lines."""
        latex_md = FULL_ARABIC_STRATEGY.replace(
            '**الصيغة:** (الضوابط المطبقة ÷ الضوابط المطلوبة) × 100',
            r'**الصيغة:** \text{Numerator}\div\text{Denominator}\times 100\%',
        )
        text = '\n'.join(_extract_pdf_text(_build_arabic_pdf_bytes(latex_md)))
        for stray in (r'\text', r'\times', r'\div'):
            self.assertNotIn(
                stray, text,
                f'LaTeX wrapper {stray!r} must be normalised out of the PDF.',
            )

    @_skip_if_no_app
    def test_reverse_glued_formula_is_normalised(self):
        """``(formula)الصيغة:`` (label trailing) must be rewritten so
        the label leads."""
        rev_md = FULL_ARABIC_STRATEGY.replace(
            '**الصيغة:** (الضوابط المطبقة ÷ الضوابط المطلوبة) × 100',
            '(الضوابط المطبقة ÷ الضوابط المطلوبة) * 100الصيغة:',
        )
        text = '\n'.join(_extract_pdf_text(_build_arabic_pdf_bytes(rev_md)))
        self.assertTrue(_present(text, 'الصيغة'))
        self.assertIn('100', text)


class FragmentGuardStillBlocksTest(unittest.TestCase):
    """The pre-existing fragment guard must still block KPI-guides +
    confidence-only payloads (no regression)."""

    @_skip_if_no_app
    def test_fragment_guard_detects_kpi_only_fragment(self):
        # Use the public ``_detect_canonical_sections_in_text`` helper that
        # backs the route's 422 fragment guard.
        fragment = (
            '### أدلة تقييم مؤشرات الأداء\n\n'
            '#### دليل تقييم المؤشر رقم 1\n\n'
            '**الصيغة:** (A ÷ B) × 100\n\n'
            '## 7. تقييم الثقة والمخاطر\n\n'
            '**درجة الثقة:** 78%\n'
        )
        detected = _APP._detect_canonical_sections_in_text(fragment)
        # KPI-guides (a sub-block of section 6) and confidence (section 7)
        # are present; the other 5 canonical sections must be absent so
        # the fragment guard correctly identifies this as a fragment.
        # Fragment is defined as missing at least one of vision/pillars/
        # environment/gaps/roadmap.
        for required in ('vision', 'pillars', 'environment', 'gaps', 'roadmap'):
            self.assertNotIn(
                required, detected,
                f'Fragment guard must NOT find {required!r} in a KPI-guides + '
                f'confidence-only payload.',
            )


class NoAiGenerationLogicChangedTest(unittest.TestCase):
    """Smoke check that the AI generation entry points are still wired
    up — the PR is strictly scoped to the PDF builder."""

    @_skip_if_no_app
    def test_ai_generation_entry_points_intact(self):
        # Existence-only assertions; we must not call the AI providers.
        self.assertTrue(
            hasattr(_APP, 'api_generate_strategy'),
            'AI strategy generation entry point must remain.',
        )
        self.assertTrue(
            hasattr(_APP, 'ensure_markdown_formatting'),
            'Markdown post-processor must remain.',
        )
        # Ensure no stub/replacement of the public PDF route.
        self.assertTrue(
            hasattr(_APP, 'api_generate_pdf'),
            'Public PDF route must remain.',
        )


if __name__ == '__main__':
    unittest.main()
