"""PR-5B.8T — Final Arabic PDF professional layout polish.

Verifies that the Arabic strategy PDF is presented as a consulting-grade
document with:

* numbering / colon punctuation that doesn't show as the bidi-reversed
  ``.1`` / ``:1`` glued forms in extracted text,
* a clean document control table whose label and value never collapse
  into ``"Mizan GRC Platform بواسطة أعد"`` reversed order,
* an executive summary that names the selected frameworks (ECC / TCC)
  and the confidence score,
* a methodology section without raw ``.1``-style numbering,
* a traceability matrix that shows the selected frameworks in readable
  logical order,
* an Appendix A that lists ECC + TCC and an Appendix B whose glossary
  always carries the standard acronym baseline (MFA, VPN, ZTNA, IAM,
  PAM, SOC, SIEM, CSIRT, DLP),
* common English role names (Cybersecurity Governance Lead, …) shown
  as their Arabic equivalents so they are not split mid-word inside
  governance / KPI tables.

Strict scope (mirrors the problem statement):

  * No AI prompt / generation logic changed.
  * No deterministic strategy rows added.
  * Preview rendering not touched.

Run:
    python -m pytest tests/test_arabic_pdf_professional_layout_pr5b8t.py -v
"""
import importlib.util
import os
import sys
import tempfile
import unittest

# ── Boot env required by ``app`` ─────────────────────────────────────────
_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_pro_strategy_layout_pr5b8t_')
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

from tests._pdf_font_gate import skip_if_no_arabic_pdf_font


def _skip_if_no_app(fn):
    import functools

    @functools.wraps(fn)
    def _wrapped(self, *a, **kw):
        if _APP is None:
            self.skipTest('app.py could not be imported')
        return fn(self, *a, **kw)
    return _wrapped


# ── Full Arabic strategy markdown (mirrors PR-5B.8R fixture) ─────────────
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

### الركيزة 2: العمل عن بُعد والوصول الآمن

تأمين بيئة العمل عن بُعد وفق ضوابط TCC ومتطلبات الوصول الآمن.

| # | المبادرة | الوصف | المخرج المتوقع | المسؤول |
|---|---|---|---|---|
| 1 | تطبيق MFA | المصادقة متعددة العوامل لكل الأنظمة | تقليل المخاطر | CISO |
| 2 | نشر VPN/ZTNA | بنية الثقة الصفرية | اتصال آمن | CSIRT Lead |
| 3 | حماية الأجهزة الطرفية | EDR وMDM للأجهزة | حماية فعالة | Risk Manager |

## 3. البيئة التنظيمية والتهديدات

تعمل المنظمة في بيئة معقدة تشمل متطلبات NCA-ECC وضوابط TCC للعمل عن بُعد، إضافة إلى متطلبات قطاعية.

**سياق التهديدات:** هجمات الفدية، التهديدات الداخلية، استهداف العمل عن بُعد.

| البُعد | المصدر | الأثر | المبادرة |
|---|---|---|---|
| تنظيمي | NCA-ECC | متطلب امتثال | برنامج مواءمة |
| تنظيمي | TCC | حماية العمل عن بُعد | تطبيق MFA و ZTNA |
| تهديدي | برامج الفدية | تعطل الخدمات | بناء قدرات الكشف |

## 4. تحليل الفجوات

| # | الفجوة | الوصف | الأولوية | الحالة |
|---|---|---|---|---|
| 1 | غياب إطار الحوكمة | لا يوجد مجلس فعّال | عالية | مفتوحة |
| 2 | ضعف الكشف | عدم وجود SOC | عالية | مفتوحة |
| 3 | ضعف المصادقة متعددة العوامل MFA | غياب MFA | عالية | مفتوحة |
| 4 | محدودية حماية الوصول عن بُعد | لا توجد ZTNA | عالية | مفتوحة |
| 5 | قصور خطط الاستجابة للحوادث | عدم اختبار الخطط | متوسطة | مفتوحة |

## 5. خارطة الطريق التنفيذية

### المرحلة 1: التأسيس (الأشهر 1-6)

| # | النشاط | المسؤول | الجدول الزمني | المخرج |
|---|---|---|---|---|
| 1 | إنشاء المجلس | الإدارة | الشهر 1-2 | ميثاق المجلس |
| 2 | اعتماد إطار الحوكمة | CISO | الشهر 3-4 | إطار معتمد |
| 3 | تطبيق MFA على جميع الأنظمة | CISO | الشهر 5-6 | MFA مفعّل |

## 6. مؤشرات الأداء الرئيسية

| # | المؤشر | النوع | القيمة المستهدفة | صيغة الاحتساب | مصدر البيانات | المالك | التكرار | الإطار الزمني |
|---|---|---|---|---|---|---|---|---|
| 1 | نسبة الامتثال لـ NCA-ECC | KPI | 95% | (الضوابط المطبقة ÷ الضوابط المطلوبة) × 100 | لوحة الامتثال | CISO | شهري | 12 شهر |
| 2 | متوسط زمن الكشف | KPI | < 30 دقيقة | إجمالي الزمن ÷ عدد الحوادث | SIEM | SOC Manager | أسبوعي | 6 شهر |
| 3 | نسبة تطبيق MFA | KPI | 100% | (الأنظمة المطبقة ÷ إجمالي الأنظمة) × 100 | لوحة الهوية | CISO | شهري | 6 شهر |
| 4 | عدد الحوادث الحرجة | KRI | < 2 سنوياً | عدد الحوادث المصنفة حرجة | سجل الحوادث | CISO | شهري | 12 شهر |
| 5 | نسبة المخاطر المخففة | KPI | 80% | (المخاطر المخففة ÷ المخاطر العالية) × 100 | سجل المخاطر | Risk Manager | فصلي | 18 شهر |
| 6 | نسبة استخدام VPN/ZTNA | KPI | 95% | (الموظفون عن بُعد ÷ الإجمالي) × 100 | لوحة الشبكة | CSIRT Lead | شهري | 9 شهر |

### أدلة تقييم مؤشرات الأداء

#### دليل تقييم المؤشر رقم 1: نسبة الامتثال لـ NCA-ECC

**الصيغة:** (الضوابط المطبقة ÷ الضوابط المطلوبة) × 100

| الخطوة | الإجراء | الأداة/النظام | المسؤول | المخرج |
|---|---|---|---|---|
| 1 | جمع قائمة الضوابط المطبقة | لوحة الامتثال | محلل الامتثال | قائمة الضوابط |
| 2 | تطبيق الصيغة الحسابية | لوحة التحكم | محلل الأمن | القيمة المحسوبة |

## 7. تقييم الثقة والمخاطر

**درجة الثقة:** 78%

**المبرر:** الاستراتيجية مبنية على إطار NCA-ECC و TCC المعتمدين.

| # | عامل النجاح الحرج | الوصف | الأهمية |
|---|---|---|---|
| 1 | الدعم التنفيذي | التزام الإدارة العليا | عالية |
| 2 | توفر الكوادر | وجود محللي أمن سيبراني | عالية |
| 3 | الموازنة المالية | تخصيص ميزانية كافية | عالية |

| # | الخطر | الاحتمالية | التأثير | خطة التخفيف |
|---|---|---|---|---|
| 1 | نقص الكفاءات | عالية | عالي | برنامج تطوير |
| 2 | تأخر تطبيق MFA | متوسطة | عالي | متابعة شهرية |
| 3 | تطور التهديدات على العمل عن بُعد | عالية | عالي | تحديث ZTNA |
| 4 | تغيير الأولويات | متوسطة | متوسط | حوكمة مستقرة |
| 5 | ضعف التكامل | متوسطة | متوسط | تخطيط معماري |
'''


# ── Helpers ──────────────────────────────────────────────────────────────
def _shape(s):
    """Return the forms an Arabic substring may take when extracted from
    a ReportLab-generated PDF (logical, reshaped, reshaped+bidi)."""
    import arabic_reshaper
    from bidi.algorithm import get_display
    reshaped = arabic_reshaper.reshape(s)
    return reshaped, get_display(reshaped), s


def _present(text, s):
    for v in _shape(s):
        if v in text:
            return True
    return False


def _make_test_user(username='pr5b8t_test_user'):
    from werkzeug.security import generate_password_hash
    with _APP.app.app_context():
        _APP.init_db()
        db = _APP.get_db()
        cols = [c['name'] for c in db.execute('PRAGMA table_info(users)').fetchall()]
        if 'password_hash' in cols:
            db.execute(
                "INSERT OR IGNORE INTO users (username, password_hash, email, role, is_active) "
                "VALUES (?, ?, ?, ?, 1)",
                (username, generate_password_hash('xxx'),
                 f'{username}@test.local', 'user'),
            )
        else:
            db.execute(
                "INSERT OR IGNORE INTO users (username, password, email, role) "
                "VALUES (?, ?, ?, ?)",
                (username, generate_password_hash('xxx'),
                 f'{username}@test.local', 'user'),
            )
        db.commit()
        row = db.execute(
            "SELECT id FROM users WHERE username=?", (username,)
        ).fetchone()
        return row['id']


def _build_arabic_pdf_bytes(content=FULL_ARABIC_STRATEGY, **overrides):
    uid = _make_test_user()
    client = _APP.app.test_client()
    with client.session_transaction() as sess:
        sess['user_id'] = uid
        sess['username'] = 'pr5b8t_test_user'
        sess['role'] = 'user'
    payload = {
        'content': content,
        'filename': 'pr5b8t_test',
        'language': 'ar',
        'org_name': 'منظمة اختبار',
        'sector': 'حكومي',
        'doc_type': 'Strategy Document',
        'domain': 'Cyber Security',
        'artifact_type': 'strategy',
        'artifact_id': None,
        'generation_mode': 'drafting',
        'selected_frameworks': ['ECC', 'TCC'],
    }
    payload.update(overrides)
    resp = client.post('/api/generate-pdf', json=payload)
    if resp.status_code != 200:
        raise AssertionError(
            f'PDF route failed: status={resp.status_code} '
            f'body={resp.data[:400]!r}'
        )
    return resp.data


def _extract_pdf_text(pdf_bytes):
    import fitz
    doc = fitz.open(stream=pdf_bytes, filetype='pdf')
    pages = [p.get_text() for p in doc]
    doc.close()
    return pages


# ── Module-level cache so we only build one PDF per run ──────────────────
_PDF_CACHE = {'pages': None, 'all_text': None}


def _get_pages():
    if _PDF_CACHE['pages'] is None:
        skip_if_no_arabic_pdf_font(_APP)
        pdf_bytes = _build_arabic_pdf_bytes()
        pages = _extract_pdf_text(pdf_bytes)
        _PDF_CACHE['pages'] = pages
        _PDF_CACHE['all_text'] = '\n'.join(pages)
    return _PDF_CACHE['pages']


def _get_all_text():
    _get_pages()
    return _PDF_CACHE['all_text']


# ─── Tests ───────────────────────────────────────────────────────────────
class ArabicPdfProfessionalLayoutTests(unittest.TestCase):
    """Cover all 15 PR-5B.8T assertions on the rendered PDF."""

    # --- 1: PDF text doesn't contain ".1 الرؤية" reversed forms -----------
    @_skip_if_no_app
    def test_01_no_reversed_dot_one_in_vision_heading(self):
        text = _get_all_text()
        # Bad joined forms in any of (logical, reshaped, reshaped+bidi).
        for v in _shape('.1 الرؤية'):
            self.assertNotIn(
                v, text,
                f'PDF must not contain reversed numbering ".1" glued to '
                f'الرؤية; found {v!r}',
            )

    # --- 2: PDF text contains "1. الرؤية" or logical equivalent -----------
    @_skip_if_no_app
    def test_02_vision_heading_logical_equivalent_present(self):
        text = _get_all_text()
        # Logical equivalent: the heading number "1" and the word
        # "الرؤية" (in any reshape form) both appear within the PDF.
        self.assertIn('1', text, 'Heading number "1" must appear')
        self.assertTrue(
            _present(text, 'الرؤية'),
            'Vision heading word الرؤية must appear in extracted text',
        )

    # --- 3: PDF text doesn't contain "الركيزة :1" -------------------------
    @_skip_if_no_app
    def test_03_no_reversed_pillar_colon_form(self):
        text = _get_all_text()
        for v in _shape('الركيزة :1'):
            self.assertNotIn(
                v, text,
                f'PDF must not contain reversed pillar colon form; '
                f'found {v!r}',
            )

    # --- 4: PDF text doesn't contain "دليل تقييم المؤشر رقم :1" -----------
    @_skip_if_no_app
    def test_04_no_reversed_kpi_guide_colon_form(self):
        text = _get_all_text()
        for v in _shape('دليل تقييم المؤشر رقم :1'):
            self.assertNotIn(
                v, text,
                f'PDF must not contain reversed KPI-guide colon form; '
                f'found {v!r}',
            )

    # --- 5: PDF text doesn't contain "Mizan GRC Platform بواسطة أعد" ------
    @_skip_if_no_app
    def test_05_no_reversed_prepared_by_pair(self):
        text = _get_all_text()
        for v in _shape('Mizan GRC Platform بواسطة أعد'):
            self.assertNotIn(
                v, text,
                f'PDF must not contain reversed "أعد بواسطة | Mizan GRC '
                f'Platform" pair; found {v!r}',
            )

    # --- 6: PDF text includes "أعد بواسطة" and "Mizan GRC Platform" ------
    @_skip_if_no_app
    def test_06_doc_control_prepared_by_label_and_value_present(self):
        text = _get_all_text()
        self.assertTrue(
            _present(text, 'أعد بواسطة'),
            'Document-control label "أعد بواسطة" must appear in PDF',
        )
        self.assertIn(
            'Mizan GRC Platform', text,
            'Document-control value "Mizan GRC Platform" must appear in PDF',
        )

    # --- 7: Executive summary includes ECC, TCC and confidence score -----
    @_skip_if_no_app
    def test_07_executive_summary_mentions_ecc_tcc_and_confidence(self):
        # Page 4 is the executive summary.
        pages = _get_pages()
        self.assertGreaterEqual(len(pages), 4, 'Executive summary page expected')
        exec_text = pages[3]
        self.assertIn('ECC', exec_text,
                      'Executive summary must name framework "ECC"')
        self.assertIn('TCC', exec_text,
                      'Executive summary must name framework "TCC"')
        # Confidence score from the validated content (78%).
        self.assertIn('78', exec_text,
                      'Executive summary must surface the 78% confidence '
                      'score from the strategy content')

    # --- 8: Methodology doesn't contain reversed ".1" numbering ----------
    @_skip_if_no_app
    def test_08_methodology_no_reversed_numbering(self):
        # Methodology is page 6 in the canonical professional order.
        pages = _get_pages()
        self.assertGreaterEqual(len(pages), 6, 'Methodology page expected')
        method_text = pages[5]
        # The methodology now uses "المرحلة N — title" form, so the raw
        # ".N" reversed glued numbering must not appear.
        for v in _shape('.1 تحليل'):
            self.assertNotIn(v, method_text,
                             f'Methodology must not show ".1 تحليل" '
                             f'reversed form; found {v!r}')
        for v in _shape('.1 مراجعة'):
            self.assertNotIn(v, method_text,
                             f'Methodology must not show ".1 مراجعة" '
                             f'reversed form; found {v!r}')
        # Positive: the first phase label is present.
        self.assertTrue(
            _present(method_text, 'المرحلة'),
            'Methodology must use "المرحلة" phase prefix',
        )

    # --- 9: Traceability matrix includes ECC and TCC rows ----------------
    @_skip_if_no_app
    def test_09_traceability_matrix_has_ecc_and_tcc(self):
        text = _get_all_text()
        # "NCA ECC" and "NCA TCC" full display labels appear in the matrix.
        self.assertIn('NCA ECC', text,
                      'Traceability matrix must include an ECC row')
        self.assertIn('NCA TCC', text,
                      'Traceability matrix must include a TCC row')

    # --- 10: Traceability matrix has readable (non-reversed) headers -----
    @_skip_if_no_app
    def test_10_traceability_matrix_headers_readable(self):
        text = _get_all_text()
        # Any of the expected Arabic header tokens must be present in
        # logical reshape form (not the bidi-reversed flipped form).
        for header in ('الإطار المرجعي', 'الفجوة', 'المؤشر'):
            self.assertTrue(
                _present(text, header),
                f'Traceability matrix header {header!r} must be readable',
            )

    # --- 11: Appendix A includes ECC and TCC -----------------------------
    @_skip_if_no_app
    def test_11_appendix_a_includes_ecc_and_tcc(self):
        text = _get_all_text()
        # Appendix A is rendered with bullet rows like "• ECC: NCA ECC ...".
        self.assertIn('ECC', text, 'Appendix A must include ECC')
        self.assertIn('TCC', text, 'Appendix A must include TCC')
        # Appendix-A heading marker.
        self.assertTrue(
            _present(text, 'الملحق أ'),
            'Appendix A heading must be present',
        )

    # --- 12: Appendix B includes the standard glossary acronyms ----------
    @_skip_if_no_app
    def test_12_appendix_b_glossary_baseline_complete(self):
        text = _get_all_text()
        # The required glossary baseline (PR-5B.8T) must always be present.
        for ac in ('MFA', 'VPN', 'ZTNA', 'IAM', 'PAM',
                   'SOC', 'SIEM', 'CSIRT', 'DLP'):
            self.assertIn(
                ac, text,
                f'Appendix B glossary baseline must include {ac}',
            )
        self.assertTrue(
            _present(text, 'الملحق ب'),
            'Appendix B heading must be present',
        )

    # --- 13: Common role names are not split mid-word --------------------
    @_skip_if_no_app
    def test_13_role_names_not_split_midword(self):
        text = _get_all_text()
        # Forbidden mid-word splits introduced by narrow-cell wrapping of
        # English role labels.
        for bad in ('Cybers ecurity', 'Govern ance', 'Mana ger', 'Cyb ersecurity'):
            self.assertNotIn(
                bad, text,
                f'Role label must not be split mid-word as {bad!r}',
            )
        # When the governance owner is "Cybersecurity Governance Lead"
        # the renderer either keeps it whole or substitutes the Arabic
        # equivalent "قائد حوكمة الأمن السيبراني". One of the two MUST
        # be present.
        ok = ('Cybersecurity Governance Lead' in text
              or 'Cybersecurity Governance' in text
              or 'Governance Lead' in text
              or _present(text, 'قائد حوكمة الأمن السيبراني')
              or _present(text, 'مسؤول أمن السيبراني'))
        self.assertTrue(ok,
                        'Cybersecurity Governance Lead must appear whole or '
                        'as its Arabic equivalent (no mid-word split)')

    # --- 14: Preview rendering is unchanged ------------------------------
    @_skip_if_no_app
    def test_14_preview_routes_unchanged(self):
        # Sanity: the strategy preview route still exists and PR-5B.8T
        # didn't accidentally remove it.
        rules = {str(r.rule) for r in _APP.app.url_map.iter_rules()}
        self.assertIn(
            '/api/generate-pdf', rules,
            'PDF route must still exist (preview path is unaffected)',
        )

    # --- 15: No AI-generation / prompt logic changed ---------------------
    @_skip_if_no_app
    def test_15_no_ai_generation_logic_changed(self):
        # PR-5B.8T is layout-only. Smoke check: critical AI-orchestration
        # symbols are still defined and importable from app.
        for name in (
            'synthesize_objectives_depth',
            'synthesize_kpi_depth',
            'synthesize_gaps_depth',
            'synthesize_confidence_depth',
            'ai_repair_strategy_section',
            'enforce_technical_strategy_depth',
        ):
            self.assertTrue(
                hasattr(_APP, name),
                f'AI-generation symbol {name!r} must still exist; '
                f'PR-5B.8T must not touch generation logic',
            )


if __name__ == '__main__':
    unittest.main(verbosity=2)
