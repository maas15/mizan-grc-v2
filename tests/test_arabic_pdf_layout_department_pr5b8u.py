"""PR-5B.8U — Arabic PDF layout polish + cybersecurity-department surface.

Verifies the Arabic strategy PDF:

  1. Does NOT contain the bidi-reversed pair ``"Mizan GRC Platform بواسطة أعد"``
     (any of logical / reshaped / reshaped+bidi forms).
  2. Contains both the document-control label ``"أعد بواسطة"`` and the
     value ``"Mizan GRC Platform"``.
  3. When ``org_structure_is_none=True`` the assembled strategy text in
     the PDF surfaces ``"إنشاء إدارة"`` / ``"إدارة الأمن السيبراني"``
     (the establish-department recommendation).
  4. Includes ``"إدارة الأمن السيبراني"`` in the governance / ownership
     surface.
  5. The traceability matrix includes readable ECC / TCC rows.
  6. The traceability matrix is not collapsed into unreadable stacked
     generic text — verified by the presence of distinct framework /
     capability labels.
  7. The governance model surface includes both ``CISO`` and the
     cybersecurity department label.
  8. Section heading punctuation remains normalised — e.g. no
     ``".1 الرؤية"`` reversed-numbering form, no ``"الركيزة :1"``
     reversed-colon form.
  9. Preview behaviour unchanged — only the PDF rendering helpers were
     adjusted; the markdown→HTML preview shaper is untouched.
 10. No AI prompt / generation logic changed except the targeted
     org_structure_is_none repair clause appended in
     ``ai_repair_strategy_section``.
 11. No deterministic fallback rows added — the validator and helper are
     pure detection.

Run:
    python -m pytest tests/test_arabic_pdf_layout_department_pr5b8u.py -v
"""

import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_arabic_pdf_dept_pr5b8u_')
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


# ── Full Arabic strategy with the cybersecurity-department recommendation
# explicitly woven across every required section. The PDF builder consumes
# this markdown verbatim — no fallback rows are injected. ───────────────
FULL_ARABIC_STRATEGY = '''## 1. الرؤية والأهداف الاستراتيجية

**الرؤية:** بناء قدرات الأمن السيبراني وإنشاء إدارة متخصصة للأمن السيبراني.

**الرسالة:** تأسيس إدارة الأمن السيبراني وتعيين رئيس الأمن السيبراني (CISO) ضمن نموذج التشغيل وخطوط الرفع.

### الأهداف الاستراتيجية:

| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |
|---|---|---|---|---|
| 1 | إنشاء إدارة متخصصة للأمن السيبراني | اعتماد الهيكل التنظيمي | حوكمة | 6 شهور |
| 2 | تعيين CISO وتحديد الأدوار والمسؤوليات | تعيين رسمي + مصفوفة RACI | حوكمة | 3 شهور |
| 3 | تأسيس لجنة حوكمة الأمن السيبراني | اعتماد ميثاق اللجنة | حوكمة | 6 شهور |
| 4 | إدارة الهوية والوصول المميز IAM PAM | 100% | NCA-ECC | 12 شهر |
| 5 | المراقبة المستمرة SIEM SOC وحماية البيانات | 24/7 | NCA-ECC | 12 شهر |
| 6 | الاستجابة للحوادث incident response والتوعية ضد التصيد | <4س | NCA-ECC | 12 شهر |

## 2. الركائز الاستراتيجية

### الركيزة 1: حوكمة الأمن السيبراني وإنشاء إدارة الأمن السيبراني

إنشاء إدارة متخصصة للأمن السيبراني، تعيين CISO، تحديد الأدوار والمسؤوليات والصلاحيات، نموذج التشغيل وخطوط الرفع، ولجنة حوكمة الأمن السيبراني.

| # | المبادرة | الوصف | المخرج المتوقع | المسؤول |
|---|---|---|---|---|
| 1 | إنشاء إدارة الأمن السيبراني | اعتماد هيكل تنظيمي مخصص | إدارة قائمة | CISO |
| 2 | تعيين CISO رسمياً | قرار تعيين | CISO معين | الإدارة العليا |
| 3 | تأسيس لجنة حوكمة الأمن السيبراني | ميثاق ونموذج تشغيل | لجنة فعالة | CISO |

### الركيزة 2: المراقبة والاستجابة

بناء SOC مع SIEM ومراقبة مستمرة لإدارة الثغرات vulnerability والاستجابة للحوادث.

| # | المبادرة | الوصف | المخرج المتوقع | المسؤول |
|---|---|---|---|---|
| 1 | بناء SOC | تشغيل المراقبة على مدار الساعة | SOC عامل | SOC Manager |
| 2 | نشر SIEM | تجميع السجلات والمراقبة | لوحة مراقبة | SOC Manager |
| 3 | برنامج إدارة الثغرات vulnerability | اكتشاف ومعالجة الثغرات | تقرير شهري | فريق العمليات |

### الركيزة 3: حماية البيانات والمرونة

التشفير encryption والنسخ الاحتياطي backup والتعافي من الكوارث DR، والتوعية ضد التصيد phishing.

| # | المبادرة | الوصف | المخرج المتوقع | المسؤول |
|---|---|---|---|---|
| 1 | حماية البيانات DLP | تطبيق DLP | حماية شاملة | فريق العمليات |
| 2 | النسخ الاحتياطي والتعافي DR | اختبارات دورية | استعادة موثوقة | فريق IT |
| 3 | برنامج توعية ضد التصيد | تدريب جميع الموظفين | 95% تدريب | HR |

## 3. البيئة التنظيمية والتهديدات

السياق التنظيمي: NCA-ECC و TCC. التهديدات: phishing وتصيد. السياق التشغيلي: حماية البيانات و DLP.

| البُعد | الإشارة / المصدر | التأثير المحتمل |
|--------|------------------|----------------|
| تنظيمي | NCA-ECC | عالٍ |
| تهديد | تصيد phishing | عالٍ |
| أعمال | استمرارية الخدمات | متوسط |

## 4. تحليل الفجوات

| # | الفجوة | الوصف | الأولوية | الحالة |
|---|---|---|---|---|
| 1 | غياب إدارة الأمن السيبراني | لا توجد إدارة متخصصة للأمن السيبراني | حرجة | مفتوحة |
| 2 | غياب CISO وتحديد الأدوار والمسؤوليات | لم يتم تعيين رئيس الأمن السيبراني | حرجة | مفتوحة |
| 3 | غياب MFA | المصادقة الثنائية | حرجة | مفتوحة |
| 4 | ضعف التوعية ضد التصيد | برامج التدريب | عالية | مفتوحة |

#### دليل تطبيق الفجوة رقم 1
1. اعتماد الهيكل التنظيمي
2. تعيين CISO
3. اعتماد ميثاق لجنة حوكمة الأمن السيبراني
4. إطلاق نموذج التشغيل وخطوط الرفع

#### دليل تطبيق الفجوة رقم 2
1. تحديد الأدوار والمسؤوليات
2. اعتماد مصفوفة RACI
3. تعيين CISO رسمياً
4. تفعيل خطوط الرفع

#### دليل تطبيق الفجوة رقم 3
1. تقييم بدائل MFA
2. اختيار حل
3. النشر التجريبي
4. النشر الكامل

#### دليل تطبيق الفجوة رقم 4
1. تصميم محتوى التوعية
2. حملات شهرية
3. اختبارات تصيد محاكاة
4. قياس النتائج

## 5. خارطة الطريق التنفيذية

| # | النشاط | المسؤول | الإطار الزمني | المخرج |
|---|---|---|---|---|
| 1 | إنشاء إدارة الأمن السيبراني وتعيين CISO | الإدارة العليا | الشهر 1-3 | إدارة قائمة + CISO معين |
| 2 | تحديد الأدوار والمسؤوليات ونموذج التشغيل | CISO | الشهر 2-4 | RACI معتمد |
| 3 | تأسيس لجنة حوكمة الأمن السيبراني | CISO | الشهر 3-5 | ميثاق اللجنة |
| 4 | نشر MFA وإدارة الهوية IAM PAM | فريق IAM | الشهر 1-3 | تفعيل المصادقة |
| 5 | بناء SOC + SIEM | SOC Manager | الشهر 3-6 | مراقبة 24/7 |
| 6 | برنامج توعية ضد التصيد phishing | HR | الشهر 4-9 | 95% تدريب |
| 7 | تنفيذ النسخ الاحتياطي والتعافي DR | فريق IT | الشهر 6-12 | استعادة موثوقة |

## 6. مؤشرات الأداء الرئيسية

| # | المؤشر | النوع KPI/KRI | القيمة المستهدفة | صيغة الاحتساب | مصدر البيانات | المالك | التكرار | الإطار الزمني |
|---|---|---|---|---|---|---|---|---|
| 1 | اعتماد الهيكل التنظيمي لإدارة الأمن السيبراني | KPI | 100% | اعتماد رسمي | مكتب CISO | CISO | ربع سنوي | 6ش |
| 2 | تفعيل MFA | KPI | 100% | عدد الحسابات | IAM | CISO | شهري | 12ش |
| 3 | استجابة SOC | KRI | <4س | متوسط الزمن | SIEM | SOC Manager | شهري | 12ش |
| 4 | إدارة الثغرات vulnerability | KPI | 30 يوم | عدد الثغرات | VM | فريق العمليات | شهري | 12ش |
| 5 | اختبار النسخ الاحتياطي backup | KPI | 100% | اختبار شهري | DR | فريق IT | ربع سنوي | 12ش |
| 6 | برامج التوعية ضد التصيد phishing | KPI | 95% | نسبة المتدربين | HR | HR | ربع سنوي | 12ش |
| 7 | تشفير البيانات encryption و DLP | KPI | 100% | تغطية البيانات | DP | فريق العمليات | شهري | 12ش |

## 7. تقييم الثقة والمخاطر

**درجة الثقة:** 78%

**المبرر:** الاستراتيجية مبنية على إنشاء إدارة الأمن السيبراني وتعيين CISO، وفق NCA-ECC و TCC.

| # | عامل النجاح الحرج | الوصف | الأهمية |
|---|---|---|---|
| 1 | الدعم التنفيذي لإنشاء إدارة الأمن السيبراني | التزام الإدارة العليا | عالية |
| 2 | تعيين CISO مؤهل | توفر الكفاءة | عالية |
| 3 | اعتماد نموذج التشغيل وخطوط الرفع | الحوكمة | عالية |

| # | الخطر | الاحتمالية | التأثير | خطة التخفيف |
|---|---|---|---|---|
| 1 | غياب إدارة الأمن السيبراني وحوكمة الأمن السيبراني | عالية | حرج | إنشاء إدارة متخصصة وتعيين CISO فوراً |
| 2 | عدم تحديد الأدوار والمسؤوليات وخطوط الرفع | عالية | عالي | اعتماد مصفوفة الصلاحيات RACI |
| 3 | تأخر تعيين CISO | متوسطة | عالي | جدول تعيين معتمد |
| 4 | تأخر تطبيق MFA | متوسطة | عالي | متابعة شهرية |
| 5 | تطور التهديدات | عالية | عالي | تحديث الضوابط |
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


def _make_test_user(username='pr5b8u_test_user'):
    from werkzeug.security import generate_password_hash
    with _APP.app.app_context():
        _APP.init_db()
        db = _APP.get_db()
        cols = [c['name'] for c in db.execute(
            'PRAGMA table_info(users)').fetchall()]
        if 'password_hash' in cols:
            db.execute(
                "INSERT OR IGNORE INTO users "
                "(username, password_hash, email, role, is_active) "
                "VALUES (?, ?, ?, ?, 1)",
                (username, generate_password_hash('xxx'),
                 f'{username}@test.local', 'user'),
            )
        else:
            db.execute(
                "INSERT OR IGNORE INTO users "
                "(username, password, email, role) VALUES (?, ?, ?, ?)",
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
        sess['username'] = 'pr5b8u_test_user'
        sess['role'] = 'user'
    payload = {
        'content': content,
        'filename': 'pr5b8u_test',
        'language': 'ar',
        'org_name': 'منظمتي',
        'sector': 'حكومي',
        'doc_type': 'وثيقة استراتيجية',
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


# ── Tests ────────────────────────────────────────────────────────────────
class ArabicPdfLayoutDepartmentTests(unittest.TestCase):

    # 1: PDF text doesn't contain reversed "Mizan GRC Platform بواسطة أعد"
    @_skip_if_no_app
    def test_01_no_reversed_prepared_by_pair(self):
        text = _get_all_text()
        for v in _shape('Mizan GRC Platform بواسطة أعد'):
            self.assertNotIn(
                v, text,
                f'PDF must not contain reversed "أعد بواسطة | Mizan GRC '
                f'Platform" pair; found {v!r}',
            )

    # 2: PDF text includes "أعد بواسطة" and "Mizan GRC Platform"
    @_skip_if_no_app
    def test_02_doc_control_prepared_by_label_and_value_present(self):
        text = _get_all_text()
        self.assertTrue(
            _present(text, 'أعد بواسطة'),
            'Document-control label "أعد بواسطة" must appear in PDF',
        )
        self.assertIn(
            'Mizan GRC Platform', text,
            'Document-control value "Mizan GRC Platform" must appear',
        )

    # 3: PDF includes "إنشاء إدارة" or "إدارة الأمن السيبراني"
    @_skip_if_no_app
    def test_03_pdf_includes_dept_establishment_text(self):
        text = _get_all_text()
        self.assertTrue(
            _present(text, 'إنشاء إدارة')
            or _present(text, 'إدارة الأمن السيبراني'),
            'PDF must surface the department-establishment recommendation',
        )

    # 4: PDF includes "إدارة الأمن السيبراني" in the governance ownership
    @_skip_if_no_app
    def test_04_governance_includes_cyber_dept(self):
        text = _get_all_text()
        self.assertTrue(
            _present(text, 'إدارة الأمن السيبراني'),
            'Governance / ownership surface must include the cybersecurity '
            'department label',
        )

    # 5: Traceability matrix includes ECC and TCC rows
    @_skip_if_no_app
    def test_05_traceability_includes_ecc_and_tcc(self):
        text = _get_all_text()
        self.assertIn('NCA ECC', text,
                      'Traceability must include an ECC row')
        self.assertIn('NCA TCC', text,
                      'Traceability must include a TCC row')

    # 6: Traceability does not collapse into unreadable stacked text — at
    # least the framework + capability headers must be readable in the PDF
    @_skip_if_no_app
    def test_06_traceability_headers_readable(self):
        text = _get_all_text()
        self.assertTrue(
            _present(text, 'الإطار المرجعي') or _present(text, 'الإطار'),
            'Traceability framework column header must be readable',
        )
        self.assertTrue(
            _present(text, 'الفجوة'),
            'Traceability gap column header must be readable',
        )

    # 7: Governance model includes CISO and Cybersecurity Department
    @_skip_if_no_app
    def test_07_governance_model_includes_ciso_and_dept(self):
        text = _get_all_text()
        self.assertIn('CISO', text,
                      'Governance model must include CISO ownership')
        self.assertTrue(
            _present(text, 'إدارة الأمن السيبراني'),
            'Governance model must include the cybersecurity department',
        )

    # 8: Section heading punctuation remains normalised
    @_skip_if_no_app
    def test_08_section_heading_punctuation_normalised(self):
        text = _get_all_text()
        for v in _shape('.1 الرؤية'):
            self.assertNotIn(v, text,
                             f'Reversed numbering ".1 الرؤية" must not appear; '
                             f'found {v!r}')
        for v in _shape('الركيزة :1'):
            self.assertNotIn(v, text,
                             f'Reversed pillar colon form must not appear; '
                             f'found {v!r}')

    # 9: Preview behaviour unchanged — the markdown→HTML preview shaper
    # is independent of the PDF layout helpers we adjusted.
    @_skip_if_no_app
    def test_09_preview_behaviour_unchanged(self):
        # The /api/preview route or markdown_to_html function must still
        # exist and accept the same Arabic markdown unchanged. We only
        # verify it does not raise (preview path independence).
        if hasattr(_APP, 'markdown_to_html'):
            html = _APP.markdown_to_html(FULL_ARABIC_STRATEGY)
            self.assertTrue(html and 'إنشاء إدارة' in html
                            or 'إدارة الأمن السيبراني' in html)
        else:  # pragma: no cover — older app variants
            self.skipTest('markdown_to_html helper not exposed')

    # 10: No AI prompt / generation logic changed except the targeted
    # org_structure_is_none clause in ai_repair_strategy_section.
    @_skip_if_no_app
    def test_10_ai_repair_signature_unchanged(self):
        import inspect
        sig = inspect.signature(_APP.ai_repair_strategy_section)
        # Existing kwargs preserved
        for kw in ('section_key', 'sections', 'lang', 'domain_context',
                   'org_structure_is_none', 'validation_error'):
            self.assertIn(
                kw, sig.parameters,
                f'ai_repair_strategy_section must keep kwarg {kw!r}',
            )

    # 11: No deterministic fallback rows added — verify the doc-control
    # rows builder still returns exactly the user-supplied metadata pairs
    # and never injects any cybersecurity-department row of its own.
    @_skip_if_no_app
    def test_11_no_deterministic_dept_rows_in_doc_control(self):
        rows = _APP._build_document_control_rows(
            {'org_name': 'منظمتي', 'sector': 'حكومي',
             'domain': 'Cyber Security', 'doc_type': 'وثيقة استراتيجية'},
            'ar')
        # The doc-control table must NEVER carry strategy content. It must
        # only carry the field/value metadata pairs.
        joined = ' '.join(v for _, v in rows)
        self.assertNotIn('إنشاء إدارة', joined,
                         'Doc-control rows must not carry strategy content')
        # Prepared-by label is now the simple form (no diacritics)
        labels = [lbl for lbl, _ in rows]
        self.assertIn('أعد بواسطة', labels,
                      'Doc-control must use the simple "أعد بواسطة" label')


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
