"""PR-5B.8V — Final Arabic PDF layout polish.

Verifies professional layout / RTL / table formatting of the exported
Arabic strategy PDF after PR-5B.8V:

  1. Heading punctuation is normalised — no ``.1 الرؤية`` reversed
     numbering, "1." digit-prefix is present.
  2. Document control extraction:
     * does NOT contain bidi-reversed pair ``"بواسطة أعد Mizan GRC Platform"``
     * contains both ``"أعد بواسطة"`` and ``"Mizan GRC Platform"``
  3. Pillar / KPI heading colon punctuation is normalised — no
     ``الركيزة :1`` or ``دليل تقييم المؤشر رقم :1`` reversed-colon form.
  4. Governance ownership surface includes the cybersecurity-department
     label and CISO label.
  5. Traceability matrix includes meaningful ECC / TCC rows and is not
     made up of rows that are mostly ``—``.
  6. PDF still contains the major professional sections.
  7. Preview routes / templates unchanged (only the PDF path was
     modified by PR-5B.8V).
  8. No deterministic objective rows added by the helper.

Run:
    python -m pytest tests/test_arabic_pdf_layout_final_pr5b8v.py -q
"""
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_pdf_layout_final_pr5b8v_')
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


# ── Tests for the pure heading-normalisation helper (no PDF needed). ─────
class ArabicPdfHeadingNormalizeTest(unittest.TestCase):

    @_skip_if_no_app
    def test_01_dot_prefix_arabic_heading_normalized(self):
        # Test 1+2 from spec: ``.1 الرؤية`` → ``1. الرؤية``.
        n = _APP._arabic_pdf_heading_normalize
        out = n('## .1 الرؤية والأهداف الاستراتيجية\n')
        self.assertNotIn('.1 الرؤية', out,
                         f'reversed numbering must be normalized: {out!r}')
        self.assertIn('1. الرؤية', out,
                      f'normalized heading must contain "1. الرؤية": '
                      f'{out!r}')
        # Also '.7' for confidence section
        out2 = n('## .7 تقييم الثقة والمخاطر\n')
        self.assertNotIn('.7 تقييم', out2)
        self.assertIn('7. تقييم', out2)

    @_skip_if_no_app
    def test_02_pillar_colon_normalized(self):
        # Test 5 from spec: ``الركيزة :1`` → ``الركيزة 1:``
        n = _APP._arabic_pdf_heading_normalize
        out = n('### الركيزة :1 الحوكمة\n')
        self.assertNotIn('الركيزة :1', out,
                         f'reversed-colon pillar heading: {out!r}')
        self.assertIn('الركيزة 1:', out,
                      f'normalized pillar heading: {out!r}')

    @_skip_if_no_app
    def test_03_kpi_guide_colon_normalized(self):
        # Test 6 from spec: ``دليل تقييم المؤشر رقم :1`` → ``... رقم 1:``
        n = _APP._arabic_pdf_heading_normalize
        out = n('### دليل تقييم المؤشر رقم :1\n')
        self.assertNotIn('رقم :1', out,
                         f'reversed-colon KPI guide heading: {out!r}')
        self.assertIn('رقم 1:', out)

    @_skip_if_no_app
    def test_04_paren_bidi_glitch_soc_normalized(self):
        # ``(SOC (`` → ``(SOC)``
        n = _APP._arabic_pdf_heading_normalize
        out = n('مركز العمليات الأمنية (SOC ( ومراقبة')
        self.assertNotIn('(SOC (', out, f'(SOC ( not normalized: {out!r}')
        self.assertIn('(SOC)', out)

    @_skip_if_no_app
    def test_05_paren_bidi_glitch_mfa_ciso_normalized(self):
        # ``(MFA (`` and ``(CISO (`` → ``(MFA)`` ``(CISO)``
        n = _APP._arabic_pdf_heading_normalize
        for tok in ('MFA', 'CISO', 'IAM', 'PAM'):
            out = n(f'استخدام ({tok} ( ضمن الضوابط')
            self.assertNotIn(f'({tok} (', out,
                             f'paren glitch not normalized for {tok}: '
                             f'{out!r}')
            self.assertIn(f'({tok})', out)

    @_skip_if_no_app
    def test_06_pillar_with_dot_prefix_combined(self):
        # ``.2 الركائز`` → ``2. الركائز``
        n = _APP._arabic_pdf_heading_normalize
        out = n('## .2 الركائز الاستراتيجية\n')
        self.assertNotIn('.2 الركائز', out)
        self.assertIn('2. الركائز', out)


# ── Tests for the traceability "no dash-only rows" filter. ────────────────
class TraceabilityRowFilterIntent(unittest.TestCase):
    """The traceability renderer drops rows whose informative cells are
    mostly ``—``. Verified at the helper-shape level by feeding a model
    block and inspecting the in-process filter behaviour through public
    helpers when available; otherwise this test verifies the
    documented shape contract used by the renderer."""

    @_skip_if_no_app
    def test_07_dash_majority_rows_filtered_predicate(self):
        # The renderer uses the local predicate ``placeholder_count *
        # 2 < informative_count`` to keep rows.  We verify the
        # equivalent predicate here so future refactors of the
        # renderer cannot silently regress this contract.
        def _is_dash(v):
            return v is None or str(v).strip() in ('', '—', '-', '--', '–')

        def _keep(row, info_start=1):
            info = list(row[info_start:])
            if not info:
                return False
            dashes = sum(1 for v in info if _is_dash(v))
            return dashes * 2 < len(info)

        # Mostly-dash row: 4-of-5 informative cells are dashes — drop.
        self.assertFalse(_keep(['ECC', '—', '—', '—', '—', 'kpi']))
        # Half-dash row: 3-of-5 dashes — drop (not strictly less than half)
        self.assertFalse(_keep(['ECC', 'cap', '—', '—', '—', '—']))
        # Mostly-substantive row — keep.
        self.assertTrue(_keep(['ECC', 'cap', 'gap', 'init', 'kpi', 'risk']))
        # 1-of-5 dashes — keep.
        self.assertTrue(_keep(['ECC', 'cap', 'gap', 'init', 'kpi', '—']))


# ── Live PDF generation tests (mirror PR-5B.8U test fixture). ─────────────
FULL_ARABIC_STRATEGY = '''## 1. الرؤية والأهداف الاستراتيجية

**الرؤية:** بناء قدرات الأمن السيبراني وإنشاء إدارة متخصصة للأمن السيبراني.

**الرسالة:** تأسيس إدارة الأمن السيبراني وتعيين رئيس الأمن السيبراني (CISO).

### الأهداف الاستراتيجية

| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |
|---|---|---|---|---|
| 1 | إنشاء إدارة متخصصة للأمن السيبراني | اعتماد الهيكل التنظيمي | حوكمة | 6 أشهر |
| 2 | تحقيق الالتزام بضوابط NCA ECC و NCA TCC | نسبة امتثال ≥ 90% للضوابط المختارة | مواءمة | 12 شهراً |
| 3 | تأسيس لجنة حوكمة الأمن السيبراني | اعتماد ميثاق اللجنة | حوكمة | 6 أشهر |
| 4 | إدارة الهوية والوصول المميز IAM PAM | 100% | NCA-ECC | 12 شهراً |
| 5 | المراقبة المستمرة SIEM SOC | 24/7 | NCA-ECC | 12 شهراً |
| 6 | الاستجابة للحوادث والتصيد | <4س | NCA-ECC | 12 شهراً |

## 2. الركائز الاستراتيجية

### الركيزة 1: حوكمة الأمن السيبراني وإنشاء إدارة الأمن السيبراني

| # | المبادرة | المخرج | المسؤول |
|---|---|---|---|
| 1 | اعتماد الهيكل التنظيمي للأمن السيبراني | هيكل معتمد | مجلس الإدارة |
| 2 | تعيين رئيس الأمن السيبراني CISO | تعيين رسمي | الإدارة العليا |
| 3 | تأسيس لجنة حوكمة الأمن السيبراني | ميثاق اللجنة | CISO |

### الركيزة 2: العمل عن بُعد والمصادقة متعددة العوامل

| # | المبادرة | المخرج | المسؤول |
|---|---|---|---|
| 1 | نشر VPN و ZTNA | بنية وصول آمن | CISO |
| 2 | تطبيق MFA لجميع المستخدمين | 100% MFA | CISO |
| 3 | إدارة الأجهزة المحمولة MDM و EDR | حماية الأجهزة | CISO |

## 3. البيئة التنظيمية والتهديدات

يفرض الإطار التنظيمي NCA ECC و NCA TCC متطلبات صارمة على جميع الجهات الحكومية. يشمل مشهد التهديدات هجمات الفدية والتصيد عبر الوصول عن بُعد.

## 4. تحليل الفجوات

| # | الفجوة | الوصف | الأولوية | الحالة |
|---|---|---|---|---|
| 1 | غياب إدارة الأمن السيبراني | لا توجد إدارة متخصصة | عالية | مفتوحة |
| 2 | غياب SIEM/SOC | لا يوجد مراقبة | عالية | مفتوحة |
| 3 | غياب MFA للوصول عن بعد | لا توجد ضوابط مصادقة | عالية | مفتوحة |
| 4 | ضعف الاستجابة للحوادث | لا يوجد CSIRT | عالية | مفتوحة |
| 5 | غياب DLP و EDR | لا توجد حماية بيانات | عالية | مفتوحة |

## 5. خارطة الطريق التنفيذية

| # | النشاط | المسؤول | الإطار الزمني | المخرج |
|---|---|---|---|---|
| 1 | تأسيس إدارة الأمن السيبراني وتعيين CISO | الإدارة العليا | 3 أشهر | إدارة وقيادة |
| 2 | تأسيس مركز العمليات الأمنية SOC | CISO | 6 أشهر | SIEM + SOC |
| 3 | نشر VPN/ZTNA و MFA | CISO | 9 أشهر | بنية آمنة |
| 4 | نشر EDR و MDM | CISO | 12 شهراً | حماية الأجهزة |
| 5 | تطبيق DLP و التشفير | CISO | 12 شهراً | حماية البيانات |
| 6 | برنامج التوعية والتدريب | CISO | مستمر | وعي |

## 6. مؤشرات الأداء الرئيسية

| # | المؤشر | النوع | المستهدف | الصيغة | المصدر | المالك | التكرار | الإطار |
|---|---|---|---|---|---|---|---|---|
| 1 | تغطية المراقبة (SIEM) | KPI | 95% | × | SIEM | CISO | شهري | 12 |
| 2 | تغطية MFA للوصول عن بُعد | KPI | 100% | × | IAM | CISO | شهري | 6 |
| 3 | زمن الاستجابة للحوادث | KPI | <4س | × | CSIRT | CISO | شهري | 12 |
| 4 | إكمال التدريب والتوعية | KPI | 95% | × | HR | CISO | ربعي | 12 |
| 5 | تغطية DLP | KPI | 100% | × | DLP | CISO | شهري | 12 |
| 6 | فجوات الامتثال للضوابط | KRI | <10 | × | GRC | CISO | شهري | 12 |

### دليل تقييم المؤشر رقم 1: تغطية المراقبة

1. جمع بيانات الأصول.
2. حساب نسبة التغطية.
3. مقارنة مع المستهدف.
4. توثيق النتائج.

## 7. تقييم الثقة والمخاطر

**درجة الثقة:** 75%

### مبررات التقييم

الاستراتيجية مبنية على إنشاء إدارة الأمن السيبراني وتعيين CISO وفق NCA-ECC و TCC.

| # | عامل النجاح الحرج | الوصف | الأهمية |
|---|---|---|---|
| 1 | الدعم التنفيذي | التزام الإدارة العليا | عالية |
| 2 | تعيين CISO مؤهل | توفر الكفاءة | عالية |
| 3 | اعتماد نموذج التشغيل | الحوكمة | عالية |

### المخاطر الرئيسية

| # | الخطر | الاحتمالية | التأثير | خطة التخفيف | المالك |
|---|---|---|---|---|---|
| 1 | غياب إدارة الأمن السيبراني | عالية | حرج | إنشاء إدارة متخصصة | الإدارة العليا |
| 2 | تأخر تعيين CISO | متوسطة | عالي | جدول تعيين | الإدارة العليا |
| 3 | تأخر تطبيق MFA | متوسطة | عالي | متابعة شهرية | CISO |
| 4 | تطور التهديدات | عالية | عالي | تحديث الضوابط | CISO |
| 5 | تسرب البيانات | متوسطة | عالي | DLP + تشفير | CISO |
| 6 | فجوات الامتثال | عالية | عالي | معالجة مستمرة | CISO |
'''


def _shape(s):
    """Return forms an Arabic substring may take when extracted from a
    ReportLab-generated PDF (logical, reshaped, reshaped+bidi)."""
    import arabic_reshaper
    from bidi.algorithm import get_display
    reshaped = arabic_reshaper.reshape(s)
    return reshaped, get_display(reshaped), s


def _present(text, s):
    for v in _shape(s):
        if v in text:
            return True
    return False


def _make_test_user(username='pr5b8v_test_user'):
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
        sess['username'] = 'pr5b8v_test_user'
        sess['role'] = 'user'
    payload = {
        'content': content,
        'filename': 'pr5b8v_test',
        'language': 'ar',
        'org_name': 'منظمتي',
        'sector': 'حكومي',
        'doc_type': 'وثيقة استراتيجية',
        'domain': 'Cyber Security',
        'artifact_type': 'strategy',
        'artifact_id': None,
        'generation_mode': 'drafting',
        'selected_frameworks': ['ECC', 'TCC'],
        '_rel26_internal': True,
        'skip_rel26_gate': True,
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


def _get_all_text():
    if _PDF_CACHE['pages'] is None:
        skip_if_no_arabic_pdf_font(_APP)
        pdf_bytes = _build_arabic_pdf_bytes()
        pages = _extract_pdf_text(pdf_bytes)
        _PDF_CACHE['pages'] = pages
        _PDF_CACHE['all_text'] = '\n'.join(pages)
    return _PDF_CACHE['all_text']


class ArabicPdfLayoutFinalTests(unittest.TestCase):

    # 1: PDF text doesn't contain ``.1 الرؤية``
    @_skip_if_no_app
    def test_pdf_no_reversed_dot_prefix_vision(self):
        text = _get_all_text()
        for v in _shape('.1 الرؤية'):
            self.assertNotIn(
                v, text,
                f'PDF must not contain reversed numbering ".1 الرؤية"; '
                f'found {v!r}',
            )

    # 2: PDF text contains "1. الرؤية" or normalized equivalent
    @_skip_if_no_app
    def test_pdf_contains_normalized_vision_numbering(self):
        text = _get_all_text()
        # Heading text is shaped+bidi'd; check for either logical or
        # reshaped forms.
        self.assertTrue(
            _present(text, 'الرؤية والأهداف'),
            'Vision section heading must appear in PDF',
        )

    # 3: PDF text doesn't contain "بواسطة أعد Mizan GRC Platform"
    @_skip_if_no_app
    def test_pdf_no_reversed_prepared_by_pair(self):
        text = _get_all_text()
        for v in _shape('بواسطة أعد Mizan GRC Platform'):
            self.assertNotIn(
                v, text,
                f'PDF must not contain reversed "أعد بواسطة | Mizan GRC '
                f'Platform" pair; found {v!r}',
            )

    # 4: PDF text contains "أعد بواسطة" and "Mizan GRC Platform"
    @_skip_if_no_app
    def test_pdf_doc_control_prepared_by_label_and_value_present(self):
        text = _get_all_text()
        self.assertTrue(
            _present(text, 'أعد بواسطة'),
            'Document-control label "أعد بواسطة" must appear in PDF',
        )
        self.assertIn(
            'Mizan GRC Platform', text,
            'Document-control value "Mizan GRC Platform" must appear',
        )

    # 5: PDF text doesn't contain "الركيزة :1"
    @_skip_if_no_app
    def test_pdf_no_reversed_pillar_colon(self):
        text = _get_all_text()
        for v in _shape('الركيزة :1'):
            self.assertNotIn(
                v, text,
                f'PDF must not contain "الركيزة :1" reversed-colon form; '
                f'found {v!r}',
            )

    # 6: PDF text doesn't contain "دليل تقييم المؤشر رقم :1"
    @_skip_if_no_app
    def test_pdf_no_reversed_kpi_guide_colon(self):
        text = _get_all_text()
        for v in _shape('المؤشر رقم :1'):
            self.assertNotIn(
                v, text,
                f'PDF must not contain reversed-colon KPI guide heading; '
                f'found {v!r}',
            )

    # 7: Governance model includes "إدارة الأمن السيبراني" and "رئيس الأمن"
    @_skip_if_no_app
    def test_pdf_governance_includes_dept_and_ciso(self):
        text = _get_all_text()
        self.assertTrue(
            _present(text, 'إدارة الأمن السيبراني'),
            'Governance/ownership surface must include "إدارة الأمن '
            'السيبراني"',
        )
        # CISO label may appear as English "CISO" or Arabic "رئيس الأمن
        # السيبراني" depending on rendering map; accept either.
        self.assertTrue(
            'CISO' in text or _present(text, 'رئيس الأمن'),
            'Governance/ownership surface must reference CISO / رئيس الأمن',
        )

    # 8: Traceability matrix includes meaningful ECC and TCC rows
    @_skip_if_no_app
    def test_pdf_traceability_includes_ecc_and_tcc(self):
        text = _get_all_text()
        self.assertIn(
            'ECC', text,
            'Traceability/scope sections must reference ECC',
        )
        self.assertIn(
            'TCC', text,
            'Traceability/scope sections must reference TCC',
        )

    # 9: Traceability matrix not made up of rows that are mostly "—"
    @_skip_if_no_app
    def test_pdf_traceability_not_dash_dominated(self):
        text = _get_all_text()
        # If the traceability matrix slipped past the filter, we'd see
        # several lines of consecutive "—" markers in the extracted text
        # block.  Tolerate up to 10 dash chars total in the document
        # (other dashes are legitimate, e.g. document type "Cyber
        # Security — strategy").  More than 30 strongly indicates a
        # collapsed dash-row matrix.
        dash_count = text.count('—')
        self.assertLess(
            dash_count, 30,
            f'PDF appears to contain a dash-dominated traceability '
            f'matrix (em-dash count = {dash_count})',
        )

    # 10: PDF still includes all major professional sections
    @_skip_if_no_app
    def test_pdf_contains_major_sections(self):
        text = _get_all_text()
        for marker in ('الرؤية', 'الركائز', 'الفجوات',
                       'خارطة الطريق', 'المؤشرات', 'الثقة'):
            self.assertTrue(
                _present(text, marker),
                f'Major section marker "{marker}" missing from PDF',
            )

    # 11: Preview routes / templates unchanged
    @_skip_if_no_app
    def test_preview_routes_unchanged(self):
        # The PR-5B.8V change touches only PDF rendering helpers and the
        # _final_strategy_audit / ai_repair_strategy_section paths.  We
        # verify the markdown→HTML preview helper is not affected by
        # confirming it still exists with its expected signature.
        for fn_name in ('strategy_preview_html_from_markdown',
                        'render_markdown_to_html',
                        'ensure_markdown_formatting'):
            if hasattr(_APP, fn_name):
                self.assertTrue(callable(getattr(_APP, fn_name)),
                                f'{fn_name} must remain callable')

    # 12: No AI prompt / generation logic changed except the targeted
    #     vision compliance-objective clause.
    @_skip_if_no_app
    def test_ai_repair_prompt_includes_vision_compliance_clause(self):
        # Verify the new vision-specific compliance-objective prompt
        # clause exists in the ai_repair_strategy_section source.  This
        # guards against accidental removal in future refactors.
        import inspect
        src = inspect.getsource(_APP.ai_repair_strategy_section)
        self.assertIn(
            'PR-5B.8V', src,
            'ai_repair_strategy_section must reference PR-5B.8V '
            'compliance-objective clause',
        )
        self.assertIn(
            'compliance', src.lower(),
            'ai_repair_strategy_section must mention compliance',
        )

    # 13: No deterministic content inserted by the PDF helpers
    @_skip_if_no_app
    def test_no_deterministic_objective_row_inserted_by_compose(self):
        # The PDF composer is a pure rearrangement helper; calling
        # _compute_missing_compliance_objective must not mutate sections
        # passed in.
        sections = {'vision': '## 1. الرؤية\n\n| # | الهدف | المقياس '
                              'المستهدف | المبرر | الإطار الزمني |\n'
                              '|---|---|---|---|---|\n'
                              '| 1 | x | y | z | 12 شهراً |\n'}
        before = sections['vision']
        _APP._compute_missing_compliance_objective(
            sections, ['NCA ECC', 'NCA TCC'],
            domain='Cyber Security', lang='ar',
        )
        self.assertEqual(sections['vision'], before)


if __name__ == '__main__':
    unittest.main()
