"""PR-CY68 — Final Cyber semantic completeness and PDF polish.

Run:
    python -m pytest tests/test_cyber_export_parity_prcy68.py -v
    pytest -k "cyber or prcy or composer_metadata"
"""

import functools
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_export_parity_prcy68_')
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
_P41 = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    _APP_PATH = os.path.join(os.path.dirname(__file__), '..', 'app.py')
    _spec = importlib.util.spec_from_file_location('app', _APP_PATH)
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
    import professional_strategy_render as _P41
except Exception as _e:  # pragma: no cover
    raise SystemExit(f'Cannot load modules: {_e!r}')


def _skip_if_no_app(fn):
    @functools.wraps(fn)
    def _wrapped(self, *a, **kw):
        if _APP is None:
            self.skipTest('app.py could not be imported')
        return fn(self, *a, **kw)
    return _wrapped


_VISION_GOV_ONLY_AR = (
    '## 1. الرؤية والأهداف الاستراتيجية\n\n'
    '### الأهداف الاستراتيجية\n\n'
    '| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n'
    '|---|---|---|---|---|\n'
    '| 1 | إنشاء إدارة الأمن السيبراني وتعيين رئيس الأمن السيبراني CISO |'
    ' تأسيس الهيكل 100% | قيادة | 6 أشهر |\n'
)

_VISION_WEAK_COMPLIANCE_AR = (
    '## 1. الرؤية والأهداف الاستراتيجية\n\n'
    '### الأهداف الاستراتيجية\n\n'
    '| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n'
    '|---|---|---|---|---|\n'
    '| 1 | تحقيق الالتزام بضوابط NCA ECC و NCA DCC |'
    ' امتثال 75% | تنظيمي | 12 شهر |\n'
)

_ROADMAP_ECC_ONLY_AR = (
    '## 5. خارطة الطريق\n\n'
    '| المرحلة | المدة | النشاط | المسؤول | المخرج | الإطار |\n'
    '|---|---|---|---|---|---|\n'
    '| المرحلة 1 | 1-6 أشهر | تأسيس SOC و SIEM | CISO | SOC تشغيلي | NCA ECC |\n'
    '| المرحلة 2 | 6-12 شهر | تطبيق IAM/PAM/MFA | CISO | MFA مفعّل | NCA ECC |\n'
    '| المرحلة 2 | 6-12 شهر | تأسيس CSIRT | CISO | فريق CSIRT | NCA ECC |\n'
    '| المرحلة 3 | 9-12 شهر | إدارة الثغرات | CISO | VM منصة | NCA ECC |\n'
)

_PILLARS_DLP_ENC_AR = (
    '## 2. الركائز\n\n'
    '| # | المبادرة | الوصف | المخرج المتوقع |\n'
    '|---|---|---|---|\n'
    '| 1 | DLP | تفعيل DLP ومراقبة تسرب البيانات مع DCC | '
    'منصة DLP وقواعد مراقبة تسرب البيانات مفعّلة مع DCC وضوابط DCC | \n'
    '| 2 | Encryption | تطبيق التشفير | '
    'ضوابط التشفير وإدارة المفاتيح مطبقة على البيانات المصنفة '
    'مع DCC وضوابط DCC | \n'
)

_KPI_DETECTION_MISMATCH_AR = (
    '## 6. مؤشرات الأداء الرئيسية\n\n'
    '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساب |'
    ' مصدر البيانات/الأداة | تواتر القياس |\n'
    '|---|---|---|---|---|---|\n'
    '| 1 | متوسط زمن اكتشاف الحوادث الأمنية | < 4 ساعات | '
    'مجموع أزمنة الاستجابة للحوادث الحرجة / عدد الحوادث الحرجة | '
    'ITSM / SOAR / SIEM | شهري |\n'
)

_KPI_STUB = (
    '## 6. مؤشرات الأداء الرئيسية\n\n'
    '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساب |'
    ' مصدر البيانات/الأداة | تواتر القياس |\n'
    '|---|---|---|---|---|---|\n'
    '| 1 | تغطية | ≥ 95% | (x/y)*100 | VM | شهري |\n'
)

_CONF_STUB = (
    '## 7. تقييم الثقة\n\n'
    '**درجة الثقة:** 82%\n'
    '**مبررات التقييم:** نص.\n'
)

_GAPS_VULN_DLP_AR = (
    '## 4. الفجوات\n\n'
    '| # | الفجوة | الإطار | الأولوية | الإجراء |\n'
    '|---|---|---|---|---|\n'
    '| 1 | ضعف إدارة الثغرات | DCC | عالية | VM | \n'
)


def _minimal_sections(**overrides):
    base = {
        'vision': _VISION_GOV_ONLY_AR,
        'pillars': '## 2. الركائز\n\nنص.\n',
        'environment': '## 3. البيئة\n\nنص.\n',
        'gaps': '## 4. الفجوات\n\nGap #1 Implementation Guide steps.\n',
        'roadmap': _ROADMAP_ECC_ONLY_AR,
        'kpis': _KPI_STUB,
        'confidence': _CONF_STUB,
    }
    base.update(overrides)
    return base


def _run_prcy68(sections, content='', **kwargs):
    buf = io.StringIO()
    with redirect_stdout(buf):
        result = _APP._prcy68_final_semantic_polish(
            sections=dict(sections),
            final_markdown=content,
            lang='ar',
            selected_frameworks=['nca_ecc', 'nca_dcc'],
            domain='cyber',
            metadata={'domain': 'cyber'},
            output_type='test',
            **kwargs,
        )
    return result, buf.getvalue()


class Prcy68SemanticPolishTests(unittest.TestCase):

    @_skip_if_no_app
    def test_helper_present(self):
        self.assertTrue(hasattr(_APP, '_prcy68_final_semantic_polish'))
        self.assertTrue(hasattr(_APP, '_prcy68_emit_semantic_polish_diag'))

    @_skip_if_no_app
    def test_dcc_objective_inserted_when_missing(self):
        sections = _minimal_sections()
        fam_before = _APP._prcy67_detect_objective_families(
            sections['vision'])
        self.assertFalse(fam_before.get('data_protection_dcc'))
        result, log = _run_prcy68(sections)
        vision = (result.get('sections') or {}).get('vision', '')
        fam_after = _APP._prcy67_detect_objective_families(vision)
        self.assertTrue(fam_after.get('data_protection_dcc'))
        self.assertTrue((result.get('diag') or {}).get(
            'dcc_objective_present'))
        self.assertIn('[CYBER-FINAL-SEMANTIC-POLISH-DIAG]', log)

    @_skip_if_no_app
    def test_compliance_target_normalized_to_90(self):
        sections = _minimal_sections(vision=_VISION_WEAK_COMPLIANCE_AR)
        result, _log = _run_prcy68(sections)
        vision = (result.get('sections') or {}).get('vision', '')
        self.assertIn('≥90%', vision)
        self.assertNotIn('75%', vision)
        self.assertTrue((result.get('diag') or {}).get(
            'compliance_target_normalized'))

    @_skip_if_no_app
    def test_roadmap_includes_dcc_classification_encryption_dlp(self):
        sections = _minimal_sections()
        result, _log = _run_prcy68(sections)
        roadmap = (result.get('sections') or {}).get('roadmap', '')
        self.assertIn('تصنيف', roadmap)
        self.assertIn('تشفير', roadmap)
        self.assertIn('DLP', roadmap)
        dcc_cnt = (result.get('diag') or {}).get('dcc_roadmap_rows_count', 0)
        self.assertGreaterEqual(dcc_cnt, 3)
        for row in roadmap.split('\n'):
            if row.strip().startswith('|') and 'DLP' in row:
                self.assertIn('NCA DCC', row)
            if row.strip().startswith('|') and 'تصنيف' in row:
                if 'NCA DCC' in row or 'NCA ECC' in row:
                    self.assertIn('NCA DCC', row)

    @_skip_if_no_app
    def test_ecc_rows_remain_soc_iam_csirt_vulnerability(self):
        sections = _minimal_sections()
        result, _log = _run_prcy68(sections)
        roadmap = (result.get('sections') or {}).get('roadmap', '')
        ecc_rows = [
            ln for ln in roadmap.split('\n')
            if ln.strip().startswith('|') and 'NCA ECC' in ln]
        self.assertGreaterEqual(len(ecc_rows), 4)
        blob = '\n'.join(ecc_rows).lower()
        self.assertIn('soc', blob)
        self.assertIn('iam', blob)
        self.assertIn('csirt', blob)
        self.assertTrue(
            'ثغر' in blob or 'vm' in blob or 'vuln' in blob)

    @_skip_if_no_app
    def test_dlp_encryption_outputs_compacted(self):
        sections = _minimal_sections(pillars=_PILLARS_DLP_ENC_AR)
        result, _log = _run_prcy68(sections)
        pillars = (result.get('sections') or {}).get('pillars', '')
        diag = result.get('diag') or {}
        self.assertIn(_APP._PRCY68_DLP_OUTPUT_AR, pillars)
        self.assertIn(_APP._PRCY68_ENCRYPTION_OUTPUT_AR, pillars)
        rows = _APP._prcy19_strip_md_table_rows(pillars)
        for r in rows:
            if r.get('kind') != 'data' or len(r.get('cells') or []) < 4:
                continue
            deliverable = r['cells'][-1]
            self.assertNotIn('DCC وضوابط DCC', deliverable)
        self.assertTrue(diag.get('dlp_output_compacted'))
        self.assertTrue(diag.get('encryption_output_compacted'))

    @_skip_if_no_app
    def test_detection_kpi_not_using_response_formula(self):
        sections = _minimal_sections(kpis=_KPI_DETECTION_MISMATCH_AR)
        result, _log = _run_prcy68(sections)
        kpis = (result.get('sections') or {}).get('kpis', '')
        self.assertIn('اكتشاف', kpis)
        self.assertIn('مجموع أزمنة اكتشاف', kpis)
        self.assertNotIn('مجموع أزمنة الاستجابة', kpis)
        self.assertIn('SIEM / SOC', kpis)
        self.assertTrue((result.get('diag') or {}).get(
            'kpi_detection_response_alignment_valid'))

    @_skip_if_no_app
    def test_dcc_traceability_dlp_not_mapped_to_vulnerability_gap(self):
        sections = _minimal_sections(
            gaps=_GAPS_VULN_DLP_AR,
            environment=(
                '## 3. البيئة\n\n'
                'DLP وتسرب البيانات والتشفير وتصنيف البيانات.\n'),
            roadmap=_ROADMAP_ECC_ONLY_AR + (
                '\n| المرحلة 3 | 9-12 شهر | تفعيل DLP | CISO | '
                'DLP | NCA DCC |\n'),
        )
        trace = _APP._build_traceability_matrix(
            sections, ['ECC', 'DCC'], 'ar', domain_code='cyber')
        dlp_rows = [
            r for r in (trace.get('rows') or [])
            if len(r) >= 6 and (
                'DLP' in str(r[1]) or 'تسرب' in str(r[1]))]
        self.assertTrue(dlp_rows, 'expected a DLP traceability row')
        for r in dlp_rows:
            gap = str(r[2])
            self.assertNotIn('ثغر', gap)
            self.assertNotIn('vulnerability', gap.lower())
        valid = _APP._prcy68_validate_traceability_dcc_mapping(
            sections, ['nca_ecc', 'nca_dcc'], 'ar')
        self.assertTrue(valid)

    @_skip_if_no_app
    def test_pdf_objectives_use_readable_card_layout(self):
        from tests.test_cyber_export_parity_prcy50 import _model
        model = _model()
        fb = _P41.compute_pdf_export_layout_fallbacks(model, 'ar')
        self.assertEqual(fb.get('strategic_objectives'), 'objective_cards')
        self.assertTrue(
            _P41.pdf_objectives_readable_layout_applied(model, 'ar'))

    @_skip_if_no_app
    def test_incident_detection_family_in_render_module(self):
        name = 'متوسط زمن اكتشاف الحوادث الأمنية'
        family = _P41._detect_kpi_metric_family(
            name, '< 4 ساعات',
            'مجموع أزمنة الاستجابة للحوادث الحرجة / عدد الحوادث',
            'KPI', 'ar')
        self.assertEqual(family, 'incident_detection_time')
        nn, _, nt, nf, ns = _P41._apply_kpi_metric_family_spec(
            family, name, 'KPI', '< 4 ساعات',
            'مجموع أزمنة الاستجابة للحوادث الحرجة / عدد الحوادث',
            'ITSM', 'ar')
        self.assertIn('اكتشاف', nn)
        self.assertIn('اكتشاف', nf)
        self.assertIn('SIEM / SOC', ns)


if __name__ == '__main__':
    unittest.main()
