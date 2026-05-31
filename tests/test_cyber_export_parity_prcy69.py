"""PR-CY69 — Enforce PR-CY68 semantic polish in the final saved/exported artifact."""

import functools
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_export_parity_prcy69_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault(
    'DATABASE_URL',
    'sqlite:///' + os.path.join(_TMP_DB_DIR, 'test.db'),
)
os.environ.setdefault('OPENAI_API_KEY', '')

_APP = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    _spec = importlib.util.spec_from_file_location(
        'app', os.path.join(os.path.dirname(__file__), '..', 'app.py'))
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
except Exception as _e:  # pragma: no cover
    raise SystemExit(f'Cannot load app module: {_e!r}')


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

_ROADMAP_ECC_ONLY_AR = (
    '## 5. خارطة الطريق\n\n'
    '| المرحلة | المدة | النشاط | المسؤول | المخرج | الإطار |\n'
    '|---|---|---|---|---|---|\n'
    '| المرحلة 1 | 1-6 أشهر | تأسيس SOC و SIEM | CISO | SOC تشغيلي | NCA ECC |\n'
    '| المرحلة 2 | 6-12 شهر | تطبيق IAM/PAM/MFA | CISO | MFA مفعّل | NCA ECC |\n'
    '| المرحلة 2 | 6-12 شهر | تأسيس CSIRT | CISO | فريق CSIRT | NCA ECC |\n'
    '| المرحلة 3 | 9-12 شهر | إدارة الثغرات | CISO | VM منصة | NCA ECC |\n'
)

_KPI_STUB = (
    '## 6. مؤشرات الأداء الرئيسية\n\n'
    '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساب |'
    ' مصدر البيانات/الأداة | تواتر القياس |\n'
    '|---|---|---|---|---|---|\n'
    '| 1 | تغطية | ≥ 95% | (x/y)*100 | VM | شهري |\n'
)

_CONF_CITC_AR = (
    '## 7. تقييم الثقة\n\n'
    '**درجة الثقة:** 82%\n'
    '**مبررات التقييم:** الامتثال لهيئة الاتصالات وتقنية المعلومات.\n'
)

_CONF_STUB = (
    '## 7. تقييم الثقة\n\n'
    '**درجة الثقة:** 82%\n'
    '**مبررات التقييم:** نص.\n'
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


class Prcy69FinalArtifactParityTests(unittest.TestCase):

    @_skip_if_no_app
    def test_helper_present(self):
        self.assertTrue(hasattr(_APP, '_prcy69_enforce_final_artifact_parity'))
        self.assertTrue(hasattr(_APP, '_prcy69_strip_internal_markers'))

    @_skip_if_no_app
    def test_section_marker_stripped(self):
        dirty = '## 1. الرؤية\n\n[SECTION]\n\nنص.\n'
        clean = _APP._prcy69_strip_internal_markers(dirty)
        self.assertNotIn('[SECTION]', clean)
        self.assertNotIn('SECTION', clean.split())

    @_skip_if_no_app
    def test_parity_requires_dcc_objective_in_final_markdown(self):
        sections = _minimal_sections()
        content = _APP._prcy66_rebuild_canonical_content(sections, '')
        result = _APP._prcy69_enforce_final_artifact_parity(
            content, sections, 'ar', ['nca_ecc', 'nca_dcc'],
            'cyber', output_type='generation')
        md = result.get('final_markdown') or ''
        diag = result.get('diag') or {}
        self.assertTrue(diag.get('dcc_objective_present_in_final_artifact'))
        self.assertTrue(
            _APP._prcy67_detect_objective_families(md).get(
                'data_protection_dcc'))
        self.assertTrue(diag.get('parity_valid'))

    @_skip_if_no_app
    def test_parity_requires_three_dcc_roadmap_rows(self):
        sections = _minimal_sections()
        content = _APP._prcy66_rebuild_canonical_content(sections, '')
        result = _APP._prcy69_enforce_final_artifact_parity(
            content, sections, 'ar', ['nca_ecc', 'nca_dcc'],
            'cyber', output_type='pdf')
        diag = result.get('diag') or {}
        self.assertGreaterEqual(
            diag.get('dcc_roadmap_rows_count_in_final_artifact', 0), 3)
        self.assertNotIn(
            'prcy68_final_artifact_missing_dcc_roadmap_rows',
            '|'.join(result.get('blockers') or []))

    @_skip_if_no_app
    def test_preview_pdf_docx_share_polished_hash(self):
        sections = _minimal_sections()
        content = _APP._prcy66_rebuild_canonical_content(sections, '')
        hashes = {}
        for route in ('preview', 'pdf', 'docx'):
            result = _APP._prcy69_enforce_final_artifact_parity(
                content, dict(sections), 'ar', ['nca_ecc', 'nca_dcc'],
                'cyber', output_type=route)
            hashes[route] = _APP._prcy25_compute_content_hash(
                result.get('final_markdown') or '')
        self.assertEqual(hashes['preview'], hashes['pdf'])
        self.assertEqual(hashes['pdf'], hashes['docx'])

    @_skip_if_no_app
    def test_confidence_regulator_normalized_to_nca(self):
        sections = _minimal_sections(confidence=_CONF_CITC_AR)
        fixed, changed = _APP._prcy69_fix_confidence_regulator_refs(
            sections['confidence'], 'ar', ['nca_ecc', 'nca_dcc'], 'cyber')
        self.assertTrue(changed)
        self.assertIn('NCA', fixed)
        self.assertNotIn('هيئة الاتصالات وتقنية المعلومات', fixed)

    @_skip_if_no_app
    def test_dcc_traceability_encryption_not_vulnerability(self):
        sections = _minimal_sections(
            gaps=(
                '## 4. الفجوات\n\n'
                '| # | الفجوة | الإطار | الأولوية | الإجراء |\n'
                '|---|---|---|---|---|\n'
                '| 1 | ضعف إدارة الثغرات | DCC | عالية | VM |\n'),
            environment='## 3. البيئة\n\nتصنيف وتشفير DLP.\n',
            roadmap=_ROADMAP_ECC_ONLY_AR + (
                '\n| المرحلة 3 | 9-12 شهر | تفعيل DLP | CISO | '
                'DLP | NCA DCC |\n'),
        )
        trace = _APP._build_traceability_matrix(
            sections, ['ECC', 'DCC'], 'ar', domain_code='cyber')
        enc_rows = [
            r for r in (trace.get('rows') or [])
            if len(r) >= 6 and 'تشفير' in str(r[1])]
        self.assertTrue(enc_rows)
        for r in enc_rows:
            gap = str(r[2])
            self.assertNotIn('ثغر', gap)
            self.assertNotIn('vulnerability', gap.lower())

    @_skip_if_no_app
    def test_dlp_traceability_maps_to_data_leakage(self):
        sections = _minimal_sections(
            gaps=(
                '## 4. الفجوات\n\n'
                '| — | غياب ضوابط منع تسرب البيانات DLP | DCC | عالية | '
                'تفعيل DLP |\n'),
            roadmap=_ROADMAP_ECC_ONLY_AR,
        )
        valid = _APP._prcy68_validate_traceability_dcc_mapping(
            sections, ['nca_ecc', 'nca_dcc'], 'ar')
        self.assertTrue(valid)

    @_skip_if_no_app
    def test_contract_blocks_section_marker_leak(self):
        bad = (
            '## 1. الرؤية والأهداف الاستراتيجية\n\n[SECTION]\n\n'
            + _VISION_GOV_ONLY_AR.split('## 1.')[1]
            + _ROADMAP_ECC_ONLY_AR + _KPI_STUB + _CONF_STUB)
        result = _APP._cyber_final_export_contract(
            bad,
            metadata={'domain': 'cyber'},
            selected_frameworks=['nca_ecc', 'nca_dcc'],
            lang='ar',
            domain='cyber',
            output_type='generation',
        )
        md = result.get('final_markdown') or ''
        blockers = result.get('blocking_errors') or []
        self.assertNotIn('[SECTION]', md)
        marker_blockers = [
            b for b in blockers
            if 'internal_marker_leak' in (b or '')]
        self.assertEqual(marker_blockers, [])


if __name__ == '__main__':
    unittest.main()
