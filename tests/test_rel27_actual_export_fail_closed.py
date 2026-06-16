"""PR-REL2.7 — fail-closed actual exported DOCX/PDF evidence gate."""

import importlib.util
import os
import sys
import tempfile
import unittest
from unittest import mock

import pytest

_TMP = tempfile.mkdtemp(prefix='test_rel27_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault(
    'DATABASE_URL',
    'sqlite:///' + os.path.join(_TMP, 'test.db'),
)
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

_APP = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    _spec = importlib.util.spec_from_file_location(
        'app', os.path.join(os.path.dirname(__file__), '..', 'app.py'))
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
    sys.modules['app'] = _APP
except Exception as _e:
    raise SystemExit(f'Cannot load app module: {_e!r}')

from release_engine.export_evidence_validator import (
    extract_text_from_docx_bytes,
    validate_actual_export_evidence,
)
from release_engine.final_quality_contract import evaluate_final_quality
from release_engine.orchestrator import process_release_artifact
from release_engine.rel27_export_checks import (
    check_kpi_canonical,
    check_missing_pillars,
    check_roadmap_coverage,
)
from release_engine.rel27_finalize import REL27_MAX_REPAIR_ATTEMPTS


def _backend(*, with_exports: bool = False):
    if not hasattr(_APP, '_rel2_backend_callables'):
        return {}
    b = _APP._rel2_backend_callables()
    if not with_exports:
        b.pop('build_docx_bytes', None)
        b.pop('build_pdf_bytes', None)
        b['validate_export_evidence'] = False
    else:
        b['validate_export_evidence'] = True
    return b


def _content(sections):
    return _APP._prcy65_rebuild_content_from_sections(sections, None)


def _live_rel27_defect_sections():
    """Latest failing Cyber Arabic Technical export fixture (REL2.7)."""
    from domains.cyber.fixtures_ar import technical_sections
    s = dict(technical_sections())
    s['vision'] = (
        '## 1. الرؤية والأهداف الاستراتيجية\n\n'
        '### الأهداف الاستراتيجية\n\n'
        '| # | الهدف الاستراتيجي | المستهدف القابل للقياس |'
        ' المبرر | الإطار الزمني |\n'
        '|---|---|---|---|---|\n'
        '| 1 | تعزيز إدارة الهوية | تحقيق ≥ 90% لـ IAM | حوكمة | 12 شهراً |\n'
    )
    s['pillars'] = (
        '## 2. الركائز الاستراتيجية\n\n'
        'الحاليةفي المنظمة حلولمنع التهديدات لل معالجة الحوادث.\n'
        'ال منظمة تعتمد على ال معلومات الحساسة.\n'
    )
    s['roadmap'] = (
        '## 5. خارطة الطريق\n\n'
        '| المرحلة | الفترة | المبادرة | المسؤول | المخرج | الإطار |\n'
        '|---|---|---|---|---|---|\n'
        '| المرحلة 1 | 1-6 | نسبة التطبيق الكامل | Owner | هيكل | ECC |\n'
        '| المرحلة 1 | 1-6 | حوكمة | Owner | هيكل | ECC |\n'
        '| المرحلة 2 | 7-12 | SOC | Owner | مركز | ECC |\n'
    )
    s['environment'] = (
        (s.get('environment') or '') + '\nالموظفينفي المنظمة.\n')
    s['kpis'] = (
        '## 6. مؤشرات\n\n'
        '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساب | مصدر | تواتر |\n'
        '|---|---|---|---|---|---|\n'
        '| NCA DCC | نسبة الترقيع الأمني خارج SLA | 100% | '
        '(القيمة المحققة / القيمة المستهدفة) × 100 | أداة | شهري |\n'
        '| 2 | متوسط زمن الاستجابة MTTR | ≤ 4 ساعات | صيغة | SOC | شهري |\n'
        '| 3 | متوسط زمن الاستجابة MTTR | ≤ 4 ساعات | صيغة | SOC | شهري |\n'
        '| 4 | عدد حوادث تسرب البيانات الحرجة | 100% | '
        '(المنجز / المخطط) × 100 | DLP | شهري |\n'
    )
    s['confidence'] = (
        '## 7. تقييم الثقة\n\n'
        '| # | عامل المخاطر | الاحتمالية | التأثير | خطة المعالجة |\n'
        '|---|---|---|---|---|\n'
        '| 1 | هجمات التصيد | متوسط | عالٍ | — |\n'
    )
    s['traceability'] = (
        '## مصفوفة التتبع\n\n'
        '| الإطار | مجال القدرة | الفجوة المرتبطة | المبادرة | المؤشر | الخطر |\n'
        '|---|---|---|---|---|---|\n'
        '| NCA DCC | حماية البيانات | DLP فقط | DLP | KPI | خطر |\n'
        '| NCA DCC | DLP | — | DLP | KPI | خطر |\n'
        '| NCA ECC | الاستجابة للحوادث | عدم وجود مركز عمليات أمنية | '
        'SOC (CSIRT) | MTTR | خطر |\n'
    )
    return s


def _build_raw_docx_text(sections):
    from docx import Document
    from io import BytesIO
    doc = Document()
    for value in sections.values():
        for line in str(value).splitlines():
            line = line.strip()
            if line:
                doc.add_paragraph(line)
    buf = BytesIO()
    doc.save(buf)
    return extract_text_from_docx_bytes(buf.getvalue())


class Rel27DetectionTests(unittest.TestCase):

    def test_latest_docx_fixture_fails_before_rel27(self):
        text = _build_raw_docx_text(_live_rel27_defect_sections())
        gate = validate_actual_export_evidence('', text, '', domain='cyber', lang='ar')
        self.assertFalse(gate['actual_export_evidence_passed'])
        self.assertTrue(gate['docx_kpi_defects'])

    def test_latest_pdf_render_fixture_fails_before_rel27(self):
        blob = '\n'.join(_live_rel27_defect_sections().values())
        gate = validate_actual_export_evidence(blob, blob, '', domain='cyber', lang='ar')
        self.assertFalse(gate['actual_export_evidence_passed'])

    def test_missing_pillars_docx_detected(self):
        text = '## 2. الركائز الاستراتيجية\n\nلا محتوى للركائز.\n'
        self.assertEqual(check_missing_pillars(text), ['missing_pillars'])
        gate = validate_actual_export_evidence('', text, '')
        self.assertTrue(
            any('missing_pillars' in e for e in gate['blocking_errors']))

    def test_missing_pillars_pdf_render_detected(self):
        text = '## 2. الركائز الاستراتيجية\n\nعنوان فقط.\n'
        gate = validate_actual_export_evidence(text, text, '')
        self.assertTrue(gate['docx_missing_sections'])

    def test_kpi_nca_framework_code_in_number_column(self):
        text = (
            '## 6. مؤشرات\n'
            '| NCA ECC | MTTR | 100% | formula | src | mo |')
        kpi = check_kpi_canonical(text)
        self.assertIn('framework_code_in_kpi_number_column', kpi['semantic_defects'])

    def test_duplicate_mttr_detected(self):
        text = (
            '## 6. مؤشرات\n'
            '| 1 | متوسط زمن الاستجابة MTTR | a | b | c | d |\n'
            '| 2 | متوسط زمن الاستجابة MTTR | a | b | c | d |\n')
        kpi = check_kpi_canonical(text)
        self.assertIn('duplicate_MTTR', kpi['duplicate_metrics'])

    def test_dlp_incident_kpi_percent_target(self):
        text = '| 1 | عدد حوادث تسرب البيانات الحرجة | 100% | f | s | m |'
        gate = validate_actual_export_evidence('', text, '')
        self.assertTrue(gate['docx_kpi_defects'])

    def test_generic_formula_detected(self):
        text = (
            '## 6. مؤشرات\n'
            '| 1 | مؤشر | 100% | '
            '(المنجز المقيس ÷ الهدف التشغيلي المعتمد) × 100 | src | mo |')
        gate = validate_actual_export_evidence('', text, '')
        self.assertTrue(gate['docx_kpi_defects'])

    def test_risk_treatment_dash_detected(self):
        text = (
            '## 7. تقييم الثقة\n'
            '| 1 | مخاطر | متوسط | عالٍ | — |')
        gate = validate_actual_export_evidence('', text, '')
        self.assertTrue(gate['docx_risk_defects'])

    def test_roadmap_below_10_rows(self):
        text = (
            '## 5. خارطة الطريق\n'
            '| 1 | 1-6 | SOC | مدير SOC | مركز | ECC |\n')
        road = check_roadmap_coverage(text)
        self.assertLess(road['visible_row_count'], 10)

    def test_traceability_soc_csirt_mixed(self):
        text = 'الاستجابة للحوادث | SOC (CSIRT) | عدم وجود مركز عمليات أمنية'
        gate = validate_actual_export_evidence('', text, '')
        self.assertTrue(gate['docx_traceability_defects'])

    def test_arabic_residues_detected(self):
        text = 'الحاليةفي الموظفينفي ال منظمة حلولمنع'
        gate = validate_actual_export_evidence('', text, '')
        self.assertTrue(gate['docx_arabic_residues'])

    def test_repair_cap_is_two(self):
        self.assertEqual(REL27_MAX_REPAIR_ATTEMPTS, 2)


class Rel27IntegrationTests(unittest.TestCase):

    def test_docx_passes_after_canonical_repair(self):
        sections = _live_rel27_defect_sections()
        out = process_release_artifact(
            {
                'sections': sections,
                'final_markdown': _content(sections),
                'blocking_errors': [],
                'sealed': False,
                'domain': 'cyber',
                'contract_meta': {'selected_frameworks': ['nca_ecc', 'nca_dcc']},
            },
            domain='cyber', lang='ar',
            backend=_backend(with_exports=True), skip_rel1=True)
        ev = ((out.get('diagnostics') or {}).get('rel2', {})
              .get('rel27', {}).get('export')
              or (out.get('diagnostics') or {}).get('rel2', {})
              .get('rel26', {}).get('export') or {})
        self.assertTrue(ev.get('actual_export_evidence_passed'), ev)
        self.assertEqual(ev.get('blocking_errors'), [])

    def test_pdf_passes_after_canonical_repair(self):
        sections = _live_rel27_defect_sections()
        out = process_release_artifact(
            {
                'sections': sections,
                'final_markdown': _content(sections),
                'blocking_errors': [],
                'sealed': False,
                'domain': 'cyber',
                'contract_meta': {'selected_frameworks': ['nca_ecc', 'nca_dcc']},
            },
            domain='cyber', lang='ar',
            backend=_backend(with_exports=True), skip_rel1=True)
        ev = ((out.get('diagnostics') or {}).get('rel2', {})
              .get('rel27', {}).get('export')
              or (out.get('diagnostics') or {}).get('rel2', {})
              .get('rel26', {}).get('export') or {})
        self.assertTrue(ev.get('actual_export_evidence_passed'), ev)

    def test_export_route_fails_closed_on_bad_docx(self):
        sections = _live_rel27_defect_sections()
        md = _content(sections)
        uid = _APP._make_test_user('rel27_docx_block') if hasattr(
            _APP, '_make_test_user') else None
        if uid is None:
            from werkzeug.security import generate_password_hash
            with _APP.app.app_context():
                _APP.init_db()
                db = _APP.get_db()
                db.execute(
                    'INSERT OR IGNORE INTO users '
                    '(username, password_hash, email, role, is_active) '
                    'VALUES (?, ?, ?, ?, 1)',
                    ('rel27_docx_block', generate_password_hash('x'),
                     'rel27@test.local', 'user'),
                )
                db.commit()
                uid = db.execute(
                    'SELECT id FROM users WHERE username=?',
                    ('rel27_docx_block',)).fetchone()['id']
        client = _APP.app.test_client()
        with client.session_transaction() as sess:
            sess['user_id'] = uid
            sess['username'] = 'rel27_docx_block'
            sess['role'] = 'user'
        with mock.patch.dict(os.environ, {'REL2_SKIP_EXPORT_EVIDENCE': ''}):
            resp = client.post('/api/generate-docx', json={
                'content': md,
                'filename': 'rel27_bad',
                'language': 'ar',
                'org_name': 'منظمة',
                'sector': 'حكومي',
                'doc_type': 'Strategy Document',
                'domain': 'Cyber Security',
                'artifact_type': 'strategy',
                'generation_mode': 'drafting',
                'selected_frameworks': ['NCA ECC', 'NCA DCC'],
            })
        self.assertEqual(resp.status_code, 422, resp.get_data(as_text=True)[:500])
        body = resp.get_json() or {}
        if _APP._PRCY28_VERSION_FLAGS.get('rel31'):
            self.assertEqual(body.get('reason'), 'rel3_export_evidence_failed')
        else:
            self.assertEqual(
                body.get('reason'), 'rel2_actual_export_evidence_failed')

    def test_release_ready_false_when_actual_export_fails(self):
        failing = validate_actual_export_evidence(
            '', 'الحاليةفي', '')
        art = {
            'sections': _live_rel27_defect_sections(),
            'final_markdown': _content(_live_rel27_defect_sections()),
            'blocking_errors': [],
            'sealed': True,
            'final_hash': 'deadbeef',
            'domain': 'cyber',
            'diagnostics': {
                'rel2': {
                    'rel23': {'section_parity': {'parity_passed': True}},
                    'rel24': {
                        'substantive_gate': {
                            'board_ready_substance_passed': True,
                            'blocking_errors': [],
                        },
                    },
                    'rel25': {
                        'evidence': {'rendered_evidence_passed': True},
                    },
                    'rel27': {'export': failing},
                },
            },
            'contract_meta': {'selected_frameworks': ['nca_ecc', 'nca_dcc']},
        }
        contract = evaluate_final_quality(
            art, document_type='strategy', lang='ar', skip_structural=True)
        self.assertFalse(contract['release_ready_final_passed'])
        self.assertFalse(contract['actual_export_evidence_passed'])


class Rel271RepairTests(unittest.TestCase):

    def test_arabic_gate_fixes_hulul_mana(self):
        from release_engine.arabic_language_gate import apply_arabic_final_gate
        sections = {'environment': 'تطبيق حلولمنع تسرب البيانات'}
        out, diag = apply_arabic_final_gate(sections, lang='ar')
        self.assertNotIn('حلولمنع', out['environment'])
        self.assertIn('حلول لمنع', out['environment'])
        self.assertEqual(diag.get('residues_after'), [])

    def test_normalize_pillar_blocks_canonical_fallback(self):
        from professional_strategy_render import normalize_pillar_blocks
        blocks = normalize_pillar_blocks('## الركائز\n\nنص بدون عناوين فرعية.', 'ar')
        self.assertTrue(blocks)
        titles = ' '.join(pb.get('title') or '' for pb in blocks)
        self.assertIn('حوكمة', titles)
        self.assertIn('الحماية', titles)

    def test_repair_for_actual_export_defects_arabic_and_pillars(self):
        from release_engine.export_evidence_validator import (
            repair_for_actual_export_defects,
        )
        sections = _live_rel27_defect_sections()
        artifact = {
            'sections': dict(sections),
            'final_markdown': _content(sections),
            'contract_meta': {'selected_frameworks': ['nca_ecc', 'nca_dcc']},
        }
        export_diag = {
            'blocking_errors': [
                'rel2_actual_export_evidence_failed:preview:حلولمنع',
                'rel2_actual_export_evidence_failed:docx:missing_pillars',
            ],
            'docx_missing_sections': ['pillars'],
            'preview_forbidden_patterns': ['حلولمنع'],
        }
        merged, repairs = repair_for_actual_export_defects(
            artifact, export_diag, domain='cyber', lang='ar', backend={})
        blob = merged.get('final_markdown') or ''
        self.assertNotIn('حلولمنع', blob)
        self.assertIn('rel271:forced_canonical_pillars_for_docx', repairs)
        self.assertIn('الحماية والكشف والاستجابة', merged['sections']['pillars'])
