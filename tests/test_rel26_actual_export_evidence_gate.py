"""PR-REL2.6 — actual exported DOCX/PDF evidence gate."""

import importlib.util
import os
import sys
import tempfile
import unittest
from unittest import mock

import pytest

_TMP = tempfile.mkdtemp(prefix='test_rel26_')
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
    extract_text_from_pdf_bytes,
    validate_actual_export_evidence,
)
from release_engine.final_quality_contract import evaluate_final_quality
from release_engine.orchestrator import process_release_artifact
from release_engine.rel26_finalize import apply_rel26_cyber_export_evidence_finalize
from release_engine.rendered_evidence_validator import (
    repair_sections_for_rendered_evidence,
)


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


def _live_rel26_defect_sections():
    """Latest live Cyber Arabic Technical DOCX/PDF defect fixture (REL2.6)."""
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
        '| 1 | نسبة الترقيع الأمني خارج SLA | 100% | '
        '(القيمة المحققة / القيمة المستهدفة) × 100 | أداة | شهري |\n'
        '| 2 | عدد حوادث تسرب البيانات الحرجة | 100% | '
        '(عدد العناصر المطابقة / إجمالي العناصر) × 100 | DLP | شهري |\n'
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
    """Minimal DOCX from section text — mirrors live defect visibility in bytes."""
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


def _build_docx_text(sections, *, raw=False):
    if raw:
        return _build_raw_docx_text(sections)
    backend = _backend(with_exports=True)
    build = backend.get('build_docx_bytes')
    if not build:
        pytest.skip('build_docx_bytes unavailable')
    md = _content(sections)
    docx_bytes = build(md, 'strategy', 'ar', domain='cyber',
                       selected_frameworks=['NCA ECC', 'NCA DCC'])
    return extract_text_from_docx_bytes(docx_bytes)


class Rel26DetectionTests(unittest.TestCase):

    def test_latest_docx_text_fails_before_rel26(self):
        sections = _live_rel26_defect_sections()
        text = _build_docx_text(sections, raw=True)
        gate = validate_actual_export_evidence(
            '', text, '', domain='cyber', lang='ar')
        self.assertFalse(gate['export_evidence_passed'])
        self.assertTrue(gate['docx_kpi_defects'])
        self.assertTrue(gate['docx_risk_defects'])

    def test_latest_pdf_or_render_text_fails_before_rel26(self):
        blob = '\n'.join(_live_rel26_defect_sections().values())
        gate = validate_actual_export_evidence(
            blob, blob, '', domain='cyber', lang='ar')
        self.assertFalse(gate['export_evidence_passed'])

    def test_docx_catches_outside_sla_kpi(self):
        text = 'نسبة الترقيع الأمني خارج SLA | 100%'
        gate = validate_actual_export_evidence('', text, '')
        self.assertIn('نسبة الترقيع الأمني خارج SLA',
                        gate['docx_kpi_defects'])

    def test_docx_catches_dlp_critical_percent(self):
        text = (
            '| 2 | عدد حوادث تسرب البيانات الحرجة | 100% | '
            '(عدد العناصر المطابقة / إجمالي العناصر) × 100 |')
        gate = validate_actual_export_evidence('', text, '')
        self.assertTrue(gate['docx_kpi_defects'])

    def test_docx_catches_generic_formula(self):
        text = '(القيمة المحققة / القيمة المستهدفة) × 100'
        gate = validate_actual_export_evidence('', text, '')
        self.assertIn('generic_formula', gate['docx_kpi_defects'])

    def test_docx_catches_risk_dash(self):
        text = (
            '## 7. تقييم الثقة\n'
            '| # | عامل | احتمال | تأثير | خطة المعالجة |\n'
            '| 1 | مخاطر | متوسط | عالٍ | — |')
        gate = validate_actual_export_evidence('', text, '')
        self.assertTrue(gate['docx_risk_defects'])

    def test_docx_catches_roadmap_bad_initiative(self):
        text = '## 5. خارطة الطريق\n| 1 | نسبة التطبيق الكامل |'
        gate = validate_actual_export_evidence('', text, '')
        self.assertTrue(
            any('نسبة التطبيق الكامل' in p
                for p in gate['docx_forbidden_patterns']))

    def test_docx_catches_arabic_residues(self):
        text = 'الحاليةفي الموظفينفي ال منظمة حلولمنع لل معالجة'
        gate = validate_actual_export_evidence('', text, '')
        self.assertTrue(gate['docx_arabic_residues'])

    def test_docx_catches_traceability_bad_mappings(self):
        text = (
            'حماية البيانات | DLP فقط\n'
            'الاستجابة للحوادث | عدم وجود مركز عمليات أمنية\n'
            'SOC (CSIRT)')
        gate = validate_actual_export_evidence('', text, '')
        self.assertTrue(gate['docx_traceability_defects'])


class Rel26RepairIntegrationTests(unittest.TestCase):

    def test_docx_evidence_passes_after_rel26(self):
        sections = _live_rel26_defect_sections()
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
              .get('rel26', {}).get('export') or {})
        self.assertTrue(ev.get('export_evidence_passed'), ev)
        self.assertEqual(ev.get('blocking_errors'), [])

    def test_pdf_evidence_or_render_passes_after_rel26(self):
        sections = _live_rel26_defect_sections()
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
              .get('rel26', {}).get('export') or {})
        self.assertTrue(ev.get('export_evidence_passed'), ev)

    def test_export_route_blocks_bad_docx(self):
        sections = _live_rel26_defect_sections()
        md = _content(sections)
        uid = _APP._make_test_user('rel26_docx_block') if hasattr(
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
                    ('rel26_docx_block', generate_password_hash('x'),
                     'rel26@test.local', 'user'),
                )
                db.commit()
                uid = db.execute(
                    'SELECT id FROM users WHERE username=?',
                    ('rel26_docx_block',)).fetchone()['id']
        client = _APP.app.test_client()
        with client.session_transaction() as sess:
            sess['user_id'] = uid
            sess['username'] = 'rel26_docx_block'
            sess['role'] = 'user'
        with mock.patch.dict(os.environ, {'REL2_SKIP_EXPORT_EVIDENCE': ''}):
            resp = client.post('/api/generate-docx', json={
                'content': md,
                'filename': 'rel26_bad',
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

    def test_release_ready_false_when_export_evidence_fails(self):
        failing = validate_actual_export_evidence(
            '', 'نسبة الترقيع الأمني خارج SLA', '')
        art = {
            'sections': _live_rel26_defect_sections(),
            'final_markdown': _content(_live_rel26_defect_sections()),
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
                    'rel26': {'export': failing},
                },
            },
            'contract_meta': {'selected_frameworks': ['nca_ecc', 'nca_dcc']},
        }
        contract = evaluate_final_quality(
            art, document_type='strategy', lang='ar', skip_structural=True)
        self.assertFalse(contract['actual_export_evidence_passed'])
        self.assertFalse(contract['release_ready_final_passed'])
