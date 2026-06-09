"""PR-REL2.5 — rendered evidence quality gates for live Cyber AR documents.

Release scope: PR-REL2.5 enforces rendered evidence on Cyber Arabic Technical.
National launch needs equivalent gates for other domains/languages/doc types.
"""

import importlib.util
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

import pytest

_TMP = tempfile.mkdtemp(prefix='test_rel25_')
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

from release_engine.final_quality_contract import evaluate_final_quality
from release_engine.orchestrator import process_release_artifact
from release_engine.rendered_evidence_validator import (
    collect_rendered_texts,
    detect_rendered_defects,
    extract_docx_visible_text,
    extract_pdf_visible_text,
    repair_sections_for_rendered_evidence,
    validate_rendered_evidence,
)
from release_engine.rel25_finalize import apply_rel25_cyber_evidence_finalize


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


def _make_test_user(username='rel25_export_user'):
    from werkzeug.security import generate_password_hash
    with _APP.app.app_context():
        _APP.init_db()
        db = _APP.get_db()
        cols = [c['name'] for c in db.execute(
            'PRAGMA table_info(users)').fetchall()]
        if 'password_hash' in cols:
            db.execute(
                'INSERT OR IGNORE INTO users '
                '(username, password_hash, email, role, is_active) '
                'VALUES (?, ?, ?, ?, 1)',
                (username, generate_password_hash('rel25'),
                 f'{username}@test.local', 'user'),
            )
        else:
            db.execute(
                'INSERT OR IGNORE INTO users '
                '(username, password, email, role) '
                'VALUES (?, ?, ?, ?)',
                (username, generate_password_hash('rel25'),
                 f'{username}@test.local', 'user'),
            )
        db.commit()
        return db.execute(
            'SELECT id FROM users WHERE username=?', (username,)
        ).fetchone()['id']


_FORBIDDEN_EXPORT_PATTERNS = (
    'تحقيق ≥ 90% لـ',
    '≥ 90% لـ',
    'نسبة الترقيع الأمني خارج SLA',
    'عدد حوادث تسرب البيانات (DLP)',
    '(عدد العناصر المطابقة / إجمالي العناصر) × 100',
    'لل معالجة',
    'للتعاملمع',
    'الاجتماعيةضد',
    'الاستعادةفي',
    'ال معلومات',
    'ال معمول',
    'ل منع',
    'ال معيارية',
    'المسؤول أمن السيبرانيe',
    'Lead e',
    'عدم وجود مركز عمليات أمنية',
)


def _forbidden_found_in(text):
    return [p for p in _FORBIDDEN_EXPORT_PATTERNS if p in (text or '')]


def _build_pdf_via_route(content, *, frameworks=None):
    uid = _make_test_user()
    client = _APP.app.test_client()
    with client.session_transaction() as sess:
        sess['user_id'] = uid
        sess['username'] = 'rel25_export_user'
        sess['role'] = 'user'
    payload = {
        'content': content,
        'filename': 'rel25_test',
        'language': 'ar',
        'org_name': 'منظمة اختبار',
        'sector': 'حكومي',
        'doc_type': 'Strategy Document',
        'domain': 'Cyber Security',
        'artifact_type': 'strategy',
        'generation_mode': 'drafting',
        'selected_frameworks': frameworks or ['NCA ECC', 'NCA DCC'],
    }
    return client.post('/api/generate-pdf', json=payload)


def _content(sections):
    return _APP._prcy65_rebuild_content_from_sections(sections, None)


def _live_rel25_defect_sections():
    """Latest live Cyber Arabic Technical DOCX/PDF defect fixture."""
    from domains.cyber.fixtures_ar import technical_sections
    s = dict(technical_sections())
    s['vision'] = (
        '## 1. الرؤية والأهداف الاستراتيجية\n\n'
        '### الأهداف الاستراتيجية\n\n'
        '| # | الهدف الاستراتيجي | المستهدف القابل للقياس |'
        ' المبرر | الإطار الزمني |\n'
        '|---|---|---|---|---|\n'
        '| 1 | تعزيز إدارة الهوية والوصول والصلاحيات المميزة | '
        'تحقيق ≥ 90% لـ تعزيز إدارة الهوية والوصول والصلاحيات المميزة | '
        'حوكمة | 12 شهراً |\n'
        '| 2 | تطوير برنامج إدارة الثغرات | ≥ 90% | تشغيل | 12 شهر |\n'
    )
    s['pillars'] = (
        '## 2. الركائز الاستراتيجية\n\n'
        '### حوكمة ونموذج التشغيل\n'
        '- اعتماد السياسات\n'
        '- ميثاق اللجنة\n'
        '- توزيع المسؤوليات\n'
    )
    s['roadmap'] = (
        '## 5. خارطة الطريق\n\n'
        '| المرحلة | الفترة | المبادرة | المسؤول | المخرج | الإطار |\n'
        '|---|---|---|---|---|---|\n'
        '| المرحلة 1 | 1-6 | حوكمة | Owner | هيكل | ECC |\n'
        '| المرحلة 2 | 7-12 | SOC | Owner | مركز | ECC |\n'
        '| المرحلة 2 | 7-12 | IAM | Owner | ضوابط | ECC |\n'
    )
    s['environment'] = (
        (s.get('environment') or '') + '\nسياق لل معالجة البيانات الحساسة.\n')
    s['gaps'] = (s.get('gaps') or '') + '\nفجوة لل معالجة البيانات.\n'
    s['kpis'] = (
        '## 6. مؤشرات\n\n'
        '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساب | مصدر | تواتر |\n'
        '|---|---|---|---|---|---|\n'
        '| 1 | نسبة الترقيع الأمني خارج SLA | 100% | '
        '(عدد العناصر المطابقة / إجمالي العناصر) × 100 | أداة | شهري |\n'
        '| 2 | عدد حوادث تسرب البيانات (DLP) | ≥95% | '
        '(عدد العناصر المطابقة / إجمالي العناصر) × 100 | DLP | شهري |\n'
    )
    s['confidence'] = (
        '## 7. تقييم الثقة\n\n'
        '| # | عامل المخاطر | الاحتمالية | التأثير | خطة المعالجة |\n'
        '|---|---|---|---|---|\n'
        '| 1 | هجمات التصيد الاحتيالي | متوسط | عالٍ | — |\n'
        '| 2 | اختراق IAM | عالٍ | عالٍ | — |\n'
    )
    s['traceability'] = (
        '## مصفوفة التتبع\n\n'
        '| الإطار | مجال القدرة | الفجوة المرتبطة | المبادرة | المؤشر | الخطر |\n'
        '|---|---|---|---|---|---|\n'
        '| NCA ECC | الاستجابة للحوادث | عدم وجود مركز عمليات أمنية | '
        'SOC | MTTR | خطر |\n'
        '| NCA DCC | DLP | — | DLP | KPI | خطر |\n'
    )
    return s


class Rel25DetectionTests(unittest.TestCase):

    def test_live_fixture_fails_before_rel25(self):
        sections = _live_rel25_defect_sections()
        blob = '\n'.join(sections.values())
        d = detect_rendered_defects(preview_text=blob)
        self.assertFalse(d['rendered_evidence_passed'])
        self.assertTrue(d['weak_objective_targets_found'])
        self.assertTrue(d['kpi_semantic_defects_found'])
        self.assertTrue(d['risk_empty_treatments_found'])
        self.assertTrue(d['traceability_bad_mappings_found'])
        self.assertTrue(d['arabic_residues_found'])

    def test_weak_iam_target_detected(self):
        blob = 'تحقيق ≥ 90% لـ تعزيز إدارة الهوية'
        d = detect_rendered_defects(preview_text=blob)
        self.assertIn('تحقيق ≥ 90% لـ', d['weak_objective_targets_found'])

    def test_outside_sla_kpi_detected(self):
        blob = 'نسبة الترقيع الأمني خارج SLA'
        d = detect_rendered_defects(preview_text=blob)
        self.assertIn('نسبة الترقيع الأمني خارج SLA',
                      d['kpi_semantic_defects_found'])

    def test_dlp_percentage_target_detected(self):
        blob = '| 2 | عدد حوادث تسرب البيانات (DLP) | ≥95% |'
        d = detect_rendered_defects(preview_text=blob)
        self.assertIn('عدد حوادث تسرب البيانات (DLP)',
                      d['kpi_semantic_defects_found'])

    def test_generic_formula_detected(self):
        blob = (
            '## 6. مؤشرات الأداء\n'
            '| # | وصف المؤشر | القيمة | صيغة الاحتساب |\n'
            '| 1 | مؤشر | 100% | '
            '(عدد العناصر المطابقة / إجمالي العناصر) × 100 |')
        d = detect_rendered_defects(preview_text=blob)
        self.assertIn('generic_formula', d['kpi_semantic_defects_found'])

    def test_risk_dash_treatment_detected(self):
        blob = (
            '## 7. تقييم الثقة\n'
            '| # | عامل المخاطر | الاحتمالية | التأثير | خطة المعالجة |\n'
            '| 1 | مخاطر | متوسط | عالٍ | — |')
        d = detect_rendered_defects(preview_text=blob)
        self.assertTrue(d['risk_empty_treatments_found'])

    def test_ecc_soc_mapping_detected(self):
        blob = 'الاستجابة للحوادث | عدم وجود مركز عمليات أمنية'
        d = detect_rendered_defects(preview_text=blob)
        self.assertTrue(d['traceability_bad_mappings_found'])

    def test_arabic_residue_detected(self):
        blob = 'لل معالجة البيانات'
        d = detect_rendered_defects(preview_text=blob)
        self.assertIn('لل معالجة', d['arabic_residues_found'])


class Rel25RepairTests(unittest.TestCase):

    def test_weak_target_repaired(self):
        sections = _live_rel25_defect_sections()
        out = repair_sections_for_rendered_evidence(
            sections, lang='ar', backend=_backend())
        self.assertNotIn('تحقيق ≥ 90% لـ', out['vision'])
        self.assertIn('IAM/PAM/MFA', out['vision'])

    def test_kpi_repaired(self):
        sections = _live_rel25_defect_sections()
        out = repair_sections_for_rendered_evidence(
            sections, lang='ar', backend=_backend())
        self.assertNotIn('نسبة الترقيع الأمني خارج SLA', out['kpis'])
        self.assertNotIn('عدد حوادث تسرب البيانات (DLP)', out['kpis'])
        self.assertNotIn(
            '(عدد العناصر المطابقة / إجمالي العناصر) × 100', out['kpis'])

    def test_risk_repaired(self):
        sections = _live_rel25_defect_sections()
        out = repair_sections_for_rendered_evidence(
            sections, lang='ar', backend=_backend())
        self.assertNotRegex(
            out['confidence'],
            r'\|\s*[^|]+\s*\|\s*[^|]+\s*\|\s*[^|]+\s*\|\s*—\s*\|')

    def test_traceability_repaired(self):
        sections = _live_rel25_defect_sections()
        out = repair_sections_for_rendered_evidence(
            sections, lang='ar', backend=_backend())
        self.assertIn('غياب فريق الاستجابة للحوادث CSIRT',
                      out['traceability'])
        self.assertNotIn('عدم وجود مركز عمليات أمنية', out['traceability'])

    def test_arabic_residue_repaired(self):
        sections = _live_rel25_defect_sections()
        out = repair_sections_for_rendered_evidence(
            sections, lang='ar', backend=_backend())
        self.assertNotIn('لل معالجة', out['environment'])


class Rel25IntegrationTests(unittest.TestCase):

    def test_rendered_evidence_passes_after_rel25(self):
        raw = {
            'sections': _live_rel25_defect_sections(),
            'final_markdown': _content(_live_rel25_defect_sections()),
            'blocking_errors': [],
            'sealed': False,
            'domain': 'cyber',
            'contract_meta': {'selected_frameworks': ['nca_ecc', 'nca_dcc']},
        }
        out, repairs, diags = apply_rel25_cyber_evidence_finalize(
            raw, domain='cyber', lang='ar', backend=_backend())
        ev = diags.get('evidence') or {}
        self.assertTrue(ev.get('rendered_evidence_passed'), ev)
        self.assertEqual(ev.get('forbidden_patterns_found'), [])
        self.assertEqual(ev.get('weak_objective_targets_found'), [])
        self.assertEqual(ev.get('kpi_semantic_defects_found'), [])
        self.assertEqual(ev.get('risk_empty_treatments_found'), [])
        self.assertTrue(repairs)

    def test_full_pipeline_release_ready(self):
        sections = _live_rel25_defect_sections()
        out = process_release_artifact(
            {
                'sections': sections,
                'final_markdown': _content(sections),
                'blocking_errors': [],
                'sealed': False,
                'domain': 'cyber',
                'contract_meta': {'selected_frameworks': ['nca_ecc', 'nca_dcc']},
            },
            domain='cyber', lang='ar', backend=_backend(), skip_rel1=True)
        contract = out.get('final_quality_contract') or {}
        ev = ((out.get('diagnostics') or {}).get('rel2', {})
              .get('rel25', {}).get('evidence') or {})
        self.assertTrue(ev.get('rendered_evidence_passed'), ev)
        self.assertTrue(contract.get('rendered_evidence_passed'))
        self.assertTrue(contract.get('rendered_evidence_passed'), contract)
        self.assertFalse(
            any('rel2_rendered_evidence_failed' in (b or '')
                for b in (contract.get('blocking_errors') or [])))

    def test_rendered_evidence_failure_blocks_release_ready(self):
        sections = _live_rel25_defect_sections()
        blob = '\n'.join(sections.values())
        failing_ev = detect_rendered_defects(preview_text=blob)
        self.assertFalse(failing_ev['rendered_evidence_passed'])
        art = {
            'sections': sections,
            'final_markdown': _content(sections),
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
                    'rel25': {'evidence': failing_ev},
                },
            },
            'contract_meta': {'selected_frameworks': ['nca_ecc', 'nca_dcc']},
        }
        contract = evaluate_final_quality(
            art, document_type='strategy', lang='ar', skip_structural=True)
        self.assertFalse(contract['rendered_evidence_passed'])
        self.assertFalse(contract['release_ready_final_passed'])

    def test_exported_docx_forbidden_patterns_absent(self):
        sections = _live_rel25_defect_sections()
        raw = {
            'sections': sections,
            'final_markdown': _content(sections),
            'blocking_errors': [],
            'sealed': False,
            'domain': 'cyber',
            'contract_meta': {'selected_frameworks': ['nca_ecc', 'nca_dcc']},
        }
        out, _, diags = apply_rel25_cyber_evidence_finalize(
            raw, domain='cyber', lang='ar', backend=_backend())
        self.assertTrue(
            (diags.get('evidence') or {}).get('rendered_evidence_passed'), diags)
        build_docx = _backend(with_exports=True).get('build_docx_bytes')
        self.assertTrue(build_docx, 'build_docx_bytes required for export test')
        docx_bytes = build_docx(
            out.get('final_markdown') or '',
            'strategy', 'ar', domain='cyber',
            selected_frameworks=['nca_ecc', 'nca_dcc'])
        docx_text = extract_docx_visible_text(docx_bytes)
        self.assertTrue(docx_text)
        found = _forbidden_found_in(docx_text)
        self.assertEqual(found, [], found)

    def test_exported_pdf_forbidden_patterns_absent(self):
        try:
            import fitz  # noqa: F401
        except ImportError:
            self.skipTest('PyMuPDF unavailable')
        sections = _live_rel25_defect_sections()
        raw = {
            'sections': sections,
            'final_markdown': _content(sections),
            'blocking_errors': [],
            'sealed': False,
            'domain': 'cyber',
            'contract_meta': {'selected_frameworks': ['nca_ecc', 'nca_dcc']},
        }
        out = process_release_artifact(
            raw, domain='cyber', lang='ar', backend=_backend(), skip_rel1=True)
        ev = ((out.get('diagnostics') or {}).get('rel2', {})
              .get('rel25', {}).get('evidence') or {})
        self.assertTrue(ev.get('rendered_evidence_passed'), ev)
        backend = _backend(with_exports=True)
        preview_text, _, pdf_text = collect_rendered_texts(
            out, backend, lang='ar', domain='cyber')
        self.assertTrue(preview_text)
        found_preview = _forbidden_found_in(preview_text)
        self.assertEqual(found_preview, [], found_preview)
        pdf_bytes = backend['build_pdf_bytes'](
            out.get('final_markdown') or '',
            'ar',
            sections=out.get('sections'),
            metadata=out.get('contract_meta'),
            selected_frameworks=['nca_ecc', 'nca_dcc'],
            domain='cyber',
        )
        if pdf_bytes:
            pdf_export_text = extract_pdf_visible_text(pdf_bytes)
            self.assertTrue(pdf_export_text.strip())
            found_pdf = _forbidden_found_in(pdf_export_text)
            self.assertEqual(found_pdf, [], found_pdf)
        elif pdf_text:
            found_pdf = _forbidden_found_in(pdf_text)
            self.assertEqual(found_pdf, [], found_pdf)
        else:
            resp = _build_pdf_via_route(out.get('final_markdown') or '')
            if resp.status_code == 200 and resp.data:
                pdf_export_text = extract_pdf_visible_text(resp.data)
                found_pdf = _forbidden_found_in(pdf_export_text)
                self.assertEqual(found_pdf, [], found_pdf)
            else:
                self.assertEqual(
                    found_preview, [],
                    'preview export text must be clean when PDF gate blocks')
