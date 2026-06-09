"""PR-REL2.3 — live artifact section parity and board-ready quality gates."""

import importlib.util
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

import pytest

_TMP = tempfile.mkdtemp(prefix='test_rel23_')
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

from release_engine.arabic_language_gate import apply_arabic_final_gate
from release_engine.kpi_model import finalize_kpi_semantics
from release_engine.pillar_model import finalize_pillars
from release_engine.roadmap_model import finalize_roadmap
from release_engine.section_parity import evaluate_section_parity
from release_engine.orchestrator import process_release_artifact


def _backend(*, with_exports: bool = False):
    if not hasattr(_APP, '_rel2_backend_callables'):
        return {}
    b = _APP._rel2_backend_callables()
    if not with_exports:
        b.pop('build_docx_bytes', None)
        b.pop('build_pdf_bytes', None)
        b['validate_export_evidence'] = False
    return b


def _content(sections):
    return _APP._prcy65_rebuild_content_from_sections(sections, None)


def _live_defect_sections():
    """Simulates live/staging Cyber Arabic Technical defects."""
    from domains.cyber.fixtures_ar import technical_sections
    s = dict(technical_sections())
    s['pillars'] = (
        '## 2. الركائز الاستراتيجية\n\n'
        'نص وصفي للركائز للتعاملمع التهديدات الاجتماعيةضد المنظمة '
        'والاستعادةفي حالات الطوارئ.\n'
    )
    s['roadmap'] = (
        '## 5. خارطة الطريق\n\n'
        '| المرحلة | الفترة | المبادرة | المسؤول | المخرج | الإطار |\n'
        '|---|---|---|---|---|---|\n'
        '| المرحلة 1 | 1-6 | حوكمة | Threat Intelligence | هيكل | ECC |\n'
        '| المرحلة 2 | 7-12 | SOC | Data Protection | مركز | ECC |\n'
        '| المرحلة 2 | 7-12 | IAM | Owner | ضوابط | ECC |\n'
    )
    s['kpis'] = (
        '## 6. مؤشرات\n\n'
        '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساب | مصدر | تواتر |\n'
        '|---|---|---|---|---|---|\n'
        '| 1 | نسبة الترقيع الأمني خارج SLA | 100% | '
        '(عدد العناصر المطابقة / إجمالي العناصر) × 100 | أداة | شهري |\n'
        '| 2 | عدد حوادث تسرب البيانات (DLP) | ≥95% | '
        '(عدد العناصر المطابقة / إجمالي العناصر) × 100 | DLP | شهري |\n'
        '| 3 | متوسط زمن الكشف MTTD | ≤ 60 د | كشف/SIEM | SIEM | شهري |\n'
        '| 4 | متوسط زمن الاستجابة MTTR | ≤ 4 س | استجابة | ITSM | شهري |\n'
    )
    return s


class Rel23SectionParityTests(unittest.TestCase):

    def test_preview_pillars_docx_pdf_missing_fails_parity(self):
        sections = _live_defect_sections()
        artifact = {
            'sections': sections,
            'final_markdown': _content(sections),
            'domain': 'cyber',
        }
        parity = evaluate_section_parity(artifact, _backend(), lang='ar')
        self.assertFalse(parity['pillars_present_docx'])
        self.assertFalse(parity['parity_passed'])
        self.assertTrue(
            'pillars' in parity['missing_sections_docx']
            or (parity.get('blocking_error_if_any') or '').endswith('pillars'))

    def test_section_hash_catches_missing_pillars(self):
        sections = _live_defect_sections()
        artifact = {
            'sections': sections,
            'final_markdown': _content(sections),
            'final_hash': _APP._prcy25_compute_content_hash(_content(sections)),
            'domain': 'cyber',
        }
        parity = evaluate_section_parity(artifact, _backend(), lang='ar')
        self.assertTrue(parity.get('final_hash'))
        if not parity['pillars_present_docx']:
            self.assertTrue(
                parity['missing_sections_docx']
                or 'docx:pillars' in parity['mismatched_sections']
                or not parity['parity_passed'])


class Rel23PillarModelTests(unittest.TestCase):

    def test_rebuilds_at_least_3_pillars(self):
        sections = {'pillars': '## 2. الركائز\n\nنص فقط.\n'}
        out, diag = finalize_pillars(
            sections, lang='ar', domain='cyber', backend=_backend())
        self.assertGreaterEqual(diag['pillar_count_after'], 3)
        self.assertTrue(all(c >= 3 for c in diag['initiative_count_by_pillar']))

    def test_empty_pillars_block(self):
        sections = {'pillars': ''}
        out, diag = finalize_pillars(sections, lang='ar', domain='cyber')
        self.assertTrue(diag['rendered_table_valid'])
        self.assertGreaterEqual(diag['pillar_count_after'], 3)


class Rel23RoadmapModelTests(unittest.TestCase):

    def test_expands_fewer_than_10_rows(self):
        sections = _live_defect_sections()
        out, diag = finalize_roadmap(
            sections, lang='ar', domain='cyber',
            selected_frameworks=['nca_ecc', 'nca_dcc'],
            backend=_backend())
        self.assertGreaterEqual(diag['row_count_after'], 10)
        self.assertLessEqual(diag['row_count_after'], 14)

    def test_repairs_missing_families(self):
        sections = _live_defect_sections()
        out, diag = finalize_roadmap(
            sections, lang='ar', domain='cyber',
            selected_frameworks=['nca_ecc', 'nca_dcc'],
            backend=_backend())
        self.assertEqual(diag['missing_families_after'], [])

    def test_replaces_placeholder_owners(self):
        sections = _live_defect_sections()
        out, diag = finalize_roadmap(
            sections, lang='ar', domain='cyber',
            backend=_backend())
        self.assertEqual(diag['weak_owners_after'], [])
        self.assertNotIn('Threat Intelligence', out.get('roadmap', ''))


class Rel23KPIModelTests(unittest.TestCase):

    def test_repairs_patch_sla_100_target(self):
        sections = _live_defect_sections()
        out, diag = finalize_kpi_semantics(sections, lang='ar', backend=_backend())
        self.assertNotIn('نسبة الترقيع الأمني خارج SLA', out.get('kpis', ''))
        self.assertIn('نسبة إغلاق الثغرات الحرجة ضمن SLA', out.get('kpis', ''))

    def test_repairs_dlp_percentage_target(self):
        sections = _live_defect_sections()
        out, diag = finalize_kpi_semantics(sections, lang='ar', backend=_backend())
        kpi = out.get('kpis', '')
        self.assertNotIn('≥95%', kpi.split('DLP')[0] if 'DLP' in kpi else kpi)

    def test_replaces_generic_formula(self):
        sections = _live_defect_sections()
        out, diag = finalize_kpi_semantics(sections, lang='ar', backend=_backend())
        self.assertEqual(diag['generic_formula_count'], 0)


class Rel23ArabicGateTests(unittest.TestCase):

    def test_removes_known_residues(self):
        sections = {
            'roadmap': 'للتعاملمع التهديدات الاجتماعيةضد والاستعادةفي الطوارئ',
        }
        out, diag = apply_arabic_final_gate(sections, lang='ar')
        text = out['roadmap']
        self.assertNotIn('للتعاملمع', text)
        self.assertNotIn('الاجتماعيةضد', text)
        self.assertNotIn('الاستعادةفي', text)
        self.assertTrue(diag['arabic_quality_passed'])


class Rel23LiveFixtureIntegrationTests(unittest.TestCase):

    def test_live_fixture_passes_after_rel23(self):
        sections = _live_defect_sections()
        art = {
            'sections': sections,
            'final_markdown': _content(sections),
            'blocking_errors': [],
            'sealed': False,
            'domain': 'cyber',
            'contract_meta': {'selected_frameworks': ['nca_ecc', 'nca_dcc']},
        }
        out = process_release_artifact(
            art, domain='cyber', lang='ar',
            backend=_backend(), skip_rel1=True)
        rel23 = (out.get('diagnostics') or {}).get('rel2', {}).get('rel23') or {}
        parity = rel23.get('section_parity') or {}
        self.assertTrue(parity.get('parity_passed'), parity)
        self.assertTrue(parity.get('pillars_present_docx'))
        self.assertTrue(parity.get('pillars_present_pdf'))

    def test_section_hashes_match_after_rel23(self):
        sections = _live_defect_sections()
        buf = io.StringIO()
        with redirect_stdout(buf):
            art = _APP._build_cyber_final_strategy_artifact(
                _content(sections),
                sections=dict(sections),
                metadata={'domain': 'cyber'},
                selected_frameworks=['nca_ecc', 'nca_dcc'],
                lang='ar',
                domain='cyber',
                output_type='generation',
                doc_subtype='technical',
            )
        rel23 = (art.get('diagnostics') or {}).get('rel2', {}).get('rel23') or {}
        parity = rel23.get('section_parity') or {}
        self.assertTrue(art.get('release_ready_final_passed'), art.get('blocking_errors'))
        self.assertTrue(parity.get('parity_passed'), parity)
        self.assertEqual(
            parity.get('docx_section_hashes', {}).get('pillars'),
            parity.get('final_section_hashes', {}).get('pillars'))


class Rel23DccPostRel2Tests(unittest.TestCase):

    def test_ecc_only_roadmap_not_blocked_for_dlp_after_rel23(self):
        """REL2.3 roadmap rebuild must not leave stale prcy74:dlp blockers."""
        sections = _live_defect_sections()
        sections['roadmap'] = (
            '## 5. خارطة الطريق\n\n'
            '| المرحلة | الفترة | المبادرة | المسؤول | المخرج | الإطار |\n'
            '|---|---|---|---|---|---|\n'
            '| المرحلة 1: تأسيس | 1-6 أشهر | حوكمة CISO | CISO | هيكل | NCA ECC |\n'
            '| المرحلة 2: تمكين | 7-18 شهر | SOC | مدير SOC | مركز | NCA ECC |\n'
            '| المرحلة 3: تحسين | 19-24 شهر | CSIRT | CISO | فريق | NCA ECC |\n'
        )
        art = _APP._build_cyber_final_strategy_artifact(
            _content(sections),
            sections=dict(sections),
            metadata={'domain': 'cyber'},
            selected_frameworks=['nca_ecc', 'nca_dcc'],
            lang='ar',
            domain='cyber',
            output_type='generation',
            doc_subtype='technical',
        )
        joined = ' '.join(art.get('blocking_errors') or [])
        self.assertNotIn(
            'prcy74_missing_required_dcc_family:dlp', joined, joined)
        self.assertNotIn(
            'final_quality_gate_failed:prcy74_missing_required_dcc_family:dlp',
            joined, joined)
        rm = (art.get('sections') or {}).get('roadmap', '')
        self.assertTrue(
            _APP._prcy83_dlp_standalone_initiative_present(rm), rm[:500])


class Rel23NationalMatrixSmoke(unittest.TestCase):

    def test_rel2_flag_enabled(self):
        self.assertTrue(_APP._PRCY28_VERSION_FLAGS.get('rel2'))


if __name__ == '__main__':
    unittest.main()
