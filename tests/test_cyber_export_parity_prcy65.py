"""PR-CY65 — Fix stale confidence score / score justification gate after repair."""

import functools
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_export_parity_prcy65_')
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
    _APP_PATH = os.path.join(os.path.dirname(__file__), '..', 'app.py')
    _spec = importlib.util.spec_from_file_location('app', _APP_PATH)
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


def _minimal_sections(confidence=''):
    return {
        'vision': '## 1. Vision\n\n### Strategic Objectives\n\n| # | Objective | Target Metric | Justification | Timeframe |\n|---|---|---|---|---|\n| 1 | A | B | C | 6 months |\n| 2 | D | E | F | 12 months |\n| 3 | G | H | I | 18 months |\n',
        'pillars': '## 2. Pillars\n\nText.\n',
        'environment': '## 3. Environment\n\nText.\n',
        'gaps': '## 4. Gaps\n\nGap #1 Implementation Guide steps.\n',
        'roadmap': '## 5. Roadmap\n\nText.\n',
        'kpis': '## 6. KPIs\n\nKPI #1 Assessment Guide steps.\n',
        'confidence': confidence,
    }


class ConfidencePreSaveRepairTests(unittest.TestCase):

    @_skip_if_no_app
    def test_helpers_present(self):
        self.assertTrue(hasattr(_APP, '_prcy65_presave_repair_confidence'))
        self.assertTrue(hasattr(_APP, '_prcy65_detect_confidence_presence'))

    @_skip_if_no_app
    def test_missing_confidence_score_inserted(self):
        sections = _minimal_sections('## 7. Confidence\n\nSome risks listed.\n')
        result = _APP._prcy65_presave_repair_confidence(
            sections=sections, content=None, domain='cyber', lang='en',
            quality_issues=['confidence_score_missing'],
            phase='test',
        )
        conf = (result.get('sections') or {}).get('confidence', '')
        self.assertTrue(_APP._prcy65_detect_confidence_presence(conf)[
            'confidence_score_present'])
        self.assertNotIn(
            'confidence_score_missing', result.get('quality_issues') or [])

    @_skip_if_no_app
    def test_missing_score_justification_inserted(self):
        sections = _minimal_sections(
            '## 7. Confidence\n\n**Confidence Score:** 76%\n')
        result = _APP._prcy65_presave_repair_confidence(
            sections=sections, content=None, domain='cyber', lang='en',
            quality_issues=['score_justification_missing'],
            phase='test',
        )
        conf = (result.get('sections') or {}).get('confidence', '')
        self.assertTrue(_APP._prcy65_detect_confidence_presence(conf)[
            'score_justification_present'])

    @_skip_if_no_app
    def test_arabic_daraja_al_thiqa_recognized(self):
        text = 'درجة الثقة: 76%\n\nمبررات التقييم:\nنص.\n'
        det = _APP._prcy65_detect_confidence_presence(text)
        self.assertTrue(det['confidence_score_present'])

    @_skip_if_no_app
    def test_arabic_mabrarat_al_taqyim_recognized(self):
        text = 'درجة الثقة: 76%\n\nمبررات التقييم:\nنص.\n'
        det = _APP._prcy65_detect_confidence_presence(text)
        self.assertTrue(det['score_justification_present'])

    @_skip_if_no_app
    def test_english_confidence_score_recognized(self):
        text = '**Confidence Score:** 82%\n\n**Score Justification:**\nText.\n'
        det = _APP._prcy65_detect_confidence_presence(text)
        self.assertTrue(det['confidence_score_present'])

    @_skip_if_no_app
    def test_english_score_justification_recognized(self):
        text = '**Confidence Score:** 82%\n\n**Score Justification:**\nText.\n'
        det = _APP._prcy65_detect_confidence_presence(text)
        self.assertTrue(det['score_justification_present'])

    @_skip_if_no_app
    def test_stale_issues_cannot_block_after_repair(self):
        sections = _minimal_sections('')
        result = _APP._prcy65_presave_repair_confidence(
            sections=sections, content=None, domain='cyber', lang='ar',
            quality_issues=[
                'confidence_score_missing', 'score_justification_missing'],
            phase='test',
        )
        issues = result.get('quality_issues') or []
        core = _APP._prcy65_critical_core_tech_issue_tags(issues)
        self.assertFalse(
            core & {'confidence_score_missing', 'score_justification_missing'},
            f'stale confidence blockers must not survive repair: {issues!r}')

    @_skip_if_no_app
    def test_canonical_content_rebuilt_after_repair(self):
        sections = _minimal_sections('')
        content = '\n\n'.join(sections[k] for k in (
            'vision', 'pillars', 'environment', 'gaps',
            'roadmap', 'kpis', 'confidence') if sections.get(k))
        result = _APP._prcy65_presave_repair_confidence(
            sections=sections, content=content, domain='cyber', lang='ar',
            quality_issues=['confidence_score_missing'],
            phase='test',
        )
        diag = result.get('diag') or {}
        self.assertTrue(diag.get('canonical_content_rebuilt'))
        out = result.get('content') or ''
        self.assertIn('درجة الثقة', out)

    @_skip_if_no_app
    def test_final_export_contract_receives_repaired_confidence(self):
        sections = _minimal_sections('')
        repaired = _APP._prcy65_presave_repair_confidence(
            sections=sections, content=None, domain='cyber', lang='ar',
            quality_issues=['confidence_score_missing'],
            phase='test',
        )
        md = _APP._prcy65_rebuild_content_from_sections(
            repaired.get('sections') or {}, repaired.get('content'))
        self.assertIn('درجة الثقة', md)
        result = _APP._cyber_final_export_contract(
            md,
            metadata={'domain': 'cyber'},
            selected_frameworks=['nca_ecc'],
            lang='ar',
            domain='cyber',
            output_type='preview',
        )
        final_md = result.get('final_markdown') or ''
        self.assertIn('درجة الثقة', final_md)

    @_skip_if_no_app
    def test_prcy64_diagnostics_still_available(self):
        self.assertTrue(hasattr(
            _APP, '_prcy64_presave_repair_strategic_objectives_section'))


if __name__ == '__main__':
    unittest.main()
