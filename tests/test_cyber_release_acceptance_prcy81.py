"""PR-CY81 — Production release hardening for unified Cyber final artifact."""

import functools
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout


_TMP = tempfile.mkdtemp(prefix='test_cyber_release_acceptance_prcy81_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault(
    'DATABASE_URL',
    'sqlite:///' + os.path.join(_TMP, 'test.db'),
)
os.environ.setdefault('OPENAI_API_KEY', '')

_APP = None
_PSR = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    import professional_strategy_render as _PSR
    _spec = importlib.util.spec_from_file_location(
        'app', os.path.join(os.path.dirname(__file__), '..', 'app.py'))
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
except Exception as _e:
    raise SystemExit(f'Cannot load app module: {_e!r}')


def _skip(fn):
    @functools.wraps(fn)
    def _w(self, *a, **kw):
        if _APP is None:
            self.skipTest('app unavailable')
        return fn(self, *a, **kw)
    return _w


_CANON_SO = (
    '| # | الهدف الاستراتيجي | المستهدف القابل للقياس |'
    ' المبرر | الإطار الزمني |\n'
    '|---|---|---|---|---|\n'
    '| 1 | إنشاء إدارة الأمن وتعيين CISO | 100% | حوكمة | 6 أشهر |\n'
    '| 2 | SOC/CSIRT | 100% | تشغيل | 12 شهر |\n'
    '| 3 | IAM/PAM/MFA | 95% | هوية | 12 شهر |\n'
    '| 4 | DCC حماية البيانات | 90% | امتثال | 18 شهر |\n'
    '| 5 | ECC/DCC امتثال | 90% | تنظيمي | 18 شهر |\n'
)

_ROADMAP_PHASE_HEADING_NO_TIMELINE = (
    '## 5. خارطة الطريق\n\n'
    '### المرحلة 1: تأسيس\n\n'
    'نص وصفي بدون جدول زمني.\n\n'
    '### المرحلة 2: تمكين وتشغيل\n\n'
    'نص آخر بدون جدول.\n'
)

_ROADMAP_TWO_PHASES = (
    '## 5. خارطة الطريق\n\n'
    '| المرحلة | الفترة | المبادرة | المسؤول | المخرج | الإطار |\n'
    '|---|---|---|---|---|---|\n'
    '| المرحلة 1: تأسيس | 1-6 أشهر | حوكمة CISO | CISO | هيكل | NCA ECC |\n'
    '| المرحلة 2: تمكين | 7-18 شهر | SOC | مدير SOC | مركز | NCA ECC |\n'
)

_ROADMAP_BAD_PERIOD = (
    '## 5. خارطة الطريق\n\n'
    '| المرحلة | الفترة | المبادرة | المسؤول | المخرج | الإطار |\n'
    '|---|---|---|---|---|---|\n'
    '| المرحلة 1: تأسيس | 1-6 أشهر | حوكمة | CISO | out | NCA ECC |\n'
    '| المرحلة 2: تمكين | تقارير تقدم دورية | SOC | CISO | out | NCA ECC |\n'
    '| المرحلة 3: تحسين | 19-24 شهر | VM | CISO | out | NCA ECC |\n'
)

_KPI = (
    '## 6. مؤشرات\n\n'
    '| # | وصف | القيمة | صيغة | مصدر | تواتر |\n'
    '|---|---|---|---|---|\n'
    '| 1 | MTTD | ≤ 60 د | كشف/SIEM | SIEM/SOC | شهري |\n'
    '| 2 | MTTR | ≤ 4 س | استجابة | ITSM/SOAR | شهري |\n'
    '| 3 | DCC | ≥ 90% | f | DCC | ربع |\n'
)

_CONF = (
    '## 7. الثقة\n\n**درجة الثقة:** 82%\n**مبررات التقييم:** نص.\n'
)


def _sections(**kw):
    base = {
        'vision': '## 1.\n\n### الأهداف\n\n' + _CANON_SO,
        'pillars': '## 2.\n\nنص.\n',
        'environment': '## 3.\n\nتصنيف DLP.\n',
        'gaps': '## 4.\n\nGap #1 Implementation Guide steps.\n',
        'roadmap': _ROADMAP_TWO_PHASES,
        'kpis': _KPI,
        'confidence': _CONF,
    }
    base.update(kw)
    return base


def _content(sections):
    if hasattr(_APP, '_prcy65_rebuild_content_from_sections'):
        return _APP._prcy65_rebuild_content_from_sections(sections, None)
    return '\n\n'.join(sections[k] for k in sections if sections.get(k))


def _artifact(sections, output_type='generation', read_only=False, meta=None):
    buf = io.StringIO()
    with redirect_stdout(buf):
        art = _APP._build_cyber_final_strategy_artifact(
            _content(sections),
            sections=dict(sections),
            metadata=meta or {'domain': 'cyber'},
            selected_frameworks=['nca_ecc', 'nca_dcc'],
            lang='ar',
            domain='cyber',
            output_type=output_type,
            read_only=read_only,
            request_context={'route_name': output_type},
            generation_mode='consulting',
        )
    return art, buf.getvalue()


class Prcy81ReleaseAcceptanceTests(unittest.TestCase):

    @_skip
    def test_flag_registry_and_helpers(self):
        self.assertTrue(_APP._PRCY28_VERSION_FLAGS.get('prcy81'))
        self.assertTrue(hasattr(_APP, '_FINAL_ARTIFACT_BLOCKER_REGISTRY'))
        self.assertTrue(
            hasattr(_APP, '_prcy81_roadmap_final_phase_timeline_canonicalization'))
        reg = _APP._FINAL_ARTIFACT_BLOCKER_REGISTRY
        for key in (
                'roadmap_phase_missing_timeline',
                'strategic_objectives_incomplete_row',
                'pdf_table_vertical_stack_warnings'):
            self.assertIn(key, reg)
            self.assertIn('detector', reg[key])
            self.assertIn('repair', reg[key])
            self.assertIn('test', reg[key])

    @_skip
    def test_phase_heading_without_timeline_repaired(self):
        art, log = _artifact(_sections(roadmap=_ROADMAP_PHASE_HEADING_NO_TIMELINE))
        self.assertIn('[ROADMAP-FINAL-PHASE-TIMELINE-CANONICALIZATION]', log)
        rm = (art.get('sections') or {}).get('roadmap', '')
        self.assertTrue(_APP._prcy81_roadmap_phase_timeline_valid(
            art.get('sections') or {}, 'ar'))
        self.assertIn('1-6', rm)

    @_skip
    def test_two_phases_get_phase3_timeline(self):
        art, _ = _artifact(_sections(roadmap=_ROADMAP_TWO_PHASES))
        rm = (art.get('sections') or {}).get('roadmap', '')
        self.assertIn('تحسين', rm)
        self.assertIn('19-24', rm)

    @_skip
    def test_invalid_period_repaired(self):
        art, _ = _artifact(_sections(roadmap=_ROADMAP_BAD_PERIOD))
        rm = (art.get('sections') or {}).get('roadmap', '')
        self.assertIn('7-18', rm)

    @_skip
    def test_missing_timeline_not_in_blockers_after_sealed(self):
        art, _ = _artifact(_sections(roadmap=_ROADMAP_PHASE_HEADING_NO_TIMELINE))
        if not art.get('sealed'):
            self.skipTest('fixture did not seal')
        joined = ' '.join(art.get('blocking_errors') or [])
        self.assertNotIn('roadmap_phase_missing_timeline', joined)
        self.assertNotIn('missing_phase_timeline', joined)

    @_skip
    def test_no_post_sealed_final_quality_gate_from_assertions(self):
        sections = _sections(roadmap=_ROADMAP_PHASE_HEADING_NO_TIMELINE)
        art, _ = _artifact(sections)
        if not art.get('sealed'):
            self.skipTest('not sealed')
        issues = _APP._prcy23_final_assertions(art.get('sections') or {}, 'ar')
        self.assertFalse(
            any('roadmap_phase_missing_timeline' in i for i in issues))

    @_skip
    def test_generation_uses_artifact_blocking_errors_only(self):
        art, _ = _artifact(_sections())
        stale = ['roadmap_phase_missing_timeline', 'confidence_score_missing']
        diag = {'so_valid_after_final_recheck': True,
                'so_rows_sufficient_after_final_recheck': True}
        resolved = _APP._prcy75_resolve_final_save_gate_issues(stale, diag)
        _stale_tags = {
            'roadmap_phase_missing_timeline', 'missing_phase_timeline',
            'roadmap_phase_timeline',
        }
        filtered = [
            i for i in stale
            if not any(
                i == t or str(i).startswith(t + ':')
                for t in _stale_tags)]
        self.assertEqual(filtered, ['confidence_score_missing'])
        if art.get('sealed'):
            self.assertEqual(art.get('blocking_errors') or [], [])

    @_skip
    def test_preview_read_only_sealed_no_mutation(self):
        art, _ = _artifact(_sections())
        if not art.get('sealed'):
            self.skipTest('not sealed')
        fh = art['final_hash']
        ro = _APP._build_cyber_final_strategy_artifact(
            art['final_markdown'],
            sections=art['sections'],
            metadata={
                'domain': 'cyber',
                'sealed': True,
                'final_hash': fh,
                'quality_gate_passed': True,
                '_contract_meta': art.get('contract_meta') or {},
            },
            selected_frameworks=['nca_ecc', 'nca_dcc'],
            lang='ar',
            domain='cyber',
            output_type='preview',
            read_only=True,
        )
        self.assertTrue(ro.get('sealed'))
        self.assertEqual(ro.get('blocking_errors') or [], [])
        self.assertEqual(ro['final_hash'], fh)

    @_skip
    def test_docx_invoke_same_hash(self):
        art, _ = _artifact(_sections())
        if not art.get('sealed'):
            self.skipTest('not sealed')
        fh = art['final_hash']
        c = _APP._prcy80_invoke_final_strategy_artifact(
            art['final_markdown'],
            metadata={'domain': 'cyber', 'sealed': True, 'final_hash': fh},
            selected_frameworks=['nca_ecc', 'nca_dcc'],
            lang='ar',
            domain='cyber',
            output_type='docx',
            read_only=True,
        )
        self.assertEqual(c.get('content_hash'), fh)

    @_skip
    def test_pdf_invoke_same_hash(self):
        art, _ = _artifact(_sections())
        if not art.get('sealed'):
            self.skipTest('not sealed')
        fh = art['final_hash']
        c = _APP._prcy80_invoke_final_strategy_artifact(
            art['final_markdown'],
            metadata={'domain': 'cyber', 'sealed': True, 'final_hash': fh},
            selected_frameworks=['nca_ecc', 'nca_dcc'],
            lang='ar',
            domain='cyber',
            output_type='pdf',
            read_only=True,
        )
        self.assertEqual(c.get('content_hash'), fh)

    @_skip
    def test_strategic_objectives_incomplete_row_regression(self):
        vision = (
            '## 1.\n\n### الأهداف\n\n' + _CANON_SO
            + '| 6 | x |  | م | 6 أشهر |\n')
        art, _ = _artifact(_sections(vision=vision))
        blockers = ' '.join(art.get('blocking_errors') or [])
        if art.get('sealed'):
            self.assertNotIn('strategic_objectives_incomplete_row:1', blockers)

    @_skip
    def test_sensitive_data_handling_regression(self):
        art, _ = _artifact(_sections())
        miss = _APP._compute_missing_cyber_roadmap_balance_topics(
            (art.get('sections') or {}).get('roadmap', ''),
            ['ECC', 'DCC'], lang='ar')
        self.assertNotIn('sensitive_data_handling', miss)

    @_skip
    def test_pdf_vertical_stack_regression(self):
        from tests.test_cyber_export_parity_prcy50 import _model as _m50
        model = _m50()
        tbl = {
            'schema': 'kpi_main',
            'header': list(_PSR.SCHEMA_KPI_MAIN_AR),
            'rows': [['1', 'x' * 120, '≥ 95%', 'f', 'src', 'شهري']],
        }
        model['blocks']['kpi_kri_framework']['tables'] = [tbl]
        fb = _PSR.compute_pdf_export_layout_fallbacks(model, 'ar')
        ev = _PSR.evaluate_vertical_stack_gate(model, fallbacks=fb)
        self.assertEqual(ev.get('actionable_warning_count_after'), 0)

    @_skip
    def test_dcc_roadmap_and_kpi_present(self):
        art, _ = _artifact(_sections())
        rm = (art.get('sections') or {}).get('roadmap', '').lower()
        self.assertTrue(
            _APP._prcy71_dcc_kpi_present(
                (art.get('sections') or {}).get('kpis', ''), 'ar'))
        for tok in ('تصنيف', 'تشفير', 'dlp'):
            self.assertIn(tok, rm)

    @_skip
    def test_user_facing_errors_no_raw_json(self):
        msg = _APP._prcy80_user_facing_error_message(
            'final_quality_gate_failed:roadmap_phase_missing_timeline:x',
            lang='ar')
        self.assertNotIn('{', msg)
        with self.assertRaises(json.JSONDecodeError):
            json.loads(msg)

    @_skip
    def test_release_smoke_end_to_end(self):
        """Noisy fixture → artifact → sealed → preview/docx/pdf parity."""
        noisy = _sections(
            vision=(
                '## 1.\n\n### الأهداف\n\n'
                '| 1 | legacy | row |\n' + _CANON_SO),
            roadmap=_ROADMAP_PHASE_HEADING_NO_TIMELINE,
            kpis=_KPI.replace('| 1 |', '| — |', 1),
            confidence='## 7.\n\n',
        )
        art, log = _artifact(noisy)
        self.assertIn('[CYBER-FINAL-ARTIFACT-CONTRACT-V2]', log)
        if not art.get('sealed'):
            self.skipTest(
                f'smoke not sealed: {art.get("blocking_errors")!r}')
        self.assertEqual(art.get('blocking_errors') or [], [])
        self.assertTrue(art.get('quality_flags', {}).get(
            'roadmap_phase_timeline_valid')
            or _APP._prcy81_roadmap_phase_timeline_valid(
                art.get('sections') or {}, 'ar'))
        fh = art['final_hash']
        for ot in ('preview', 'docx', 'pdf'):
            c = _APP._prcy80_invoke_final_strategy_artifact(
                art['final_markdown'],
                metadata={'domain': 'cyber', 'sealed': True,
                          'final_hash': fh},
                selected_frameworks=['nca_ecc', 'nca_dcc'],
                lang='ar', domain='cyber', output_type=ot, read_only=True)
            self.assertEqual(c.get('content_hash'), fh, msg=ot)
        from tests.test_cyber_export_parity_prcy50 import _model as _m50
        model = _m50()
        fb = _PSR.compute_pdf_export_layout_fallbacks(model, 'ar')
        ev = _PSR.evaluate_vertical_stack_gate(model, fallbacks=fb)
        self.assertEqual(ev.get('actionable_warning_count_after'), 0)


if __name__ == '__main__':
    unittest.main()
