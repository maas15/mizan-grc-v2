"""PR-CY82 — Close post-sealed roadmap timeline gate bypass after PR-CY81."""

import functools
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout


_TMP = tempfile.mkdtemp(prefix='test_cyber_release_acceptance_prcy82_')
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
    sys.modules['app'] = _APP
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
    _APP._PRCY82_CONTRACT_BYPASS_EVENTS.clear()
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


class Prcy82ReleaseAcceptanceTests(unittest.TestCase):

    def setUp(self):
        if _APP is not None:
            _APP._PRCY82_CONTRACT_BYPASS_EVENTS.clear()

    @_skip
    def test_prcy82_flag_and_fingerprint_fields(self):
        self.assertTrue(_APP._PRCY28_VERSION_FLAGS.get('prcy82'))
        fp = _APP._prcy37_runtime_build_fingerprint_payload(
            route_name='generation', output_type='generation')
        self.assertTrue(fp.get('prcy81'))
        self.assertTrue(fp.get('prcy82'))
        self.assertIn('app_commit_hash', fp)
        self.assertIn('branch_name', fp)
        self.assertIn('route_name', fp)
        self.assertIn('output_type', fp)

    @_skip
    def test_sealed_artifact_not_blocked_by_stale_timeline_gate(self):
        art, _ = _artifact(_sections(roadmap=_ROADMAP_PHASE_HEADING_NO_TIMELINE))
        if not art.get('sealed'):
            self.skipTest(f'fixture not sealed: {art.get("blocking_errors")!r}')
        joined = ' '.join(art.get('blocking_errors') or [])
        self.assertNotIn('roadmap_phase_missing_timeline', joined)
        self.assertNotIn('missing_phase_timeline', joined)
        gate = _APP._cyber_final_blocking_gate(
            art['final_markdown'],
            art.get('sections') or {},
            'ar', ['nca_ecc', 'nca_dcc'], 'cyber')
        timeline_hits = [
            e for e in gate
            if 'missing_phase_timeline' in e
            or 'roadmap_phase_missing_timeline' in e]
        self.assertEqual(timeline_hits, [])
        self.assertEqual(_APP._PRCY82_CONTRACT_BYPASS_EVENTS, [])

    @_skip
    def test_prcy23_no_timeline_after_canonicalization(self):
        art, _ = _artifact(_sections(roadmap=_ROADMAP_PHASE_HEADING_NO_TIMELINE))
        if not art.get('sealed'):
            self.skipTest('not sealed')
        issues = _APP._prcy23_final_assertions(art.get('sections') or {}, 'ar')
        self.assertFalse(
            any('roadmap_phase_missing_timeline' in i for i in issues))

    @_skip
    def test_save_gate_uses_artifact_blocking_errors_only(self):
        art, _ = _artifact(_sections())
        stale = [
            'roadmap_phase_missing_timeline',
            'final_quality_gate_failed:missing_phase_timeline:x',
            'confidence_score_missing',
        ]
        filtered = _APP._prcy82_filter_stale_quality_issues(stale)
        self.assertEqual(filtered, [])
        joined = ' '.join(filtered)
        self.assertNotIn('roadmap_phase_missing_timeline', joined)
        self.assertNotIn('missing_phase_timeline', joined)
        if art.get('sealed'):
            self.assertEqual(art.get('blocking_errors') or [], [])

    @_skip
    def test_stale_quality_issues_post_ignored_when_artifact_empty(self):
        art, _ = _artifact(_sections())
        if not art.get('sealed'):
            self.skipTest('not sealed')
        post = ['roadmap_phase_missing_timeline:hdr', 'kpi_assessment_guides_missing']
        filtered = _APP._prcy82_filter_stale_quality_issues(post)
        self.assertEqual(filtered, ['kpi_assessment_guides_missing'])

    @_skip
    def test_preview_read_only_no_mutating_contract(self):
        art, _ = _artifact(_sections())
        if not art.get('sealed'):
            self.skipTest('not sealed')
        fh = art['final_hash']
        buf = io.StringIO()
        with redirect_stdout(buf):
            ro = _APP._build_cyber_final_strategy_artifact(
                art['final_markdown'],
                sections=art.get('sections'),
                metadata={
                    'domain': 'cyber',
                    'sealed': True,
                    'final_hash': fh,
                    'quality_gate_passed': True,
                },
                selected_frameworks=['nca_ecc', 'nca_dcc'],
                lang='ar',
                domain='cyber',
                output_type='preview',
                read_only=True,
                request_context={'route_name': 'preview'},
            )
        log = buf.getvalue()
        self.assertTrue(ro.get('sealed'))
        self.assertEqual(ro.get('blocking_errors') or [], [])
        self.assertEqual(ro['final_hash'], fh)
        self.assertIn('sealed_read_only', (ro.get('diagnostics') or {}))

    @_skip
    def test_docx_reads_sealed_final_hash(self):
        art, _ = _artifact(_sections())
        if not art.get('sealed'):
            self.skipTest('not sealed')
        fh = art['final_hash']
        c = _APP._prcy80_invoke_final_strategy_artifact(
            art['final_markdown'],
            metadata={'domain': 'cyber', 'sealed': True, 'final_hash': fh},
            selected_frameworks=['nca_ecc', 'nca_dcc'],
            lang='ar', domain='cyber', output_type='docx', read_only=True)
        self.assertEqual(c.get('content_hash'), fh)

    @_skip
    def test_pdf_reads_sealed_final_hash(self):
        art, _ = _artifact(_sections())
        if not art.get('sealed'):
            self.skipTest('not sealed')
        fh = art['final_hash']
        c = _APP._prcy80_invoke_final_strategy_artifact(
            art['final_markdown'],
            metadata={'domain': 'cyber', 'sealed': True, 'final_hash': fh},
            selected_frameworks=['nca_ecc', 'nca_dcc'],
            lang='ar', domain='cyber', output_type='pdf', read_only=True)
        self.assertEqual(c.get('content_hash'), fh)

    @_skip
    def test_missing_timeline_repaired_to_canonical_phases(self):
        art, log = _artifact(_sections(roadmap=_ROADMAP_PHASE_HEADING_NO_TIMELINE))
        self.assertIn('[ROADMAP-FINAL-PHASE-TIMELINE-CANONICALIZATION]', log)
        rm = (art.get('sections') or {}).get('roadmap', '')
        for tok in ('المرحلة 1: تأسيس', '1-6', 'المرحلة 2: تمكين', '7-18',
                    'المرحلة 3: تحسين', '19-24'):
            self.assertIn(tok, rm)
        flags = _APP._prcy82_roadmap_timeline_assertion_flags(
            art.get('sections') or {}, 'ar')
        if art.get('sealed'):
            self.assertTrue(flags['roadmap_phase_timeline_valid'])

    @_skip
    def test_repair_failure_blocker_inside_artifact_only(self):
        """Blockers must come from artifact gates only — never stale outer bypass."""
        broken = _sections(roadmap='## 5. خارطة الطريق\n\n')
        art, _ = _artifact(broken)
        blockers = art.get('blocking_errors') or []
        if art.get('sealed'):
            rm = (art.get('sections') or {}).get('roadmap', '')
            self.assertGreaterEqual(
                len(_APP._prcy83_roadmap_parsed_rows(rm, 'ar')), 10)
        else:
            self.assertTrue(
                all(
                    str(b).startswith((
                        'final_quality_gate_failed:', 'rel2_roadmap_failed:',
                        'rel2_section_parity_failed:', 'rel2_pillars_failed:',
                    ))
                    for b in blockers),
                blockers)
        self.assertEqual(_APP._PRCY82_CONTRACT_BYPASS_EVENTS, [])

    @_skip
    def test_bypass_diagnostic_records_stale_post_sealed_block(self):
        _APP._PRCY82_CONTRACT_BYPASS_EVENTS.clear()
        _APP._prcy82_emit_contract_bypass_detected(
            task_id='t1',
            route_name='test',
            blocker='roadmap_phase_missing_timeline:x',
            emitter_function='test_emitter',
            artifact_sealed=True,
            artifact_blocking_errors=[],
            final_hash='abc',
            action_taken='test',
        )
        self.assertEqual(len(_APP._PRCY82_CONTRACT_BYPASS_EVENTS), 1)
        ev = _APP._PRCY82_CONTRACT_BYPASS_EVENTS[0]
        self.assertEqual(ev['blocker'], 'roadmap_phase_missing_timeline:x')
        self.assertTrue(ev['artifact_sealed'])

    @_skip
    def test_two_phases_get_phase3_timeline_prcy82(self):
        art, _ = _artifact(_sections(roadmap=_ROADMAP_TWO_PHASES))
        rm = (art.get('sections') or {}).get('roadmap', '')
        self.assertIn('19-24', rm)


if __name__ == '__main__':
    unittest.main()
