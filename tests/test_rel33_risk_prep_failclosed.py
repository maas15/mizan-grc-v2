"""REL3.3 — ERM risk export-prep fail-closed wiring + diagnostic surfacing.

Live staging @ 1479095 kept failing ERM with the raw guard blocker because a
fail-closed export-prep contract silently reverted to client/original content,
and the contract diagnostics were print-only (invisible to Cloud Agent). This
suite pins:
  * the resolver fail-closed / repair / exception outputs,
  * the export-route hard-block wiring (no fallback to client content),
  * the gated export-status diagnostic surfacing
    ([REL33-RISK-EXPORT-PREP-CONTRACT] / [REL33-EXPORT-GATE-ROUTING-DIAG]),
  * that diagnostics are absent by default and blocked in production-like mode.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix='test_rel33_prep_failclosed_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from release_engine_v3.domain_codes import normalize_domain_code
from release_engine_v3 import rel33_risk_generation_contract as _gc_mod
from release_engine_v3.rel33_risk_artifact import (
    resolve_rel33_risk_export_artifact,
)
from release_engine_v3.rel33_risk_generation_contract import (
    detect_forbidden_strategy_sections,
)

_STRAT_NO_CYBER = (
    '## الرؤية والأهداف الاستراتيجية\n'
    'رؤية عامة لإدارة المخاطر التشغيلية.\n\n'
    '## 3. جدول تقييم المخاطر — سجل المخاطر\n'
    '| الخطر | الاحتمالية |\n|---|---|\n| توقف | متوسطة |\n\n'
    '## 6. جدول استراتيجية المعالجة والضوابط\n'
    '| الضابط | المالك |\n|---|---|\n| خطة | مالك المخاطر |\n'
    '| نسخ | لجنة المخاطر |\n')

_CYBER_IN_RISK = (
    '## 1. وصف السيناريو\n'
    'يتطلب حوكمة الأمن السيبراني ومركز العمليات الأمنية كعنصر أساسي.\n\n'
    '## 6. جدول استراتيجية المعالجة والضوابط\n'
    '| الضابط | المالك |\n|---|---|\n| مراجعة | مالك المخاطر |\n')

_CLEAN = (
    '## 1. وصف السيناريو\nسيناريو مخاطر تشغيلية.\n\n'
    '## 3. جدول تقييم المخاطر — سجل المخاطر\n'
    '| الخطر | الاحتمالية |\n|---|---|\n| توقف | متوسطة |\n\n'
    '## 6. جدول استراتيجية المعالجة والضوابط\n'
    '| الضابط | المالك |\n|---|---|\n| خطة | مالك المخاطر |\n| نسخ | لجنة |\n')


def _norm(d):
    return normalize_domain_code(d, default='') or d


def _assemble(secs):
    return '\n\n'.join(str(v) for v in secs.values())


def _none(a, u, domain=''):
    return None


def _load(content):
    def _l(rid, uid):
        return {'id': rid, 'analysis': content,
                'domain': 'Enterprise Risk Management', 'document_type': 'risk'}
    return _l


def _resolve(content, *, risk_id=1):
    return resolve_rel33_risk_export_artifact(
        artifact_id=risk_id, risk_id=risk_id, user_id=1,
        domain='Enterprise Risk Management', route='docx', client_content='',
        load_risk_row=_load(content), load_strategy_risk_row=_none,
        assemble_sections=_assemble, normalize_domain_fn=_norm)


class ResolverFailClosedTests(unittest.TestCase):
    """Req 5, 13, 14 — resolver repair / fail-closed / exception outputs."""

    def test_cyber_primary_fails_closed_empty_content(self):
        out = _resolve(_CYBER_IN_RISK, risk_id=2)
        self.assertEqual(out['content'], '')
        self.assertEqual(out['sections'], {})
        self.assertFalse(out.get('export_prep_contract_passed'))
        self.assertIn('rel33_risk_export_prep_not_risk_native',
                      out.get('blocking_errors') or [])
        self.assertTrue(out.get('export_prep_diag'))

    def test_strategy_shape_no_cyber_repairs(self):
        out = _resolve(_STRAT_NO_CYBER, risk_id=3)
        self.assertTrue(out['content'].strip())
        self.assertTrue(out.get('export_prep_contract_passed'))
        self.assertEqual(detect_forbidden_strategy_sections(out['content']), [])
        diag = out.get('export_prep_diag') or {}
        self.assertTrue(diag.get('export_content_differs_from_saved'))

    def test_clean_passes_without_repair(self):
        out = _resolve(_CLEAN, risk_id=4)
        self.assertTrue(out['content'].strip())
        self.assertTrue(out.get('export_prep_contract_passed'))
        diag = out.get('export_prep_diag') or {}
        self.assertFalse(diag.get('risk_export_prep_repair_attempted'))

    def test_export_prep_exception_fails_closed(self):
        # Force the contract to raise; resolver must fail closed (no content).
        orig = _gc_mod.evaluate_risk_export_prep_contract

        def _boom(*a, **k):
            raise RuntimeError('boom-prep')

        _gc_mod.evaluate_risk_export_prep_contract = _boom
        try:
            out = _resolve(_STRAT_NO_CYBER, risk_id=5)
        finally:
            _gc_mod.evaluate_risk_export_prep_contract = orig
        self.assertEqual(out['content'], '')
        self.assertIn('rel33_risk_export_prep_contract_exception',
                      out.get('blocking_errors') or [])
        self.assertFalse(out.get('export_prep_contract_passed'))


class AppWiringTests(unittest.TestCase):
    """Req 1-4, 7-12 — hard-block wiring + gated diagnostic surfacing."""

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('app', ROOT / 'app.py')
        cls.app = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.app)

    def _block(self, prep, data, *, base_url='http://staging.local/'):
        with self.app.app.test_request_context('/api/generate-docx-async',
                                                base_url=base_url):
            return self.app._rel33_risk_prep_hard_block_response(
                prep, data, route='docx', domain='Enterprise Risk Management',
                art_type='risk', art_id=1, risk_id=1)

    def test_hard_block_on_prep_failed_no_fallback(self):
        prep = {'content': '', 'export_prep_contract_passed': False,
                'blocking_errors': ['rel33_risk_export_prep_not_risk_native'],
                'export_prep_diag': {'tag': '[REL33-RISK-EXPORT-PREP-CONTRACT]',
                                     'contract_passed': False}}
        resp = self._block(prep, {'rel33_debug_export_evidence': True})
        self.assertIsNotNone(resp)
        body, status = resp
        self.assertEqual(status, 422)
        payload = json.loads(body.get_data())
        self.assertIn('rel33_risk_export_prep_not_risk_native',
                      payload['blocking_errors'])

    def test_no_block_when_prep_passed(self):
        prep = {'content': 'x', 'export_prep_contract_passed': True,
                'blocking_errors': []}
        self.assertIsNone(self._block(prep, {}))

    def test_no_block_for_artifact_not_found(self):
        # risk_artifact_not_found must NOT hard-block (client fallback intended).
        prep = {'content': '', 'blocking_errors': ['risk_artifact_not_found']}
        self.assertIsNone(self._block(prep, {}))

    def test_diag_present_with_debug_flag(self):
        prep = {'content': '', 'export_prep_contract_passed': False,
                'blocking_errors': ['rel33_risk_export_prep_not_risk_native'],
                'export_prep_diag': {'tag': '[REL33-RISK-EXPORT-PREP-CONTRACT]',
                                     'contract_passed': False}}
        resp = self._block(prep, {'rel33_debug_export_evidence': True})
        payload = json.loads(resp[0].get_data())
        self.assertIn('rel33_risk_export_prep_contract', payload)
        self.assertIn('rel33_export_gate_routing_diag', payload)
        routing = payload['rel33_export_gate_routing_diag']
        self.assertEqual(routing['section_splitter_selected'], 'risk_native')
        self.assertEqual(routing['domain_guard_selected'], 'risk_native')
        self.assertFalse(routing['model_drift_gate_applied'])

    def test_diag_absent_by_default(self):
        prep = {'content': '', 'export_prep_contract_passed': False,
                'blocking_errors': ['rel33_risk_export_prep_not_risk_native'],
                'export_prep_diag': {'tag': 'x'}}
        # No debug flag in data → diagnostics omitted.
        resp = self._block(prep, {})
        payload = json.loads(resp[0].get_data())
        self.assertNotIn('rel33_risk_export_prep_contract', payload)
        self.assertNotIn('rel33_export_gate_routing_diag', payload)
        # But it STILL hard-blocks with the blocker.
        self.assertIn('rel33_risk_export_prep_not_risk_native',
                      payload['blocking_errors'])

    def test_diag_blocked_in_production_like_mode(self):
        prep = {'content': '', 'export_prep_contract_passed': False,
                'blocking_errors': ['rel33_risk_export_prep_not_risk_native'],
                'export_prep_diag': {'tag': 'x'}}
        _prev = os.environ.pop('REL33_STAGING_EXPORT_DIAG', None)
        _prev_env = os.environ.pop('FLASK_ENV', None)
        try:
            # production-like host + flag set: still blocked (no diag).
            resp = self._block(prep, {'rel33_debug_export_evidence': True},
                               base_url='http://app.production.example/')
        finally:
            if _prev is not None:
                os.environ['REL33_STAGING_EXPORT_DIAG'] = _prev
            if _prev_env is not None:
                os.environ['FLASK_ENV'] = _prev_env
        payload = json.loads(resp[0].get_data())
        self.assertNotIn('rel33_risk_export_prep_contract', payload)
        self.assertNotIn('rel33_export_gate_routing_diag', payload)

    def test_routing_diag_builder_for_docx_and_pdf(self):
        for out_type in ('docx', 'pdf'):
            d = self.app.build_rel33_export_gate_routing_diag(
                output_type=out_type, route=out_type, domain='erm',
                document_type='risk', artifact_type='risk', risk_id='1',
                export_handler=f'api_generate_{out_type}',
                blocking_errors=['rel33_risk_export_prep_not_risk_native'],
                passed=False)
            self.assertEqual(d['output_type'], out_type)
            self.assertEqual(d['section_splitter_selected'], 'risk_native')
            self.assertFalse(d['model_drift_gate_applied'])
            self.assertIn('risk_frozen_completeness', d['risk_gates_applied'])
            self.assertIn('risk_treatment_evidence', d['risk_gates_applied'])

    def test_generation_contract_exception_fails_closed_no_save(self):
        # Req 6 — a generation-contract exception must fail closed: the risk is
        # NOT saved (no DB write) and fail_background_task is called.
        app = self.app
        calls = {'fail': None, 'db': False}

        def _fail(task_id, msg):
            calls['fail'] = msg

        def _db():
            calls['db'] = True
            raise AssertionError('DB save must not run after fail-closed')

        _orig = {
            'gen': getattr(app, 'generate_ai_content', None),
            'emf': getattr(app, 'ensure_markdown_formatting', None),
            'rev': getattr(app, '_repair_and_revalidate', None),
            'fail': getattr(app, 'fail_background_task', None),
            'db': getattr(app, 'get_db_direct', None),
            'gc': _gc_mod.evaluate_risk_generation_contract,
        }
        app.generate_ai_content = lambda *a, **k: (
            '## الرؤية والأهداف الاستراتيجية\nحوكمة الأمن السيبراني.\n')
        app.ensure_markdown_formatting = lambda c: c
        app._repair_and_revalidate = lambda c, t, l: (
            c, {'valid': True, 'score': 80, 'issues': []})
        app.fail_background_task = _fail
        app.get_db_direct = _db

        def _boom(*a, **k):
            raise RuntimeError('boom-generation')

        _gc_mod.evaluate_risk_generation_contract = _boom
        try:
            app._run_risk_generation_task(
                'task-x', 1, {'_prompt': 'x', 'language': 'ar',
                              'domain': 'Enterprise Risk Management',
                              '_risk_level': 'HIGH'})
        finally:
            app.generate_ai_content = _orig['gen']
            app.ensure_markdown_formatting = _orig['emf']
            app._repair_and_revalidate = _orig['rev']
            app.fail_background_task = _orig['fail']
            app.get_db_direct = _orig['db']
            _gc_mod.evaluate_risk_generation_contract = _orig['gc']
        self.assertEqual(calls['fail'],
                         'rel33_risk_generation_contract_exception')
        self.assertFalse(calls['db'])

    def test_debug_gate_off_by_default_and_prod_blocked(self):
        self.assertFalse(self.app._rel33_debug_export_allowed({}))
        with self.app.app.test_request_context(
                '/x', base_url='http://app.production.example/'):
            self.assertFalse(self.app._rel33_debug_export_allowed(
                {'rel33_debug_export_evidence': True}))
        with self.app.app.test_request_context(
                '/x', base_url='http://staging.local/'):
            self.assertTrue(self.app._rel33_debug_export_allowed(
                {'rel33_debug_export_evidence': True}))


if __name__ == '__main__':
    unittest.main()
