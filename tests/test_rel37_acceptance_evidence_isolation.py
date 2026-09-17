"""Acceptance imports must not enable REL2_SKIP_EXPORT_EVIDENCE.

Required persist/export/security acceptance runs with evidence gates
enabled. Unit-only files may setdefault a legacy bypass in their own
process; that bypass must not leak into an acceptance process or be
restored by acceptance tearDown.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ.pop('REL2_SKIP_EXPORT_EVIDENCE', None)
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('REL37_DATA_AI_DT_COMPILER', '1')
_ISO_TMP = tempfile.mkdtemp(prefix='test_rel37_iso_')
os.environ.setdefault(
    'DATABASE_PATH', os.path.join(_ISO_TMP, 'rel37_iso.db'))
os.environ.setdefault(
    'DATABASE_URL', 'sqlite:///' + os.path.join(_ISO_TMP, 'rel37_iso.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('ANTHROPIC_API_KEY', '')
os.environ.setdefault('GOOGLE_API_KEY', '')

import app as app_mod  # noqa: E402

from release_engine.export_evidence_validator import (  # noqa: E402
    block_export_if_evidence_fails,
    validate_actual_export_evidence,
)
from release_engine_v3.rel31_authority import (  # noqa: E402
    _enforce_document_quality_blockers,
)
from release_engine_v3.rel37_canonical_document import CanonicalDocument  # noqa: E402
from release_engine_v3.rel37_export_content_parity import (  # noqa: E402
    evaluate_export_parity,
)
from release_engine_v3.rel37_render import model_to_markdown  # noqa: E402

ACCEPTANCE_MODULES = (
    'tests.test_rel37_ui_request_type_contract',
    'tests.test_rel37_export_content_parity',
    'tests.test_rel37_guide_completeness_persist',
    'tests.test_rel37_sync_pdf_ownership',
)
CI_COMBINED_ORDER = (
    'tests.test_rel37_ui_request_type_contract',
    'tests.test_rel37_deterministic_compilers',
    'tests.test_rel37_live_attach',
    'tests.test_rel37_early_authority',
    'tests.test_rel37_preview_section_contract',
    'tests.test_rel37_framework_label_canonicalization',
    'tests.test_rel37_export_content_parity',
    'tests.test_rel37_guide_completeness_persist',
)
SECOND_ORDER = (
    'tests.test_rel37_guide_completeness_persist',
    'tests.test_rel37_export_content_parity',
    'tests.test_rel37_ui_request_type_contract',
)
FIXTURE = ROOT / 'tests' / 'fixtures' / 'rel37' / 'data_en_saved_canonical_model.json'


def _probe_script(modules, *, call_teardown=()):
    quoted = ', '.join(repr(name) for name in modules)
    teardown = ', '.join(repr(name) for name in call_teardown)
    return f'''
import importlib, json, os, sys, tempfile
sys.path.insert(0, {str(ROOT)!r})
os.environ.pop("REL2_SKIP_EXPORT_EVIDENCE", None)
tmp = tempfile.mkdtemp(prefix="rel37_iso_probe_")
os.environ["ADMIN_PASSWORD"] = "test-admin-password"
os.environ["SECRET_KEY"] = "test-secret-key"
os.environ["DATABASE_PATH"] = tmp + "/probe.db"
os.environ["DATABASE_URL"] = "sqlite:///" + tmp + "/probe.db"
os.environ["OPENAI_API_KEY"] = ""
os.environ["REL37_DATA_AI_DT_COMPILER"] = "1"
trace = []
for name in [{quoted}]:
    importlib.import_module(name)
    trace.append({{
        "module": name,
        "skip": os.environ.get("REL2_SKIP_EXPORT_EVIDENCE"),
    }})
for name in [{teardown}]:
    mod = sys.modules[name]
    if hasattr(mod, "tearDownModule"):
        mod.tearDownModule()
    trace.append({{
        "module": name + ".tearDownModule",
        "skip": os.environ.get("REL2_SKIP_EXPORT_EVIDENCE"),
    }})
import app as app_mod
payload = {{
    "skip": os.environ.get("REL2_SKIP_EXPORT_EVIDENCE"),
    "should_gate": bool(app_mod._rel26_should_gate_export("cyber", "ar")),
    "trace": trace,
}}
print(json.dumps(payload, default=str))
'''


def _run_probe(modules, *, call_teardown=()):
    env = os.environ.copy()
    env.pop('REL2_SKIP_EXPORT_EVIDENCE', None)
    env['PYTHONPATH'] = str(ROOT)
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    proc = subprocess.run(
        [sys.executable, '-c', _probe_script(modules, call_teardown=call_teardown)],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
    )
    if proc.returncode != 0:
        raise AssertionError(
            'probe failed rc=%s stdout=%s stderr=%s'
            % (proc.returncode, proc.stdout[-2000:], proc.stderr[-2000:])
        )
    line = [part for part in proc.stdout.splitlines() if part.startswith('{')][-1]
    return json.loads(line)


class Rel37AcceptanceEvidenceIsolationTests(unittest.TestCase):
    def setUp(self):
        os.environ.pop('REL2_SKIP_EXPORT_EVIDENCE', None)
        app_mod.rate_limit_store.clear()

    def test_00_this_acceptance_module_does_not_enable_bypass(self):
        self.assertNotEqual(os.environ.get('REL2_SKIP_EXPORT_EVIDENCE'), '1')
        self.assertFalse(bool(os.environ.get('REL2_SKIP_EXPORT_EVIDENCE')))

    def test_01_acceptance_imports_do_not_enable_bypass(self):
        for name in ACCEPTANCE_MODULES:
            payload = _run_probe((name,))
            self.assertNotEqual(payload['skip'], '1', (name, payload))
            self.assertFalse(bool(payload['skip']), (name, payload))
            self.assertTrue(payload['should_gate'], (name, payload))
            for row in payload['trace']:
                self.assertNotEqual(row['skip'], '1', (name, row))

    def test_02_ci_order_and_second_order_leave_evidence_enabled(self):
        first = _run_probe(
            CI_COMBINED_ORDER,
            call_teardown=(
                'tests.test_rel37_export_content_parity',
                'tests.test_rel37_guide_completeness_persist',
            ),
        )
        self.assertNotEqual(first['skip'], '1', first)
        self.assertFalse(bool(first['skip']), first)
        self.assertTrue(first['should_gate'], first)
        for row in first['trace']:
            if row['module'].endswith('tearDownModule') or row['module'] in (
                    'tests.test_rel37_export_content_parity',
                    'tests.test_rel37_guide_completeness_persist',
                    'tests.test_rel37_ui_request_type_contract'):
                self.assertNotEqual(row['skip'], '1', row)
                self.assertFalse(bool(row['skip']), row)
        second = _run_probe(SECOND_ORDER)
        self.assertNotEqual(second['skip'], '1', second)
        self.assertTrue(second['should_gate'], second)

    def test_03_effective_runtime_settings_remain_correct(self):
        self.assertFalse(bool(os.environ.get('REL2_SKIP_EXPORT_EVIDENCE')))
        self.assertTrue(app_mod._rel26_should_gate_export('cyber', 'ar'))
        self.assertTrue(_enforce_document_quality_blockers(
            {'contract_meta': {'document_type': 'strategy'}},
            domain='cyber', lang='ar'))
        artifact = {'diagnostics': {}, 'sections': {'vision': 'x'}}
        out = app_mod._rel2_apply_release_engine(
            artifact, domain='cyber', lang='ar', document_type='strategy')
        self.assertIsInstance(out, dict)

    def test_04_required_validators_execute_on_real_export_path(self):
        allowed, errors, gate = app_mod._rel26_gate_export_bytes(
            docx_bytes=b'PK\x03\x04not-a-docx',
            pdf_bytes=b'%PDF-1.4 empty',
            preview_text='نسبة الترقيع الأمني خارج SLA',
            domain='cyber',
            lang='ar',
            document_type='strategy',
            route='docx',
        )
        self.assertFalse(allowed, (errors, gate))
        self.assertTrue(errors, gate)
        preview_ok, preview_errs, _pgate = app_mod._rel26_gate_preview_sections(
            {'vision': 'نسبة الترقيع الأمني خارج SLA'},
            domain='cyber',
            lang='ar',
        )
        self.assertFalse(preview_ok, preview_errs)
        failing = validate_actual_export_evidence(
            '', 'نسبة الترقيع الأمني خارج SLA', '')
        ok, blockers = block_export_if_evidence_fails(failing)
        self.assertFalse(ok)
        self.assertTrue(blockers)
        model = CanonicalDocument.from_dict(
            json.loads(FIXTURE.read_text(encoding='utf-8')))
        if not model.model_hash:
            model.compute_hashes()
        parity = evaluate_export_parity(
            model=model,
            persist_ok=True,
            download_ok=True,
            parsed_ok=True,
            preview_text=model_to_markdown(model),
            docx_bytes=b'',
            pdf_bytes=b'%PDF-1.4 empty',
            source_hash=model.model_hash,
        )
        self.assertNotEqual(parity.content_parity, 'passed', parity.blockers)
        self.assertTrue(parity.blockers)

    def test_05_later_acceptance_case_does_not_inherit_bypass_or_db(self):
        first_db = os.environ.get('DATABASE_PATH')
        os.environ['REL2_SKIP_EXPORT_EVIDENCE'] = '1'
        try:
            self.assertFalse(app_mod._rel26_should_gate_export('cyber', 'ar'))
        finally:
            os.environ.pop('REL2_SKIP_EXPORT_EVIDENCE', None)
        self.assertTrue(app_mod._rel26_should_gate_export('cyber', 'ar'))
        later = _run_probe(('tests.test_rel37_guide_completeness_persist',))
        self.assertNotEqual(later['skip'], '1', later)
        self.assertTrue(later['should_gate'], later)
        self.assertFalse(bool(os.environ.get('REL2_SKIP_EXPORT_EVIDENCE')))
        self.assertTrue(app_mod._rel26_should_gate_export('cyber', 'ar'))
        self.assertEqual(os.environ.get('DATABASE_PATH'), first_db)


if __name__ == '__main__':
    unittest.main()
