"""REL36.6 — ERM risk isolation and Data/AI NIST CSF leakage."""

from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix='test_rel36_6_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from release_engine_v3.contracts import RenderTree
from release_engine_v3.exporters.docx_exporter import export_docx
from release_engine_v3.exporters.pdf_exporter import export_pdf
from release_engine_v3.rel33_quality_matrix import REL33_TYPE_FIXTURES_AR
from release_engine_v3.rel33_risk_artifact import resolve_rel33_risk_export_artifact
from release_engine_v3.rel35_domain_framework_fidelity import (
    detect_visible_frameworks,
    repair_dga_interoperability_sections,
    repair_sections_for_fidelity,
    dga_interoperability_covered,
)
from release_engine_v3.rel36_6_erm_risk_domain_isolation import (
    REL36_6_ERM_RISK_DOMAIN_ISOLATION_TAG,
    evaluate_rel36_6_erm_risk_domain_isolation,
    emit_rel36_6_erm_risk_domain_isolation,
    risk_cache_key,
)
from tests.test_rel33_risk_export_gate_isolation import _CLEAN_RISK_MD
from tests.test_rel35_domain_framework_fidelity import (
    _ai_sections,
    _data_sections,
    _dt_sections,
)


def _norm(d):
    from release_engine_v3.domain_codes import normalize_domain_code
    return normalize_domain_code(d, default='') or d


def _assemble(secs):
    return '\n\n'.join(str(v) for v in secs.values() if str(v).strip())


_CYBER_STRATEGY_MD = (
    '## الرؤية والأهداف الاستراتيجية\n'
    'تفعيل حوكمة الأمن السيبراني وفق NCA ECC و NCA DCC مع CISO وSIEM.\n\n'
    '## الركائز الاستراتيجية\n'
    'ركيزة الحوكمة وSOC/SIEM.\n'
)


class Rel366CacheKeyTests(unittest.TestCase):
    def test_risk_id_namespace_not_bare_strategy_id(self):
        key = risk_cache_key(1, domain='erm', document_type='risk')
        self.assertEqual(key, 'risk:erm:risk:1')
        self.assertNotEqual(key, '1')
        self.assertTrue(key.startswith('risk:'))


class Rel366CollisionTests(unittest.TestCase):
    def test_overlapping_strategy_id_is_not_loaded_as_risk(self):
        def _load_risk(rid, uid):
            return None

        def _load_strategy(sid, uid, domain=''):
            return {
                'id': 1,
                'domain': 'Cyber Security',
                'document_type': 'strategy',
                'sections': {'vision': _CYBER_STRATEGY_MD},
                'content': _CYBER_STRATEGY_MD,
            }

        buf = io.StringIO()
        with redirect_stdout(buf):
            prep = resolve_rel33_risk_export_artifact(
                artifact_id=1,
                risk_id=1,
                user_id=1,
                domain='Enterprise Risk Management',
                route='erm:risk:ar',
                load_risk_row=_load_risk,
                load_strategy_risk_row=_load_strategy,
                assemble_sections=_assemble,
                normalize_domain_fn=_norm,
            )
        log = buf.getvalue()
        self.assertTrue(prep['diag']['artifact_id_collision_detected'])
        self.assertFalse((prep.get('content') or '').strip())
        self.assertIn('NCA ECC', _CYBER_STRATEGY_MD)
        self.assertNotIn('NCA ECC', prep.get('content') or '')
        self.assertIn(REL36_6_ERM_RISK_DOMAIN_ISOLATION_TAG, log)
        iso = prep.get('rel36_6') or {}
        self.assertEqual(iso.get('document_type'), 'risk')
        self.assertEqual(iso.get('cache_key'), 'risk:erm:risk:1')
        self.assertTrue(iso.get('contains_cyber_primary') or iso.get('blocking_errors'))
        self.assertFalse(iso.get('passed'))

    def test_risk_row_uses_risk_namespace_not_strategy_fallback(self):
        row = {
            'id': 1,
            'analysis': _CLEAN_RISK_MD,
            'content': _CLEAN_RISK_MD,
            'domain': 'Enterprise Risk Management',
            'document_type': 'risk',
            'sections': dict(REL33_TYPE_FIXTURES_AR['risk']),
        }

        def _load_risk(rid, uid):
            return row if int(rid) == 1 else None

        def _load_strategy(sid, uid, domain=''):
            return {
                'id': 1,
                'domain': 'Cyber Security',
                'document_type': 'strategy',
                'content': _CYBER_STRATEGY_MD,
                'sections': {'vision': _CYBER_STRATEGY_MD},
            }

        buf = io.StringIO()
        with redirect_stdout(buf):
            prep = resolve_rel33_risk_export_artifact(
                artifact_id=1,
                risk_id=1,
                user_id=1,
                domain='Enterprise Risk Management',
                route='erm:risk:ar',
                load_risk_row=_load_risk,
                load_strategy_risk_row=_load_strategy,
                assemble_sections=_assemble,
                normalize_domain_fn=_norm,
            )
        self.assertEqual(prep['diag']['source_table_or_store'], 'risks')
        self.assertEqual(prep['diag']['loaded_from_risk_id'], '1')
        self.assertIn('جدول تقييم المخاطر', prep.get('content') or '')
        self.assertIn('استراتيجية المعالجة', prep.get('content') or '')
        self.assertNotIn('NCA ECC', prep.get('content') or '')
        self.assertNotIn('الرؤية والأهداف الاستراتيجية', prep.get('content') or '')
        iso = prep.get('rel36_6') or {}
        self.assertEqual(iso.get('cache_key'), 'risk:erm:risk:1')
        self.assertEqual(iso.get('document_type'), 'risk')
        self.assertFalse(iso.get('contains_cyber_primary'), iso)
        self.assertFalse(iso.get('contains_strategy_sections'), iso)
        self.assertTrue(iso.get('passed'), iso)
        self.assertIn(REL36_6_ERM_RISK_DOMAIN_ISOLATION_TAG, buf.getvalue())


class Rel366PrepareFrozenOverlayTests(unittest.TestCase):
    def test_prepare_rel32_does_not_overlay_cyber_strategy_on_risk(self):
        from release_engine_v3.canonical_document import clear_artifact_registry
        from release_engine_v3.orchestrator import (
            clear_rel3_caches,
            rel3_build_render_tree,
            rel3_freeze_artifact,
        )
        from release_engine_v3.rel31_authority import (
            clear_rel3_route_artifact_hashes,
            repair_canonical_before_freeze,
        )
        from release_engine_v3.rel32_frozen_export_lock import (
            clear_rel32_frozen_export_lock,
            prepare_rel32_export_artifact_dict,
            register_rel32_frozen_export_lock,
        )
        from release_engine_v3.rel33_quality_matrix import (
            _load_app_module,
            ensure_test_env,
        )

        ensure_test_env()
        app = _load_app_module()
        clear_rel3_caches()
        clear_rel3_route_artifact_hashes()
        clear_rel32_frozen_export_lock()
        clear_artifact_registry()
        backend = app._rel31_backend_callables()
        cyber_secs = {
            'vision': '## الرؤية والأهداف الاستراتيجية\nNCA ECC CISO SIEM\n',
            'pillars': '## الركائز\nSOC/SIEM\n',
            'environment': 'NCA ECC',
            'gaps': '| فجوة | عالية |\n',
            'roadmap': '| Q1 | SIEM | CISO |\n',
            'kpis': '| MTTD | 15 |\n',
            'confidence': 'ثقة\n',
            'governance': 'CISO\n',
            'traceability': '| NCA ECC | حوكمة |\n',
        }
        md = app._prcy65_rebuild_content_from_sections(cyber_secs, None)
        art = {
            'sections': cyber_secs,
            'final_markdown': md,
            'domain': 'cyber',
            'document_type': 'strategy',
            'sealed': True,
            'strategy_id': '1',
            'contract_meta': {'lang': 'ar'},
        }
        art, _ = repair_canonical_before_freeze(art, backend=backend)
        frozen = rel3_freeze_artifact(art, strategy_id='1')
        tree = rel3_build_render_tree(frozen)
        frozen.render_tree_hash = tree.render_tree_hash
        register_rel32_frozen_export_lock(
            frozen, render_tree_hash=tree.render_tree_hash)

        risk_art = {
            'sections': dict(REL33_TYPE_FIXTURES_AR['risk']),
            'final_markdown': _CLEAN_RISK_MD,
            'domain': 'erm',
            'document_type': 'risk',
            'artifact_type': 'risk',
            'strategy_id': '1',
            'artifact_id': '1',
            'risk_id': '1',
            'contract_meta': {
                'lang': 'ar',
                'domain': 'erm',
                'document_type': 'risk',
            },
        }
        prepared = prepare_rel32_export_artifact_dict(
            risk_art,
            backend=backend,
            flags={'rel3': True, 'rel31': True, 'rel32': True},
        )
        self.assertFalse(prepared.get('_rel32_frozen_loaded'))
        joined = str(prepared.get('final_markdown') or '') + str(
            prepared.get('sections') or '')
        self.assertNotIn('NCA ECC', joined)
        self.assertIn('سجل المخاطر', joined)


class Rel366RiskExportTests(unittest.TestCase):
    def test_erm_risk_docx_pdf_allowed_without_cyber_or_vision(self):
        tree = RenderTree(
            artifact_id='risk-1', canonical_hash='c' * 16,
            render_tree_hash='r' * 16, nodes=[], markdown_view=_CLEAN_RISK_MD)
        backend_docx = {
            'build_docx_bytes': lambda content, filename, lang, **kw: b'PK-docx',
            'split_sections': lambda _c: {},
            'document_type': 'risk',
        }
        backend_pdf = {
            'build_pdf_bytes': lambda content, **kw: b'%PDF-bytes',
            'split_sections': lambda _c: {},
            'document_type': 'risk',
        }
        docx = export_docx(
            tree, backend=backend_docx, domain='erm', document_type='risk')
        pdf = export_pdf(
            tree, backend=backend_pdf, domain='erm', document_type='risk')
        self.assertEqual(docx.blocking_errors, [], docx.blocking_errors)
        self.assertEqual(pdf.blocking_errors, [], pdf.blocking_errors)
        self.assertTrue(docx.bytes_data)
        self.assertTrue(pdf.bytes_data)
        for blk in list(docx.blocking_errors) + list(pdf.blocking_errors):
            self.assertNotIn('rel33_domain_contamination', blk)
            self.assertNotIn('cyber_primary', blk)
            self.assertNotIn('الرؤية_والأهداف_الاستراتيجية', blk)


class Rel366NistCsfFidelityTests(unittest.TestCase):
    def test_data_ndmo_pdpl_strips_unselected_nist_csf(self):
        leaked = dict(_data_sections())
        leaked['environment'] = (
            str(leaked.get('environment') or '')
            + ' وإطار NIST Cybersecurity Framework (NIST CSF) الصادر عن المعهد.'
        )
        leaked['vision'] = (
            str(leaked.get('vision') or '') + '\nNIST CSF و ISO 27001'
        )
        repaired, diag = repair_sections_for_fidelity(
            leaked, domain='data', document_type='strategy',
            selected_frameworks=['NDMO', 'PDPL'], lang='ar')
        blob = '\n'.join(str(v) for v in repaired.values())
        fw = detect_visible_frameworks(blob)
        self.assertIn('NDMO', fw)
        self.assertIn('PDPL', fw)
        self.assertNotIn('NIST CSF', fw)
        self.assertNotIn('NIST CSF', blob)
        self.assertNotIn('NIST Cybersecurity Framework', blob)
        self.assertNotIn('NCA ECC', blob)
        self.assertNotIn('NIST AI RMF', blob)
        self.assertNotIn('rel35_unexpected_frameworks', str(diag.get('blocking_errors')))

    def test_ai_sdaia_strips_unselected_nist_csf(self):
        leaked = dict(_ai_sections())
        leaked['environment'] = (
            str(leaked.get('environment') or '')
            + ' NIST CSF and NIST Cybersecurity Framework and NIST AI RMF.'
        )
        leaked['vision'] = str(leaked.get('vision') or '') + '\nNIST CSF'
        repaired, diag = repair_sections_for_fidelity(
            leaked, domain='ai', document_type='strategy',
            selected_frameworks=['SDAIA'], lang='ar')
        blob = '\n'.join(str(v) for v in repaired.values())
        fw = detect_visible_frameworks(blob)
        self.assertIn('SDAIA', fw)
        self.assertNotIn('NIST CSF', fw)
        self.assertNotIn('NIST CSF', blob)
        self.assertNotIn('NIST Cybersecurity Framework', blob)
        self.assertNotIn('NIST AI RMF', blob)
        self.assertNotIn('NCA ECC', blob)
        self.assertNotIn('rel35_unexpected_frameworks', str(diag.get('blocking_errors')))

    def test_dt_dga_interoperability_still_passes(self):
        repaired, _ = repair_dga_interoperability_sections(
            _dt_sections(), lang='ar')
        self.assertTrue(dga_interoperability_covered(repaired))

    def test_cyber_keeps_nca_when_selected(self):
        blob = 'NCA ECC and NCA DCC and NIST CSF'
        fw = detect_visible_frameworks(blob)
        self.assertIn('NCA ECC', fw)
        self.assertIn('NCA DCC', fw)
        self.assertIn('NIST CSF', fw)


class Rel366AcceptancePayloadTests(unittest.TestCase):
    def test_p1_payload_uses_domain_frameworks_not_nist_csf(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            'rel33_accept',
            ROOT / 'scripts' / '_rel33_all_domain_staging_acceptance.py',
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        data = mod._base_payload(
            {'domain': 'data', 'document_type': 'strategy', 'lang': 'ar'})
        ai = mod._base_payload(
            {'domain': 'ai', 'document_type': 'strategy', 'lang': 'ar'})
        cyber = mod._base_payload(
            {'domain': 'cyber', 'document_type': 'strategy', 'lang': 'ar',
             'doc_subtype': 'technical'})
        erm = mod._base_payload(
            {'domain': 'erm', 'document_type': 'risk', 'lang': 'ar'})
        self.assertEqual(data['frameworks'], ['NDMO', 'PDPL'])
        self.assertEqual(ai['frameworks'], ['SDAIA'])
        self.assertTrue(any('ECC' in str(x) for x in cyber['frameworks']))
        self.assertTrue(any('DCC' in str(x) for x in cyber['frameworks']))
        self.assertNotIn('NIST CSF', data['frameworks'])
        self.assertNotIn('NIST CSF', ai['frameworks'])
        self.assertNotIn('NIST CSF', erm['frameworks'])
        self.assertEqual(erm['document_type'], 'risk')


class Rel366DiagnosticShapeTests(unittest.TestCase):
    def test_diagnostic_fields_and_tag(self):
        diag = evaluate_rel36_6_erm_risk_domain_isolation(
            route='erm:risk:ar',
            domain='erm',
            document_type='risk',
            lang='ar',
            risk_id=2,
            strategy_id='',
            source_artifact_type='risk',
            loaded_artifact_type='risk',
            loaded_domain='erm',
            loaded_document_type='risk',
            content=_CLEAN_RISK_MD,
        )
        for key in (
                'route', 'domain', 'document_type', 'lang', 'risk_id',
                'strategy_id', 'cache_key', 'source_artifact_type',
                'loaded_artifact_type', 'loaded_domain', 'loaded_document_type',
                'contains_strategy_sections', 'contains_cyber_primary',
                'contamination_before', 'contamination_after',
                'repair_applied', 'blocking_errors', 'passed'):
            self.assertIn(key, diag)
        self.assertTrue(diag['passed'], diag)
        buf = io.StringIO()
        with redirect_stdout(buf):
            emit_rel36_6_erm_risk_domain_isolation(diag)
        self.assertIn(REL36_6_ERM_RISK_DOMAIN_ISOLATION_TAG, buf.getvalue())


if __name__ == '__main__':
    unittest.main()
