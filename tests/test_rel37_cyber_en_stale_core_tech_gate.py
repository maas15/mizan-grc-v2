"""Cyber EN technical-strategy save gate: stale issue lists and substance.

Attempt 6a4909ab-2046-44c9-b98d-abe32960685d failed at
core_tech_missing_post_normalization after the post-normalization
pipeline had already re-audited the same attempt and cleared the four
flags. ``list(quality_issues or previous)`` treated that empty list as
missing and restored the stale flags.

These fixtures are test-owned mechanism fixtures. They are not an exact
replay of the unavailable provider bodies.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix='rel37_cyber_en_stale_gate_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ['OPENAI_API_KEY'] = ''
os.environ['ANTHROPIC_API_KEY'] = ''
os.environ['GOOGLE_API_KEY'] = ''
os.environ['GROQ_API_KEY'] = ''
os.environ['DEEPSEEK_API_KEY'] = ''

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import app as appmod  # noqa: E402

STALE_FOUR = [
    'confidence_score_missing',
    'gap_guidance_missing',
    'kpi_assessment_guides_missing',
    'score_justification_missing',
]

_JUST = (
    'This test-owned rating reflects input completeness, NCA ECC and '
    'NCA DCC coverage, roadmap feasibility, and control readiness for '
    'Example Cyber Org. It is not a live organizational assessment.'
)


def _gap_guide(idx, name):
    return (
        f'#### Gap #{idx} Implementation Guide: {name}\n\n'
        '| Step | Action | Owner | Timeline | Output |\n'
        '|---|---|---|---|---|\n'
        f'| 1 | Confirm the {name} control gap against NCA ECC and NCA DCC | '
        'CISO | Month 1 | Gap confirmation record |\n'
        f'| 2 | Implement the {name} remediation and record the operating evidence | '
        'Security Engineering | Months 2-4 | Implemented control |\n'
    )


def _kpi_guide(idx, name):
    return (
        f'#### KPI #{idx} Assessment Guide: {name}\n\n'
        '| Step | Action | Tool/System | Owner | Output |\n'
        '|---|---|---|---|---|\n'
        f'| 1 | Measure {name} from the SIEM control register using the stated formula | '
        'SIEM | CISO | Assessment record |\n'
        f'| 2 | Compare {name} with the target and record the evidence source | '
        'SIEM | CISO | Variance note |\n'
    )


def _initiative_table(rows):
    lines = [
        '| # | Initiative | Description | Expected Deliverable |',
        '|---|---|---|---|',
    ]
    for idx, (name, desc, deliverable) in enumerate(rows, 1):
        lines.append(f'| {idx} | {name} | {desc} | {deliverable} |')
    return '\n'.join(lines)


def _kpi_row(idx, name, formula, why):
    return (
        f'| {idx} | {name} | 90% | {formula} | {why} | 6 months |'
    )


def _sections():
    gaps = (
        '## 4. Gap Analysis\n\n'
        'Confirmed deficiencies against NCA ECC and NCA DCC.\n\n'
        '| # | Gap | Description | Priority | Status |\n'
        '|---|---|---|---|---|\n'
        '| 1 | Backup and Recovery Controls | Backups lack tested restoration | High | Open - Confirmed |\n'
        '| 2 | Monitoring Coverage | SIEM sources are incomplete | Medium | Open - Confirmed |\n\n'
        '### Gap Implementation Guidance\n\n'
        + _gap_guide(1, 'Backup and Recovery Controls')
        + '\n'
        + _gap_guide(2, 'Monitoring Coverage')
    )
    kpi_names = (
        (1, 'Backup Restore Success Rate',
         '(Successful restores / Restore tests) x 100',
         'Shows recovery readiness from the data source'),
        (2, 'Monitoring Coverage Rate',
         '(Sources onboarded / Required sources) x 100',
         'Shows detection coverage from the data source'),
        (3, 'Vulnerability Closure Rate',
         '(Closed vulnerabilities / Open vulnerabilities) x 100',
         'Shows vulnerability management progress'),
        (4, 'Awareness Completion Rate',
         '(Staff trained / Total staff) x 100',
         'Shows awareness programme completion'),
    )
    kpis = (
        '## 6. Key Performance Indicators\n\n'
        'Assessment frequency is monthly. Each KPI names its data source.\n\n'
        '| # | KPI Description | Target Value | Calculation Formula | Justification | Timeframe |\n'
        '|---|---|---|---|---|---|\n'
        + '\n'.join(_kpi_row(*row) for row in kpi_names)
        + '\n\n'
        + '\n'.join(_kpi_guide(idx, name) for idx, name, _f, _w in kpi_names)
    )
    confidence = (
        '## 7. Confidence Assessment & Risks\n\n'
        'Programme confidence for this test-owned fixture.\n\n'
        '**Confidence Score:** 72%\n\n'
        f'**Score Justification:**\n{_JUST}\n\n'
        '| # | Factor | Description | Importance |\n'
        '|---|---|---|---|\n'
        '| 1 | ECC control ownership | Named owners for NCA ECC controls | High |\n'
        '| 2 | DCC evidence | Evidence for NCA DCC data protection controls | High |\n'
        '| 3 | Incident exercise | A tested incident response exercise | Medium |\n'
        '| 4 | Monitoring sources | SIEM sources connected for detection | High |\n\n'
        '| # | Risk | Likelihood | Impact | Mitigation Plan |\n'
        '|---|---|---|---|---|\n'
        '| 1 | Untested backup restoration | Medium | High | Run a quarterly restore test and record the evidence |\n'
        '| 2 | Incomplete monitoring coverage | High | High | Onboard the missing SIEM sources and review alerts monthly |\n'
        '| 3 | Delayed vulnerability closure | Medium | Medium | Track closure against the vulnerability management register |\n'
        '| 4 | Awareness gap | Medium | Medium | Complete the awareness programme for government staff |\n'
    )
    vision = (
        '## 1. Vision\n\n'
        'Example Cyber Org will operate NCA ECC and NCA DCC controls with '
        'identity, MFA, SIEM monitoring, incident response, vulnerability '
        'management, backup, awareness, and data protection.\n\n'
        '### Strategic Objectives\n\n'
        '| # | Objective | Target Metric | Justification | Timeframe |\n'
        '|---|---|---|---|---|\n'
        '| 1 | Establish ECC governance | Committee charter approved | Required by NCA ECC | 6 months |\n'
        '| 2 | Classify sensitive data | Register approved | Required by NCA DCC | 6 months |\n'
        '| 3 | Connect monitoring sources | 90 percent coverage | Detection gap | 9 months |\n'
        '| 4 | Test backup restoration | Quarterly restore test | Resilience gap | 9 months |\n'
    )
    pillars = (
        '## 2. Strategic Pillars\n\n'
        '### Pillar 1: Cybersecurity Governance\n\n'
        'The CISO office owns NCA ECC governance, committee cadence, and '
        'control accountability for Example Cyber Org, including identity '
        'and MFA access decisions.\n\n'
        + _initiative_table([
            ('ECC governance charter', 'Approve the NCA ECC governance charter', 'Approved charter'),
            ('Control accountability', 'Assign an owner to each ECC control', 'Control owner register'),
            ('Committee cadence', 'Hold the cybersecurity committee monthly', 'Committee minutes'),
        ])
        + '\n\n### Pillar 2: Detection and Response\n\n'
        'SIEM monitoring and incident response follow NCA ECC operational '
        'requirements for the government sector.\n\n'
        + _initiative_table([
            ('SIEM source onboarding', 'Connect required monitoring sources', 'Source coverage report'),
            ('Incident response playbooks', 'Publish incident response playbooks', 'Approved playbooks'),
            ('Alert review', 'Review SIEM alerts on a monthly cycle', 'Alert review record'),
        ])
        + '\n\n### Pillar 3: Resilience and Protection\n\n'
        'Vulnerability management, backup restoration, awareness, and data '
        'protection close the remaining NCA ECC and NCA DCC gaps.\n\n'
        + _initiative_table([
            ('Vulnerability management', 'Close critical vulnerabilities on a monthly cycle', 'Closure report'),
            ('Backup restoration tests', 'Test backup restoration each quarter', 'Restore evidence'),
            ('Awareness and data protection', 'Train staff and apply data protection controls', 'Training and DLP records'),
        ])
    )
    environment = (
        '## 3. Environment\n\n'
        'Example Cyber Org operates in the Government sector under the NCA ECC '
        'and NCA DCC regulatory frameworks. Business operations depend on a '
        'centralized security function, identity services, and SIEM monitoring.\n\n'
        'The threat environment includes ransomware, phishing, and intrusion '
        'attempts against government services. Incident response, vulnerability '
        'management, backup, awareness, and data protection are in scope.\n\n'
        '| Topic | Current state | Framework |\n'
        '|---|---|---|\n'
        '| Regulatory | NCA ECC and NCA DCC apply | NCA |\n'
        '| Threat | Ransomware and phishing are active | NCA ECC |\n'
        '| Business | Government services require continuity | NCA DCC |\n'
    )
    roadmap = (
        '## 5. Implementation Roadmap\n\n'
        '| Phase | Timeframe | Initiative | Owner | Output | Framework |\n'
        '|---|---|---|---|---|---|\n'
        '| Phase 1: Foundation | Months 1-6 | ECC governance charter | CISO | Charter | NCA ECC |\n'
        '| Phase 1: Foundation | Months 1-6 | DCC data register | DPO | Register | NCA DCC |\n'
        '| Phase 2: Detection | Months 4-9 | SIEM monitoring coverage | SOC | Coverage report | NCA ECC |\n'
        '| Phase 2: Resilience | Months 6-12 | Backup restore testing | CISO | Restore evidence | NCA ECC |\n'
    )
    return {
        'vision': vision,
        'pillars': pillars,
        'environment': environment,
        'gaps': gaps,
        'roadmap': roadmap,
        'kpis': kpis,
        'confidence': confidence,
    }


def _issues(sections):
    _ok, issues = appmod._audit_doc_quality(
        sections, 'technical', 'en', generation_mode='drafting')
    return list(issues)


def _core(issues):
    return set(appmod._prcy65_critical_core_tech_issue_tags(issues))


class StaleIssueListTests(unittest.TestCase):
    def test_empty_refined_list_replaces_stale_flags(self):
        restored = list([] or STALE_FOUR)
        self.assertEqual(restored, STALE_FOUR)
        adopted = appmod._adopt_pipeline_issue_list(
            {'quality_issues': []}, STALE_FOUR)
        self.assertEqual(adopted, [])
        self.assertFalse(appmod._legacy_postnorm_core_tech_blocks(
            appmod._prcy65_critical_core_tech_issue_tags(adopted),
            'cyber security', False))

    def test_missing_key_keeps_previous_flags(self):
        adopted = appmod._adopt_pipeline_issue_list({}, STALE_FOUR)
        self.assertEqual(adopted, STALE_FOUR)

    def test_display_name_does_not_exempt_remaining_flags(self):
        self.assertTrue(appmod._legacy_postnorm_core_tech_blocks(
            set(STALE_FOUR), 'cyber security', False))
        self.assertFalse(appmod._legacy_postnorm_core_tech_blocks(
            set(STALE_FOUR), 'cyber', False))

    def test_token_count_is_not_an_input_to_the_gate(self):
        import inspect
        src = inspect.getsource(appmod._legacy_postnorm_core_tech_blocks)
        self.assertNotIn('token', src)
        adopted = appmod._adopt_pipeline_issue_list(
            {'quality_issues': []}, STALE_FOUR)
        self.assertEqual(adopted, [])


class SubstanceRefusalTests(unittest.TestCase):
    def test_valid_fixture_has_no_core_flags(self):
        self.assertEqual(_core(_issues(_sections())), set())

    def test_each_missing_requirement_is_refused(self):
        sections = _sections()
        sections['confidence'] = sections['confidence'].replace(
            '**Confidence Score:** 72%\n\n', '')
        self.assertIn('confidence_score_missing', _core(_issues(sections)))

        sections = _sections()
        sections['confidence'] = sections['confidence'].replace(
            f'**Score Justification:**\n{_JUST}\n\n',
            '**Score Justification:**\n\n')
        self.assertIn('score_justification_missing', _core(_issues(sections)))

        sections = _sections()
        sections['gaps'] = (
            '## 4. Gap Analysis\n\n'
            '| # | Gap | Description | Priority | Status |\n'
            '|---|---|---|---|---|\n'
            '| 1 | Backup and Recovery Controls | Backups lack tested restoration | High | Open |\n'
        )
        self.assertIn('gap_guidance_missing', _core(_issues(sections)))

        sections = _sections()
        sections['kpis'] = (
            '## 6. Key Performance Indicators\n\n'
            '| # | KPI Description | Target Value | Calculation Formula | Justification | Timeframe |\n'
            '|---|---|---|---|---|---|\n'
            '| 1 | Backup Restore Success Rate | 95% | (Successful restores / Restore tests) x 100 | '
            'Shows recovery readiness | 6 months |\n'
        )
        self.assertIn('kpi_assessment_guides_missing', _core(_issues(sections)))

    def test_heading_only_empty_step_and_orphan_guides_do_not_pass(self):
        sections = _sections()
        sections['gaps'] = (
            '## 4. Gap Analysis\n\n'
            '| # | Gap | Description | Priority | Status |\n'
            '|---|---|---|---|---|\n'
            '| 1 | Backup and Recovery Controls | Backups lack tested restoration | High | Open |\n\n'
            '#### Gap #1 Implementation Guide: Backup and Recovery Controls\n'
        )
        self.assertIn('gap_guidance_missing', _core(_issues(sections)))

        sections['gaps'] = (
            '## 4. Gap Analysis\n\n'
            '| # | Gap | Description | Priority | Status |\n'
            '|---|---|---|---|---|\n'
            '| 1 | Backup and Recovery Controls | Backups lack tested restoration | High | Open |\n\n'
            '#### Gap #1 Implementation Guide: Backup and Recovery Controls\n\n'
            '| Step | Action | Owner | Timeline | Output |\n'
            '|---|---|---|---|---|\n'
            '| 1 |  | CISO | Month 1 |  |\n'
        )
        self.assertIn('gap_guidance_missing', _core(_issues(sections)))

        sections['gaps'] = (
            '## 4. Gap Analysis\n\n'
            '| # | Gap | Description | Priority | Status |\n'
            '|---|---|---|---|---|\n'
            '| 1 | Backup and Recovery Controls | Backups lack tested restoration | High | Open |\n\n'
            + _gap_guide(9, 'Unrelated Vendor Gap')
        )
        self.assertIn('gap_guidance_missing', _core(_issues(sections)))

        sections = _sections()
        sections['kpis'] = (
            '## 6. Key Performance Indicators\n\n'
            '| # | KPI Description | Target Value | Calculation Formula | Justification | Timeframe |\n'
            '|---|---|---|---|---|---|\n'
            '| 1 | Backup Restore Success Rate | 95% | (Successful restores / Restore tests) x 100 | '
            'Shows recovery readiness | 6 months |\n\n'
            '#### KPI #1 Assessment Guide: Backup Restore Success Rate\n'
        )
        self.assertIn('kpi_assessment_guides_missing', _core(_issues(sections)))

        sections['kpis'] = (
            '## 6. Key Performance Indicators\n\n'
            '| # | KPI Description | Target Value | Calculation Formula | Justification | Timeframe |\n'
            '|---|---|---|---|---|---|\n'
            '| 1 | Backup Restore Success Rate | 95% | (Successful restores / Restore tests) x 100 | '
            'Shows recovery readiness | 6 months |\n\n'
            + _kpi_guide(1, 'Unrelated Phishing Rate')
        )
        self.assertIn('kpi_assessment_guides_missing', _core(_issues(sections)))


_CASE_A_TABLE = (
    '| Step | Action | Owner | Timeline | Output |\n'
    '|---|---|---|---|---|\n'
    '| 1 | Confirm the backup control gap against the restoration evidence | '
    'CISO | Month 1 | Gap confirmation record |\n'
    '| 2 | Implement the backup remediation and verify successful restoration | '
    'Security Engineering | Months 2-4 | Implemented control |\n'
)

_CASE_B_METHOD = (
    'Review restore evidence, calculate the success ratio, and compare it to the target'
)


def _case_a_gaps(hashes):
    return (
        '## 4. Gap Analysis\n\n'
        '| # | Gap | Description | Priority | Status |\n'
        '|---|---|---|---|---|\n'
        '| 1 | Backup and Recovery Controls | Backups lack tested restoration | High | Open |\n\n'
        f'{hashes} Gap #1 Implementation Guide: Backup and Recovery Controls\n\n'
        + _CASE_A_TABLE
    )


def _case_b_kpis(method):
    return (
        '## 6. Key Performance Indicators\n\n'
        '| # | KPI Description | Target Value | Calculation Formula | Justification | Timeframe |\n'
        '|---|---|---|---|---|---|\n'
        '| 1 | Backup Restore Success Rate | 95% | (Successful restores / Restore tests) x 100 | '
        'Shows recovery readiness | 6 months |\n\n'
        '### KPI Assessment Guidelines\n'
        '| # | KPI | Assessment Method |\n'
        '|---|---|---|\n'
        f'| 1 | Backup Restore Success Rate | {method} |\n'
    )


class GuideSubstanceCompatibilityTests(unittest.TestCase):
    """Heading depth and assessment-column regressions.

    Helper results and ``_audit_doc_quality`` flags are separate. Neither
    result is a save or download decision.
    """

    def test_heading_depth_keeps_the_same_gap_guide(self):
        for hashes in ('####', '###'):
            gaps = _case_a_gaps(hashes)
            self.assertTrue(
                appmod._gap_implementation_guides_substantive(gaps), hashes)
            sections = _sections()
            sections['gaps'] = gaps
            self.assertNotIn(
                'gap_guidance_missing', _issues(sections), hashes)

        borrowed = (
            '## 4. Gap Analysis\n\n'
            '| # | Gap | Description | Priority | Status |\n'
            '|---|---|---|---|---|\n'
            '| 1 | Backup and Recovery Controls | Backups lack tested restoration | High | Open |\n\n'
            '### Gap #1 Implementation Guide: Backup and Recovery Controls\n\n'
            '## 5. Roadmap\n\n'
            + _CASE_A_TABLE
        )
        self.assertFalse(appmod._gap_implementation_guides_substantive(borrowed))
        sections = _sections()
        sections['gaps'] = borrowed
        self.assertIn('gap_guidance_missing', _issues(sections))

    def test_assessment_method_is_not_the_kpi_label(self):
        positive = _case_b_kpis(_CASE_B_METHOD)
        self.assertTrue(appmod._kpi_assessment_guides_substantive(positive))
        sections = _sections()
        sections['kpis'] = positive
        self.assertNotIn('kpi_assessment_guides_missing', _issues(sections))

        mutated = _case_b_kpis(' ')
        self.assertFalse(appmod._kpi_assessment_guides_substantive(mutated))
        sections = _sections()
        sections['kpis'] = mutated
        self.assertIn('kpi_assessment_guides_missing', _issues(sections))

    def test_arabic_level3_gap_guide_action_column(self):
        gaps = (
            '## 4. تحليل الفجوات\n\n'
            '| # | الفجوة | الوصف | الأولوية | الحالة |\n'
            '|---|---|---|---|---|\n'
            '| 1 | ضوابط النسخ الاحتياطي | النسخ تفتقر إلى اختبار الاستعادة | عالية | مفتوحة |\n\n'
            '### دليل تنفيذ الفجوة رقم 1: ضوابط النسخ الاحتياطي\n\n'
            '| الخطوة | الإجراء | المسؤول | الجدول الزمني | الناتج |\n'
            '|---|---|---|---|---|\n'
            '| 1 | تأكيد فجوة النسخ الاحتياطي مقابل دليل الاستعادة | CISO | الشهر 1 | سجل تأكيد الفجوة |\n'
            '| 2 | تنفيذ معالجة النسخ والتحقق من نجاح الاستعادة | هندسة الأمن | الأشهر 2-4 | ضابط مُنفذ |\n'
        )
        self.assertTrue(appmod._gap_implementation_guides_substantive(gaps))
        sections = _sections()
        sections['gaps'] = gaps
        self.assertNotIn('gap_guidance_missing', _issues(sections))


class PipelineAdoptionTests(unittest.TestCase):
    def test_real_pipeline_empty_list_is_what_the_gate_evaluates(self):
        calls = {'n': 0}

        def _no_provider(*_a, **_k):
            calls['n'] += 1
            raise RuntimeError('provider_disabled_in_test')

        original = appmod.generate_ai_content
        appmod.generate_ai_content = _no_provider
        try:
            result = appmod._prcy66_presave_canonical_repair_pipeline(
                sections=_sections(),
                content='\n\n'.join(_sections().values()),
                domain='cyber',
                lang='en',
                metadata={'domain': 'cyber'},
                selected_frameworks=[
                    'NCA ECC (Essential Cybersecurity Controls)',
                    'NCA DCC (Data Cybersecurity Controls)',
                ],
                task_id='mechanism-fixture',
                phase='pre_save_post_norm',
                doc_subtype='technical',
                generation_mode='drafting',
                quality_issues=list(STALE_FOUR),
            )
        finally:
            appmod.generate_ai_content = original
        self.assertEqual(calls['n'], 0)
        adopted = appmod._adopt_pipeline_issue_list(result, STALE_FOUR)
        self.assertFalse(appmod._legacy_postnorm_core_tech_blocks(
            appmod._prcy65_critical_core_tech_issue_tags(adopted),
            'cyber security', False))
        self.assertTrue(appmod._legacy_postnorm_core_tech_blocks(
            appmod._prcy65_critical_core_tech_issue_tags(
                list([] or STALE_FOUR)),
            'cyber security', False))

    def test_rel37_stays_off_cyber(self):
        from release_engine_v3.rel37_live_attach import attach_rel37_before_save
        attached = attach_rel37_before_save(
            _sections(),
            domain='cyber',
            domain_input='Cyber Security',
            lang='en',
            document_type='strategy',
            selected_frameworks=[
                'NCA ECC (Essential Cybersecurity Controls)',
                'NCA DCC (Data Cybersecurity Controls)',
            ],
            explicit_selection=True,
        )
        self.assertFalse(attached.diagnostic.get('compiler_used'))
        self.assertNotIn('_rel37_model', attached.sections)


def _markdown():
    return '\n\n'.join(_sections().values())


class AsyncPersistTests(unittest.TestCase):
    def setUp(self):
        self._orig = appmod.generate_ai_content
        self.provider_calls = 0

        def _mock(prompt, language='en', task_type='generate', content_type=None):
            self.provider_calls += 1
            text = prompt or ''
            sections = _sections()
            # Section repairs must not receive the whole document. Returning
            # every heading into one section is what contaminated the fixture.
            import re as _re_mock
            marker = _re_mock.search(
                r"You are repairing section ##\s*([1-7])\.|"
                r"Return ONLY the '##\s*([1-7])\.|"
                r'أرجع قسم "\\?#?#?\s*([1-7])\.|'
                r'أعد إنتاج القسم ##\s*([1-7])\.',
                text,
            )
            if marker:
                number = next(g for g in marker.groups() if g)
                key = {
                    '1': 'vision', '2': 'pillars', '3': 'environment',
                    '4': 'gaps', '5': 'roadmap', '6': 'kpis', '7': 'confidence',
                }[number]
                return sections[key]
            if content_type == 'strategy':
                return _markdown()
            raise RuntimeError('provider_disabled_in_test')

        appmod.generate_ai_content = _mock
        with appmod.app.app_context():
            db = appmod.get_db()
            db.execute(
                'INSERT OR IGNORE INTO users '
                '(id, username, password_hash, role, is_active) '
                "VALUES (41, 'cyber-en-gate', 'x', 'user', 1)")
            db.commit()

    def tearDown(self):
        appmod.generate_ai_content = self._orig

    def _run(self, challenges):
        captured = []
        real = threading.Thread

        def _capture(*args, **kwargs):
            thread = real(*args, **kwargs)
            captured.append(thread)
            return thread

        threading.Thread = _capture
        payload = {
            'domain': 'Cyber Security',
            'language': 'en',
            'org_name': 'Example Cyber Org',
            'sector': 'Government',
            'size': 'Medium (100-1000)',
            'budget': '1M-5M SAR',
            'frameworks': [
                'NCA ECC (Essential Cybersecurity Controls)',
                'NCA DCC (Data Cybersecurity Controls)',
            ],
            'org_structure': 'centralized',
            'technologies': ['SIEM'],
            'maturity_level': 'developing',
            'challenges': challenges,
            'doc_subtype': 'technical',
            'generation_mode': 'drafting',
            'diagnostic_id': None,
            'csrf_token': 'csrf-mechanism',
        }
        try:
            client = appmod.app.test_client()
            with client.session_transaction() as sess:
                sess['user_id'] = 41
                sess['username'] = 'cyber-en-gate'
                sess['role'] = 'user'
                sess['csrf_token'] = 'csrf-mechanism'
            before = self._strategy_ids()
            resp = client.post(
                '/api/generate-strategy-async',
                json=payload,
                headers={'X-CSRFToken': 'csrf-mechanism'},
            )
            self.assertEqual(resp.status_code, 200, resp.get_data(as_text=True)[:400])
            body = resp.get_json()
            self.assertTrue(body.get('task_id'))
            self.assertEqual(len(captured), 1)
            self.assertIs(type(captured[0]), real)
            captured[0].join(timeout=180)
            self.assertFalse(captured[0].is_alive(), 'worker still pending')
            status = client.get(f"/api/strategy-status/{body['task_id']}")
            return body['task_id'], status.get_json(), before
        finally:
            threading.Thread = real

    def _strategy_ids(self):
        with appmod.app.app_context():
            rows = appmod.get_db().execute(
                'SELECT id FROM strategies WHERE user_id = 41'
            ).fetchall()
        return {row['id'] if hasattr(row, 'keys') else row[0] for row in rows}

    def test_valid_fixture_reaches_done_and_reloads(self):
        _task, status, before = self._run('mechanism fixture valid core sections')
        self.assertEqual(status.get('status'), 'done', json.dumps(status)[:800])
        result = status.get('result') or {}
        sid = result.get('strategy_id')
        self.assertTrue(sid)
        self.assertNotIn(sid, before)
        client = appmod.app.test_client()
        with client.session_transaction() as sess:
            sess['user_id'] = 41
            sess['username'] = 'cyber-en-gate'
            sess['role'] = 'user'
            sess['csrf_token'] = 'csrf-mechanism'
        doc = client.get(f'/api/document/strategy/{sid}')
        self.assertEqual(doc.status_code, 200, doc.get_data(as_text=True)[:300])
        body = doc.get_json()
        content = body.get('content') or ''
        self.assertRegex(content, r'Confidence Score[\s\S]{0,80}\d{1,3}\s*%')
        self.assertIn('Score Justification', content)
        self.assertIn('Implementation Guide', content)
        self.assertIn('Assessment Guide', content)
        self.assertIn('NCA ECC', content)
        self.assertIn('NCA DCC', content)
        self.assertGreater(self.provider_calls, 0)
        from release_engine_v3.render_tree import _markdown_to_preview_html
        preview = _markdown_to_preview_html(content)
        self.assertIn('Confidence Score', preview)
        self.assertIn('Score Justification', preview)
        self.assertIn('Implementation Guide', preview)
        self.assertIn('Assessment Guide', preview)
        export = {
            'strategy_id': sid,
            'artifact_id': sid,
            'artifact_type': 'strategy',
            'domain': 'Cyber Security',
            'language': 'en',
            'org_name': 'Example Cyber Org',
            'sector': 'Government',
            'doc_type': 'Strategy Document',
            'generation_mode': 'drafting',
            'content': content,
            'csrf_token': 'csrf-mechanism',
        }
        headers = {'X-CSRFToken': 'csrf-mechanism'}
        docx = client.post('/api/generate-docx', json=export, headers=headers)
        self.assertEqual(docx.status_code, 200, docx.get_data()[:180])
        self.assertTrue(docx.data.startswith(b'PK'))
        pdf = client.post('/api/generate-pdf', json=export, headers=headers)
        self.assertEqual(pdf.status_code, 200, pdf.get_data()[:180])
        self.assertTrue(pdf.data.startswith(b'%PDF'))

    def test_incomplete_fixture_saves_no_strategy_row(self):
        heading_only = []
        rows = []
        for idx in range(1, 11):
            name = f'Gap family {idx} control'
            rows.append(
                f'| {idx} | {name} | Missing operating evidence for this control | '
                'High | Open - Confirmed |')
            heading_only.append(f'#### Gap #{idx} Implementation Guide: {name}')
        gaps = (
            '## 4. Gap Analysis\n\n'
            '| # | Gap | Description | Priority | Status |\n'
            '|---|---|---|---|---|\n'
            + '\n'.join(rows)
            + '\n\n'
            + '\n\n'.join(heading_only)
            + '\n'
        )
        sections = _sections()
        sections['gaps'] = gaps

        def _thin(prompt, language='en', task_type='generate', content_type=None):
            self.provider_calls += 1
            text = prompt or ''
            import re as _re_mock
            marker = _re_mock.search(
                r"You are repairing section ##\s*([1-7])\.|"
                r"Return ONLY the '##\s*([1-7])\.",
                text,
            )
            if marker:
                number = next(g for g in marker.groups() if g)
                key = {
                    '1': 'vision', '2': 'pillars', '3': 'environment',
                    '4': 'gaps', '5': 'roadmap', '6': 'kpis', '7': 'confidence',
                }[number]
                return sections[key]
            if content_type == 'strategy':
                return '\n\n'.join(sections.values())
            raise RuntimeError('provider_disabled_in_test')

        appmod.generate_ai_content = _thin
        _task, status, before = self._run('mechanism fixture heading-only gap guides')
        self.assertNotEqual(status.get('status'), 'done', json.dumps(status)[:500])
        self.assertEqual(self._strategy_ids(), before)
        error = status.get('error') or ''
        self.assertIn('Gap Implementation Guides', error)
        self.assertNotEqual(status.get('status'), 'pending')


if __name__ == '__main__':
    unittest.main()
