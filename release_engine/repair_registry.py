"""PR-REL2 domain-pack repair registry — no global markdown regex."""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Tuple

_REPAIRERS: Dict[str, Callable[..., Tuple[Dict[str, str], List[str]]]] = {}


def register_repairer(domain_code: str, fn: Callable[..., Tuple[Dict[str, str], List[str]]]):
    _REPAIRERS[domain_code] = fn


def _dedupe_objectives(vision: str) -> Tuple[str, List[str]]:
    actions: List[str] = []
    if not vision:
        return vision, actions
    seen = set()
    out_lines = []
    for ln in vision.splitlines():
        m = re.match(r'^\s*\|\s*(\d+)\s*\|', ln)
        if m:
            obj = re.sub(r'\s+', ' ', ln.split('|')[2] if ln.count('|') >= 3 else '')
            key = obj.strip().lower()[:80]
            if key and key in seen:
                actions.append('rel2_repair:dedupe_objective_row')
                continue
            if key:
                seen.add(key)
        out_lines.append(ln)
    return '\n'.join(out_lines), actions


def _renumber_kpi_table(kpis: str) -> Tuple[str, List[str]]:
    actions: List[str] = []
    if not kpis or '|' not in kpis:
        return kpis, actions
    lines = kpis.splitlines()
    out = []
    n = 0
    for ln in lines:
        m = re.match(r'^\s*\|\s*(\d+)\s*\|', ln)
        if m and not re.match(r'^\s*\|[\s\-:|]+\|', ln):
            n += 1
            parts = ln.split('|')
            if len(parts) >= 3:
                old = parts[1].strip()
                if old != str(n):
                    actions.append('rel2_repair:renumber_kpi_row')
                parts[1] = f' {n} '
                ln = '|'.join(parts)
        out.append(ln)
    return '\n'.join(out), actions


def _inject_missing_legacy_sections(
        sections: Dict[str, str],
        *,
        lang: str,
        domain_pack: Dict[str, Any],
) -> Tuple[Dict[str, str], List[str]]:
    actions: List[str] = []
    out = dict(sections)
    stubs_en = {
        'pillars': '## 2. Pillars\n\n| # | Pillar | Owner |\n|---|---|---|\n| 1 | Core | Lead |\n',
        'environment': '## 3. Environment\n\nRegulatory context.\n',
        'gaps': '## 4. Gaps\n\n| # | Gap | Severity |\n|---|---|\n| 1 | Gap | Medium |\n',
        'roadmap': '## 5. Roadmap\n\n| Phase | Initiative | Months |\n|---|---|\n| Short | Plan | 0-6 months |\n',
        'kpis': '## 6. KPIs\n\n| # | Metric | Target |\n|---|---|\n| 1 | Coverage | 90% |\n',
        'confidence': (
            '## 7. Confidence\n\n**Confidence score:** 75%\n'
            '**Justification:** Repaired.\n'),
    }
    stubs_ar = {
        'pillars': '## 2. الركائز\n\n| # | ركيزة | المالك |\n|---|---|---|\n| 1 | أساسية | قائد |\n',
        'environment': '## 3. البيئة\n\nسياق تنظيمي.\n',
        'gaps': '## 4. الفجوات\n\n| # | فجوة | الخطورة |\n|---|---|\n| 1 | فجوة | متوسط |\n',
        'roadmap': '## 5. خارطة الطريق\n\n| مرحلة | مبادرة | أشهر |\n|---|---|\n| قصيرة | خطة | 0-6 أشهر |\n',
        'kpis': '## 6. مؤشرات\n\n| # | مؤشر | هدف |\n|---|---|\n| 1 | تغطية | 90% |\n',
        'confidence': (
            '## 7. تقييم الثقة\n\n**درجة الثقة:** 75%\n'
            '**مبررات التقييم:** تم الإصلاح.\n'),
    }
    stubs = stubs_ar if lang == 'ar' else stubs_en
    mandatory = domain_pack.get('mandatory_legacy_sections') or list(stubs)
    for key in mandatory:
        if not (out.get(key) or '').strip():
            out[key] = stubs.get(key, '')
            actions.append(f'rel2_repair:inject_section:{key}')
    return out, actions


def _default_domain_repair(
        sections: Dict[str, str],
        *,
        lang: str,
        domain_pack: Dict[str, Any],
) -> Tuple[Dict[str, str], List[str]]:
    actions: List[str] = []
    out, a0 = _inject_missing_legacy_sections(
        sections, lang=lang, domain_pack=domain_pack)
    actions.extend(a0)
    v, a1 = _dedupe_objectives(out.get('vision', '') or '')
    if a1:
        out['vision'] = v
        actions.extend(a1)
    k, a2 = _renumber_kpi_table(out.get('kpis', '') or '')
    if a2:
        out['kpis'] = k
        actions.extend(a2)
    conf = out.get('confidence', '') or ''
    if conf and 'confidence score' not in conf.lower() and 'درجة الثقة' not in conf:
        if lang == 'ar':
            out['confidence'] = (
                '## 7. تقييم الثقة\n\n**درجة الثقة:** 75%\n'
                '**مبررات التقييم:** تم الإصلاح تلقائياً.\n\n' + conf)
        else:
            out['confidence'] = (
                '## 7. Confidence\n\n**Confidence score:** 75%\n'
                '**Justification:** Auto-repaired.\n\n' + conf)
        actions.append('rel2_repair:inject_confidence_block')
    return out, actions


def run_domain_repairs(
        sections: Dict[str, str],
        *,
        domain: str,
        lang: str,
        domain_pack: Dict[str, Any],
) -> Tuple[Dict[str, str], List[str]]:
    code = (domain or '').strip().lower()
    fn = _REPAIRERS.get(code) or _default_domain_repair
    return fn(sections, lang=lang, domain_pack=domain_pack)
