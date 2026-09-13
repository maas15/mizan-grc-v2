# Migration from current `main` to REL37

**From:** `origin/main` `fb61736` (REL36.18.1)  
**Not from:** PR #128 / `f04f60b`

## 1. Sequence

1. Keep production at `ec779cc` / `autoDeploy=no`.
2. Keep PR #128 open; add no more commits to that branch.
3. Land REL37 plan (this folder) on `feature/rel37-deterministic-data-ai-dt-compilers`.
4. After approval, implement compilers + `tests/test_rel37_deterministic_compilers.py` on the same branch.
5. Wire a **domain selector** in generation for Data/AI/DT strategy only. Cyber remains on `main` REL32/REL36.8–18.1 path.
6. Phase 2: persist model JSON; point Data/AI/DT preview/export at `rel37_render`.
7. Phase 3: QA Harness.

## 2. What to reuse from `main` (code)

- `CanonicalStrategyDocument` dataclasses as a seed (extend, do not break Cyber).
- `DATA_*` / `AI_*` / `DT_*` catalogs in `rel32_registries.py` as v1 inventory.
- `rel33_domain_guard` so ERM never runs the strategy compiler.
- Cyber and Auth tests listed in the test plan.

## 3. What not to bring from PR #128

- Any `_apply_rel36_19` … `_apply_rel36_23_2` wrapper.
- `rel36_23_2_dt_ar_live_kpi_and_token_integrity.py` global counter.
- Markdown DGA row insertion / KPI table collapse helpers.
- Cherry-picks of `931900f`–`f04f60b`.

## 4. Compatibility

Old Data/AI/DT artifacts saved on production (`ec779cc`) or `main` remain markdown. Phase 1 does not migrate them. Phase 2 adapter:

- If `rel37_model` present → validate model.
- Else → import markdown into model **best-effort** for export only; do not run PR #128 repairs; fail closed on leakage / missing coverage rather than regex-rewrite tables.

## 5. Flag

`REL37_DATA_AI_DT_COMPILER=1` in tests. Production stays off until a later, explicit deploy decision (not this work).
