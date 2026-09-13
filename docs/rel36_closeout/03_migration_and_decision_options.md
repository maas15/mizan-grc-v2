# REL36 → REL37 Migration Plan and Decision Options

**Status:** Decision requested. No code until approved.  
**Date:** 2026-09-13  
**PR #128:** remains OPEN / unmerged as evidence.

## 1. Migration plan (after a decision option is chosen)

### 1.1 Freeze

- Production: keep `ec779cc` / `dep-dabg86710e5c73fu2uig` / `autoDeploy=no`.
- Do not call the production hook.
- Do not merge PR #128.
- Do not implement REL36.24.
- Do not start QA Harness.

### 1.2 Inventory what is reusable vs toxic

**Reusable (copy as reference, re-express as registry/compiler rules):**

- REL32 dataclasses and family registries (`canonical_strategy_document.py`, `rel32_registries.py`).
- REL33 document-type compiler selection (do not run strategy compiler on ERM risk).
- REL36.19.1 bilingual rules: preserve exact `org_name`; do not strip legitimate Arabic in English docs; repair **before** canonical hash (as a model-level rule, not a late markdown patch).
- REL36.20 family lists for Data roadmap / gap / KPI.
- REL36.21 required SO objectives for NDMO/PDPL/SDAIA.
- REL36.22 DGA families: `citizen_experience`, `interoperability`, `digital_services`.
- REL36.23 guide 1:1 intent and English SO header canon.
- REL36.23.2 *intent* only: formula/source is not a KPI main table; tokens must be contiguous before persist.

**Toxic on the live path (do not cherry-pick as mutators):**

- Global full-schema KPI header regex gate from REL36.23.2 (`_count_full_kpi_main_headers_for_gate` replacing loose count for all domains).
- Post-hoc DGA row insert without typed guides (REL36.22 / 23.1 / 23.2 collapse).
- Helper-on-copy diagnostics treated as save-path proof.
- Any repair that mutates markdown after `model_hash`.

### 1.3 New branch rule

All REL37 work happens on a **new branch from `origin/main`** (`fb61736`, REL36.18.1), unless option B is explicitly chosen.

Suggested name shape (when implementation is approved): `cursor/rel37-data-ai-dt-compiler-<id>`.

PR #128 stays where it is. Do not rebase it, force-push it, or use it as the REL37 integration branch.

### 1.4 Cut-over sequence

1. Add `schema_version` + model JSON persist beside existing `sections_json` (shadow write, unused by gates).
2. Build Data/AI/DT compilers; unit-test model invariants.
3. Point Data/AI/DT save gates at `validate(model)` behind a domain flag.
4. Point preview/export for those domains at `model.render`.
5. Disable REL36.19–23.2 apply wrappers for those domains only.
6. Keep Cyber on current `main` path until Phase 2 fixtures say otherwise.
7. Only then run QA Harness (Phase 3).

### 1.5 Staging contract for REL37 (later)

Official 6/6 remains required, but critical live inspection must use **saved latest + export bytes**, not helper-on-copy. A domain compiler is not done until:

- Official route save/DOCX/PDF allowed
- Model hash equals persist hash equals export input hash
- Guide counts equal row counts
- KPI main object count is 1
- Formula/source object is optional and uncounted
- Language parity and coverage come from the model

## 2. Decision options

### A. Abandon PR #128 and rebuild clean from `main`

- Close or leave #128 open but never merge.
- New REL37 branch from `fb61736`.
- Zero cherry-picks from #128.
- **Pros:** Smallest blast radius; no 23.2 gate regression on `main`; clean history.
- **Cons:** Re-derives bilingual/`org_name`/DGA family knowledge from scratch (still available by reading #128).
- **Use when:** The team wants a hard reset and accepts rewriting 19.1 language rules in the compiler.

### B. Cherry-pick only safe REL36.19.1 language-parity pieces

- New branch from `main`.
- Cherry-pick or manually port **19.1 only** (`94936cc` intent: `org_name` preservation, pre-canonical repair, no duplicate KPI *seed* table, do not delete legitimate Arabic in English docs).
- Do **not** cherry-pick REL36.20–23.2 mutators or the 23.2 global header counter.
- **Pros:** Keeps the one #128 change that is closest to a model-level rule.
- **Cons:** 19.1 still lives as markdown sanitization; it must be re-expressed as a model rule quickly or it becomes REL36.24 by another name. Cherry-pick conflicts with later files on #128 (`rel36_19_bilingual_language_parity.py` was edited again in 20–23).
- **Use when:** English-with-Arabic-`org_name` is the next demo risk and must not regress while compilers are built.

### C. Keep PR #128 as reference only and create a new branch from `main` (recommended)

- **Do not close PR #128** unless later instructed. It is the forensic record (CI greens, staging 5/6 then 6/6-with-bad-latest then 1/6, leftover Codex comments, +15k repair lines).
- New REL37 branch from `origin/main`.
- Engineers read #128 modules and tests as a **requirement catalog**, then implement those requirements as registry rows and compiler builders.
- No merge, no cherry-pick of 20–23.2, optional later port of 19.1 rules as in B.
- **Pros:** Evidence preserved; `main` stays free of the 23.2 cross-domain 0/1 gate; REL37 is not stacked on a failing hotfix tower.
- **Cons:** Requires discipline not to “just apply the old helper” under time pressure.

## 3. Recommendation

**Choose C.** Optionally fold the *rules* from B into the REL37 language layer (not the 19.1 markdown file).

Do not choose “merge #128 then fix 23.2 on main.” That continues the escalation the closeout is meant to stop.

## 4. Approval gate

Implementation starts only after explicit approval of:

1. This closeout (stop REL36.24).
2. The REL37 design (`02_rel37_deterministic_compiler_design.md`).
3. Decision A, B, or C (default recommendation: C).

Until then: no code, no QA Harness, no production deploy, PR #128 open.
