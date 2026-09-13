# REL37 Architecture Note

**Base:** `origin/main` (REL36.18.1). Cyber stays on this path in Phase 1.  
**Core rule:** LLM writes narrative prose only. Compilers build all structural tables.

## 1. Problem REL37 solves

On `main`, REL32 already has typed rows (`CanonicalStrategyDocument`) and `rel32_compiler.py`. After compile, the live path still:

1. Flattens the model back to markdown strings.
2. Lets the LLM emit pipe tables.
3. Re-parses those strings in save gates, preview JS, and DOCX/PDF extractors.
4. Stacks REL36.7–18 mutators (on `main`) plus the unmerged REL36.19–23.2 stack (on PR #128).

REL37 makes the typed document the **only** structural authority for Data / AI / DT **strategy** documents.

## 2. Authority diagram (target)

```text
Request metadata
  document_type, domain, lang, selected_frameworks[], org_name
        │
        ▼
LLM prose pass  ──► vision / rationale sentences / guide body prose
        │                 (no pipe tables, no column sets)
        ▼
REL37 compilers (Data | AI | DT) × (ar | en)
        │
        ▼
CanonicalDocument.assemble()
  typed tables + 1:1 guides + coverage + model_hash
        │
        ├─► validate(model)          save gate
        ├─► persist model JSON       sections_json / model blob
        ├─► render(md|html|docx|pdf|txt|print)
        └─► evidence(extract) == model.expected_evidence()
```

No regex repair may mutate tables after `validate(model)` succeeds.

## 3. What stays on `main` in Phase 1

- Cyber strategy generation and its REL36.8–18.1 stabilizers.
- ERM risk native compiler selection (`rel33_domain_guard`).
- Auth/CSRF export denials (`csrf_invalid`, `cross_user_export_denied`).
- Existing smoke scripts.

REL37 compilers are **additive** modules. They are selected only when:

```text
document_type == strategy
AND domain in {data, ai, dt}
AND rel37_compiler_enabled (flag, default on in tests)
```

Cyber must not enter this selector in Phase 1.

## 4. Module layout (when implementation is approved)

Proposed new files (not created on this plan push):

```text
release_engine_v3/rel37_canonical_document.py    # CanonicalDocument + table types
release_engine_v3/rel37_schema_registry.py       # versioned schemas + headers
release_engine_v3/rel37_coverage_registry.py     # families × frameworks
release_engine_v3/rel37_data_strategy_compiler.py
release_engine_v3/rel37_ai_strategy_compiler.py
release_engine_v3/rel37_dt_strategy_compiler.py
release_engine_v3/rel37_render.py                # md/html/docx/pdf/txt/print
release_engine_v3/rel37_validate.py              # model gates
tests/test_rel37_deterministic_compilers.py
```

Seed types from `canonical_strategy_document.py` on `main`. Do not import PR #128 modules.

## 5. LLM contract

Allowed LLM outputs (JSON or constrained prose fields):

- Vision / context paragraphs
- Optional cell wording for a **registry-known** family (KPI name gloss, gap description)

Forbidden:

- Markdown tables
- Extra columns
- Extra KPI or SO tables
- Framework names not in `request.selected_frameworks`
- Structural headings that invent a second schema

If LLM cell prose fails language or leakage checks, the compiler substitutes the registry default for that family.

## 6. Validation vs render vs evidence

| Layer | Input | Pass condition |
|---|---|---|
| Model validate | `CanonicalDocument` | invariants in § schema |
| Persist | model JSON | `persist_hash == model_hash` |
| Render | model + target | labels from schema only |
| Evidence | extracted DOCX/PDF/HTML | equals `model.expected_evidence()` |

Markdown is a **render**, not a source. Save gates do not count `_KPI_MAIN_TABLE_HEADER_RE`.

## 7. Phase plan (unchanged)

**Phase 1:** Data/AI/DT compilers + tests + Cyber/Auth/smoke regressions. Production frozen.  
**Phase 2:** Cut Data/AI/DT live save/preview/export to the model; golden fixtures.  
**Phase 3:** QA Harness (not started now).
