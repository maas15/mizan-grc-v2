# REL37 Test plan

New tests must **not** depend on PR #128 repair-stack behavior.  
File to add when implementation is approved: `tests/test_rel37_deterministic_compilers.py`.

## 1. Required groups (in that module)

| # | Group | Assert |
|---|---|---|
| 1 | Data AR | Valid model; preview/DOCX/PDF render; NDMO+PDPL families; AR headers |
| 2 | Data EN | Same for English; EN headers; no Arabic generated prose |
| 3 | AI AR | SDAIA families; AR headers; no Cyber leakage |
| 4 | AI EN | SDAIA families; EN headers |
| 5 | DT AR | DGA digital_services / interoperability / citizen_experience; contiguous `المستفيد`; AR headers |
| 6 | DT EN | Same families; EN headers |
| 7 | KPI vs formula/source | Two types; formula object not in main count; both may render |
| 8 | KPI guides 1:1 | `len(kpi_guides) == len(kpis)` after compile |
| 9 | Gap guides 1:1 | `len(gap_guides) == len(gaps)` |
| 10 | Data roadmap families | All required families present; no duplicate; no restart |
| 11 | AI SDAIA coverage | SO + families from registry; `missing_families == []` |
| 12 | DT DGA coverage | citizen / interop / digital present in KPI + required sections |
| 13 | Language parity | EN/AR structural labels; no wrong-language generated prose |
| 14 | Arabic `org_name` | English compile with `org_name=شركة مثال` preserves exact string in model + all renders |
| 15 | No domain leakage | Deny-lists on Data/AI/DT (see registry) |
| 16 | Same model hash | Evidence projection identical across preview/DOCX/PDF |
| 17 | Old saved artifact plan | Test documents the adapter contract; fixtures of pre-REL37 markdown are imported **without** calling PR #128 mutators (skip-impl until Phase 2 if adapter not built) |
| 18 | Cyber regression | Existing Cyber tests on `main` stay green; REL37 selector does not capture Cyber |
| 19 | Auth/CSRF regression | Existing export auth tests stay green (`csrf_invalid`, `cross_user_export_denied`) |
| 20 | Smoke | `smoke_document_type_matrix.py` and `smoke_all_domains_preview_docx_pdf.py` pass |

Group 17 in Phase 1 may be a **contract test** (adapter API exists or is explicitly skipped with a Phase 2 ticket) rather than a full import of production DB rows.

## 2. Required local gates (implementation turn)

```text
python3 -m py_compile app.py professional_strategy_render.py
pytest tests/test_rel37_deterministic_compilers.py
pytest tests/test_rel36_11_english_cyber_export_stability.py \
       tests/test_rel36_8_english_cyber_pillars_parity.py \
       tests/test_rel36_9_english_cyber_live_stability.py \
       tests/test_rel36_12_english_cyber_presave_pillar_stability.py \
       tests/test_rel36_13_english_cyber_core_completeness.py \
       tests/test_rel36_14_english_cyber_final_counted_structures.py \
       tests/test_rel36_16_english_cyber_vision_pillars_objectives.py \
       tests/test_rel36_17_english_cyber_final_save_gate_stabilizer.py
pytest tests/test_rel36_11_english_cyber_export_stability.py   # Auth/CSRF surface
python3 scripts/smoke_document_type_matrix.py
python3 scripts/smoke_all_domains_preview_docx_pdf.py
```

Do not run QA Harness in Phase 1 plan/implementation until Phase 2 is approved.

## 3. Explicit non-tests

- Do not assert PR #128 helper-on-copy `passed=true`.
- Do not assert the REL36.23.2 global full-schema counter.
- Do not require `kpi_main_header_count` regex on formula/source headers.

## 4. Fixture style

Each domain×lang compile uses a **request object** (`domain`, `lang`, `frameworks`, `org_name`) and optional prose JSON. Golden files (Phase 2) store model JSON + evidence projection, not only markdown snapshots.
