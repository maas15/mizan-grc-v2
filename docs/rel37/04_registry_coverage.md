# REL37 Registry — rows, families, framework coverage

Phase 1 compilers generate these families from **request `selected_frameworks`**, not from body-text salvage.

## 0. Supported selections (Phase 1 gate)

`rel37_supported_selection()` decides whether REL37 may compile. Unsupported combinations no-op onto the existing `main` path. REL37 never silently drops unsupported tokens and compiles the remainder.

| Domain | Supported selections | Default when `explicit_selection=false` and list empty |
|---|---|---|
| Data | `NDMO` / `PDPL` / `NDMO+PDPL` | `NDMO+PDPL` |
| AI | `SDAIA` | `SDAIA` |
| DT | `DGA` | `DGA` |

Unsupported (examples; not exhaustive): Data+`NCA`, AI+`EU AI Act` / `NIST AI RMF` / `UNESCO`, DT+`NIST CSF`, Cyber, ERM, Global, `policy` / `procedure` / `audit`, explicit empty selection.

Diagnostic line: `[REL37-SUPPORTED-FRAMEWORK-SELECTION]` with `domain`, `lang`, `document_type`, `selected_frameworks_input`, `explicit_selection`, `normalized_frameworks`, `unsupported_frameworks`, `default_expanded`, `supported`, `reason`.

Seed catalogs already on `main` (`rel32_registries.py`: `DATA_*`, `AI_*`, `DT_*`) are the starting inventory. REL37 versions them as `rel37.strategy.v1` and adds the families listed below that `main` under-specifies (for example explicit `citizen_experience` / `digital_services` DT rows).

## 1. Shared leakage deny-lists

Applied to structural cells and generated prose (not to `org_name`).

| Domain | Denied unless explicitly selected |
|---|---|
| Data | `NCA`, `NCA ECC`, `NCA DCC`, `CISO`, `SIEM`, `SOC`, `CSIRT`, `NIST`, `NIST CSF` |
| AI | Data list plus `IAM`, `PAM`, `MFA` as Cyber-control leakage (not generic “identity”) |
| DT | `NCA`, `CISO`, `SIEM`, `SOC`, `CSIRT`, `NIST` |

Owner allow-lists are domain-specific (Data: CDO / Data Governance Manager / DPO / Steward; AI: AI Governance Lead / Model Risk Owner; DT: Digital Transformation Lead / Service Owner). Cyber titles (`CISO`, `SOC Lead`) are not Data/AI/DT default owners.

## 2. Data strategy (AR + EN)

**Frameworks (when selected):** `NDMO`, `PDPL`.

**Required SO coverage (first SO table):**

- NDMO selected → one SO row `family=ndmo_compliance` (compliance/alignment wording).
- PDPL selected → one SO row `family=pdpl_compliance`.

**Required families (KPI + gap + roadmap as specified):**

| Family | KPI | Gap | Roadmap | Notes |
|---|---|---|---|---|
| `data_catalog` | yes | yes | yes | `data_catalog_metadata` on `main` maps here |
| `data_lifecycle` | yes | yes | yes | `data_lifecycle_retention` / `lifecycle_management` |
| `privacy_governance` | yes | yes | yes | NDMO + PDPL overlap |
| `personal_data_classification` | yes | yes | yes | `data_classification` |
| `consent_management` | yes | yes | yes | `consent_rights` |
| `data_subject_rights` | yes | yes | yes | may share roadmap row with consent if one initiative covers both **and** both families are marked satisfied |
| `breach_notification` | yes | yes | yes | `data_breach_notification` |
| `data_quality` | yes | yes | yes | already on `main` |
| `metadata_stewardship` | yes | yes | yes | catalog + steward; `data_stewardship` |
| `data_sharing` | yes | yes | yes | already on `main` |

Default Phase 1 request for tests: `frameworks=['NDMO','PDPL']` → all rows above required.

## 3. AI strategy (AR + EN)

**Frameworks (when selected):** `SDAIA`.

**Required SO coverage:** one `family=sdaia_compliance` row in the first SO table.

**Required families:**

| Family | Intent |
|---|---|
| `responsible_ai_governance` | SDAIA policy / board oversight (`ai_governance`) |
| `ai_model_registry` | 100% production models registered (`model_inventory`) |
| `model_risk` | high-risk model assessment |
| `human_oversight` | human-in-the-loop for high-risk systems |
| `data_readiness` | training/eval data fitness |
| `bias_fairness` | fairness tests |
| `explainability` | explainability for critical models |
| `monitoring` | production drift / quality monitoring |
| `mlops` | deployment / CI for models |
| `incident_handling` | AI incident / rollback |

Default Phase 1 request: `frameworks=['SDAIA']`.

## 4. DT strategy (AR + EN)

**Frameworks (when selected):** `DGA`.

**Required SO coverage:** one DGA alignment/compliance SO row.

**Required families:**

| Family | Intent |
|---|---|
| `digital_services` | improved / automated digital services (DGA) |
| `interoperability` | API / government integration; preserve `dga_interoperability` |
| `citizen_experience` | beneficiary / user-journey satisfaction (contiguous `المستفيد` / `المستفيدين` in AR) |
| `apis_integration` | service integration catalog |
| `beneficiary_user_journey` | journey coverage (may alias into citizen_experience if one row satisfies both **explicitly**) |
| `service_quality` | service-level / quality KPIs |

Default Phase 1 request: `frameworks=['DGA']`.

Citizen token rule: the model stores `المستفيد` / `المستفيدين` only. Split forms `المست فيد` / `المست فيدين` are invalid cell values.

## 5. Guide generation

For every compiled `GapRow` / `KpiRow`, emit one guide whose first-200-char body includes `family`, `framework`, and `row.number` so uniqueness is structural, not a post-hash repair.

## 6. Roadmap generation

`roadmap.rows = [build(family) for family in required_roadmap_families]` in registry order.  
No second pass that re-appends the same family. Countability is `len(rows)`, not a markdown pipe parse.

## 7. Versioning

`rel37.coverage.v1` lives with `rel37.strategy.v1`. Adding a family is a schema bump. Gates load the version stored on the document.
