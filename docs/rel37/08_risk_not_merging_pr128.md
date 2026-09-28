# Risk analysis: not merging PR #128

## Decision

Do not merge PR #128. Retain it as evidence. Build REL37 from `origin/main`.

## Risks of not merging

| Risk | Severity | Mitigation |
|---|---|---|
| English docs still lose Arabic `org_name` on `main` | Medium | Encode 19.1 as a REL37 model rule (group 14) before Data/AI/DT cut-over; Cyber stays on `main` until then |
| Arabic Data roadmap countability still fragile on `main` | Medium | REL37 Data compiler generates countable rows (group 10); `main` REL36.7/10 remain until cut-over |
| EN Data/AI missing NDMO/PDPL/SDAIA SO rows on `main` | Medium | REL37.21 requirement in compiler (groups 1–4, 11) |
| DT DGA `citizen_experience` missing on `main` | Medium | REL37 DT compiler (groups 5–6, 12). `main` does not have 22/23.x |
| Unique gap guides / EN SO header drift on `main` | Medium | Schema-owned headers (renderer contract); 1:1 guides |
| Formula/source counted as KPI main on `main` (the 23.1 live DT bug) | High for DT | REL37 types (group 7). Accept DT on `main` remains imperfect until Phase 2 cut-over |
| Staging currently running `f04f60b` (1/6 broken) | Operational | Do not use that staging SHA for demos; optional later redeploy staging to `main` (not production) when someone explicitly asks |
| Lost +15k lines of “fixes” | Low | They are a requirement catalog, not a working system. Re-implement as registry rows |
| Codex leftover P1/P2 on #128 never “closed” by merge | Low | Re-state 19.1 in REL37 language layer; leave comments on #128 |

## Risks of merging PR #128 instead

| Risk | Severity |
|---|---|
| Official staging 1/6: Cyber/Data/AI/Global cannot save | **Critical** |
| Global KPI counter false-negative (`المصدر` → 0/1) | **Critical** |
| DT 8 guides vs 11 rows | **Critical** |
| Cross-domain blast from a DT-only intent | **Critical** |
| Continues REL36.24 pressure | High |

## Residual accepted debt

Until REL37 Phase 2 ships, Data/AI/DT on `main` keep the pre-19 repair/LLM-table behavior. That is **better than shipping 23.2**. Production is still REL36.11 and is not offered these changes.

## Conclusion

Not merging #128 avoids a proven save-gate outage. The cost is deferred bilingual/DT coverage on `main`, which REL37 is designed to pay down without the 23.2 counter.
