# REL37 export-contract reimplementation

This branch is a **new implementation** from baseline `3bd104c8c900360c1cd59bf68905ef7af87dd7bb`.

It is **not** a recovery of the unavailable historical commits
`d2f2d5016123fa2fd93770fb25ec5e1146a4a56c` and
`99af805daa160b21fbc0892765f29d610512117e`. Those objects were absent
in the inspected scope. Their SHAs are incident identifiers only.

Historical local test claims and `/opt/cursor/artifacts/rel37_19_ar_row/`
dumps do **not** transfer. New tests and gate results use **new**
commit/tree identities on
`recovery/rel37-export-contract-reimplementation`.

PR #130 remains at `3bd104c` until a separate integration decision.
