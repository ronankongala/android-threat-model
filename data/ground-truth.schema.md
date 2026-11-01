# Ground truth dataset schema

File: `data/ground-truth.csv`. One row per Ghera benchmark (57 rows) at tag `Jan2019` (commit `6289f39d`). UTF-8, comma separated, RFC 4180 quoting, header on the first line.

## Sources

Every value comes from one of these, and from nothing else:
- the files under `docs/threat-models/` (`benchmark-index.md`, the threat models `ICC-*.md` and `Web-*.md`, and `other-categories-mapping.md`);
- the benchmark `README.md`;
- the benchmark Testing code (`Testing/**/androidTest/**/*.java`).

A cell is blank when these sources have nothing for it. A blank cell means "not stated in the sources", not "none".

## Columns

| Column | Type | Source | Meaning |
|--------|------|--------|---------|
| `category` | text | `benchmark-index.md` | Ghera category: Crypto, ICC, Networking, NonAPI, Permission, Storage, System or Web. |
| `folder` | text | `benchmark-index.md` | Benchmark folder name under `benchmarks/ghera/<category>/`. Primary key. |
| `lean_or_fat` | `Lean` or `Fat` | `benchmark-index.md` | Ghera benchmark kind. |
| `android_versions_readme` | text | README | Text under the README heading "Android versions affected" (or "Versions of Android affected"), copied as written. |
| `vulnerability_summary` | text | `benchmark-index.md` | The Summary cell of the index, copied as written. |
| `expected_benign_result` | text | README, Testing code, or threat model Evidence | What the README or the Benign test expects when the exploit runs against Benign, with a short source reference. |
| `expected_secure_result` | text | README, Testing code, or threat model Evidence | What the README or the Secure test expects when the exploit runs against Secure, with a short source reference. |
| `cwe_ids` | list | threat model or mapping | CWE IDs from the standards table, in table order. |
| `masvs_ids` | list | threat model or mapping | OWASP MASVS v2 control IDs from the standards table. |
| `maswe_ids` | list | threat model or mapping | OWASP MASWE IDs from the standards table. |
| `mastg_ids` | list | threat model or mapping | OWASP MASTG test IDs from the standards table. |
| `model_file` | path | `docs/threat-models/` | Repo-relative path to the threat model, or to the benchmark's section of `other-categories-mapping.md` (with a `#` anchor). Blank when no model or mapping exists. |
| `evidence_status` | text | threat model or mapping, and `benchmark-index.md` | Run status from the Evidence section, with the index "Model done" value in brackets. |

## Conventions

- List cells separate IDs with `; ` (semicolon and space), in the order of the standards table. IDs only, no titles.
- Only IDs in a standards table row are listed. IDs a model or mapping names as considered and rejected are left out.
- Every ID is in `docs/threat-models/standards-reference.md`.
- Benchmarks with no model or mapping have blank ID cells: the index CWE and MASVS columns for those rows are unverified guesses ("Needs check") and are not ground truth.
- Nothing in this dataset has been observed on an emulator. The expected results are what the README and Testing code say should happen.
