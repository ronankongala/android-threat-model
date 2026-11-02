# Ground truth dataset schema

File: `data/ground-truth.csv`. One row per Ghera benchmark (57 rows) at tag `Jan2019` (commit `6289f39d`). UTF-8, comma separated, RFC 4180 quoting, header on the first line.

## Sources

Every value except `secondary_cwe_ids` (derived from the evaluator and a reviewed correction, see Columns) comes from one of these, and from nothing else:
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
| `secondary_cwe_ids` | list | `tools/evaluate.py` `SECONDARY_CWE`; P1-3 review | Alternative CWEs that the evaluator counts as a match in the expanded score (the strict score uses `cwe_ids` only). Most entries are the reverse of the evaluator mapping (Fix A). Two were added after a review of the threat model and README (P1-3): CWE-200 for `ClipboardUse-InformationExposure-Lean` (parent of CWE-359) and CWE-829 for `WebViewAllowFileAccess-UnauthorizedFileAccess-Lean` (parent of CWE-830). Blank when no alternative applies. |
| `masvs_ids` | list | threat model or mapping | OWASP MASVS v2 control IDs from the standards table. |
| `maswe_ids` | list | threat model or mapping | OWASP MASWE IDs from the standards table. |
| `mastg_ids` | list | threat model or mapping | OWASP MASTG test IDs from the standards table. |
| `model_file` | path | `docs/threat-models/` | Repo-relative path to the threat model, or to the benchmark's section of `other-categories-mapping.md` (with a `#` anchor). Blank when no model or mapping exists. |
| `evidence_status` | text | threat model or mapping, and `benchmark-index.md` | Run status from the Evidence section, with the index "Model done" value in brackets. |
| `vulnerable_component` | list | threat model or mapping; README; Benign and Secure source (A1-1) | The class or classes that carry the benchmark's weakness, fully qualified, separated by `; `. `(application)` when the weakness is an app-level manifest setting rather than a class. Used by `tools/evaluate.py` to decide Secure false positives (see below). |

### `vulnerable_component` (A1-1)

What is listed: the class whose code or manifest entry carries the weakness the README describes and the exploit uses, as named in the threat model (Components table, Standards mapping and Evidence sections) or in the mapping section's "What the code does" text. In practice this is where the Secure app's fix lands. A class that only appears in a secondary, Partial CWE row outside the exploit path is left out, for example `MyIntentService` (always-true host name verifier, kept unchanged in Secure) for `CheckValidity-InformationExposure-Lean`, `MainActivity` (own implicit broadcast) for `UnprotectedBroadcastRecv-PrivEscalation-Lean`, and `MainActivity` (the JavaScript bridge and the `readKey`/`writeKey` interface) for `WebView-NoUserPermission-InformationExposure-Lean` and `WebViewInterceptRequest-MITM-Lean`, where the fix is in `GPSTracker` and `MyWebViewClient`.

Where the class names come from:
- The class is named in the threat model or mapping for every row except `WeakChecksOnDynamicInvocation-DataInjection-Lean` and `UnprotectedBroadcastRecv-PrivEscalation-Fat`, which have no model.
- Packages were confirmed from the Java source under `benchmarks/ghera/<category>/<folder>/Benign` and `Secure` (`app/src/main/java`, and the `logutil` and `Library` modules). The models give most paths, not always the package.
- When the Secure app keeps the class in a different Java package, the Secure name is listed too, since the false positive rule runs on Secure findings: `edu.ksu.cs.secure.*` for `BlockCipher-NonRandomIV-InformationExposure-Lean`, `PBE-ConstantSalt-InformationExposure-Lean`, `OpenSocket-InformationLeak-Lean` and `UnEncryptedSocketComm-MITM-Lean`, and `edu.cs.ksu.benign.MainActivity` for `EmptyPendingIntent-PrivEscalation-Lean`.
- `WeakChecksOnDynamicInvocation-DataInjection-Lean`: the README names the provider `FileContentProvider`; the Benign source class is `edu.ksu.cs.benign.FIleContentProvider` (sic), which is listed.
- `UnprotectedBroadcastRecv-PrivEscalation-Fat`: the README names `SmsReceiver` of the system app `com.android.mms` without its package, so the simple name is listed.
- `(application)`: `TaskAffinity-LauncherActivity-PhishingAttack-Lean` and `TaskAffinityAndReparenting-PhishingAndDoSAttack-Lean`, where the weakness is the default task affinity of the whole app and the Secure fix is `android:taskAffinity=""` on `<application>`.

No row is blank.

How `tools/evaluate.py` uses it. A Secure APK is a false positive only if one of its findings has a CWE that is exactly one of the row's `cwe_ids` (not a `secondary_cwe_ids` entry and not through `SECONDARY_CWE`) and that same finding is on a listed component. A finding's `component` is the component class for manifest findings, the smali class for code findings (for example `edu.ksu.cs.benign.MainActivity$1`) and `(application)` for app-level findings. It matches a listed name when it is the same class or an inner class of it (`Outer$Inner` matches `Outer`); a listed name without a package is compared with the finding's simple class name. A blank cell or `(application)` matches every finding, so the CWE alone decides. An `(application)` finding does not match a named class. The legacy definition (any Secure finding is a false positive) is still written as `false_positive_any` in the evaluation results.

## Conventions

- List cells separate IDs with `; ` (semicolon and space), in the order of the standards table. IDs only, no titles.
- Only IDs in a standards table row are listed. IDs a model or mapping names as considered and rejected are left out.
- Every ID is in `docs/threat-models/standards-reference.md`.
- Benchmarks with no model or mapping have blank ID cells: the index CWE and MASVS columns for those rows are unverified guesses ("Needs check") and are not ground truth.
- Nothing in this dataset has been observed on an emulator. The expected results are what the README and Testing code say should happen.
