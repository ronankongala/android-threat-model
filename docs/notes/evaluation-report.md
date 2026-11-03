# Evaluation report

## Latest run: precision round (P-1 to P-9)

Run of `python tools/evaluate.py --no-dynamic` on 2026-11-02 after the precision work P-1 to P-9, split into three shards with `--only` that ran side by side; `python tools/evaluate.py --rescore` then wrote `data/evaluation-results.csv` from the reports in `data/eval-tmp/`. Same 53 benchmarks and static layers as below. A Secure APK is a false positive under the A1-1 definition: one of its findings has an exact `cwe_ids` CWE of the benchmark, on the vulnerable component, at medium or high confidence (see `tools/evaluate.py`). The sections after this one describe earlier rounds and keep their own numbers.

### Standard mode

| Category | Benchmarks | TP | FP | Precision | Recall |
|----------|-----------:|---:|---:|----------:|-------:|
| Crypto | 5 | 5 | 5 | 0.50 | 1.00 |
| ICC | 16 | 15 | 3 | 0.83 | 0.94 |
| Networking | 8 | 8 | 1 | 0.89 | 1.00 |
| NonAPI | 1 | 1 | 0 | 1.00 | 1.00 |
| Permission | 2 | 2 | 1 | 0.67 | 1.00 |
| Storage | 7 | 7 | 4 | 0.64 | 1.00 |
| System | 6 | 6 | 0 | 1.00 | 1.00 |
| Web | 8 | 8 | 0 | 1.00 | 1.00 |
| **Overall** | **53** | **52** | **14** | **0.79** | **0.98** |

Strict CWE match (no secondary CWEs): 51 true positives, precision 0.78, recall 0.96. Legacy definition (any Secure finding is a false positive): precision 0.51.

| Run | TP | FP | Precision | Recall |
|-----|---:|---:|----------:|-------:|
| Before P-1 (commit 2ae19e3) | 52 | 18 | 0.74 | 0.98 |
| After P-1 to P-9, standard mode | 52 | 14 | 0.79 | 0.98 |
| After P-1 to P-9, `--rescore --calibrate` (P-9, leave-one-out) | 45 | 14 | 0.76 | 0.85 |
| After P-1 to P-9, `--diff-mode` (P-8) | 42 | 3 | 0.93 | 0.79 |
| After P-1 to P-9, `--diff-mode --calibrate` | 39 | 3 | 0.93 | 0.74 |

The target of this round (precision above 0.85 with recall at 0.96 or above) is not met in standard mode. `docs/notes/false-positive-analysis.md` explains why: 13 of the 14 remaining false positives are findings that are true of the Secure APK, whose fix lies elsewhere (9 components that both apps export with no permission, a trust-all TrustManager the Secure app keeps, a keystore written to external storage, an implicit broadcast, a file name from an intent extra written to external storage, and an implicit service PendingIntent). Suppressing them would hide real weaknesses.

### What changed

| Item | Change | Effect on this set |
|------|--------|--------------------|
| P-1 | `docs/notes/false-positive-analysis.md`: root cause of each of the 18 false positives | none (analysis) |
| P-2 | `exported-no-permission`: a provider with only one of readPermission and writePermission drops to low; any permission, `exported="false"` and no-filter components were already skipped | none: no false positive component has a permission |
| P-3 | `empty_trustmanager`: linear scan for a throw or an unswallowed check call; an empty `checkClientTrusted` is low when `checkServerTrusted` of the class can throw | CheckValidity-InformationExposure-Lean no longer a false positive |
| P-4 | `pending_intent_mutable` skipped when targetSdkVersion is below 31 (apktool.yml, else the decoded manifest) | ImplicitPendingIntent-IntentHijack-Lean no longer a false positive; EmptyPendingIntent-PrivEscalation-Lean stays one through a true `pending_intent_implicit` |
| P-5 | `external_storage_io`: low when the path is only literals with no sensitive word; medium for intent extra or user input, unknown parts or sensitive words | UniqueIDs-IdentityLeak-Lean no longer a false positive |
| P-6 | taint flows validated before the sink (matches, contains, startsWith, endsWith, equals, a validating callee, or a throw) are reported low | none: no taint-flow false positive |
| P-7 | `implicit_broadcast` skipped for any permission argument other than a constant null; manifest `implicit-intent` skips components with a permission; `ordered_broadcast_priority` without a priority needs a `getResult*` read | OrderedBroadcast-DataInjection-Lean no longer a false positive |
| P-8 | `--diff-mode`: scores Benign minus Secure and Secure minus Benign findings, matched on issue, CWE and class name without package | separate numbers, above |
| P-9 | `data/rule-precision.json` (per-rule true and false positive counts); `src/ate.py --calibrate` and `tools/evaluate.py --rescore --calibrate` | separate numbers, above; off by default |

### Differential mode (P-8)

`python tools/evaluate.py --rescore --diff-mode` (per benchmark: `data/evaluation-results-diff.csv`) keeps only findings that differ between the two APKs. Precision rises to 0.93 because findings shared by both apps no longer count, but recall drops to 0.79: in 10 benchmarks the matching finding is still present in the Secure app (for example `cleartext-http` in the Web benchmarks, `exported-no-permission` in UnnecesaryPerms and the SQL benchmarks, `empty_trustmanager` and `hostname_not_verified` in CheckValidity), so the difference no longer contains it. The 3 remaining false positives are findings the Secure app adds: `pending_intent_implicit` (EmptyPendingIntent), `implicit_broadcast` (StickyBroadcast) and `external_storage_io` (ExposedCredentials). Diff mode needs the fixed APK, so it measures whether the tool sees what a fix changed. It is not the precision of the tool on a single unknown APK, and it is not comparable with the standard mode.

### Confidence calibration (P-9)

Per-rule precision over the 53 benchmarks (`data/rule-precision.json`): most rules have no false positive; `exported-no-permission` is 18 TP / 9 FP (0.67), `external_storage_io` 4 / 2 (0.67), `empty_trustmanager` 4 / 1 (0.80), `sql_injection_raw` 2 / 2 (0.50), `implicit_broadcast` and `pending_intent_implicit` 0 / 1. Calibrated confidence is base confidence (high 0.9, medium 0.6, low 0.3) times rule precision, and only findings above 0.3 are kept. Scored with leave-one-out precision (each benchmark calibrated by the other 52, so no benchmark calibrates itself), it lowers both scores: every low finding is dropped, including true positives such as `default-task-affinity` (TaskAffinity benchmarks) and the low `external_storage_io` of ExternalStorage-DataInjection-Lean, while `exported-no-permission` (0.67) stays above the threshold and keeps its 9 false positives. Calibration is therefore opt-in (`--calibrate`) and the standard numbers above do not use it. In-sample scoring (precision computed with the benchmark itself) would also be biased upward and is not reported.

## Independent Validation

On 2026-11-02 the tool was run (static, default flags) on three intentionally vulnerable apps that publish their own vulnerability lists and were not used to write or tune the rules: BugBazaar v1.2.1, InsecureShop v1.0 and DIVA (2016 beta). A known vulnerability is a true positive when a finding names its weakness on the component where it lives; a finding that matches no listed vulnerability is a false positive; findings that only locate a listed vulnerability (for example, the exported deep-link activity whose URL check is the actual flaw) are neither, and that vulnerability counts as a false negative. Full method, per-finding labels and analysis: [validation-results.md](validation-results.md).

| App | Known Vulnerabilities | Tool Findings | True Positives | False Positives | False Negatives | Precision | Recall |
|-----|----------------------:|--------------:|---------------:|----------------:|----------------:|----------:|-------:|
| BugBazaar | 42 | 44 | 13 | 16 | 29 | 0.45 | 0.31 |
| InsecureShop | 19 | 29 | 8 | 6 | 11 | 0.57 | 0.42 |
| DIVA | 13 | 11 | 5 | 2 | 8 | 0.71 | 0.38 |
| **Overall** | **74** | **84** | **26** | **24** | **48** | **0.52** | **0.35** |

Compared with Ghera (precision 0.79, recall 0.98), both numbers drop, and the scoring is stricter here: every finding outside the README lists counts against precision, and 8 of the 74 listed items are server-side, runtime or logic issues that a static APK scan cannot see (recall without them: 0.39).

- **Generalizes:** exported components and IPC (15 of 21 found), SQL injection and dynamic code loading (4 of 6), WebView settings and `onReceivedSslError` proceeding.
- **Does not generalize:** URL and host checks in WebView and deep-link handlers, intent redirection, plain credential storage and logging (2 of 15 storage and leakage items), hardcoded secrets (0 of 4), the `debuggable` and `allowBackup` flags, FileProvider paths and native code.
- **Precision:** 18 of the 24 false positives are in bundled third-party libraries (Razorpay, Glide, Evernote android-job, Picasso, uploadservice). Without them precision would be 0.81.

## Previous round (P1 and P2)

Run of the analysis tool (`src/ate.py`) against the Ghera ground truth (`data/ground-truth.csv`), produced by `python tools/evaluate.py --no-dynamic` on 2026-11-02 after the Phase 1 and Phase 2 detection improvements (P1-1 to P1-5, P2-1 to P2-5; listed below). The earlier fixes (Fix 1 to Fix 7, Fix A to Fix E) are included. The run was split into two halves with `--only` that ran side by side; `python tools/evaluate.py --rescore` then wrote `data/evaluation-results.csv` from the saved reports in `data/eval-tmp/`.

## Scope

The evaluator takes every benchmark with a successful `api27` build in `data/build-results.csv`: 53 benchmarks across all eight categories. The Secure APK of `MergeManifest-UnintendedBehavior-Lean` was not built, so that benchmark is scored with 0 Secure findings. This round reports the static layers only: manifest rules, code patterns and taint analysis. The full emulator run (`--dynamic --auto-readme`, which also covers two-app scoring) was stopped for low system memory after 2 of 53 benchmarks, so no dynamic, two-app or README runner score is reported for this round (see "Dynamic evaluation").

## Definitions

Per benchmark (from `tools/evaluate.py`):
- **True positive (TP)**: the Benign APK has at least one finding, and at least one finding's CWE matches one of the benchmark's ground-truth CWEs. A CWE matches either directly or through the secondary CWE mapping added in Fix A (`SECONDARY_CWE` in `tools/evaluate.py`, and the `secondary_cwe_ids` column of `data/ground-truth.csv`):

  | Finding CWE | Counts as |
  |-------------|-----------|
  | CWE-829 | CWE-749 |
  | CWE-925 | CWE-926 |
  | CWE-360 | CWE-925 |
  | CWE-348 | CWE-927 |
  | CWE-346 | CWE-927 |
  | CWE-441 | CWE-926 |

  The mapping is applied one step only. Since P1-3 a finding whose CWE is listed in the row's `secondary_cwe_ids` column also counts (see "Ground truth correction" below). The evaluator also records the strict match, with `cwe_ids` matches only, in the `strict_true_positive` column, so the effect of both can be seen on its own.
- **False positive (FP)**: the Secure APK has at least one finding (of any kind).
- With `--dynamic`, two-app findings (P1-4) are added on both sides: Benign plus Malicious to the Benign findings, Secure plus Malicious to the Secure findings. With `--auto-readme`, README runner findings (P1-5) are added to the Benign findings only, so they can add true positives but never false positives.

Per category:
- **Precision** = TP / (TP + FP).
- **Recall** = TP / number of benchmarks evaluated. Every Ghera benchmark has a known vulnerability in its Benign app, so each evaluated benchmark counts as one expected detection.

## Results

| Category | Benchmarks evaluated | TP | FP | Precision | Recall |
|----------|---------------------:|---:|---:|----------:|-------:|
| Crypto | 5 | 4 | 4 | 0.50 | 0.80 |
| ICC | 16 | 11 | 11 | 0.50 | 0.69 |
| Networking | 8 | 7 | 8 | 0.47 | 0.88 |
| NonAPI | 1 | 1 | 0 | 1.00 | 1.00 |
| Permission | 2 | 1 | 1 | 0.50 | 0.50 |
| Storage | 7 | 5 | 4 | 0.56 | 0.71 |
| System | 6 | 6 | 0 | 1.00 | 1.00 |
| Web | 8 | 6 | 8 | 0.43 | 0.75 |
| **Overall** | **53** | **41** | **36** | **0.53** | **0.77** |

With the strict CWE match (`cwe_ids` only, no secondary CWEs): 39 TP, precision 0.52, recall 0.74.

### Change from the previous run

| Run | TP | FP | Precision | Recall |
|-----|---:|---:|----------:|-------:|
| Before Fix 1 to Fix 7 (commit 8e2d04b) | 34 | 35 | 0.49 | 0.64 |
| After Fix 1 to Fix 7 (commit 6e8ac60) | 36 | 35 | 0.51 | 0.68 |
| After Fix A to Fix E (commit 05c7a3c) | 37 | 35 | 0.51 | 0.70 |
| After P1 and P2, strict CWE match | 39 | 36 | 0.52 | 0.74 |
| After P1 and P2, with secondary CWEs | 41 | 36 | 0.53 | 0.77 |

Per benchmark:
- `FragmentInjection-PrivEscalation-Lean`: new TP (strict). `fragment_injection` (P1-2, CWE-470) reports the Benign app, which loads a fragment by a name read from an intent extra through `Class.forName`. The Secure app checks the name in `isValidFragment` and is not reported.
- `UnpinnedCertificates-MITM-Lean`: new TP (strict). `certificate_pinning_missing` (P1-1, CWE-295) reports the Benign app. The Secure app pins in code with a KeyStore-backed TrustManagerFactory, which the rule skips.
- `ClipboardUse-InformationExposure-Lean`: new TP through the P1-3 secondary CWE-200 (`clipboard_sensitive`). Its Secure app has no finding.
- `WebViewAllowFileAccess-UnauthorizedFileAccess-Lean`: new TP through the P1-3 secondary CWE-829 (`webview_file_access`). Its Secure app was already a false positive.
- `UnEncryptedSocketComm-MITM-Lean`: new FP. `certificate_pinning_missing` reports its Secure app, which opens a network connection with no pinning. The rule also fires on the Secure apps of `CheckValidity`, `IncorrectHostNameVerification`, `InsecureSSLSocketFactory`, `InvalidCertificateAuthority` and `HttpConnection`, which already had other findings.

Rules of this round with no score change on this set:
- P2-1 (class hierarchy taint) and P2-2 (inter-component taint): no taint finding added or removed on the 48 ICC and Storage APKs. P2-2 resolves 12 cross-component edges in 6 benchmarks, but no receiving component has a new sink reachable from the extras.
- P2-3 (`webview_js_interface`, CWE-749): 0 findings on the 110 Benign and Secure APKs. The two Web benchmarks that use `addJavascriptInterface` expose a location getter and SharedPreferences access, which are not in the rule's sensitive list.
- P2-4 (`sticky_broadcast_receiver`, CWE-927): 0 findings. `StickyBroadcast-DataInjection-Lean` sends a sticky broadcast but has no receiver of its own.
- P2-5 (`provider-path-permission-only`, candidate CWE-284): fires on the Benign app of `InadequatePathPermission-InformationExposure-Lean` and not on its Secure app. That benchmark was already a TP through CWE-926. CWE-284 is DISCOURAGED in `standards-reference.md`, so the finding carries a candidate note.

### Ground truth correction (P1-3)

For each benchmark that had findings but no true positive, each Benign finding CWE was checked against the threat model or mapping and the README. Only CWEs that name the benchmark's own weakness were added to `secondary_cwe_ids`.

| Benchmark | Finding CWE (issue) | Decision | Reason |
|-----------|---------------------|----------|--------|
| ClipboardUse-InformationExposure-Lean | CWE-200 (clipboard_sensitive) | accepted | The finding is the README weakness: the secret is copied to the clipboard and read by Malicious. CWE-359 in the ground truth is a child of CWE-200; the mapping chose CWE-359 because CWE-200 is DISCOURAGED for primary mapping, not because it does not apply. |
| WebViewAllowFileAccess-UnauthorizedFileAccess-Lean | CWE-829 (webview_file_access) | accepted | The README names `setAllowFileAccessFromFileURLs(true)` as what lets the injected script read internal files. CWE-830 in the ground truth is a Variant child of CWE-829. |
| WebViewAllowFileAccess-UnauthorizedFileAccess-Lean | CWE-749 (js_enabled), CWE-319 (cleartext-http), CWE-926 (dynamic receiver) | rejected | JavaScript is only a precondition; the cleartext flag and the WebView internal receivers are unrelated to the weakness. |
| WebViewIgnoreSSLWarning-MITM-Lean | CWE-319, CWE-749, CWE-926 | rejected | The weakness is `handler.proceed()` on SSL errors (CWE-295). |
| WebViewOverrideUrl-MITM-Lean | CWE-319, CWE-749, CWE-926 | rejected | The weakness is `shouldOverrideUrlLoading` returning false (CWE-829 in the model); HTTP only delivers the attack. |
| HighPriority-ActivityHijack-Lean | CWE-926 (taint-flow) | rejected | ImageEditor is not exported; the weakness is the implicit intent (CWE-927). |
| WeakChecksOnDynamicInvocation-DataInjection-Lean | CWE-926 (two findings) | rejected | The row has no `cwe_ids`; adding a secondary CWE would create new ground truth. |
| OpenSocket-InformationLeak-Lean | CWE-319 (cleartext-http) | rejected | The weakness is a ServerSocket that never verifies its peer (CWE-940). |
| UnpinnedCertificates-MITM-Lean | CWE-319 (cleartext-http) | rejected | The app uses TLS; the weakness is the missing pinning (CWE-295), now found by P1-1. |

### Benchmarks with no true positive (12)

ICC: `HighPriority-ActivityHijack-Lean`, `TaskAffinity-LauncherActivity-PhishingAttack-Lean`, `TaskAffinityAndReparenting-PhishingAndDoSAttack-Lean`, `UnhandledException-DOS-Lean`, `WeakChecksOnDynamicInvocation-DataInjection-Lean` (no ground-truth CWE, so it can never score).
Crypto: `ExposedCredentials-InformationExposure-Lean`.
Networking: `OpenSocket-InformationLeak-Lean`.
Permission: `WeakPermission-UnauthorizedAccess-Lean`.
Storage: `ExternalStorage-DataInjection-Lean`, `ExternalStorage-InformationLeak-Lean`.
Web: `WebViewIgnoreSSLWarning-MITM-Lean`, `WebViewOverrideUrl-MITM-Lean`.

Most of these need rules that do not exist yet: external storage writes, WebView SSL error handlers, open server sockets, the default task affinity, intent filter priority on activities and uncaught exceptions.

### Why most Secure APKs are false positives

A Secure APK counts as a false positive when it has any finding, of any kind. Many Secure apps still export components or keep code that the rules report, so precision stays near 0.5 even where the actual weakness is fixed. `docs/notes/secure-app-bugs.md` also documents two Secure apps whose permission protection works only by accident.

## Drift study (P3-1)

`python tools/drift_study.py --static-only` wrote `data/drift-matrix-results.csv` (53 API 27 rows; the dynamic columns are blank because they were not measured) and `data/drift-static-patterns.csv` (the static patterns each Benign app fires). Only the API 27 system image is installed, so no other level could be run, and the emulator run of this round did not complete. The most common static patterns on the Benign apps are `exported-no-permission` (21 apps), `cleartext-http` (16), `implicit-intent`, `certificate_pinning_missing` and `js_enabled` (7 each) and `taint-flow` (6).

## Comparison with Rekha

The Rekha evaluation (Ranganath and Mitra; preprint 2018, Empirical Software Engineering 2019) ran a different set of tools, on an earlier version of Ghera, with its own definition of a detection. The numbers here use a different tool, a CWE-based match and a 53-benchmark sample, so any comparison with Rekha is directional only.

## Dynamic evaluation

This round: `python tools/evaluate.py --dynamic --auto-readme` was started on the `ghera27` emulator and stopped for low system memory after 2 of 53 benchmarks, so it produced no score. Two-app scoring (P1-4) was checked live on `TaskAffinity-ActivityHijack-Lean`: Benign plus Malicious reports `dynamic-task-hijack` (CWE-1021), Secure plus Malicious reports nothing. The numbers below are from the previous round (after Fix A to Fix E) and do not include the P1 and P2 rules.

### Previous round

Run of `python tools/evaluate.py --dynamic` on 2026-11-01, after Fix A to Fix E, on the `ghera27` emulator (`emulator-5554`), over the same 53 benchmarks. Each Benign and Secure APK was passed to `src/ate.py --dynamic`, so the static layers ran first and then the APK was installed and exercised on the emulator (Layer 4). Per-benchmark results: `data/evaluation-results-dynamic.csv`. The definitions above apply, including the Fix A secondary CWE mapping. As before, the Secure APK of `MergeManifest-UnintendedBehavior-Lean` was not built and is scored with 0 Secure findings. Every other APK ran without errors.

| Category | Benchmarks evaluated | TP | FP | Precision | Recall |
|----------|---------------------:|---:|---:|----------:|-------:|
| Crypto | 5 | 4 | 4 | 0.50 | 0.80 |
| ICC | 16 | 10 | 11 | 0.48 | 0.62 |
| Networking | 8 | 6 | 7 | 0.46 | 0.75 |
| NonAPI | 1 | 1 | 0 | 1.00 | 1.00 |
| Permission | 2 | 1 | 1 | 0.50 | 0.50 |
| Storage | 7 | 5 | 4 | 0.56 | 0.71 |
| System | 6 | 5 | 0 | 1.00 | 0.83 |
| Web | 8 | 5 | 8 | 0.38 | 0.62 |
| **Overall** | **53** | **37** | **35** | **0.51** | **0.70** |

With the strict CWE match the numbers are the same. The scores equal the static run in every category: precision 0.51 and recall 0.70. Against the previous dynamic run (precision 0.51, recall 0.68), the only change is `OrderedBroadcast-DataInjection-Lean`, which is now a true positive through the static Fix B rule.

The dynamic layer reported the same 56 findings as in the previous run, across the same 11 benchmarks: 47 `dynamic-receiver-accepts-external` (CWE-926), 7 `dynamic-task-hijack` (CWE-1021), 1 `dynamic-file-deleted` (CWE-922) and 1 `dynamic-permission-denial-observed`. None of them changes a score:
- Every benchmark that gained dynamic findings is either already a true positive or has ground-truth CWEs that these findings do not match, even with the secondary mapping. For example, the WebView benchmarks get CWE-926 for receivers registered at run time, while their ground truth lists CWE-830, CWE-295 and CWE-829.
- Every Secure APK that gained dynamic findings already had static findings, so it was already a false positive.
- `UnhandledException-DOS-Lean` gets no dynamic finding and remains a miss. The README replay (Fix E) also showed no crash of the Benign app on API 27.
