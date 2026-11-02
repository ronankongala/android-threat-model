# Evaluation report

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
