# Evaluation report

Run of the analysis tool (`src/ate.py`) against the Ghera ground truth (`data/ground-truth.csv`), produced by `python tools/evaluate.py --no-dynamic` on 2026-11-01 after the detection improvements (Fix 1 to Fix 7, listed below). Raw output: `docs/notes/evaluation-run.log`. Per-benchmark results: `data/evaluation-results.csv`.

## Scope

The evaluator takes every benchmark with a successful `api27` build in `data/build-results.csv`: 53 benchmarks across all eight categories. The Secure APK of `MergeManifest-UnintendedBehavior-Lean` was not built, so that benchmark is scored with 0 Secure findings. Dynamic analysis (Layer 4) was not used in this run (`--no-dynamic`), so the numbers cover the static layers only: manifest rules, code patterns and taint analysis. Fix 7 (the dynamic sweep) therefore does not change these numbers.

## Definitions

Per benchmark (from `tools/evaluate.py`, unchanged):
- **True positive (TP)**: the Benign APK has at least one finding, and at least one finding's CWE is among the benchmark's ground-truth CWEs.
- **False positive (FP)**: the Secure APK has at least one finding (of any kind).

Per category:
- **Precision** = TP / (TP + FP).
- **Recall** = TP / number of benchmarks evaluated. Every Ghera benchmark has a known vulnerability in its Benign app, so each evaluated benchmark counts as one expected detection.

## Results

| Category | Benchmarks evaluated | TP | FP | Precision | Recall |
|----------|---------------------:|---:|---:|----------:|-------:|
| Crypto | 5 | 4 | 4 | 0.50 | 0.80 |
| ICC | 16 | 9 | 11 | 0.45 | 0.56 |
| Networking | 8 | 6 | 7 | 0.46 | 0.75 |
| NonAPI | 1 | 1 | 0 | 1.00 | 1.00 |
| Permission | 2 | 1 | 1 | 0.50 | 0.50 |
| Storage | 7 | 5 | 4 | 0.56 | 0.71 |
| System | 6 | 5 | 0 | 1.00 | 0.83 |
| Web | 8 | 5 | 8 | 0.38 | 0.62 |
| **Overall** | **53** | **36** | **35** | **0.51** | **0.68** |

### Change from the previous run

| Run | TP | FP | Precision | Recall |
|-----|---:|---:|----------:|-------:|
| Before the fixes (commit 8e2d04b) | 34 | 35 | 0.49 | 0.64 |
| After Fix 1 to Fix 7 | 36 | 35 | 0.51 | 0.68 |

The two new true positives are `TaskAffinity-ActivityHijack-Lean` and `TaskAffinity-PhishingAttack-Lean`. In both, the Benign `ImageEditor` activity sets `android:taskAffinity="edu.ksu.santos.benign.editImage"`, which is not under the app package `edu.ksu.cs.benign`, so the new `task-affinity-hijack` rule (Fix 2) reports it. Their Secure apps still count as false positives through other findings, so the false positive count does not change.

The target of 0.90 recall (48 of 53) was not reached. The fixes as specified add detections for weaknesses that most of the missed benchmarks do not contain in the form the rules look for:
- Fix 1 (trust manager and host name checks) and Fix 3 (pending intents) extend rules whose benchmarks were already true positives. `getSocket` / `createSocket` on an `InetAddress` was already flagged before Fix 1.
- Fix 4 (`ordered_broadcast_priority`) needs an intent filter priority above 0. The receiver in `OrderedBroadcast-DataInjection-Lean` declares no priority, so the rule does not fire there. It was checked on a synthetic receiver instead.
- Fix 5 removes cleartext findings only when the network security config permits cleartext to local hosts only, or when minSdkVersion is below 23. Every benchmark in this run is an api27 build with minSdkVersion 27, so neither case occurs here.
- Fix 6 (return values flowing back to callers in taint analysis) finds no new flow with a ground-truth CWE in these apps.
- `TaskAffinity-LauncherActivity-PhishingAttack-Lean` and `TaskAffinityAndReparenting-PhishingAndDoSAttack-Lean` set no activity-level `taskAffinity` in the Benign app. The weakness there is the default affinity (in the Secure app it is cleared at the application level), which the rule as specified does not cover.

### Benchmarks with no true positive (17)

ICC: `FragmentInjection-PrivEscalation-Lean`, `HighPriority-ActivityHijack-Lean`, `OrderedBroadcast-DataInjection-Lean`, `TaskAffinity-LauncherActivity-PhishingAttack-Lean`, `TaskAffinityAndReparenting-PhishingAndDoSAttack-Lean`, `UnhandledException-DOS-Lean`, `WeakChecksOnDynamicInvocation-DataInjection-Lean` (no ground-truth CWE, so it can never score).
Crypto: `ExposedCredentials-InformationExposure-Lean`.
Networking: `OpenSocket-InformationLeak-Lean`, `UnpinnedCertificates-MITM-Lean`.
Permission: `WeakPermission-UnauthorizedAccess-Lean`.
Storage: `ExternalStorage-DataInjection-Lean`, `ExternalStorage-InformationLeak-Lean`.
System: `ClipboardUse-InformationExposure-Lean`.
Web: `WebViewAllowFileAccess-UnauthorizedFileAccess-Lean`, `WebViewIgnoreSSLWarning-MITM-Lean`, `WebViewOverrideUrl-MITM-Lean`.

Several of these are found by a rule, but under a CWE that the ground truth does not list. One example is `webview_file_access`, which reports a different CWE from the one the ground truth lists for `WebViewAllowFileAccess`. Others need rules that do not exist yet: external storage writes, WebView SSL error handlers, open server sockets, the default task affinity, intent filter priority on activities, fragment injection and uncaught exceptions. `UnhandledException-DOS-Lean` is the kind of weakness the new `dynamic-receiver-crash` check targets, but it only runs with `--dynamic`.

### Why most Secure APKs are false positives

A Secure APK counts as a false positive when it has any finding, of any kind. Many Secure apps still export components or keep code that the rules report, so precision stays near 0.5 even where the actual weakness is fixed.

## Comparison with Rekha

The Rekha evaluation (Ranganath and Mitra; preprint 2018, Empirical Software Engineering 2019) ran a different set of tools, on an earlier version of Ghera, with its own definition of a detection. The numbers here use a different tool, a CWE-based match and a 53-benchmark sample, so any comparison with Rekha is directional only.
