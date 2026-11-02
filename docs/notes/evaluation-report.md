# Evaluation report

Run of the analysis tool (`src/ate.py`) against the Ghera ground truth (`data/ground-truth.csv`), produced by `python tools/evaluate.py --no-dynamic` on 2026-11-01 after Fix A to Fix E (listed below). The earlier fixes (Fix 1 to Fix 7) are included. Raw output: `docs/notes/evaluation-run.log`. Per-benchmark results: `data/evaluation-results.csv`.

## Scope

The evaluator takes every benchmark with a successful `api27` build in `data/build-results.csv`: 53 benchmarks across all eight categories. The Secure APK of `MergeManifest-UnintendedBehavior-Lean` was not built, so that benchmark is scored with 0 Secure findings. The main run uses the static layers only (`--no-dynamic`): manifest rules, code patterns and taint analysis. The dynamic run is reported separately below. Neither run uses `--auto-readme` (Fix E), for the reason given under "Fix E" below.

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

  The mapping is applied one step only. The evaluator also records the strict match, with direct CWE matches only, in the `strict_true_positive` column, so the effect of the mapping can be seen on its own.
- **False positive (FP)**: the Secure APK has at least one finding (of any kind).

Per category:
- **Precision** = TP / (TP + FP).
- **Recall** = TP / number of benchmarks evaluated. Every Ghera benchmark has a known vulnerability in its Benign app, so each evaluated benchmark counts as one expected detection.

## Results

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

With the strict CWE match (no secondary mapping) the numbers are the same: 37 TP, precision 0.51, recall 0.70.

### Change from the previous run

| Run | TP | FP | Precision | Recall |
|-----|---:|---:|----------:|-------:|
| Before Fix 1 to Fix 7 (commit 8e2d04b) | 34 | 35 | 0.49 | 0.64 |
| After Fix 1 to Fix 7 (commit 6e8ac60) | 36 | 35 | 0.51 | 0.68 |
| After Fix A to Fix E | 37 | 35 | 0.51 | 0.70 |

The one new true positive is `OrderedBroadcast-DataInjection-Lean`. Its effect on each fix:

- **Fix A (secondary CWE mapping): no change on this set.** No missed benchmark has a Benign finding whose CWE maps to one of its ground-truth CWEs. For example, `webview_file_access` reports CWE-829, which maps to CWE-749, but `WebViewAllowFileAccess-UnauthorizedFileAccess-Lean` lists CWE-830, not CWE-749. Its main effect would be on dynamic findings with CWE-925 in benchmarks that list CWE-926.
- **Fix B (ordered broadcast): +1 TP, no FP change.** `FormatOutgoingCallReceiver` in `OrderedBroadcast-DataInjection-Lean` declares no priority but calls `setResultData` on itself in `onReceive`, so the extended `ordered_broadcast_priority` rule now reports it (CWE-927, medium). The rule also fires on the Secure app, which calls `setResultData` too. That Secure app already had other findings, so the false positive count does not change.
- **Fix C (singleTask and singleInstance): no change on this set.** None of the 110 built Benign and Secure APKs sets `android:launchMode`. Only the Malicious app of `TaskAffinity-PhishingAttack-Lean`, which is not scored, uses `singleTask`. The rule matters for real-world APKs. `TaskAffinity-LauncherActivity-PhishingAttack-Lean` and `TaskAffinityAndReparenting-PhishingAndDoSAttack-Lean` remain misses: their weakness is the default task affinity, which no rule covers.
- **Fix D (two-app dynamic testing): not part of the scored run.** `ate.py --dynamic-two-app MALICIOUS_APK` installs the Benign and Malicious apps together. On `TaskAffinity-ActivityHijack-Lean`, the Benign plus Malicious run reports `dynamic-task-hijack` (CWE-1021): the malicious task holds the affinity `edu.ksu.santos.benign.editImage` declared by the benign app. The Secure plus Malicious run reports nothing. `tools/evaluate.py` scores single APKs, so these findings are not in the tables.
- **Fix E (README runner): not part of the scored run.** `tools/readme_runner.py` parses 58 of the 59 Ghera READMEs. A dry run maps 81% of the steps that are not emulator setup (206 of 484 steps in all) to an automated action: install, launch, tap, back or an `adb` command. `tools/evaluate.py --auto-readme` replays each README and adds the observations as Benign findings. The README steps exercise only the Benign app, so these findings can add true positives but never false positives. Mixing them into the score would bias precision, so the numbers above do not use the flag.

### Benchmarks with no true positive (16)

ICC: `FragmentInjection-PrivEscalation-Lean`, `HighPriority-ActivityHijack-Lean`, `TaskAffinity-LauncherActivity-PhishingAttack-Lean`, `TaskAffinityAndReparenting-PhishingAndDoSAttack-Lean`, `UnhandledException-DOS-Lean`, `WeakChecksOnDynamicInvocation-DataInjection-Lean` (no ground-truth CWE, so it can never score).
Crypto: `ExposedCredentials-InformationExposure-Lean`.
Networking: `OpenSocket-InformationLeak-Lean`, `UnpinnedCertificates-MITM-Lean`.
Permission: `WeakPermission-UnauthorizedAccess-Lean`.
Storage: `ExternalStorage-DataInjection-Lean`, `ExternalStorage-InformationLeak-Lean`.
System: `ClipboardUse-InformationExposure-Lean`.
Web: `WebViewAllowFileAccess-UnauthorizedFileAccess-Lean`, `WebViewIgnoreSSLWarning-MITM-Lean`, `WebViewOverrideUrl-MITM-Lean`.

Most of these need rules that do not exist yet: external storage writes, WebView SSL error handlers, open server sockets, the default task affinity, intent filter priority on activities, fragment injection and uncaught exceptions. In the Web benchmarks, some rules fire under a CWE that neither the ground truth nor the secondary mapping lists.

### Why most Secure APKs are false positives

A Secure APK counts as a false positive when it has any finding, of any kind. Many Secure apps still export components or keep code that the rules report, so precision stays near 0.5 even where the actual weakness is fixed.

## Comparison with Rekha

The Rekha evaluation (Ranganath and Mitra; preprint 2018, Empirical Software Engineering 2019) ran a different set of tools, on an earlier version of Ghera, with its own definition of a detection. The numbers here use a different tool, a CWE-based match and a 53-benchmark sample, so any comparison with Rekha is directional only.

## Dynamic evaluation results

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
