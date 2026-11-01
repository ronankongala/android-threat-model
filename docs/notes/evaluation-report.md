# Evaluation report

Second run of the analysis tool (`src/ate.py`) against the Ghera ground truth (`data/ground-truth.csv`), produced by `python tools/evaluate.py --no-dynamic` on 2026-11-01 after Layer 2 (smali code patterns, `src/code_analyzer.py`) and Layer 3 (taint analysis, `src/taint_analyzer.py`) were added. Raw output: `docs/notes/evaluation-run.log`. Per-benchmark results: `data/evaluation-results.csv`.

## Scope

The evaluator takes every benchmark with a successful `api27` build in `data/build-results.csv`: 19 benchmarks, 5 in Crypto and 14 in ICC. No Networking, NonAPI, Permission, Storage, System or Web benchmark has an `api27` build yet, so the code rules for those categories (trust managers, host name verifiers, WebView settings, SQL, file paths, clipboard, dynamic code loading, unique IDs) are not measured here. Dynamic analysis (Layer 4) was not used in this run (`--no-dynamic`), so the numbers cover the static layers only: manifest rules, code patterns and taint analysis.

## Definitions

Per benchmark (from `tools/evaluate.py`, unchanged from the first run):
- **True positive (TP)**: the Benign APK has at least one finding, and at least one finding's CWE is among the benchmark's ground-truth CWEs.
- **False positive (FP)**: the Secure APK has at least one finding (of any kind).

Per category:
- **Precision** = TP / (TP + FP).
- **Recall** = TP / number of benchmarks evaluated. Every Ghera benchmark has a known vulnerability in its Benign app, so each evaluated benchmark counts as one expected detection.

## Results

| Category | Benchmarks evaluated | TP | FP | Precision | Recall |
|----------|---------------------:|---:|---:|----------:|-------:|
| Crypto | 5 | 4 | 5 | 0.44 | 0.80 |
| ICC | 14 | 7 | 14 | 0.33 | 0.50 |
| Networking | 0 | | | n/a | n/a |
| NonAPI | 0 | | | n/a | n/a |
| Permission | 0 | | | n/a | n/a |
| Storage | 0 | | | n/a | n/a |
| System | 0 | | | n/a | n/a |
| Web | 0 | | | n/a | n/a |
| **Overall** | **19** | **11** | **19** | **0.37** | **0.58** |

### Effect of Layers 2 and 3

The same 19 reports, filtered to manifest findings only, give the manifest-only baseline. The filter is approximate, because a manifest finding is dropped from a report when a code finding with the same component and CWE has a higher confidence.

| Run | TP | FP | Precision | Recall |
|-----|---:|---:|----------:|-------:|
| Manifest rules only | 9 | 19 | 0.32 | 0.47 |
| Manifest, code patterns and taint | 11 | 19 | 0.37 | 0.58 |

The two new true positives are both in ICC and both CWE-927: `EmptyPendingIntent-PrivEscalation-Lean` (a pending intent that wraps an empty intent, `pending_intent_empty`) and `ImplicitPendingIntent-IntentHijack-Lean` (a pending intent that wraps an implicit intent, `pending_intent_implicit`). The code rules also find the actual weakness in `NoValidityCheckOnBroadcastMsg-UnintendedInvocation-Lean` (CWE-925, a receiver that starts an activity without checking the action), which was already a true positive through CWE-926. In Crypto the code rules now find the benchmark's actual weakness: ECB mode (CWE-327) and the hard-coded key (CWE-321) in `BlockCipher-ECB`, the constant IV (CWE-329) in `BlockCipher-NonRandomIV`, the constant key (CWE-321) in `ConstantKey-ForgeryAttack` and the constant salt (CWE-760) in `PBE-ConstantSalt`. Crypto recall does not change, because each of those benchmarks already matched on CWE-926 for an exported activity, which the ground truth also lists.

### Why every Secure APK is a false positive

Every app has an exported launcher activity, and the manifest rules always report it (`exported-no-permission`, low confidence), so by the definition above every Secure APK is a false positive and precision cannot exceed TP / (TP + number of benchmarks). Counting a Secure APK as a false positive only when it has a finding whose CWE is one of the benchmark's ground-truth CWEs gives 10 false positives and an overall precision of 0.52 (Crypto 0.50, ICC 0.54). Most of those 10 are CWE-926 findings on components that the Secure app still exports. The code rules add three Secure findings that match a ground-truth CWE:
- `PBE-ConstantSalt` Secure: the salt is random but the password is still a constant string (`hardcoded_key_pbe`, low confidence, CWE-760).
- `EmptyPendingIntent` Secure: the pending intent wraps an intent with an action but no component (`pending_intent_implicit`, CWE-927).
- `StickyBroadcast` Secure: still sends an implicit broadcast with extras (`implicit_broadcast`, CWE-927).

### Benchmarks with no true positive

`ExposedCredentials-InformationExposure-Lean` (CWE-922, credentials in shared preferences; no rule covers it), `HighPriority-ActivityHijack-Lean`, `OrderedBroadcast-DataInjection-Lean`, the four `TaskAffinity` benchmarks and `UnhandledException-DOS-Lean`. The task affinity and priority weaknesses are manifest attributes (`taskAffinity`, `allowTaskReparenting`, intent filter priority) that `src/apk.py` does not read yet, and the dynamic task hijack check needs the attacker app to be running.

## Taint analysis on these benchmarks

Taint analysis finds few flows in Crypto and ICC: an intent extra forwarded to `startActivity` in `DynamicRegBroadcastReceiver`, and text from an `EditText` passed to `startActivity` in three apps. These flows exist in both the Benign and the Secure variant, so taint analysis does not tell the variants apart in these categories. Its main sinks (`rawQuery`, `execSQL`, `openFileOutput`, `File`) belong to the Storage benchmarks, which are not built yet.

## Comparison with Rekha

The Rekha evaluation (Ranganath and Mitra; preprint 2018, Empirical Software Engineering 2019) ran a different set of tools, on an earlier version of Ghera, with its own definition of a detection. The numbers here use a different tool, a CWE-based match and a 19-benchmark sample from two categories, so any comparison with Rekha is directional only.
