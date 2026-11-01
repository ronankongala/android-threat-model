# Evaluation report

First run of the analysis tool (`src/ate.py`) against the Ghera ground truth (`data/ground-truth.csv`), produced by `tools/evaluate.py` on 2026-11-01. Raw output: `docs/notes/evaluation-run.log`. Per-benchmark results: `data/evaluation-results.csv`.

## Scope

The evaluator takes every benchmark with a successful `api27` build in `data/build-results.csv`. That file currently has one benchmark, `Crypto/BlockCipher-ECB-InformationExposure-Lean`, because `tools/build_all.ps1` has so far been run on that benchmark only. **The numbers below therefore come from one benchmark and are not a measure of the tool's accuracy.** They show that the evaluation pipeline works end to end. Running `tools/build_all.ps1` on all 57 benchmarks and then `tools/evaluate.py` again will give the first meaningful numbers.

## Definitions

Per benchmark (from `tools/evaluate.py`):
- **True positive (TP)**: the Benign APK has at least one finding, and at least one finding's CWE is among the benchmark's ground-truth CWEs.
- **False positive (FP)**: the Secure APK has at least one finding (of any kind).

Per category:
- **Precision** = TP / (TP + FP).
- **Recall** = TP / number of benchmarks evaluated. Every Ghera benchmark has a known vulnerability in its Benign app, so each evaluated benchmark counts as one expected detection.

## Results

| Category | Benchmarks evaluated | TP | FP | Precision | Recall |
|----------|---------------------:|---:|---:|----------:|-------:|
| Crypto | 1 | 1 | 1 | 0.50 | 1.00 |
| ICC | 0 | | | n/a | n/a |
| Networking | 0 | | | n/a | n/a |
| NonAPI | 0 | | | n/a | n/a |
| Permission | 0 | | | n/a | n/a |
| Storage | 0 | | | n/a | n/a |
| System | 0 | | | n/a | n/a |
| Web | 0 | | | n/a | n/a |
| **Overall** | **1** | **1** | **1** | **0.50** | **1.00** |

### The one benchmark

`BlockCipher-ECB-InformationExposure-Lean` has ground-truth CWEs CWE-327, CWE-321 and CWE-926. Benign and Secure both get the same three findings: `exported-no-permission` (CWE-926) on `ResetPasswordActivity` (the launcher, low confidence) and on `NewPasswordActivity` (medium), and `implicit-intent` (CWE-927) on `NewPasswordActivity`.

- The true positive is a match on CWE-926 for `NewPasswordActivity`, the exported activity that Malicious sends the forged token to. The benchmark's main weakness, ECB mode and the hard-coded key (CWE-327, CWE-321), is in code and was not detected.
- The false positive is the same set of findings on Secure. `docs/notes/benchmark-issues.md` already records that Secure "still exports `NewPasswordActivity`", so the finding is correct about the app; it counts as a false positive only because the scoring treats any Secure finding as one. The launcher finding (low confidence) appears in every app and would make every Secure app a false positive by this definition.

## Limits of manifest-only detection

The tool reads only the decoded `AndroidManifest.xml`. It cannot see anything that exists only in code: receivers registered at run time with `registerReceiver` (the vulnerability in `ICC/DynamicRegBroadcastReceiver-UnrestrictedAccess-Lean`, whose manifest contains no receiver at all), implicit intents and pending intents created in code, WebView settings such as JavaScript and file access, trust managers and host name verifiers, SQL built from strings, hard-coded keys and weak cipher modes. Six of the tool's ten issue kinds (`dynamic-receiver-no-permission`, `missing-certificate-validation`, `sql-no-parameterization`, `js-enabled-webview`, `hardcoded-key`, `weak-cipher`) need code-level rules and have none yet. Recall on the Crypto, Networking, Storage and Web categories, where most vulnerabilities live in code, is expected to be low until those rules exist, and CWE-926 matches (exported components are common) may overstate recall in the meantime.

## Comparison with Rekha

The Rekha evaluation (Ranganath and Mitra; preprint 2018, Empirical Software Engineering 2019) ran a different set of tools, on an earlier version of Ghera, with its own definition of a detection. The numbers here use a different tool, a CWE-based match and a one-benchmark sample, so any comparison with Rekha is directional only.
