# Slides outline: android-threat-engine

Ten slides for a talk on the project. Every number comes from `README.md`, `docs/notes/evaluation-report.md`, `docs/notes/project-summary.md`, `docs/notes/benchmark-issues.md`, `docs/notes/secure-app-bugs.md`, `docs/threat-models/benchmark-index.md` or `docs/notes/progress.md`. The Rekha figures are from Ranganath and Mitra, Empirical Software Engineering 2019 (arXiv:1806.09059 v8).

## Slide 1. Title

- android-threat-engine: threat models, ground truth and an analysis tool built on the Ghera benchmarks
- Ronan, Northeastern University
- Built on Ghera (tag `Jan2019`, 57 benchmarks) and the Rekha evaluation
- Status as of 2026-11-02

Visual: the architecture diagram `docs/diagrams/architecture.svg` as a faded background, or one Benign versus Secure screenshot pair from `docs/screenshots/`.

## Slide 2. Background: Ghera and Rekha

- Ghera (Mitra and Ranganath, PROMISE 2017): each benchmark is a Benign app with one known vulnerability, a Malicious app that exploits it, a Secure app that fixes it, and usually a Testing project
- Tag `Jan2019` holds 57 benchmarks in eight categories: Crypto 5, ICC 18, Networking 8, NonAPI 2, Permission 2, Storage 7, System 7, Web 8
- Rekha (Ranganath and Mitra, Empirical Software Engineering 2019): 14 vulnerability detection tools run on 42 Ghera benchmarks
- All tools together detected 30 of 42; no single tool detected more than 15 of 42
- Best Table 8 entries: Marvin-SA precision 0.938 and recall 0.357, QARK 1.000 and 0.333, MobSF 1.000 and 0.310

Visual: table of the 57 benchmarks by category (from `docs/threat-models/benchmark-index.md`) next to a small table of the three Rekha Table 8 rows.

## Slide 3. What we built

- Threat model library: 24 full models (16 ICC, 8 Web) plus standards mappings for the 31 benchmarks in the other categories
- Ground truth dataset (`data/ground-truth.csv`): one row per benchmark, expected Benign and Secure results, CWE, MASVS, MASWE and MASTG IDs
- Drift matrix (`data/drift-matrix.csv`): one row per benchmark and API level (22, 25, 27, 28, 30, 33, 34; 399 rows)
- Benchmark issues log: 234 differences between READMEs, code and tests, in 56 benchmarks
- APK analysis tool (`src/ate.py`) with a static, dynamic and privacy policy layer, plus an evaluator (`tools/evaluate.py`) and a docs lint (`tools/lint_docs.py`)

Visual: a five-box diagram (threat models, ground truth, drift matrix, issues log, tool) with arrows from the ground truth into the evaluator; reuse `docs/diagrams/architecture.svg` if a single image is preferred.

## Slide 4. Threat model library

- Fixed ten-section template: system description, assets and attacker model, STRIDE, LINDDUN, attack tree, standards mapping, evidence, mitigation, open questions
- Every statement about an app points to a file and line in the benchmark
- Every CWE, MASVS v2, MASWE and MASTG ID checked against its official page and recorded with its exact title (`docs/threat-models/standards-reference.md`)
- Two Mermaid diagrams per model: 50 diagrams rendered to SVG in `docs/diagrams/`
- Not drafted: `UnprotectedBroadcastRecv-PrivEscalation-Fat` and `WeakChecksOnDynamicInvocation-DataInjection-Lean`

Visual: one ICC diagram pair, for example `docs/diagrams/ICC-UnprotectedBroadcastRecv-PrivEscalation-1.svg` and `-2.svg`, and one Web diagram, `docs/diagrams/Web-WebViewInterceptRequest-MITM-1.svg`.

## Slide 5. Tool architecture

- Manifest layer: `src/apk.py` decodes the APK with apktool; `src/surface.py` extracts exported components, intent filters, permissions and provider settings and merges all findings
- Code patterns (Layer 2): `src/code_analyzer.py` scans smali for weak ciphers, hard-coded keys, trust managers, WebView settings, SQL, intents and broadcasts
- Taint (Layer 3): `src/call_graph.py` and `src/taint_analyzer.py` trace intent extras and user input to sensitive sinks, interprocedural and across class hierarchies
- Dynamic (Layer 4): `src/dynamic_analyzer.py` exercises the app on an emulator over adb (`--dynamic`); `--dynamic-two-app` installs Benign or Secure together with Malicious
- Output and extras: `src/report.py` writes JSON and Markdown with CWE, confidence and evidence; `src/privacy_checker.py` (`ate.py --policy`) compares a privacy policy with the permissions and SDK packages the APK declares

Visual: `docs/diagrams/architecture.svg`, plus the run screenshot `docs/screenshots/step_demo_01_tool-run-summary.png`.

## Slide 6. Evaluation methodology

- Scope: the 53 benchmarks with a successful `api27` build, across all eight categories (`data/build-results.csv`)
- True positive: the Benign APK has a finding whose CWE matches a ground-truth CWE (directly or through a one-step secondary mapping; the strict match gives the same numbers)
- False positive: the Secure APK has any finding at all
- Precision = TP / (TP + FP); recall = TP / benchmarks evaluated
- Two runs: static only (`--no-dynamic`) and with the dynamic layer on the `ghera27` emulator; the two-app mode and README replay (`--auto-readme`) are kept out of the scored numbers

Visual: a flow diagram from Benign and Secure APK through `src/ate.py` into `tools/evaluate.py` and `data/evaluation-results.csv`.

## Slide 7. Results

- Overall: 53 benchmarks, 37 TP, 35 FP, precision 0.51, recall 0.70; static and dynamic runs give the same scores
- Progress across fix rounds: precision 0.49 and recall 0.64, then 0.51 and 0.68, then 0.51 and 0.70
- Best categories: System (precision 1.00, recall 0.83) and NonAPI (1 of 1); weakest precision: Web (0.38)
- 16 benchmarks with no true positive, mostly where rules do not exist yet (external storage, WebView SSL error handlers, open sockets, default task affinity)
- Rekha comparison is directional only: different Ghera version, different tools, different detection definition; Rekha's best single tools had high precision and recall near 0.31 to 0.36

Visual: the per-category table from `docs/notes/evaluation-report.md` and a precision and recall bar chart per category (the dashboard `docs/dashboard.html`, being built, can supply it).

## Slide 8. Key findings: incomplete Secure fixes in Ghera

- Permission name mismatch: in `UnprotectedBroadcastRecv-PrivEscalation-Lean` and `IncorrectHandlingImplicitIntent-UnauthorizedAccess-Lean`, Secure declares a signature permission under one name and requires a different, undefined name; any app that defines that name passes the check (`docs/notes/secure-app-bugs.md`)
- Exposure left in place: `InsecureSSLSocket-MITM-Lean` keeps the trust-all TrustManager, `CheckValidity-InformationExposure-Lean` keeps an always-true HostnameVerifier, `WebViewInterceptRequest-MITM-Lean` keeps the JavaScript bridge, `EmptyPendingIntent` and `StickyBroadcast` still send implicit broadcasts
- Fixes that break the app (`BlockCipher-NonRandomIV`, `PBE-ConstantSalt`: random IV or salt never stored) and Secure tests that pass either way (`MergeManifest` is `assert true;`, `UniqueIDs` repeats the Benign assertion)
- Status: all of these come from reading source; each is marked "Read in code, not yet run" in `docs/notes/benchmark-issues.md`
- Link to false positives: the evaluation report says many Secure apps still export components or keep code that the rules report, but it does not tie individual Secure false positives to these bugs; that mapping is open work

Visual: the summary table from `docs/notes/secure-app-bugs.md` (declared versus required permission, with file and line), plus the manifest snippet with the one-line fix.

## Slide 9. Future work

- Run the drift study: stock APKs on API 22 to 34, then rebuild against newer target SDKs (`docs/notes/drift-harness-design.md`)
- Confirm or reject each "not yet run" issue on an emulator, starting with the incomplete Secure fixes; offer the confirmed fixes upstream to Ghera
- New rules for the 16 missed benchmarks, and a Secure-side check that scores whether the specific weakness is fixed rather than counting any finding
- Real-world case study on 5 F-Droid apps (Loop Habit Tracker, Tasks.org, Markor, OpenTracks, drip) with the tool and the privacy policy checker: in progress
- A Rekha-style re-run of current free tools against the same 53 benchmarks

Visual: a simple timeline or checklist; the drift matrix header from `data/drift-matrix.csv` as a small table.

## Slide 10. Conclusion

- Ghera is still a usable ground truth, but its Secure apps are not all secure and its tests cannot always tell fixed from broken
- A code-referenced threat model library (24 models, 50 diagrams) and a ground truth dataset make the benchmarks testable by machine
- A layered tool reaches precision 0.51 and recall 0.70 on 53 benchmarks; low precision mostly reflects Secure apps that keep reportable code
- Next: drift study, emulator confirmation of the Secure bugs, and the F-Droid case study
- Questions

Visual: the Benign versus Secure screenshot pair `docs/screenshots/step01_21_exploit-success-benign.png` and `docs/screenshots/step01_25_exploit-fails-secure.png`.
