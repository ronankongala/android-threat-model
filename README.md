# android-threat-engine

android-threat-engine is an Android app security research project built on the [Ghera](https://bitbucket.org/secure-it-i/android-app-vulnerability-benchmarks) benchmark repository (tag `Jan2019`, 57 benchmarks). It combines a library of code-referenced threat models for the benchmarks, a ground truth dataset mapped to CWE and OWASP MASVS, MASWE and MASTG, a plan and matrix for measuring how each vulnerability behaves on newer Android versions, and a command line tool that decodes an APK and reports its manifest attack surface, scored against the ground truth.

## Features

- **Threat model library**: 24 full threat models (ICC and Web) with STRIDE, LINDDUN, attack trees, standards mappings and Mermaid diagrams, plus standards mappings for the 31 benchmarks in the other categories. Every claim points to a file and line in the benchmark.
- **Verified standards reference**: every CWE, MASVS, MASWE and MASTG ID used is checked against its official page and recorded with its exact title.
- **Ground truth dataset**: one row per benchmark with the expected Benign and Secure results and the mapped IDs (`data/ground-truth.csv`).
- **Drift matrix**: one row per benchmark and API level (22 to 34) for recording whether exploits and fixes still hold on newer Android versions (`data/drift-matrix.csv`).
- **Benchmark issues log**: 234 differences between the Ghera READMEs, code and tests, including Secure apps whose fix looks incomplete.
- **APK analysis tool**: decodes an APK with apktool, extracts exported components, intent filters, permissions and provider settings from the manifest, detects insecure code patterns in the smali code (weak ciphers, hard-coded keys, trust managers, WebView settings, SQL, intents and broadcasts), traces intent extras and user input to sensitive sinks with taint analysis, optionally exercises the app on an emulator over adb (`--dynamic`), and writes findings with CWE IDs, confidence levels and evidence as JSON and Markdown.
- **Evaluator and docs lint**: scores the tool against the ground truth, and checks the documentation for unknown IDs, wrong titles, missing sections, broken links and invalid diagrams.

## Architecture

<img src="docs/diagrams/architecture.svg" alt="Architecture diagram">


`src/ate.py` runs the three stages in order and prints a one-line summary. `tools/evaluate.py` runs the CLI on the Benign and Secure APK of each built benchmark and compares the findings with `data/ground-truth.csv`.

## Tools and tech stack

| Area | Tools |
|------|-------|
| Analysis tool | Python 3 (standard library), apktool 3.0.3, Java 8 (Eclipse Temurin) |
| Tests | pytest |
| Benchmark builds | Gradle 4.4, Android Gradle plugin 3.1.2, Android SDK Platform 27, Build-Tools 27.0.3, JDK 8 |
| Emulators | Android SDK Command-line Tools 23.0 (with JDK 17), Android Emulator, Google APIs x86 system images |
| Automation | PowerShell (`env.ps1`, `tools/build_all.ps1`, `tools/create_avds.ps1`), Python (`tools/lint_docs.py`, `tools/evaluate.py`, `tools/render_diagrams.py`) |
| Diagrams | Mermaid, rendered with mermaid-cli on a portable Node.js |
| Standards | CWE, OWASP MASVS v2, MASWE, MASTG |

## Results

Static evaluation (`python tools/evaluate.py --no-dynamic`, 2026-11-02) on the 53 benchmarks with an `api27` build, across all eight categories, using manifest rules, code patterns (Layer 2) and taint analysis (Layer 3), after the precision round (P-1 to P-9):

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

Final scores: precision 0.79 and recall 0.98, up from precision 0.53 and recall 0.77 two rounds earlier. A Secure APK counts as a false positive only when one of its findings has the benchmark's own CWE on the vulnerable component at medium or high confidence. Under the legacy rule (any finding on the Secure APK is a false positive) precision is 0.51. With a strict CWE match (no reviewed secondary CWEs) recall is 0.96. Most remaining false positives are findings that are true of the Secure app, whose fix is elsewhere ([docs/notes/false-positive-analysis.md](docs/notes/false-positive-analysis.md)). The differential mode (`--diff-mode`, only findings that differ between the Benign and Secure APK) scores precision 0.93 and recall 0.79; it needs the fixed app, so it is not comparable with the numbers above. Details and limits: [docs/notes/evaluation-report.md](docs/notes/evaluation-report.md).

## Screenshots

**Exploit succeeds against Benign** (Malicious triggers an email with no permissions):

<img src="docs/screenshots/step01_21_exploit-success-benign.png" alt="Exploit success" width="200">

**Exploit blocked by Secure** (no message appears after SEND BROADCAST):

<img src="docs/screenshots/step01_25_exploit-fails-secure.png" alt="Exploit blocked" width="200">

**System log confirming the block** (Permission Denial from adb logcat):

![Permission denial log](docs/screenshots/step01_26_secure-permission-denial-log.png)

## Tool in Action

![Tool run](docs/screenshots/step_demo_01_tool-run-summary.png)
*Running the tool on a Ghera benchmark APK: 3 findings detected in 2 components*

![Tool findings](docs/screenshots/step_demo_02_tool-report-output.png)
*The analysis tool detecting CWE-925, CWE-927 and a taint flow (CWE-926) in the DynamicRegBroadcastReceiver Benign APK*

![Tool report](docs/screenshots/step_demo_03_tool-report-file.png)
*The generated Markdown report showing component, issue type, CWE, confidence and evidence*

## Repo structure

```text
android-threat-engine/
  src/                 analysis tool: apk.py, surface.py, code_analyzer.py, call_graph.py,
                       taint_analyzer.py, dynamic_analyzer.py, report.py, ate.py (CLI)
  tests/               pytest tests for the tool
  tools/               build, emulator, lint, evaluation and diagram scripts
  data/                ground truth, drift matrix, evaluation results
  docs/
    threat-models/     threat models, standards reference, benchmark index, mappings
    diagrams/          SVG renderings of the threat model diagrams
    notes/             setup log, benchmark issues, designs, reports
    screenshots/       emulator screenshots from Step 1 smoke test and extra emulator runs
  results/             drift run output (empty until the drift runs start)
  benchmarks/          Ghera checkout (not committed; see Getting started)
  env.ps1              per-session toolchain environment
  requirements.txt     Python packages for the tests
  .github/CITATION.cff citations for Ghera and Rekha
```

## Getting started

### Prerequisites

- Java 8 or later (the tool uses `JAVA_HOME`, then `C:\Android\jdk8`, then `java` on `PATH`)
- Python 3
- Internet access on the first run: `src/apk.py` downloads the latest stable apktool jar to `tools/apktool.jar` and checks its SHA-256
- For the benchmark builds and the evaluator: the Android SDK and the Ghera repository cloned into `benchmarks/ghera` at tag `Jan2019` (see `docs/notes/SETUP_LOG.md`)

### Install

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt   # pytest, needed only for the tests
```

### Example

```powershell
python src\ate.py --apk path\to\app.apk --out results
python src\ate.py --apk path\to\app.apk --out results --dynamic   # with the emulator running
```

This writes `results\app-report.json` and `results\app-report.md` and prints a summary such as `5 findings in 3 components`. Run the tests with `.venv\Scripts\python -m pytest tests`.

## Citation

If you use this project, please cite the Ghera and Rekha papers listed in [.github/CITATION.cff](.github/CITATION.cff).
