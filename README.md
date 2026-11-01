# android-threat-engine

Placeholder. This project is an Android security research effort. A full description of scope, methods, and results will be added once the toolchain is set up and the first experiments are complete.

## Usage

The analysis tool in `src/` decodes an Android APK and reports its manifest attack surface (exported components without permissions, components reachable by implicit intents, cleartext HTTP, content providers protected only by path) as JSON and as a Markdown table.

### Prerequisites

- Java 8 or later. The tool uses `JAVA_HOME`, then `C:\Android\jdk8`, then `java` on `PATH`.
- Python 3 (standard library only for the tool).
- Internet access on the first run: `src/apk.py` downloads the latest stable apktool jar to `tools/apktool.jar` and checks its SHA-256.

### Install

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt   # pytest, needed only for the tests
```

### Example

```powershell
python src\ate.py --apk path\to\app.apk --out results
```

This writes `results\app-report.json` and `results\app-report.md` and prints a summary such as `5 findings in 3 components`. Run the tests with `.venv\Scripts\python -m pytest tests`.

## Evaluation

First run of `tools/evaluate.py` (2026-11-01): overall precision 0.50 and recall 1.00. These numbers come from one benchmark (`Crypto/BlockCipher-ECB-InformationExposure-Lean`), the only one with a successful `api27` build in `data/build-results.csv` so far, so they show that the pipeline works, not how accurate the tool is. See `docs/notes/evaluation-report.md` for definitions, details and limits.
