# Tool test results

Run on 2026-11-01 with `.venv\Scripts\python -m pytest tests -v -p no:cacheprovider` from the project root.

- Python 3.15.0, pytest 9.2.0 (in a project `.venv`, from `requirements.txt`)
- apktool 3.0.3 (`tools/apktool.jar`, downloaded by `src/apk.py`, SHA-256 checked against the GitHub release digest), run with JDK 8 (`C:\Android\jdk8`)
- Fixture: `benchmarks/ghera/ICC/DynamicRegBroadcastReceiver-UnrestrictedAccess-Lean/Benign/app/build/outputs/apk/api27/debug/app-api27-debug.apk` (built in the smoke test, `SETUP_LOG.md`)

## Result

3 passed, 0 failed, 0 skipped.

| Test | What it checks | Result |
|------|----------------|--------|
| `test_apk_returns_dict_with_components` | `apk.decode` returns a dict with `package`, `permissions`, `declared_permissions` and a non-empty `components` list whose entries have `name`, `type`, `exported`, `intent_filters` and `permission` | Passed |
| `test_surface_finds_exported_no_permission` | `surface.find` returns at least one `exported-no-permission` finding, and every finding uses a known issue, its CWE and a known confidence | Passed |
| `test_report_writes_both_files` | `report.write` creates `fixture-report.json` (equal to the findings) and `fixture-report.md` (with the table header) | Passed |

## What the fixture shows

The decoded manifest has two components: `MainActivity` (launcher, exported through its intent filter, no permission) and `EmailActivity` (not exported). The surface extractor returns one finding:

| Component | Type | Issue | CWE | Confidence |
|---|---|---|---|---|
| edu.ksu.cs.benign.MainActivity | activity | exported-no-permission | CWE-926 | low |

This finding is the launcher activity, which every app must export. It is not the benchmark's vulnerability. The vulnerable receiver in this benchmark is registered at run time in code (`registerReceiver`), so it does not appear in the manifest, and the `dynamic-receiver-no-permission` issue cannot be found by manifest-only rules. The test therefore shows that the rule fires, not that the tool detects this benchmark.

## Raw output

```text
============================= test session starts =============================
platform win32 -- Python 3.15.0, pytest-9.2.0, pluggy-1.7.0 -- C:\Users\konga\Projects\android-threat-engine\.venv\Scripts\python.exe
rootdir: C:\Users\konga\Projects\android-threat-engine
collecting ... collected 3 items

tests/test_ate.py::test_apk_returns_dict_with_components PASSED          [ 33%]
tests/test_ate.py::test_surface_finds_exported_no_permission PASSED      [ 66%]
tests/test_ate.py::test_report_writes_both_files PASSED                  [100%]

============================== 3 passed in 2.89s ==============================
```
