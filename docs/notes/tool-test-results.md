# Tool test results

Run on 2026-11-01 after the detection improvements (Fix 1 to Fix 7) with `.venv/Scripts/python -m pytest tests -v -rs -p no:cacheprovider` from the project root. No emulator was attached for this run.

- Python 3.15.0, pytest 9.2.0 (in a project `.venv`, from `requirements.txt`)
- apktool 3.0.3 (`tools/apktool.jar`), run with JDK 8 (`C:/Android/jdk8`)
- Fixtures: the api27 debug APKs of Ghera Benign apps under `benchmarks/ghera/`. A test whose APK has not been built is skipped, not failed. All pattern and taint fixtures are now built.
- New offline tests for the dynamic sweep (`run_all`): `test_parse_foreground_task`, `test_crash_lines`, `test_new_dynamic_issues_have_cwes`. They use sample dumpsys and logcat text, so they need no device.

## Result

30 passed, 0 failed, 1 skipped.

| Test | Result |
|------|--------|
| `test_apk_returns_dict_with_components` | Passed |
| `test_surface_finds_exported_no_permission` | Passed |
| `test_report_writes_both_files` | Passed |
| `test_code_pattern_detected[clipboard_sensitive]` | Passed |
| `test_code_pattern_detected[constant_iv]` | Passed |
| `test_code_pattern_detected[directory_traversal]` | Passed |
| `test_code_pattern_detected[dynamic_code_load]` | Passed |
| `test_code_pattern_detected[ecb_mode]` | Passed |
| `test_code_pattern_detected[empty_trustmanager]` | Passed |
| `test_code_pattern_detected[hardcoded_key]` | Passed |
| `test_code_pattern_detected[hardcoded_key_pbe]` | Passed |
| `test_code_pattern_detected[hostname_not_verified]` | Passed |
| `test_code_pattern_detected[implicit_broadcast]` | Passed |
| `test_code_pattern_detected[insecure_ssl_socket_factory]` | Passed |
| `test_code_pattern_detected[js_enabled]` | Passed |
| `test_code_pattern_detected[no_validity_check]` | Passed |
| `test_code_pattern_detected[pending_intent_empty]` | Passed |
| `test_code_pattern_detected[sql_injection_no_args]` | Passed |
| `test_code_pattern_detected[sql_injection_raw]` | Passed |
| `test_code_pattern_detected[sticky_broadcast]` | Passed |
| `test_code_pattern_detected[unique_ids]` | Passed |
| `test_code_pattern_detected[webview_file_access]` | Passed |
| `test_surface_merges_code_findings` | Passed |
| `test_call_graph_maps_callers_and_callees` | Passed |
| `test_taint_flow_detected[directory_traversal]` | Passed |
| `test_taint_flow_detected[receiver_extra_to_activity]` | Passed |
| `test_taint_flow_detected[sqlite_rawquery]` | Passed |
| `test_dynamic_receiver_accepts_external` | Skipped |
| `test_parse_foreground_task` | Passed |
| `test_crash_lines` | Passed |
| `test_new_dynamic_issues_have_cwes` | Passed |

## Skip reasons

- emulator not running

## Raw output

```text
============================= test session starts =============================
platform win32 -- Python 3.15.0, pytest-9.2.0, pluggy-1.7.0 -- C:\Users\konga\Projects\android-threat-engine\.venv\Scripts\python.exe
rootdir: C:\Users\konga\Projects\android-threat-engine
collecting ... collected 31 items

tests/test_ate.py::test_apk_returns_dict_with_components PASSED          [  3%]
tests/test_ate.py::test_surface_finds_exported_no_permission PASSED      [  6%]
tests/test_ate.py::test_report_writes_both_files PASSED                  [  9%]
tests/test_ate.py::test_code_pattern_detected[clipboard_sensitive] PASSED [ 12%]
tests/test_ate.py::test_code_pattern_detected[constant_iv] PASSED        [ 16%]
tests/test_ate.py::test_code_pattern_detected[directory_traversal] PASSED [ 19%]
tests/test_ate.py::test_code_pattern_detected[dynamic_code_load] PASSED  [ 22%]
tests/test_ate.py::test_code_pattern_detected[ecb_mode] PASSED           [ 25%]
tests/test_ate.py::test_code_pattern_detected[empty_trustmanager] PASSED [ 29%]
tests/test_ate.py::test_code_pattern_detected[hardcoded_key] PASSED      [ 32%]
tests/test_ate.py::test_code_pattern_detected[hardcoded_key_pbe] PASSED  [ 35%]
tests/test_ate.py::test_code_pattern_detected[hostname_not_verified] PASSED [ 38%]
tests/test_ate.py::test_code_pattern_detected[implicit_broadcast] PASSED [ 41%]
tests/test_ate.py::test_code_pattern_detected[insecure_ssl_socket_factory] PASSED [ 45%]
tests/test_ate.py::test_code_pattern_detected[js_enabled] PASSED         [ 48%]
tests/test_ate.py::test_code_pattern_detected[no_validity_check] PASSED  [ 51%]
tests/test_ate.py::test_code_pattern_detected[pending_intent_empty] PASSED [ 54%]
tests/test_ate.py::test_code_pattern_detected[sql_injection_no_args] PASSED [ 58%]
tests/test_ate.py::test_code_pattern_detected[sql_injection_raw] PASSED  [ 61%]
tests/test_ate.py::test_code_pattern_detected[sticky_broadcast] PASSED   [ 64%]
tests/test_ate.py::test_code_pattern_detected[unique_ids] PASSED         [ 67%]
tests/test_ate.py::test_code_pattern_detected[webview_file_access] PASSED [ 70%]
tests/test_ate.py::test_surface_merges_code_findings PASSED              [ 74%]
tests/test_ate.py::test_call_graph_maps_callers_and_callees PASSED       [ 77%]
tests/test_ate.py::test_taint_flow_detected[directory_traversal] PASSED  [ 80%]
tests/test_ate.py::test_taint_flow_detected[receiver_extra_to_activity] PASSED [ 83%]
tests/test_ate.py::test_taint_flow_detected[sqlite_rawquery] PASSED      [ 87%]
tests/test_ate.py::test_dynamic_receiver_accepts_external SKIPPED (e...) [ 90%]
tests/test_ate.py::test_parse_foreground_task PASSED                     [ 93%]
tests/test_ate.py::test_crash_lines PASSED                               [ 96%]
tests/test_ate.py::test_new_dynamic_issues_have_cwes PASSED              [100%]

=========================== short test summary info ===========================
SKIPPED [1] tests\test_ate.py:213: emulator not running
================== 30 passed, 1 skipped in 143.43s (0:02:23) ==================
```
