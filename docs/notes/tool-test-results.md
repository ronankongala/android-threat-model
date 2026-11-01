# Tool test results

Run on 2026-11-01 (Layer 4, ghera27 emulator running) with `.venv/Scripts/python -m pytest tests -v -rs -p no:cacheprovider` from the project root.

- Python 3.15.0, pytest 9.2.0 (in a project `.venv`, from `requirements.txt`)
- apktool 3.0.3 (`tools/apktool.jar`), run with JDK 8 (`C:/Android/jdk8`)
- Fixtures: the api27 debug APKs of Ghera Benign apps under `benchmarks/ghera/`. A test whose APK has not been built is skipped, not failed.

## Result

15 passed, 0 failed, 13 skipped.

| Test | Result |
|------|--------|
| `test_apk_returns_dict_with_components` | Passed |
| `test_surface_finds_exported_no_permission` | Passed |
| `test_report_writes_both_files` | Passed |
| `test_code_pattern_detected[clipboard_sensitive]` | Skipped |
| `test_code_pattern_detected[constant_iv]` | Passed |
| `test_code_pattern_detected[directory_traversal]` | Skipped |
| `test_code_pattern_detected[dynamic_code_load]` | Skipped |
| `test_code_pattern_detected[ecb_mode]` | Passed |
| `test_code_pattern_detected[empty_trustmanager]` | Skipped |
| `test_code_pattern_detected[hardcoded_key]` | Passed |
| `test_code_pattern_detected[hardcoded_key_pbe]` | Passed |
| `test_code_pattern_detected[hostname_not_verified]` | Skipped |
| `test_code_pattern_detected[implicit_broadcast]` | Passed |
| `test_code_pattern_detected[insecure_ssl_socket_factory]` | Skipped |
| `test_code_pattern_detected[js_enabled]` | Skipped |
| `test_code_pattern_detected[no_validity_check]` | Passed |
| `test_code_pattern_detected[pending_intent_empty]` | Passed |
| `test_code_pattern_detected[sql_injection_no_args]` | Skipped |
| `test_code_pattern_detected[sql_injection_raw]` | Skipped |
| `test_code_pattern_detected[sticky_broadcast]` | Passed |
| `test_code_pattern_detected[unique_ids]` | Skipped |
| `test_code_pattern_detected[webview_file_access]` | Skipped |
| `test_surface_merges_code_findings` | Passed |
| `test_call_graph_maps_callers_and_callees` | Passed |
| `test_taint_flow_detected[directory_traversal]` | Skipped |
| `test_taint_flow_detected[receiver_extra_to_activity]` | Passed |
| `test_taint_flow_detected[sqlite_rawquery]` | Skipped |
| `test_dynamic_receiver_accepts_external` | Passed |

## Skip reasons

- fixture APK not built: benchmarks/ghera/System/ClipboardUse-InformationExposure-Lean/Benign/app/build/outputs/apk/api27/debug/app-api27-debug.apk (1)
- fixture APK not built: benchmarks/ghera/Storage/InternalStorage-DirectoryTraversal-Lean/Benign/app/build/outputs/apk/api27/debug/app-api27-debug.apk (1)
- fixture APK not built: benchmarks/ghera/System/DynamicCodeLoading-CodeInjection-Lean/Benign/app/build/outputs/apk/api27/debug/app-api27-debug.apk (1)
- fixture APK not built: benchmarks/ghera/Networking/InvalidCertificateAuthority-MITM-Lean/Benign/app/build/outputs/apk/api27/debug/app-api27-debug.apk (1)
- fixture APK not built: benchmarks/ghera/Networking/IncorrectHostNameVerification-MITM-Lean/Benign/app/build/outputs/apk/api27/debug/app-api27-debug.apk (1)
- fixture APK not built: benchmarks/ghera/Networking/InsecureSSLSocketFactory-MITM-Lean/Benign/app/build/outputs/apk/api27/debug/app-api27-debug.apk (1)
- fixture APK not built: benchmarks/ghera/Web/JavaScriptExecution-CodeInjection-Lean/Benign/app/build/outputs/apk/api27/debug/app-api27-debug.apk (1)
- fixture APK not built: benchmarks/ghera/Storage/SQLlite-SQLInjection-Lean/Benign/app/build/outputs/apk/api27/debug/app-api27-debug.apk (1)
- fixture APK not built: benchmarks/ghera/Storage/SQLlite-RawQuery-SQLInjection-Lean/Benign/app/build/outputs/apk/api27/debug/app-api27-debug.apk (1)
- fixture APK not built: benchmarks/ghera/System/UniqueIDs-IdentityLeak-Lean/Benign/app/build/outputs/apk/api27/debug/app-api27-debug.apk (1)
- fixture APK not built: benchmarks/ghera/Web/WebViewAllowFileAccess-UnauthorizedFileAccess-Lean/Benign/app/build/outputs/apk/api27/debug/app-api27-debug.apk (1)

## Raw output

```text
============================= test session starts =============================
platform win32 -- Python 3.15.0, pytest-9.2.0, pluggy-1.7.0 -- C:\Users\konga\Projects\android-threat-engine\.venv\Scripts\python.exe
rootdir: C:\Users\konga\Projects\android-threat-engine
collecting ... collected 28 items

tests/test_ate.py::test_apk_returns_dict_with_components PASSED          [  3%]
tests/test_ate.py::test_surface_finds_exported_no_permission PASSED      [  7%]
tests/test_ate.py::test_report_writes_both_files PASSED                  [ 10%]
tests/test_ate.py::test_code_pattern_detected[clipboard_sensitive] SKIPPED [ 14%]
tests/test_ate.py::test_code_pattern_detected[constant_iv] PASSED        [ 17%]
tests/test_ate.py::test_code_pattern_detected[directory_traversal] SKIPPED [ 21%]
tests/test_ate.py::test_code_pattern_detected[dynamic_code_load] SKIPPED [ 25%]
tests/test_ate.py::test_code_pattern_detected[ecb_mode] PASSED           [ 28%]
tests/test_ate.py::test_code_pattern_detected[empty_trustmanager] SKIPPED [ 32%]
tests/test_ate.py::test_code_pattern_detected[hardcoded_key] PASSED      [ 35%]
tests/test_ate.py::test_code_pattern_detected[hardcoded_key_pbe] PASSED  [ 39%]
tests/test_ate.py::test_code_pattern_detected[hostname_not_verified] SKIPPED [ 42%]
tests/test_ate.py::test_code_pattern_detected[implicit_broadcast] PASSED [ 46%]
tests/test_ate.py::test_code_pattern_detected[insecure_ssl_socket_factory] SKIPPED [ 50%]
tests/test_ate.py::test_code_pattern_detected[js_enabled] SKIPPED (f...) [ 53%]
tests/test_ate.py::test_code_pattern_detected[no_validity_check] PASSED  [ 57%]
tests/test_ate.py::test_code_pattern_detected[pending_intent_empty] PASSED [ 60%]
tests/test_ate.py::test_code_pattern_detected[sql_injection_no_args] SKIPPED [ 64%]
tests/test_ate.py::test_code_pattern_detected[sql_injection_raw] SKIPPED [ 67%]
tests/test_ate.py::test_code_pattern_detected[sticky_broadcast] PASSED   [ 71%]
tests/test_ate.py::test_code_pattern_detected[unique_ids] SKIPPED (f...) [ 75%]
tests/test_ate.py::test_code_pattern_detected[webview_file_access] SKIPPED [ 78%]
tests/test_ate.py::test_surface_merges_code_findings PASSED              [ 82%]
tests/test_ate.py::test_call_graph_maps_callers_and_callees PASSED       [ 85%]
tests/test_ate.py::test_taint_flow_detected[directory_traversal] SKIPPED [ 89%]
tests/test_ate.py::test_taint_flow_detected[receiver_extra_to_activity] PASSED [ 92%]
tests/test_ate.py::test_taint_flow_detected[sqlite_rawquery] SKIPPED     [ 96%]
tests/test_ate.py::test_dynamic_receiver_accepts_external PASSED         [100%]

=========================== short test summary info ===========================
SKIPPED [1] tests\test_ate.py:82: fixture APK not built: benchmarks\ghera\System\ClipboardUse-InformationExposure-Lean\Benign\app\build\outputs\apk\api27\debug\app-api27-debug.apk
SKIPPED [2] tests\test_ate.py:82: fixture APK not built: benchmarks\ghera\Storage\InternalStorage-DirectoryTraversal-Lean\Benign\app\build\outputs\apk\api27\debug\app-api27-debug.apk
SKIPPED [1] tests\test_ate.py:82: fixture APK not built: benchmarks\ghera\System\DynamicCodeLoading-CodeInjection-Lean\Benign\app\build\outputs\apk\api27\debug\app-api27-debug.apk
SKIPPED [1] tests\test_ate.py:82: fixture APK not built: benchmarks\ghera\Networking\InvalidCertificateAuthority-MITM-Lean\Benign\app\build\outputs\apk\api27\debug\app-api27-debug.apk
SKIPPED [1] tests\test_ate.py:82: fixture APK not built: benchmarks\ghera\Networking\IncorrectHostNameVerification-MITM-Lean\Benign\app\build\outputs\apk\api27\debug\app-api27-debug.apk
SKIPPED [1] tests\test_ate.py:82: fixture APK not built: benchmarks\ghera\Networking\InsecureSSLSocketFactory-MITM-Lean\Benign\app\build\outputs\apk\api27\debug\app-api27-debug.apk
SKIPPED [1] tests\test_ate.py:82: fixture APK not built: benchmarks\ghera\Web\JavaScriptExecution-CodeInjection-Lean\Benign\app\build\outputs\apk\api27\debug\app-api27-debug.apk
SKIPPED [1] tests\test_ate.py:82: fixture APK not built: benchmarks\ghera\Storage\SQLlite-SQLInjection-Lean\Benign\app\build\outputs\apk\api27\debug\app-api27-debug.apk
SKIPPED [2] tests\test_ate.py:82: fixture APK not built: benchmarks\ghera\Storage\SQLlite-RawQuery-SQLInjection-Lean\Benign\app\build\outputs\apk\api27\debug\app-api27-debug.apk
SKIPPED [1] tests\test_ate.py:82: fixture APK not built: benchmarks\ghera\System\UniqueIDs-IdentityLeak-Lean\Benign\app\build\outputs\apk\api27\debug\app-api27-debug.apk
SKIPPED [1] tests\test_ate.py:82: fixture APK not built: benchmarks\ghera\Web\WebViewAllowFileAccess-UnauthorizedFileAccess-Lean\Benign\app\build\outputs\apk\api27\debug\app-api27-debug.apk
======================= 15 passed, 13 skipped in 46.60s =======================
```
