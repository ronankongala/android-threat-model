# Tool test results

Run on 2026-11-01 (Layer 3) with `.venv/Scripts/python -m pytest tests -v -rs -p no:cacheprovider` from the project root.

- Python 3.15.0, pytest 9.2.0 (in a project `.venv`, from `requirements.txt`)
- apktool 3.0.3 (`tools/apktool.jar`), run with JDK 8 (`C:/Android/jdk8`)
- Fixtures: the api27 debug APKs of Ghera Benign apps under `benchmarks/ghera/`. A test whose APK has not been built is skipped, not failed.

## Result

14 passed, 0 failed, 13 skipped.

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
collecting ... collected 27 items

tests/test_ate.py::test_apk_returns_dict_with_components PASSED          [  3%]
tests/test_ate.py::test_surface_finds_exported_no_permission PASSED      [  7%]
tests/test_ate.py::test_report_writes_both_files PASSED                  [ 11%]
tests/test_ate.py::test_code_pattern_detected[clipboard_sensitive] SKIPPED [ 14%]
tests/test_ate.py::test_code_pattern_detected[constant_iv] PASSED        [ 18%]
tests/test_ate.py::test_code_pattern_detected[directory_traversal] SKIPPED [ 22%]
tests/test_ate.py::test_code_pattern_detected[dynamic_code_load] SKIPPED [ 25%]
tests/test_ate.py::test_code_pattern_detected[ecb_mode] PASSED           [ 29%]
tests/test_ate.py::test_code_pattern_detected[empty_trustmanager] SKIPPED [ 33%]
tests/test_ate.py::test_code_pattern_detected[hardcoded_key] PASSED      [ 37%]
tests/test_ate.py::test_code_pattern_detected[hardcoded_key_pbe] PASSED  [ 40%]
tests/test_ate.py::test_code_pattern_detected[hostname_not_verified] SKIPPED [ 44%]
tests/test_ate.py::test_code_pattern_detected[implicit_broadcast] PASSED [ 48%]
tests/test_ate.py::test_code_pattern_detected[insecure_ssl_socket_factory] SKIPPED [ 51%]
tests/test_ate.py::test_code_pattern_detected[js_enabled] SKIPPED (f...) [ 55%]
tests/test_ate.py::test_code_pattern_detected[no_validity_check] PASSED  [ 59%]
tests/test_ate.py::test_code_pattern_detected[pending_intent_empty] PASSED [ 62%]
tests/test_ate.py::test_code_pattern_detected[sql_injection_no_args] SKIPPED [ 66%]
tests/test_ate.py::test_code_pattern_detected[sql_injection_raw] SKIPPED [ 70%]
tests/test_ate.py::test_code_pattern_detected[sticky_broadcast] PASSED   [ 74%]
tests/test_ate.py::test_code_pattern_detected[unique_ids] SKIPPED (f...) [ 77%]
tests/test_ate.py::test_code_pattern_detected[webview_file_access] SKIPPED [ 81%]
tests/test_ate.py::test_surface_merges_code_findings PASSED              [ 85%]
tests/test_ate.py::test_call_graph_maps_callers_and_callees PASSED       [ 88%]
tests/test_ate.py::test_taint_flow_detected[directory_traversal] SKIPPED [ 92%]
tests/test_ate.py::test_taint_flow_detected[receiver_extra_to_activity] PASSED [ 96%]
tests/test_ate.py::test_taint_flow_detected[sqlite_rawquery] SKIPPED     [100%]

=========================== short test summary info ===========================
SKIPPED [1] tests\test_ate.py:78: fixture APK not built: benchmarks\ghera\System\ClipboardUse-InformationExposure-Lean\Benign\app\build\outputs\apk\api27\debug\app-api27-debug.apk
SKIPPED [2] tests\test_ate.py:78: fixture APK not built: benchmarks\ghera\Storage\InternalStorage-DirectoryTraversal-Lean\Benign\app\build\outputs\apk\api27\debug\app-api27-debug.apk
SKIPPED [1] tests\test_ate.py:78: fixture APK not built: benchmarks\ghera\System\DynamicCodeLoading-CodeInjection-Lean\Benign\app\build\outputs\apk\api27\debug\app-api27-debug.apk
SKIPPED [1] tests\test_ate.py:78: fixture APK not built: benchmarks\ghera\Networking\InvalidCertificateAuthority-MITM-Lean\Benign\app\build\outputs\apk\api27\debug\app-api27-debug.apk
SKIPPED [1] tests\test_ate.py:78: fixture APK not built: benchmarks\ghera\Networking\IncorrectHostNameVerification-MITM-Lean\Benign\app\build\outputs\apk\api27\debug\app-api27-debug.apk
SKIPPED [1] tests\test_ate.py:78: fixture APK not built: benchmarks\ghera\Networking\InsecureSSLSocketFactory-MITM-Lean\Benign\app\build\outputs\apk\api27\debug\app-api27-debug.apk
SKIPPED [1] tests\test_ate.py:78: fixture APK not built: benchmarks\ghera\Web\JavaScriptExecution-CodeInjection-Lean\Benign\app\build\outputs\apk\api27\debug\app-api27-debug.apk
SKIPPED [1] tests\test_ate.py:78: fixture APK not built: benchmarks\ghera\Storage\SQLlite-SQLInjection-Lean\Benign\app\build\outputs\apk\api27\debug\app-api27-debug.apk
SKIPPED [2] tests\test_ate.py:78: fixture APK not built: benchmarks\ghera\Storage\SQLlite-RawQuery-SQLInjection-Lean\Benign\app\build\outputs\apk\api27\debug\app-api27-debug.apk
SKIPPED [1] tests\test_ate.py:78: fixture APK not built: benchmarks\ghera\System\UniqueIDs-IdentityLeak-Lean\Benign\app\build\outputs\apk\api27\debug\app-api27-debug.apk
SKIPPED [1] tests\test_ate.py:78: fixture APK not built: benchmarks\ghera\Web\WebViewAllowFileAccess-UnauthorizedFileAccess-Lean\Benign\app\build\outputs\apk\api27\debug\app-api27-debug.apk
======================= 14 passed, 13 skipped in 38.42s =======================
```
