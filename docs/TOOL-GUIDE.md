# Tool guide: src/ate.py

`src/ate.py` is the command line entry point of the APK analysis tool. It decodes an Android APK with apktool, checks the manifest and the smali code for known weaknesses, traces untrusted input to dangerous calls, and writes the findings as JSON and Markdown. On request it also installs the APK on an emulator and exercises it over adb, and compares a privacy policy text with what the APK declares.

This guide covers installation, a first run, every flag, how to read each kind of finding, the known limits, and how to add a rule. Every statement here was checked against the code in `src/` on 2026-11-02.

## Contents

1. [How the tool works](#1-how-the-tool-works)
2. [Installation](#2-installation)
3. [Quick start](#3-quick-start)
4. [Command line flags](#4-command-line-flags)
5. [Output files](#5-output-files)
6. [Interpreting findings](#6-interpreting-findings)
7. [Known limitations](#7-known-limitations)
8. [Contributing detection rules](#8-contributing-detection-rules)

## 1. How the tool works

| Step | Module | What it does |
|------|--------|--------------|
| Decode | [`src/apk.py`](../src/apk.py) | Runs `java -jar tools/apktool.jar d <apk>` into a temporary folder and parses `AndroidManifest.xml` and `apktool.yml` into a manifest dict (package, permissions, components, intent filters, SDK levels, application attributes). |
| Manifest rules | [`src/surface.py`](../src/surface.py) | Reads only the manifest dict. Reports exported components, implicit intent exposure, cleartext traffic, provider path permissions and task affinity. |
| Code patterns | [`src/code_analyzer.py`](../src/code_analyzer.py) | Reads the app's own smali (library packages such as `android/`, `androidx/`, `kotlin/` and `com/google/` are skipped) with a simple register model and reports insecure API use. |
| Taint analysis | [`src/taint_analyzer.py`](../src/taint_analyzer.py) | Follows values from untrusted sources (intent extras, user input, cursors) to dangerous sinks (SQL, files, intents, SMS), across calls and across components. |
| Dynamic analysis (optional) | [`src/dynamic_analyzer.py`](../src/dynamic_analyzer.py) | Installs the APK on a running device over adb, sends broadcasts, reads logcat, the task stack and the app's files, then uninstalls it. |
| Privacy check (optional) | [`src/privacy_checker.py`](../src/privacy_checker.py) | Compares negative claims in a policy text with the manifest permissions and the advertising and analytics SDK packages in the APK. |
| Report | [`src/report.py`](../src/report.py) | Writes `<name>-report.json`, `<name>-report.md` and, with a policy, `<name>-privacy.json`. |

The manifest, code and taint findings are merged by `surface.find`: for each pair (component name, CWE) only one finding is kept, the one with the highest confidence. The decoded folder is deleted before the dynamic step starts.

## 2. Installation

### Python

Python 3 is required. The tool itself uses only the standard library ([requirements.txt](../requirements.txt) lists only `pytest`, which is needed for the tests).

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
```

### Java

apktool is a Java program. `apk.find_java()` looks for `java` in this order:

1. `%JAVA_HOME%\bin\java.exe`
2. `C:\Android\jdk8\bin\java.exe`
3. `java` on `PATH`

If none is found the tool stops with `error: java not found: set JAVA_HOME or put java on PATH`. The project uses Java 8 (Eclipse Temurin).

### apktool

Nothing to install by hand. On the first run `apk.ensure_apktool()` asks the GitHub API for the latest apktool release, refuses a prerelease or draft, downloads the `apktool_<version>.jar` asset to `tools/apktool.jar` and checks it against the SHA-256 digest GitHub publishes for the asset. The first run therefore needs internet access. Later runs reuse the jar. To pin a version, place the jar at `tools/apktool.jar` yourself.

### env.ps1

[env.ps1](../env.ps1) sets up the toolchain for the current PowerShell session only. Dot-source it from the project root:

```powershell
. .\env.ps1
```

It sets `JAVA_HOME` to `C:\Android\jdk8`, `ANDROID_HOME` and `ANDROID_SDK_ROOT` to `C:\Android\Sdk`, and puts the JDK `bin`, `cmdline-tools\latest\bin`, `platform-tools` and `emulator` folders first on `PATH`. It warns when `C:\Android\jdk8` or `C:\Android\Sdk` is missing. Static analysis only needs Java; the SDK paths matter for building benchmarks and for dynamic analysis.

### adb and an emulator (dynamic analysis only)

`--dynamic` and `--dynamic-two-app` need `adb` and a running emulator or device. `dynamic_analyzer.find_adb()` looks for `adb` on `PATH`, then under `%ANDROID_HOME%\platform-tools`, then at `C:\Android\Sdk\platform-tools\adb.exe`. With more than one device attached, set `ANDROID_SERIAL`. The project uses the `ghera27` AVD (Android 8.1, API 27), created by `tools/create_avds.ps1`:

```powershell
. .\env.ps1
emulator -avd ghera27
adb devices
```

The file checks use `adb shell run-as <package>`, so they work only for debuggable APKs (the Ghera `debug` builds are).

## 3. Quick start

This run uses the Benign APK of the Ghera benchmark `UnprotectedBroadcastRecv-PrivEscalation-Lean` (`api27` debug build) and writes the report to a folder outside the repository:

```powershell
python src\ate.py --apk benchmarks\ghera\ICC\UnprotectedBroadcastRecv-PrivEscalation-Lean\Benign\app\build\outputs\apk\api27\debug\app-api27-debug.apk --out C:\Users\konga\AppData\Local\Temp\claude\tool-guide-run
```

Printed output (the run took about 15 seconds):

```text
3 findings in 3 components
```

Files written: `app-api27-debug-report.json` and `app-api27-debug-report.md` (the name comes from the APK file name without `.apk`). The Markdown report:

```text
# app-api27-debug report

| Component | Type | Issue | CWE | Confidence | Evidence |
|---|---|---|---|---|---|
| edu.ksu.cs.benign.MyReceiver | receiver | exported-no-permission | CWE-926 | high |  |
| edu.ksu.cs.benign.MainActivity$1 | class | taint-flow | CWE-927 | high | `source L70: invoke-virtual {v1}, Landroid/widget/EditText;->getText()Landroid/text/Editable; \| sink L100: invoke-virtual {v3, v2}, Ledu/ksu/cs/benign/MainActivity;->sendBroadcast(Landroid/content/Intent;)V` |
| edu.ksu.cs.benign.MyReceiver | class | taint-flow | CWE-200 | high | `source L47: invoke-virtual {p2, v0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String; \| sink L96: invoke-virtual/range {v1 .. v6}, Landroid/telephony/SmsManager;->sendTextMessage(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/app/PendingIntent;Landroid/app/PendingIntent;)V` |

## Dynamic Analysis Findings

Dynamic analysis was skipped. To enable it, start the ghera27 emulator (check `adb devices`) and run `python src/ate.py --apk APK --dynamic`.
```

What this says: the receiver `MyReceiver` is exported with no permission (`android:exported="true"`, so confidence high), its `onReceive` passes an intent extra straight to `SmsManager.sendTextMessage`, and `MainActivity$1` sends text from an `EditText` in an implicit broadcast. That is the weakness the benchmark is about: any app can make the Benign app send an SMS.

Why "3 components" for what looks like two classes: the summary counts distinct (type, component) pairs, so `MyReceiver` as a `receiver` (manifest finding) and `MyReceiver` as a `class` (taint finding) count separately.

## 4. Command line flags

```text
python src/ate.py --apk APK [--out DIR] [--dynamic] [--dynamic-two-app MALICIOUS_APK]
                  [--policy POLICY_TXT] [--no-ai]
```

Static analysis (manifest, code patterns, taint) always runs and is the default. There is no `--no-dynamic` flag: leaving out `--dynamic` and `--dynamic-two-app` gives a static-only run. (`--no-dynamic` is a flag of `tools/evaluate.py`, not of `ate.py`.)

### --apk APK (required)

Path to the APK to analyze. A missing file stops the run with `error: APK not found: <path>` and exit code 1; an apktool failure stops it with `error: apktool failed (exit N): ...`.

```powershell
python src\ate.py --apk path\to\app.apk
```

### --out DIR

Folder for the report files. Default: the current directory. The folder is created if needed. Existing reports with the same name are overwritten.

```powershell
python src\ate.py --apk path\to\app.apk --out results
```

### --dynamic

After the static report data is collected, installs the APK on the running emulator or device and calls `dynamic_analyzer.run_all`: clear logcat, start the launcher activity, read logcat, the task stack and `dumpsys package`, send an explicit broadcast from the shell to every exported receiver, probe receivers registered at run time (read from `dumpsys activity broadcasts`) with their registered actions, record crashes, foreground task changes and changes in the app's `files/` folder around each broadcast, and finally uninstall the package.

```powershell
python src\ate.py --apk path\to\app.apk --out results --dynamic
```

If adb finds no device, the tool prints `warning: no emulator or device found by adb; dynamic analysis skipped (start the ghera27 emulator and check "adb devices")` to stderr and still writes the static report. In that case the "Dynamic Analysis Findings" section reads "No findings." (the skipped note appears only when no dynamic flag was given).

### --dynamic-two-app MALICIOUS_APK

Installs the analyzed APK (the benign app) and `MALICIOUS_APK` together, starts the benign app, then the malicious one, and reports task hijacks, foreign activities in the benign app's foreground task, files created in or deleted from the benign app's internal storage, and Permission Denial lines naming either package (`dynamic_analyzer.run_two_app`). Both apps are uninstalled at the end. The findings go to the same "Dynamic Analysis Findings" section; the flag can be combined with `--dynamic`, in which case both lists are concatenated.

```powershell
$B = "benchmarks\ghera\ICC\TaskAffinity-ActivityHijack-Lean"
python src\ate.py --apk "$B\Benign\app\build\outputs\apk\api27\debug\app-api27-debug.apk" --dynamic-two-app "$B\Malicious\app\build\outputs\apk\api27\debug\app-api27-debug.apk" --out results
```

According to [docs/notes/evaluation-report.md](notes/evaluation-report.md) (Fix D), on `TaskAffinity-ActivityHijack-Lean` this reports `dynamic-task-hijack` (CWE-1021) for the Benign plus Malicious pair, because the malicious task holds the affinity `edu.ksu.santos.benign.editImage` declared by the benign app, and nothing for the Secure plus Malicious pair. If the malicious APK cannot be decoded, a warning is printed and the two-app step is skipped.

### --policy POLICY_TXT

Compares a privacy policy (plain UTF-8 text) with the manifest permissions and the advertising and analytics SDK packages found in the APK's smali folders or component names. Prints a second summary line, adds a "Privacy Policy Analysis" section to the Markdown report and writes `<name>-privacy.json`. An unreadable policy file stops the run with `error: cannot read policy file: ...` and exit code 1, before the APK is decoded.

Example with a two-sentence policy ("All your data stays on your device. We do not share data with third parties.") and the Benign APK of `CheckValidity-InformationExposure-Lean`:

```powershell
python src\ate.py --apk benchmarks\ghera\Networking\CheckValidity-InformationExposure-Lean\Benign\app\build\outputs\apk\api27\debug\app-api27-debug.apk --out C:\Users\konga\AppData\Local\Temp\claude\tool-guide-run\policy --policy C:\Users\konga\AppData\Local\Temp\claude\tool-guide-run\policy.txt
```

```text
4 findings in 3 components
1 privacy policy contradictions
```

The added report section:

```text
## Privacy Policy Analysis

Policy file: `policy.txt`

| Severity | Rule | Policy claim | Manifest evidence |
|---|---|---|---|
| medium | data-stays-on-device | All your data stays on your device. | manifest requests android.permission.INTERNET |
```

The "no third parties" sentence produced nothing, because the APK holds none of the listed SDK packages.

### --no-ai

Reserved. The flag is accepted and has no effect (`help='reserved; has no effect yet'` in `ate.py`).

### Exit codes

| Code | When |
|------|------|
| 0 | Report written (also when the dynamic step was skipped for lack of a device). |
| 1 | Policy file unreadable, APK not found, apktool failed or Java not found. |

A network failure while downloading apktool on the first run is not caught and ends with a Python traceback.

## 5. Output files

| File | Content |
|------|---------|
| `<name>-report.json` | One flat JSON list: the static findings, then the dynamic findings. |
| `<name>-report.md` | `# <name> report`, a table of the static findings, then a "Dynamic Analysis Findings" section (table, "No findings.", or the skipped note), then the privacy section when `--policy` was given. |
| `<name>-privacy.json` | Only with `--policy`: `{"policy": <file name>, "privacy": [findings]}`. |

Every finding has these keys:

| Key | Meaning |
|-----|---------|
| `component` | Fully qualified class name, `(application)` for app-wide findings, or for receivers registered at run time `<package> (registered for <action>)`. |
| `component_type` | `activity`, `activity-alias`, `service`, `receiver` or `provider` for manifest and some dynamic findings; `class` for code and taint findings; `application` for app-wide findings; `dynamic-receiver` for receivers registered at run time. |
| `issue` | The finding name (see section 6). For taint findings it is always `taint-flow`. |
| `cwe` | The CWE ID, or `n/a` for `dynamic-permission-denial-observed`. |
| `confidence` | `high`, `medium` or `low`. |

Code findings add `pattern` (same value as `issue`), `file` (smali path relative to the decoded folder), `line` and `evidence` (the smali line). Taint findings add `pattern` (`taint:<source>-><sink>`), `file`, `line` (the sink), `evidence`, `source_line` and `sink_line`. Some manifest findings (`task-affinity-hijack`, `provider-path-permission-only`) carry `evidence` with the manifest attributes; `provider-path-permission-only` also has a `note`. Dynamic findings have `evidence` with the adb or logcat observation.

The Markdown table shows the Issue column from `issue`, so taint findings appear as `taint-flow`; the source and sink names are in `pattern` in the JSON. Privacy findings use different keys: `rule`, `claim`, `evidence`, `severity`.

The printed summary `N findings in M components` counts static plus dynamic findings, and M counts distinct (component_type, component) pairs. Privacy contradictions are not part of N; they get their own line.

## 6. Interpreting findings

Confidence is assigned per rule, as listed below. Examples come from runs of the current code on the Ghera `api27` debug APKs (2026-11-02) or, where marked, from the reports left in `data/eval-tmp/` by the evaluation runs of 2026-11-01 described in [docs/notes/evaluation-report.md](notes/evaluation-report.md). Per-benchmark scores are in [data/evaluation-results.csv](../data/evaluation-results.csv).

### 6.1 Manifest findings (surface.py)

| Issue | CWE | Confidence | Fires when |
|-------|-----|------------|------------|
| `exported-no-permission` | CWE-926 | high when `android:exported="true"`; medium when exported only through an intent filter | An exported component has no permission (the application permission counts; a provider needs both read and write permissions, or `android:permission`). Launcher activities are skipped. |
| `implicit-intent` | CWE-927 | medium when a filter has a custom action; low when all actions start with `android.` | A component other than a provider is exported only because it has an intent filter (no `android:exported`), and it is not the launcher. |
| `path-not-sanitized` | CWE-22 | medium when an exported provider has path permissions but no `android:permission`; low when it grants URI permissions | Exported content provider whose access depends on the caller's path. |
| `provider-path-permission-only` | CWE-284 (candidate, see note) | medium | Exported provider with `<path-permission>` children and no provider-level permission, or a path-permission using exact `android:path` so subpaths are open. The finding carries a `note`: CWE-284 is DISCOURAGED in [standards-reference.md](threat-models/standards-reference.md), and children such as CWE-285 or CWE-732 are to be reviewed. |
| `task-affinity-hijack` | CWE-1021 | high when an activity's `android:taskAffinity` names another package; medium when it only uses `launchMode` `singleTask` or `singleInstance` | Activity that can join or start a task another app can own. One finding per activity. |
| `cleartext-http` | CWE-319 | high for `usesCleartextTraffic="true"` (with minSdkVersion 23 or more, or unknown) or a network security config whose base-config permits cleartext; medium for a config that permits it for named domains; low when nothing is set and targetSdkVersion is below 28 | The app requests `INTERNET` and may send cleartext HTTP. Skipped when the config permits cleartext only to `localhost`, `127.0.0.1` or `10.0.2.2`. Component is `(application)`. |

Examples:

- `UnprotectedBroadcastRecv-PrivEscalation-Lean`: `exported-no-permission` (high) on `MyReceiver` (quick start above).
- `InadequatePathPermission-InformationExposure-Lean`: on `provider.UserDetailsContentProvider`, `exported-no-permission` (high), `path-not-sanitized` (medium) and `provider-path-permission-only` (medium) with evidence `<path-permission android:pathPrefix="/user" android:readPermission="edu.ksu.cs.benign.permission.internalRead"/>; provider has no android:permission, android:readPermission or android:writePermission, so other paths are unprotected; ...`. `UserDetailsActivity` gets `exported-no-permission` (medium) and `implicit-intent` (medium).
- `TaskAffinity-ActivityHijack-Lean` and `TaskAffinity-PhishingAttack-Lean`: `task-affinity-hijack` (high) on `ImageEditor` (from `data/eval-tmp/`).
- `NoValidityCheckOnBroadcastMsg-UnintendedInvocation-Lean`: `implicit-intent` (low) on `LowMemoryReceiver`, whose filter has only a platform action (from `data/eval-tmp/`).
- `UnpinnedCertificates-MITM-Lean` and 15 other Benign APKs in `data/eval-tmp/`: `cleartext-http` (low), from the pre-API 28 default.

`surface.py` also lists `dynamic-receiver-no-permission`, `missing-certificate-validation`, `sql-no-parameterization`, `js-enabled-webview`, `hardcoded-key` and `weak-cipher` in its `CWE` table. No rule emits these names; the code rules report those weaknesses under their own pattern names below.

### 6.2 Code pattern findings (code_analyzer.py)

For these, `issue` and `pattern` hold the same name, `component_type` is `class` (or `application` for `certificate_pinning_missing`) and `evidence` is the smali line.

| Pattern | CWE | Confidence | Fires when | Ghera example |
|---------|-----|------------|------------|---------------|
| `ecb_mode` | CWE-327 | high | `Cipher.getInstance` with a constant transformation containing ECB, or bare `AES`, `DES` or `DESede` | `BlockCipher-ECB-InformationExposure-Lean`: `NewPasswordActivity` line 67 and `ResetPasswordActivity` line 66 (eval-tmp) |
| `constant_iv` | CWE-329 | high for a literal array or string; medium for a zero-filled array or a constant passed through a helper method | `IvParameterSpec` built from a constant | `BlockCipher-NonRandomIV-InformationExposure-Lean`: `Util.Encrypt` line 43, medium (eval-tmp) |
| `hardcoded_key` | CWE-321 | high or medium as above; medium for a `KeyGenerator` seeded by a constant `SecureRandom` | `SecretKeySpec` built from a constant | `ConstantKey-ForgeryAttack-Lean`: `NewPasswordActivity` line 85, high (eval-tmp) |
| `hardcoded_key_pbe` | CWE-760 | high or medium for a constant salt; low when only the password is constant | `PBEKeySpec` with a constant salt | `PBE-ConstantSalt-InformationExposure-Lean`: `Util.Encrypt` line 36, medium (eval-tmp) |
| `empty_trustmanager` | CWE-295 | high when `check*Trusted` is empty; medium when `checkServerTrusted` has code but no throw and no call to a `*check*` or `*verify*` method | Custom `X509TrustManager` | `CheckValidity-InformationExposure-Lean`: `MyTrustManager` (current run) |
| `hostname_not_verified` | CWE-297 | high when `verify` is only `const/4 vN, 0x1` and return; medium for another branch-free body returning true, or a read of `ALLOW_ALL_HOSTNAME_VERIFIER` | `HostnameVerifier.verify` that accepts every host | `CheckValidity-InformationExposure-Lean`: `MyIntentService$1` (current run) |
| `insecure_ssl_socket_factory` | CWE-295 | high for `SSLCertificateSocketFactory.getInsecure`; medium for `createSocket` or `getSocket` taking an `InetAddress` | No certificate or host name check | `InsecureSSLSocketFactory-MITM-Lean` (high) and `InsecureSSLSocket-MITM-Lean` (medium), both in `MyIntentService` (eval-tmp) |
| `certificate_pinning_missing` | CWE-295 | high | The app's own code makes network or TLS calls, the network security config has no `pin-set` with a `pin` (or there is no config and `usesCleartextTraffic` is not `"false"`), and the code does not pin with okhttp3 `CertificatePinner` or a `KeyStore` passed to `TrustManagerFactory.init` | `UnpinnedCertificates-MITM-Lean`: `no network security config, usesCleartextTraffic unset; network call invoke-static {v1}, Ljavax/net/ssl/SSLContext;->getInstance(...)` (current run) |
| `js_enabled` | CWE-749 | medium | `WebSettings.setJavaScriptEnabled(true)` | `JavaScriptExecution-CodeInjection-Lean`: `MainActivity` line 114 (eval-tmp) |
| `webview_file_access` | CWE-829 | high for `setAllowFileAccessFromFileURLs` or `setAllowUniversalAccessFromFileURLs(true)`; medium for `setAllowFileAccess(true)` | WebView file access enabled | `WebViewAllowFileAccess-UnauthorizedFileAccess-Lean`: `MainActivity`, high (current run) |
| `sql_injection_raw` | CWE-89 | high when the query is a concatenated string; medium when `append` or `concat` was called earlier in the method | `rawQuery`, `rawQueryWithFactory` or `execSQL` | `SQLite-execSQL-Lean`: `MiddleActivity` line 77 (eval-tmp) |
| `sql_injection_no_args` | CWE-89 | medium | `query`, `update` or `delete` (database or content resolver) with a selection that is not a constant containing `?`, and null selection arguments | `SQLlite-SQLInjection-Lean`: `MiddleActivity` line 366 (eval-tmp) |
| `directory_traversal` | CWE-22 | high when a name read from an intent reaches the call; medium when an intent getter was called earlier and the name is not constant | `File` or `FileOutputStream` constructor, or `openFileOutput` | `InternalStorage-DirectoryTraversal-Lean`: `MainActivity` line 157 (eval-tmp) |
| `clipboard_sensitive` | CWE-200 | medium | `ClipboardManager.setPrimaryClip` in a method that called `getPassword` or that reads an input field (up to two call levels) | `ClipboardUse-InformationExposure-Lean`: `MainActivity$1` line 71 (current run and eval-tmp) |
| `dynamic_code_load` | CWE-494 | high | `DexClassLoader`, `PathClassLoader` or `InMemoryDexClassLoader` created | `DynamicCodeLoading-CodeInjection-Lean`: `MainActivity$1`, `PathClassLoader.<init>` (current run) |
| `sticky_broadcast` | CWE-927 | high | `sendStickyBroadcast` or `sendStickyOrderedBroadcast` (and the `AsUser` forms) | `StickyBroadcast-DataInjection-Lean`: `MainActivity` (current run) |
| `implicit_broadcast` | CWE-927 | medium | `sendBroadcast`, `sendOrderedBroadcast` or `sendBroadcastAsUser` with no receiver permission and an Intent that names no target | `DynamicRegBroadcastReceiver-UnrestrictedAccess-Lean`: `MainActivity$1` (current run) |
| `pending_intent_empty` | CWE-927 | high | `PendingIntent.getActivity`, `getBroadcast`, `getService` or `getForegroundService` wrapping `new Intent()` or an Intent with no action and no target | `ImplicitPendingIntent-IntentHijack-Lean`: `MainActivity$1`, `PendingIntent.getService` (current run); `EmptyPendingIntent-PrivEscalation-Lean`: `MainActivity$1` line 64 (eval-tmp) |
| `pending_intent_implicit` | CWE-927 | medium | Same calls, wrapping an Intent built in the same method with no `setPackage`, `setClass`, `setClassName` or other target | Fires together with `pending_intent_empty` on the same class and CWE, so the merge keeps only the high `pending_intent_empty` in both PendingIntent benchmarks |
| `no_validity_check` | CWE-925 | medium | `onReceive` starts an activity or service, or binds a service, without comparing the intent action first | `NoValidityCheckOnBroadcastMsg-UnintendedInvocation-Lean`: `LowMemoryReceiver` line 46 (eval-tmp); `DynamicRegBroadcastReceiver-UnrestrictedAccess-Lean`: `EmailBroadcastRecv` (current run) |
| `ordered_broadcast_priority` | CWE-927 | medium | A receiver whose `onReceive` calls `setResult`, `setResultData`, `setResultExtras` or `abortBroadcast` and is declared with an intent filter priority above 0, or (any priority) calls one of them on itself | `OrderedBroadcast-DataInjection-Lean`: `FormatOutgoingCallReceiver` line 52 (eval-tmp) |
| `unique_ids` | CWE-359 | high | `TelephonyManager.getDeviceId`, `getImei`, `getMeid`, `getSimSerialNumber`, `getSubscriberId`, `Build.getSerial`, or `Settings.Secure.getString(..., "android_id")` | `UniqueIDs-IdentityLeak-Lean`: `MainActivity` line 45 (eval-tmp) |
| `fragment_injection` | CWE-470 | high when a `PreferenceActivity` subclass declares no `isValidFragment` (medium when targetSdkVersion is 19 or more); medium when `isValidFragment` always returns true; medium for `Fragment.instantiate` (or an app method that calls `Class.forName` or `Fragment.instantiate` and returns a Fragment) in a class that reads an intent extra and has no method whose name contains "valid" | Fragment class chosen by the caller | `FragmentInjection-PrivEscalation-Lean`: `MainActivity$1`, `invoke-static {v2}, Ledu/ksu/cs/benign/Util;->getFragmentInstance(...)` (current run) |
| `webview_js_interface` | CWE-749 | high | A method of an object passed to `addJavascriptInterface` does file access, network, database or intent sending, directly or one call level down. Only `@JavascriptInterface` methods count, unless minSdkVersion is below 17 | No Ghera example found in the five Web Benign APKs run with this rule for this guide |

`fragment_injection` and `webview_js_interface` were added to the working tree on 2026-11-02, after the evaluation runs, so they are not reflected in the scores in section 7.

### 6.3 Taint findings (taint_analyzer.py)

Every taint finding has `issue` `taint-flow` and a `pattern` `taint:<source>-><sink>`. The CWE depends on the sink:

| Sink label | Matched calls | CWE |
|------------|---------------|-----|
| `rawQuery` | `rawQuery`, `rawQueryWithFactory` | CWE-89 |
| `execSQL` | `execSQL` | CWE-89 |
| `openFileOutput` | `openFileOutput` | CWE-22 |
| `File.<init>` | `new File(...)` | CWE-22 |
| `sendBroadcast` | `sendBroadcast`, `sendBroadcastAsUser`, `sendOrderedBroadcast`, `sendStickyBroadcast` (with an Intent argument) | CWE-927 |
| `sendTextMessage` | `sendTextMessage`, `sendMultipartTextMessage` | CWE-200 |
| `startActivity` | `startActivity`, `startActivityForResult`, `startActivityIfNeeded` (with an Intent argument) | CWE-926 |
| `startService` | `startService`, `startForegroundService` (with an Intent argument) | CWE-926 |

Sources: Intent `getStringExtra`, `getIntExtra`, `getByteArrayExtra`, `getAction`, `getData`; Bundle `getString`; `get*` on a cursor returned by `ContentResolver.query`; `getText` on an `EditText` or `TextView`. Flows into a receiving component use sources labelled `icc:<getter>`, and their evidence starts with `icc <Sender>.<method> L<n> (<sink>) -> <Receiver> | `.

Confidence: high when source and sink are in one method, medium through one call level, low through two or more. A flow that crosses a component boundary drops one more step. A null check (`if-eqz` or `if-nez`) or an `equals` on the tainted value stops the flow, and a sink inside a try block is not reported.

Evidence reads `source L<n>: <smali line> | sink L<m>: <smali line>`.

Examples:

- `UnprotectedBroadcastRecv-PrivEscalation-Lean`: `taint:getStringExtra->sendTextMessage` (CWE-200, high) in `MyReceiver`, and `taint:getText->sendBroadcast` (CWE-927, high) in `MainActivity$1` (quick start above).
- `DynamicRegBroadcastReceiver-UnrestrictedAccess-Lean`: `taint-flow` (CWE-926, high) in `EmailBroadcastRecv`, `source L34: ... getStringExtra ... | sink L58: ... startActivity ...` (current run).
- `HighPriority-ActivityHijack-Lean` and `TaskAffinity-ActivityHijack-Lean`: `taint:getText->startActivity` (CWE-926, high) in `HomeActivity$1` and `HomeActivity$2` (eval-tmp). These match CWE-926 rather than the benchmarks' main weakness.

### 6.4 Dynamic findings (dynamic_analyzer.py)

Produced only with `--dynamic` or `--dynamic-two-app`.

| Issue | CWE | Confidence | Fires when |
|-------|-----|------------|------------|
| `dynamic-receiver-accepts-external` | CWE-926 when the receiver has no permission, else CWE-925 | high when the broadcast had a visible effect (new activity, non-zero result code, new logcat lines from the app, removed files); medium otherwise | A receiver ran a broadcast sent by the shell user with no Permission Denial. |
| `dynamic-file-created` | CWE-922 | high when tied to one broadcast or to the malicious app in a two-app run; medium for a file that appeared at some point during the run | A new file in `files/` (or, in two-app mode, in the benign app's internal storage). |
| `dynamic-file-deleted` | CWE-922 | high when tied to one broadcast or to the malicious app; medium when only seen between the start and end of the run | A file disappeared. |
| `dynamic-task-hijack` | CWE-1021 | high when an activity of another package sits in the same task as the app's activities, or a malicious activity tops a benign task; medium when a task of another package holds the app's affinity | Task stack from `dumpsys activity activities`. |
| `dynamic-foreground-foreign-activity` | CWE-1021 | high | An activity of another package appeared in the app's foreground task after a broadcast or after the malicious app started. |
| `dynamic-receiver-crash` | CWE-248 | high with FATAL EXCEPTION lines; medium when only the process id changed or the process died | The app crashed after a broadcast (`--dynamic` only). |
| `dynamic-permission-denial-observed` | `n/a` | high | logcat shows a Permission Denial naming the package. The platform blocked the call, so this is evidence that a protection works, not a weakness. |

Examples from the dynamic evaluation run (`data/eval-tmp/`, 2026-11-01, `ghera27` emulator):

- `NoValidityCheckOnBroadcastMsg-UnintendedInvocation-Lean` Benign: `dynamic-receiver-accepts-external` (CWE-926, high) on `LowMemoryReceiver`, evidence `Broadcast completed: result=0; started edu.ksu.cs.benign/.DeleteStatusActivity; ...; removed files/myfile`, and `dynamic-file-deleted` (CWE-922, high) `files/myfile disappeared after the broadcast`.
- `UnprotectedBroadcastRecv-PrivEscalation-Lean` Benign: `dynamic-receiver-accepts-external` (CWE-926, medium) on `MyReceiver`, evidence `Broadcast completed: result=0`.
- `UnprotectedBroadcastRecv-PrivEscalation-Lean` Secure: `dynamic-permission-denial-observed` on `MyReceiver`, evidence `... Permission Denial: broadcasting Intent { flg=0x400010 cmp=edu.ksu.cs.benign/.MyReceiver } from null (pid=9951, uid=2000) requires edu.ksu.cs.secure.permission1 ...`.
- `JavaScriptExecution-CodeInjection-Lean` Benign: `dynamic-receiver-accepts-external` (CWE-926, high) on `edu.ksu.cs.benign (registered for edu.ksu.cs.benign.GPU_PROFILER_START)`, a receiver registered at run time.

Over all 53 benchmarks the dynamic layer reported 47 `dynamic-receiver-accepts-external`, 7 `dynamic-task-hijack`, 1 `dynamic-file-deleted` and 1 `dynamic-permission-denial-observed`; none changed a score (see the evaluation report).

### 6.5 Privacy findings (privacy_checker.py)

Produced only with `--policy`. They have no CWE; `severity` replaces confidence. Each finding is a contradiction between a negative claim in a policy sentence and what the APK declares, not proof that data is collected or sent.

| Rule | Claim it looks for | Evidence and severity |
|------|--------------------|-----------------------|
| `location-not-collected` | A negation followed within a few words by a verb such as collect, access, track, store or use, then location, GPS or whereabouts | `ACCESS_FINE_LOCATION` or `ACCESS_BACKGROUND_LOCATION`: high; `ACCESS_COARSE_LOCATION`: medium |
| `contacts-not-collected` | Same pattern with contact or contacts | `READ_CONTACTS`: high; `GET_ACCOUNTS`: low |
| `camera-not-collected` | Same pattern with camera or photos | `CAMERA`: medium |
| `microphone-not-collected` | Same pattern with microphone, audio or voice | `RECORD_AUDIO`: high |
| `sms-not-collected` | Same pattern with SMS or text messages | `READ_SMS`, `RECEIVE_SMS`: high |
| `call-log-not-collected` | Same pattern with call log or phone calls | `READ_CALL_LOG`: high |
| `data-stays-on-device` | "stays on your device", "never leaves the device", "not sent to our servers", "no network access" and similar | `INTERNET` requested: medium; high when an advertising or analytics SDK package is also present |
| `no-third-party-sharing` | "we do not share/sell/disclose ... third parties", "no ads", "no tracking", "no analytics" and similar | Advertising SDK package (for example `com.google.android.gms.ads`, `com.facebook.ads`, `com.mopub`): high; analytics SDK package (for example `com.google.firebase.analytics`, `com.flurry`, `io.sentry`): medium |

Example: the `data-stays-on-device` (medium) finding on `CheckValidity-InformationExposure-Lean` shown under `--policy` above. The Ghera APKs contain none of the listed SDK packages, so `no-third-party-sharing` cannot be shown on them.

## 7. Known limitations

### Evaluation results

`python tools/evaluate.py --no-dynamic` on 2026-11-01 scored 53 benchmarks (those with a successful `api27` build in `data/build-results.csv`): 37 true positives, 35 false positives, precision 0.51, recall 0.70. The dynamic run gave the same scores. Definitions, from the evaluation report:

- **True positive**: the Benign APK has a finding whose CWE matches one of the benchmark's ground-truth CWEs, directly or through the one-step secondary mapping in `tools/evaluate.py` (`SECONDARY_CWE`).
- **False positive**: the Secure APK has any finding at all, of any kind and any CWE. Many Secure apps still export components or keep code that the rules report, so precision stays near 0.5 even where the actual weakness is fixed. A false positive under this definition does not mean the Secure app's fix was flagged.

### The 16 benchmarks with no true positive

From [docs/notes/evaluation-report.md](notes/evaluation-report.md):

| Category | Benchmark | Why it is missed |
|----------|-----------|------------------|
| ICC | `FragmentInjection-PrivEscalation-Lean` | The 2026-11-01 reports contain no fragment injection finding. The current code reports `fragment_injection` (CWE-470) on this Benign APK (see 6.2), which matches its ground-truth CWE-470. Not re-scored for this guide. |
| ICC | `HighPriority-ActivityHijack-Lean` | No rule for intent filter priority on activities. The Benign app does get a `taint:getText->startActivity` (CWE-926) finding, which does not match its ground truth. |
| ICC | `TaskAffinity-LauncherActivity-PhishingAttack-Lean` | The weakness is the default task affinity, which no rule covers. |
| ICC | `TaskAffinityAndReparenting-PhishingAndDoSAttack-Lean` | Same: default task affinity. |
| ICC | `UnhandledException-DOS-Lean` | No uncaught exception rule; the dynamic run and the README replay showed no crash on API 27. |
| ICC | `WeakChecksOnDynamicInvocation-DataInjection-Lean` | Has no ground-truth CWE, so it can never score. |
| Crypto | `ExposedCredentials-InformationExposure-Lean` | No keystore rule. |
| Networking | `OpenSocket-InformationLeak-Lean` | No open server socket rule. |
| Networking | `UnpinnedCertificates-MITM-Lean` | The 2026-11-01 reports in `data/eval-tmp/` contain no pinning finding. The current code reports `certificate_pinning_missing` (CWE-295) on this Benign APK (see 6.2), which matches its ground truth, so the scores appear to predate that rule. Not re-scored for this guide. |
| Permission | `WeakPermission-UnauthorizedAccess-Lean` | No weak permission rule. |
| Storage | `ExternalStorage-DataInjection-Lean` | No external storage rule. |
| Storage | `ExternalStorage-InformationLeak-Lean` | No external storage rule. |
| System | `ClipboardUse-InformationExposure-Lean` | `clipboard_sensitive` fires, but under CWE-200, while the ground truth lists CWE-359. |
| Web | `WebViewAllowFileAccess-UnauthorizedFileAccess-Lean` | `webview_file_access` fires under CWE-829 (mapped to CWE-749), while the ground truth lists CWE-830. |
| Web | `WebViewIgnoreSSLWarning-MITM-Lean` | No rule for WebView SSL error handlers. |
| Web | `WebViewOverrideUrl-MITM-Lean` | No rule for `shouldOverrideUrlLoading`. |

`DynamicRegBroadcastReceiver-UnrestrictedAccess-Lean` is not among the 53 scored benchmarks: `data/build-results.csv` records its `api27` build as a failure, although an `api27` debug APK is present in its build folder and the tool runs on it (section 6.2).

### Other limits

- **Heuristic register model.** `code_analyzer.py` and `taint_analyzer.py` read each method top to bottom and do not follow branches. A value set on one branch and used on another may be missed or misreported.
- **Library code is skipped.** Classes under `android/`, `androidx/`, `kotlin/` and `com/google/` are not analyzed, so weaknesses in bundled libraries (for example `OutdatedLibrary-DirectoryTraversal-Lean`) are seen only when the app's own code shows them.
- **Taint depth.** Calls are followed up to 3 levels (`MAX_DEPTH`), subclass overrides up to 2 levels (`MAX_HIERARCHY`), and component boundaries up to 2 (`MAX_ICC`). Reflection, native code, threads and callbacks registered with the framework are not modelled.
- **Taint sanitizers are coarse.** Any null check or `equals` on a tainted value stops the flow, even when it does not sanitize anything; any sink inside a try block is dropped. Both cause misses.
- **Merge hides findings.** Only one finding per (component name, CWE) survives. For example `pending_intent_implicit` never appears next to `pending_intent_empty` on the same class.
- **CWE choices can differ from the ground truth.** Some rules fire under a nearby CWE (CWE-200 for the clipboard, CWE-829 for WebView file access), which the scoring counts as a miss.
- **Pinning detection.** Only the network security config and two code idioms (okhttp3 `CertificatePinner`, a `KeyStore` passed to `TrustManagerFactory.init`) count as pinning. A config with a pin for one domain counts as pinned for all hosts.
- **Dynamic analysis needs a device and a debuggable APK.** Without adb or a device the step is skipped. File diffs use `run-as`, so release builds give no file findings. Receivers are probed from the shell user, not from a third-party app, so a receiver protected by a permission the shell holds may look open. Task findings read the whole task stack, so a system activity in the app's task can be reported: in `data/eval-tmp/`, `UnprotectedBroadcastRecv-PrivEscalation-Lean` Benign has a `dynamic-task-hijack` whose foreign activity is the system `GrantPermissionsActivity`.
- **Privacy rules are keyword based.** They match negative sentences with regular expressions and compare them with declared permissions and SDK package folders. They do not check whether a permission is used or an SDK is active, they miss claims worded differently, and they can match sentences that only look negative. A finding is a contradiction to review, not proof.
- **Manifest edge cases.** The default export rule is applied from `targetSdkVersion` (providers exported by default below 17; other components when they have an intent filter). Manifest merging, `android:enabled="false"` and run-time permission checks in code are not considered.

## 8. Contributing detection rules

### Where rules live

| Kind of rule | File | How to add one |
|--------------|------|----------------|
| Manifest | [`src/surface.py`](../src/surface.py) | Add the issue name and its CWE to the `CWE` dict. Write a function that takes a component dict (from `apk.parse_manifest`) and returns a confidence or `None` (or `(confidence, evidence)`), and call it in `_manifest_findings`. App-wide rules take the whole manifest dict, like `_cleartext`. If the rule needs a manifest attribute that is not parsed yet, add it in `parse_manifest` in [`src/apk.py`](../src/apk.py). |
| Code pattern | [`src/code_analyzer.py`](../src/code_analyzer.py) | Add the pattern name and its CWE to `PATTERNS` and to the Patterns list in the module docstring. For a check on one call, add it to the handler that fits (`crypto`, `tls`, `webview`, `sql`, `files`, `icc`, `misc`); `_Method.invoke` calls them all for every `invoke-*` line, with the owner class, method name, descriptor and the register values. Report with `self.report(pattern, confidence, no, text)`. Whole-class checks go in `_class_rules` and use `ctx.emit`; app-wide checks use `_emit_app`, like `_pinning_rules`. |
| Taint | [`src/taint_analyzer.py`](../src/taint_analyzer.py) | New sink: add a label and CWE to `SINKS` and the method names to `_SINK_NAMES` (`_sink` handles the special cases). New source: extend `_INTENT_SOURCES` or `_source`. New propagating call: add `(class descriptor, method)` to `_PASS`. |
| Dynamic | [`src/dynamic_analyzer.py`](../src/dynamic_analyzer.py) | Add the issue and CWE to `ISSUES` and build findings with `_finding(component, component_type, issue, confidence, evidence)`. |
| Privacy | [`src/privacy_checker.py`](../src/privacy_checker.py) | Add a data kind to `DATA_KINDS`, an SDK prefix to `AD_PACKAGES` or `ANALYTICS_PACKAGES`, or a new regular expression in `check`. |

Use only CWE IDs listed in [docs/threat-models/standards-reference.md](threat-models/standards-reference.md). If the best CWE is DISCOURAGED there, follow the `provider-path-permission-only` example: keep it as a candidate and add a `note` key.

### Finding shape

A code finding, as `code_analyzer` emits it:

```json
{
  "component": "edu.ksu.cs.benign.MyTrustManager",
  "component_type": "class",
  "file": "smali/edu/ksu/cs/benign/MyTrustManager.smali",
  "line": 21,
  "pattern": "empty_trustmanager",
  "issue": "empty_trustmanager",
  "cwe": "CWE-295",
  "confidence": "high",
  "evidence": ".method public checkClientTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V"
}
```

A manifest finding has only `component`, `component_type`, `issue`, `cwe` and `confidence`, plus optional `evidence` and `note`. `report.py` prints whatever the six table keys hold, so a new rule needs no change there. Keep `component` equal to the class name the other layers use, so that the merge in `surface.merge` can combine findings for the same class.

### Add a test

Tests live in [`tests/`](../tests/) and run with pytest. Most build a small synthetic input in pytest's `tmp_path` instead of decoding a real APK; for example `tests/test_fix_b.py` writes smali files and an `AndroidManifest.xml` and calls `code_analyzer.analyze(tmp_path)`. Cover at least one case where the rule fires (with the expected `cwe` and `confidence`) and one where it must not (the Secure variant of the code).

```powershell
.venv\Scripts\python -m pytest tests
```

### Re-run the evaluation and the docs lint

```powershell
python tools\evaluate.py --no-dynamic
python tools\lint_docs.py
```

`tools/evaluate.py --no-dynamic` runs `ate.py` on the Benign and Secure APK of every benchmark with a successful `api27` build and rewrites `data/evaluation-results.csv`. To try a rule on a few benchmarks without overwriting that file, use `--only BENCH` (repeatable) together with `--out other.csv`. Compare the TP and FP counts with the tables in [docs/notes/evaluation-report.md](notes/evaluation-report.md); a rule that also fires on the Secure APK adds a false positive only if that Secure APK had no finding before.

`tools/lint_docs.py` checks the Markdown under `docs/threat-models/` and `docs/notes/` for unknown IDs, wrong titles, missing model sections, em dashes and banned words, broken relative links and invalid Mermaid blocks. Run it after updating any note that describes the new rule; it must report 0 blocking findings.
