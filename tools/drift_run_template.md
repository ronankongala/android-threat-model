# Drift run: one benchmark on one API level

Copy this file once per run, for example to `docs/drift-runs/<Benchmark>-api<API>.md`, fill in every row, and copy the result into `data/drift-matrix.csv`.

## Run details

| Field | Value |
|-------|-------|
| Benchmark name | `<Benchmark folder name>` |
| API level | `<22, 25, 27, 28, 30, 33 or 34>` (AVD `ghera<API>`) |
| Target SDK of the built APK | `<value>` (check with `aapt dump badging <apk> \| findstr targetSdkVersion`) |
| Build flavor | `<api22 to api27 or apiDIST>` |
| Date run | `<YYYY-MM-DD>` |

## Checklist

- [ ] Environment set: `. .\env.ps1` from the project root
- [ ] Emulator started: `emulator -avd ghera<API> -no-snapshot-load`
- [ ] Device ready: `adb wait-for-device` then `adb shell getprop ro.build.version.sdk` shows `<API>`
- [ ] Old copies removed: `adb uninstall edu.ksu.cs.benign` and `adb uninstall edu.ksu.cs.malicious`
- [ ] Logcat cleared: `adb logcat -c`

## Install commands

Pair 1: Benign + Malicious

```powershell
adb install -r -t benchmarks\ghera\<Category>\<Benchmark>\Benign\app\build\outputs\apk\<flavor>\debug\app-<flavor>-debug.apk
adb install -r -t benchmarks\ghera\<Category>\<Benchmark>\Malicious\app\build\outputs\apk\<flavor>\debug\app-<flavor>-debug.apk
```

Pair 2: Secure + Malicious (uninstall Benign first if Secure shares its package name)

```powershell
adb uninstall edu.ksu.cs.benign
adb install -r -t benchmarks\ghera\<Category>\<Benchmark>\Secure\app\build\outputs\apk\<flavor>\debug\app-<flavor>-debug.apk
```

## Steps to run by hand

Copy the steps from the benchmark README or the threat model Evidence section.

1. `<step>`
2. `<step>`
3. `<step>`

## Logcat command

```powershell
adb logcat -v time > docs\drift-logs\<Benchmark>-api<API>.log
```

Filter while running, for example: `adb logcat -v time | findstr /i "benign malicious AndroidRuntime"`

## Result

| Field | Value |
|-------|-------|
| Result, Benign + Malicious | `<exploited, blocked or inconclusive>` |
| Result, Secure + Malicious | `<exploited, blocked or inconclusive>` |
| Screenshot file name | `docs/screenshots/<Benchmark>-api<API>-<pair>.png` (take with `adb exec-out screencap -p > <file>`) |
| Notes | `<what was seen, error messages, differences from the README>` |

Result values:
- **exploited**: the expected exploit result from the README or Testing code was observed.
- **blocked**: the exploit ran and the expected result did not appear, with a clear cause (for example a SecurityException, the platform refusing the install, or the Secure fix).
- **inconclusive**: the run could not complete or the outcome is unclear (build or install failure, crash before the exploit step, missing dependency).
