# Drift harness design

Design for running every Ghera benchmark (tag `Jan2019`, commit `6289f39d`) on several Android versions and recording the results. This is a plan only. No emulator has been created and no test has been run for it. The only AVD that exists is `ghera27` (see `docs/notes/SETUP_LOG.md`).

## Goal

Ghera's READMEs say the benchmarks were tested on Android 4.4 to 8.1 (API 19 to 27). The harness answers one question per benchmark and API level: does the exploit still work against Benign, and does the Secure fix still block it?

## Two axes

Each run is described by two numbers, and they are kept apart on purpose.

| Axis | What it is | Where it comes from | Column in `data/drift-matrix.csv` |
|------|------------|---------------------|-----------------------------------|
| Device API level | The Android version the emulator runs | The AVD `ghera<API>` | `api_level` |
| Rebuilt target SDK | The `targetSdkVersion` in the installed APK | The build flavor (`api22` to `api27`, `apiDIST`) or a rebuild with a newer SDK | `target_sdk` |

Many platform changes apply only to apps that target a new SDK (for example the API 26 limits on implicit broadcasts, the API 31 rule that components with intent filters must set `android:exported`, and the API 31 rule that pending intents must set a mutability flag). Others apply to every app on a new device (for example the API 29 and 30 limits on background activity starts). Running the same APK on newer devices measures the second kind. Rebuilding with a newer target SDK and running again measures the first kind. A result change between two rows with the same `api_level` and different `target_sdk` comes from the target SDK; a change between rows with the same `target_sdk` and different `api_level` comes from the device.

### Phase 1: device axis only

Build once with the highest flavor Ghera provides (`api27`, target SDK 27) and run that APK on every device level. On API 22 and 25, use the matching flavor (`api22`, `api25`) instead, because those flavors also set `minSdkVersion` to the same level and the `api27` APK will not install on an older device. Record the APK's real target SDK with `aapt dump badging <apk>` in the `target_sdk` column; do not copy it from the flavor name.

### Phase 2: target SDK axis

For benchmarks whose result changes in phase 1, and for benchmarks whose model names a target-SDK-gated behavior, rebuild with a raised `targetSdkVersion` (28, 30, 33, 34) and run on each device level at or above that target. This needs a newer Android Gradle plugin, newer build tools and newer platforms than the benchmarks use (see Risks). The rebuild changes must be made in a copy outside `benchmarks/`, for example `build/drift/<Benchmark>/`, so that the Ghera checkout stays untouched.

## API levels and images

| API level | Android version | Image | Installed now | AVD |
|----------:|-----------------|-------|---------------|-----|
| 22 | 5.1 | `system-images;android-22;google_apis;x86` | No | `ghera22` |
| 25 | 7.1.1 | `system-images;android-25;google_apis;x86` | No | `ghera25` |
| 27 | 8.1 | `system-images;android-27;google_apis;x86` | Yes | `ghera27` (exists) |
| 28 | 9 | `system-images;android-28;google_apis;x86` | No | `ghera28` |
| 30 | 11 | `system-images;android-30;google_apis;x86` | No | `ghera30` |
| 33 | 13 | `system-images;android-33;google_apis;x86` | No | `ghera33` |
| 34 | 14 | `system-images;android-34;google_apis;x86` | No | `ghera34` |

Status is from `docs/notes/sdk-images.md`. Install an image with JDK 17 and the quoting from `SETUP_LOG.md`, then run `tools/create_avds.ps1`, which skips any level whose image is missing. Before installing the API 30, 33 and 34 images, check with `sdkmanager --list` that a `google_apis;x86` (32-bit) image is still offered at that level; if only `x86_64` is offered, use it and note the ABI in the run notes. Ghera's Gradle setup builds no native code, so the ABI should not change the results.

The levels cover: the oldest level the flavors support (22), the last level inside most README ranges (25 for READMEs that stop at Android 7.1, 27 for those that stop at 8.1), and four levels after Ghera (28, 30, 33, 34), each of which added ICC, storage, network or WebView restrictions.

### Benchmarks that need special images

| Benchmark | Why | Image needed |
|-----------|-----|--------------|
| `ICC/TaskAffinity-LauncherActivity-PhishingAttack-Lean` | The README range is Android 5.1.1 to 7.1, so API 25 is the last level where the README itself states the expected result. On API 27 only the Testing code states it (`@SdkSuppress(minSdkVersion = 22, maxSdkVersion = 27)`; see the threat model, Evidence section). | API 25 (`ghera25`). Not installed yet; install it before running this benchmark. |
| `ICC/UnprotectedBroadcastRecv-PrivEscalation-Fat` | README says "Tested on Android 4.4" (API 19). The Malicious app sets `targetSdkVersion 19` and `minSdkVersion 17`, does not use `Misc/sdkFlavors.gradle`, uses build tools 26.0.0, and the benchmark has no Testing folder; the other part is a prebuilt `Mms.apk`. | API 19 (`system-images;android-19;google_apis;x86`, AVD `ghera19`), outside the seven standard levels. Run by hand only; record it with `api_level` 19 in extra rows. |

## Running the Testing folders

Every benchmark except the Fat one has a `Testing/` Gradle project with two modules, `benign_app` and `secure_app`. Each holds one `Tests.java` under `src/androidTest/` written with UI Automator 2 (`uiautomator-v18:2.1.3`) and the support test runner (`android.support.test.runner.AndroidJUnitRunner`). Both modules use the `applicationId` `edu.ksu.cs.benign`, so the test APK is `edu.ksu.cs.benign.test` and it instruments the installed Benign or Secure app. Each module applies `Misc/sdkFlavors.gradle`, so it builds one test APK per flavor.

Ghera's own driver, `Misc/functional-test.ps1`, shows the intended order. The harness follows it, with three changes: AVDs are named `ghera<API>`, the API list is the one above, and results go to the drift matrix instead of loose log files.

Per benchmark and API level:

1. Build (once per benchmark and flavor, not per run): `gradlew.bat assembleDebug` in Benign, BenignPartner (if present), Malicious and Secure, and `gradlew.bat assembleAndroidTest` in `Testing`, with JDK 8. `tools/build_all.ps1 -IncludeTesting` already does the build step; for phase 2 the same commands run in the copy under `build/drift/`.
2. Boot: `emulator -avd ghera<API> -port 5554 -wipe-data -no-snapshot -no-boot-anim -no-window`, then wait until `adb shell getprop sys.boot_completed` returns `1`.
3. If the benchmark has a `source-script.ps1` (20 of them do, mostly Networking and Web, which start the LocalServer or a socket server), dot-source it and call its hook functions at the same points as `functional-test.ps1` (`before_install_vuln`, `before_test_vuln` and so on).
4. Benign pair: install Benign, BenignPartner and Malicious for the flavor, install `Testing/benign_app/build/outputs/apk/androidTest/<flavor>/debug/benign_app-<flavor>-debug-androidTest.apk` with `-t`, then run `adb shell am instrument -w -r edu.ksu.cs.benign.test/android.support.test.runner.AndroidJUnitRunner`. `-r` gives raw output with one status block per test, which is easier to parse than the default summary.
5. Uninstall `edu.ksu.cs.benign`, `edu.ksu.cs.benignpartner`, `edu.ksu.cs.malicious` and `edu.ksu.cs.benign.test`.
6. Secure pair: same as step 4 with the Secure APK and `secure_app` test APK. Secure uses the package name `edu.ksu.cs.benign`, so step 5 must run first.
7. Save the instrumentation output and `adb logcat -d -v time` to `results/drift/<Benchmark>/api<API>/` (`benign.txt`, `secure.txt`, `logcat.txt`), take a screenshot with `adb exec-out screencap -p`, and shut the emulator down (`adb emu kill`).

Booting once per API level and looping over all benchmarks inside it (as `functional-test.ps1` does) saves most of the boot time. Wiping data between benchmarks is then done by uninstalling, not by `-wipe-data`; for benchmarks that write to shared storage, also clear `/sdcard` the way each `source-script.ps1` `clean_data` does.

### Tests that will not run as written

- Each test class has `@SdkSuppress(minSdkVersion = 22, maxSdkVersion = 27)` or a similar range. On API 28, 30, 33 and 34 the runner skips the class and reports 0 tests, which is not a pass. The harness must treat "0 tests run" as `inconclusive`, and to get a real result on those levels it needs a copy of the Testing project (under `build/drift/`) with the `maxSdkVersion` raised. `UnhandledException-DOS-Lean` Secure stops at 25 (see `docs/notes/benchmark-issues.md`).
- Several tests pass for reasons other than the vulnerability, or cannot fail (listed in `docs/notes/benchmark-issues.md`, for example `MergeManifest-UnintendedBehavior-Lean` Secure is `assert true;`, `BlockCipher-ECB-InformationExposure-Lean` Secure looks for an ID in the wrong package). For these, a test pass is recorded together with a note, and the result comes from the manual steps in `tools/drift_run_template.md` instead.
- The Fat benchmark has no tests; it is run by hand with the template.

## Results in `data/drift-matrix.csv`

The file has one row per benchmark and API level: 57 benchmarks times 7 levels, 399 rows. Columns:

| Column | Filled from |
|--------|-------------|
| `benchmark`, `category`, `lean_or_fat`, `api_level` | Already filled. |
| `target_sdk` | `aapt dump badging` on the installed Benign APK. |
| `exploit_result` | Benign pair: `exploited` when the Benign test passes (or the manual steps show the README result), `blocked` when it fails with a clear cause, `inconclusive` for 0 tests run, build or install failure, or a crash before the exploit step. |
| `blocked_result` | Secure pair: same values. The expected value is `blocked`. |
| `notes` | Test counts and failure messages from the `-r` output, the cause of a `blocked` or `inconclusive` result, and any issue from `benchmark-issues.md` that affects the reading. |
| `screenshot` | Path under `docs/screenshots/`, named `<Benchmark>-api<API>-<pair>.png`. |
| `date_run` | `YYYY-MM-DD`. |

Rules:
- A phase 2 run is a new row with the same `benchmark` and `api_level` and a different `target_sdk`; phase 1 rows are never overwritten. The pair (`benchmark`, `api_level`, `target_sdk`) is the key.
- API 19 rows for the Fat benchmark are added the same way.
- The raw files under `results/drift/` are the evidence. A CSV value that is not backed by a raw file is not entered.
- A small parser can turn `INSTRUMENTATION_STATUS_CODE` lines into the result values; it should be written and checked by hand against a few runs before it fills the CSV.

## Risks

| Risk | Effect | Mitigation |
|------|--------|------------|
| Old build tools with new SDKs | The benchmarks use Gradle 4.4, Android Gradle plugin 3.1.2, build tools 27.0.3 and the `android.support` test libraries, which need JDK 8. Raising `targetSdkVersion` past 28 needs a newer `compileSdkVersion`; AGP 3.1.2 does not support compile SDK 31 and later (and its D8 and AAPT2 are older than those platforms), and the API 31 `exported` and pending intent mutability rules will make some builds fail. Moving to AGP 7 or 8 also means JDK 11 or 17, AndroidX test libraries and changed Gradle syntax (`jcenter()` is read-only). | Do phase 1 with the stock toolchain. For phase 2, port one benchmark first and record every change; keep the ported copies outside `benchmarks/`; record a build failure as `inconclusive` with the error, because a benchmark that no longer builds is itself a drift result. |
| Disk use | The API 27 image takes 3.2 GB and the `ghera27` AVD 3.3 GB after use. Seven images are an estimated 15 to 25 GB (newer images are larger), plus a few GB per AVD, plus build outputs for 7 flavors in 216 Gradle projects (Testing included). The C: drive has about 300 GB free now. | Install images one level at a time; delete `build/` folders after each benchmark's APKs are copied out; use `-wipe-data` instead of keeping snapshots. |
| Emulator boot time | A cold boot takes about 1 to 3 minutes on WHPX; newer images take longer. 57 benchmarks times 7 levels at one boot each would be many hours of boot alone. | Boot once per API level and loop over benchmarks inside it; run headless (`-no-window`, `-no-boot-anim`); wait on `sys.boot_completed` instead of fixed sleeps. |
| `@SdkSuppress` ranges | Tests are skipped above API 27 and reported as 0 tests. | Treat 0 tests as `inconclusive`; raise the range only in a copy. |
| Weak or broken tests | Some tests pass either way (see above). | Note them in `notes`; confirm by hand. |
| Shared state between benchmarks | Many apps use the same package names and write to `/sdcard`. | Uninstall every package after each pair; clear shared storage; reboot if `$strict` is set as in `functional-test.ps1`. |
| LocalServer dependencies | Networking and Web benchmarks need the Flask LocalServer or `WriteToSocket`; its certificates expired in 2018 and 2019. | Start servers through each `source-script.ps1`; record certificate errors in `notes`; consider setting the emulator clock only as a separate, labelled run. |
| x86 image availability | Newer levels may offer only `x86_64` Google APIs images. | Check before installing; record the ABI. |
| Test runner on new devices | The support test runner 1.0.2 and UI Automator 2.1.3 are old and may behave differently on API 33 and 34 (for example notification permission prompts on 33). | Watch the first runs on each new level; record runner errors as `inconclusive`. |

## Out of scope for this note

Creating emulators, installing images, running tests, and changing anything under `benchmarks/`.
