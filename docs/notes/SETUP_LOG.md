# Setup Log

Record of every tool installed or configured for android-threat-engine.

Host: Windows 11 Home 10.0.26200, x86_64 (AMD64), WSL2 available (Ubuntu-24.04)

| Date | Tool | Version | Command used | Problem and fix |
|------|------|---------|--------------|-----------------|
| 2026-10-31 | git | 2.55.0.windows.1 | `git init` | None |
| 2026-10-31 | Eclipse Temurin JDK 8 | 8u504-b01 (1.8.0_504) | Zip `OpenJDK8U-jdk_x64_windows_hotspot_8u504b01.zip` from the Adoptium API (`api.adoptium.net/v3`), SHA-256 verified, unpacked to `C:\Android\jdk8` | Planned winget install was not possible: winget (App Installer) is not installed, and the Temurin MSI needs admin rights. Fix: used the portable zip build, no installer and no admin. |
| 2026-10-31 | Eclipse Temurin JDK 17 | 17.0.20.1+1 | Zip `OpenJDK17U-jdk_x64_windows_hotspot_17.0.20.1_1.zip` from the Adoptium API, SHA-256 verified, unpacked to `C:\Android\jdk17` | No JDK was present on the machine (no `java` on PATH, no `JAVA_HOME`). Current cmdline-tools need Java 17+ and will not run on JDK 8. Fix: added JDK 17 only for running SDK tools; JDK 8 stays the project `JAVA_HOME`. |
| 2026-10-31 | Android SDK Command-line Tools | 23.0 | `commandlinetools-win-16111833_latest.zip` from `dl.google.com`, SHA-1 verified against `repository2-3.xml`, unpacked to `C:\Android\Sdk\cmdline-tools\latest` | In 23.0, `sdkmanager` is a deprecated wrapper around the new `android` CLI (`android sdk ...`). `sdkmanager --licenses` reports it is no longer needed; `licenses\android-sdk-license` is written on install. |
| 2026-10-31 | Android SDK Platform-Tools | 37.0.1 (adb 1.0.41) | `sdkmanager --sdk_root=C:\Android\Sdk platform-tools` (JAVA_HOME=JDK 17 for the command only) | None |
| 2026-10-31 | Android Emulator | 37.2.13 | `sdkmanager --sdk_root=C:\Android\Sdk emulator` | None. `emulator -accel-check`: WHPX installed and usable, no admin change needed. |
| 2026-10-31 | Android SDK Platform 27 | `platforms;android-27` rev 3 | `sdkmanager --% --sdk_root=C:\Android\Sdk "platforms;android-27"` | First attempt reported "Package platforms not found" / "Package android-27 not found" with exit code 0. Cause: `sdkmanager.bat` runs through cmd.exe, which splits unquoted arguments on `;`, and PowerShell drops the quotes. Fix: pass arguments verbatim with `--%` so the quotes reach cmd.exe (or call `android.exe sdk install platforms/android-27`). Always check `--list_installed` afterwards. |
| 2026-10-31 | Android SDK Build-Tools | 27.0.3 | `sdkmanager --% --sdk_root=C:\Android\Sdk "build-tools;27.0.3"` | Same `;` splitting issue and fix as above. |
| 2026-10-31 | System image Google APIs x86, API 27 | `system-images;android-27;google_apis;x86` rev 11 | `sdkmanager --% --sdk_root=C:\Android\Sdk "system-images;android-27;google_apis;x86"` | Same `;` splitting issue and fix as above. |
| 2026-10-31 | env.ps1 | n/a | `. .\env.ps1` from the project root | Sets JAVA_HOME (JDK 8), ANDROID_HOME, ANDROID_SDK_ROOT and prepends JDK 8 bin, cmdline-tools, platform-tools and emulator to PATH for the current session only. User and machine variables are unchanged. |
| 2026-10-31 | Ghera benchmark repository | Tag `Jan2019`, commit `6289f39d` | `git clone` of the Ghera repository, checked out at tag `Jan2019` | None. Clone size about 185 MiB. |
| 2026-10-31 | Android Virtual Device `ghera27` | Pixel, Android 8.1 (API 27), `system-images;android-27;google_apis;x86` | `avdmanager create avd` (JAVA_HOME=JDK 17 for the command only) | None. WHPX acceleration confirmed usable. |
| 2026-10-31 | Benchmark Gradle wrapper | 4.4 | Benchmark builds run with JAVA_HOME=JDK 8 | None |

## Problems and fixes

| Problem | Fix |
|---------|-----|
| winget is not installed, so the planned winget install of the JDKs was not possible. | Used portable Temurin JDK zips unpacked under `C:\Android`. No admin rights needed. |
| Current cmdline-tools need Java 17 and will not run on JDK 8. | JDK 17 is used only for `sdkmanager` and `avdmanager`. JDK 8 is used for benchmark builds. |
| PowerShell splits package names containing semicolons (for example `platforms;android-27`). | Wrap the package name in single quotes around double quotes, for example `'"platforms;android-27"'`. |
| A shell opened as administrator started in `C:\WINDOWS\system32`. | Use a regular (non-admin) shell started from the project folder. |
