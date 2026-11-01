# Installed SDK images

Checked on 2026-11-01 with `sdkmanager --list_installed` (cmdline-tools 23.0, run with JAVA_HOME=C:\Android\jdk17, SDK root `C:\Android\Sdk`).

## System images

| API level | Image | Installed |
|----------:|-------|-----------|
| 22 | `system-images;android-22;google_apis;x86` | No |
| 25 | `system-images;android-25;google_apis;x86` | No |
| 27 | `system-images;android-27;google_apis;x86` | Yes (11.0.0) |
| 28 | `system-images;android-28;google_apis;x86` | No |
| 30 | `system-images;android-30;google_apis;x86` | No |
| 33 | `system-images;android-33;google_apis;x86` | No |
| 34 | `system-images;android-34;google_apis;x86` | No |

Only the API 27 image is present, so `tools/create_avds.ps1` can create `ghera27` only; the other six levels are skipped until their images are installed.

## Raw output

```text
WARNING: The SDK Manager CLI tool (sdkmanager) is deprecated. Android CLI will be used instead.
The 'android' binary can also be found in the cmdline-tools directory, and 'android sdk' is the replacement for 'sdkmanager'.
To learn more about the Android CLI and how to use it, see the documentation (https://d.android.com/tools/agents/android-cli)

Installed packages:
  build-tools/27.0.3                               27.0.3                      Android SDK Build-Tools 27.0.3
  cmdline-tools/latest                             unknown   ->        23.0.0  Android SDK Command-line Tools (latest)
  emulator                                         37.2.13                     Android Emulator
  platform-tools                                   37.0.1                      Android SDK Platform-Tools
  platforms/android-27                             3.0.0                       Android SDK Platform 27
  system-images/android-27/google_apis/x86         11.0.0                      Google APIs Intel x86 Atom System Image
```
