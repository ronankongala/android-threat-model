# net.gsantner.markor_164 privacy report

Permissions: android.permission.INTERNET, android.permission.MANAGE_EXTERNAL_STORAGE, android.permission.READ_EXTERNAL_STORAGE, android.permission.REQUEST_INSTALL_PACKAGES, android.permission.WRITE_EXTERNAL_STORAGE, com.android.launcher.permission.INSTALL_SHORTCUT, net.gsantner.markor.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION

SDK packages found: none

## Privacy Policy Analysis

Policy file: `policies/net.gsantner.markor.txt`

| Severity | Rule | Policy claim | Manifest evidence |
|---|---|---|---|
| medium | data-stays-on-device | The app works completely offline, no internet connection required! | manifest requests android.permission.INTERNET |
