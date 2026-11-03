# BugBazaar known vulnerabilities

Source: README of https://github.com/payatu/BugBazaar (section "Vulnerabilities"), fetched 2026-11-02.
APK: BugBazaar_v1.2.1.apk from release v1.2.1 (2024-08-14),
SHA-256 c307c7856b270da40357006eaa763c06bcdc2913d0d0b0bab7e0b2ed564f5f4c.

Note: the task named OWASP/mas-reference-apps as the source. That repository does not exist
on GitHub. BugBazaar is published by Payatu at payatu/BugBazaar, so that release was used.

The README gives names only. The CWE column is our mapping, added for scoring in Step 3.
The "APP Protection" section (RootBeer, Magisk, emulator and Frida detection) lists
protections to bypass, not vulnerabilities, so it is not counted.

| ID | Category | Vulnerability (README wording) | Mapped CWE |
|----|----------|--------------------------------|------------|
| BB-01 | WebView | Opening arbitrary URLs in the webview | CWE-939 |
| BB-02 | WebView | XSS | CWE-79 |
| BB-03 | WebView | Open redirection | CWE-601 |
| BB-04 | WebView | Account takeover via stealing session ID (host validation bypass) | CWE-940 |
| BB-05 | WebView | Stealing user token via JavaScriptInterface class | CWE-749 |
| BB-06 | WebView | Access of arbitrary files via insecure flags (API 28 and lower) | CWE-200 |
| BB-07 | WebView | Stealing arbitrary files via insecure WebResourceResponse | CWE-22 |
| BB-08 | Intent | Intent interception | CWE-927 |
| BB-09 | Intent | Account takeover via intent spoofing | CWE-925 |
| BB-10 | Intent | Steal user contacts via insecure PendingIntent | CWE-927 |
| BB-11 | Intent | RCE through insecure dynamic code loading | CWE-94 |
| BB-12 | Deep link | CSRF to add the product to cart | CWE-352 |
| BB-13 | Deep link | Deep link hijacking to load URLs in webview | CWE-939 |
| BB-14 | Deep link | Content spoofing on Offers activity | CWE-451 |
| BB-15 | IPC | Exported components | CWE-926 |
| BB-16 | IPC | Steal user contacts via typo permission in content provider | CWE-276 |
| BB-17 | IPC | Insecure broadcast receiver | CWE-925 |
| BB-18 | IPC | Access to protected components via broadcast receiver | CWE-926 |
| BB-19 | IPC | Insecure services | CWE-926 |
| BB-20 | IPC | Fragment injection in Refer-Us | CWE-470 |
| BB-21 | Injection | SQL injection via user input in My Order | CWE-89 |
| BB-22 | Injection | Content provider SQL injection in Address | CWE-89 |
| BB-23 | Injection | Data insertion via insecure content provider in Address | CWE-926 |
| BB-24 | Data leakage | Copy/paste buffer caching | CWE-200 |
| BB-25 | Data leakage | Application backgrounding (screenshot in recents) | CWE-200 |
| BB-26 | Data leakage | Insecure logging (user credentials) | CWE-532 |
| BB-27 | Insecure storage | Unencrypted database | CWE-312 |
| BB-28 | Insecure storage | Man-in-the-disk attack | CWE-921 |
| BB-29 | Insecure storage | Storing sensitive info in SharedPreferences | CWE-312 |
| BB-30 | Insecure storage | Hardcoded secrets | CWE-798 |
| BB-31 | Others | Improper input validation | CWE-20 |
| BB-32 | Others | Unrestricted file upload | CWE-434 |
| BB-33 | Others | Misconfigured Firebase Firestore | CWE-284 |
| BB-34 | Others | Passcode bypass | CWE-287 |
| BB-35 | Others | Tapjacking | CWE-1021 |
| BB-36 | Others | Improper exception handling | CWE-755 |
| BB-37 | Others | Debuggable application | CWE-489 |
| BB-38 | Others | Backup enabled | CWE-530 |
| BB-39 | Others | Task hijacking | CWE-1021 |
| BB-40 | Others | Improper cache handling | CWE-524 |
| BB-41 | Runtime | Runtime code modification | CWE-693 |
| BB-42 | Runtime | Login PIN bypass via Frida/Objection | CWE-603 |
