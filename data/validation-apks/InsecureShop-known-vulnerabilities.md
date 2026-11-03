# InsecureShop known vulnerabilities

Source: README of https://github.com/hax0rgb/InsecureShop (section "Vulnerabilities"), fetched 2026-11-02.
APK: InsecureShop.apk from release v1.0 (2022-02-28),
SHA-256 a83298ae4a37fcab8101e8b41e513dd2199af71a94ea537d556a318e07d4d1bd.

The README wording is kept. The CWE column is our mapping, added for scoring in Step 3.

| ID | Vulnerability | README description | Mapped CWE |
|----|---------------|--------------------|------------|
| IS-01 | Hardcoded credentials | Credentials are hardcoded somewhere and can be used to log in | CWE-798 |
| IS-02 | Insufficient URL validation | Possible to load any arbitrary URL in webview via deeplink | CWE-939 |
| IS-03 | Weak host validation check | Possible to bypass host validation to load any URL in webview | CWE-940 |
| IS-04 | Arbitrary code execution | Arbitrary code execution via third-party package contexts | CWE-94 |
| IS-05 | Access to protected components | Embedded Intent passed to startActivity lets any app launch protected components | CWE-926 |
| IS-06 | Unprotected data URIs | Untrusted URIs passed to loadUrl allow arbitrary URLs in webview | CWE-939 |
| IS-07 | Theft of arbitrary files | Possible to steal files from local storage via ChooserActivity | CWE-22 |
| IS-08 | Using components with known vulnerabilities | Vulnerable library lets local files be exfiltrated | CWE-1104 |
| IS-09 | Insecure broadcast receiver | Exported activity registers a receiver, attacker sets an arbitrary web_url | CWE-925 |
| IS-10 | AWS Cognito misconfiguration | Misconfigured Cognito instance gives access to an S3 bucket | CWE-284 |
| IS-11 | Insecure FilePaths in FileProvider | Wide file sharing declaration exposes the root directory | CWE-552 |
| IS-12 | Implicit intent broadcast with sensitive data | Third-party apps can steal credentials from an implicit broadcast | CWE-927 |
| IS-13 | Intercepting implicit intent to load arbitrary URL | Third-party apps can make the webview load any URL | CWE-927 |
| IS-14 | Insecure setResult in exported activity | ResultActivity can be used to access arbitrary content providers | CWE-926 |
| IS-15 | Insecure content provider | Any third-party app can read user credentials from the provider | CWE-926 |
| IS-16 | Lack of SSL certificate validation | Unsafe onReceivedSslError lets webview traffic be eavesdropped | CWE-295 |
| IS-17 | Insecure WebView properties enabled | WebView settings let local data be exfiltrated to a remote domain | CWE-200 |
| IS-18 | Insecure data storage | Credentials stored locally without encryption | CWE-312 |
| IS-19 | Insecure logging | User credentials leaked in logcat | CWE-532 |
