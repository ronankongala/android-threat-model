# DIVA known vulnerabilities

Source: README of https://github.com/payatu/diva-android ("Current Challenges include"), fetched 2026-11-02.

APK: the repository has no GitHub releases, and the download page named in the README
(payatu.com/damn-insecure-and-vulnerable-app) no longer serves the file (404). The original
Payatu tarball diva-beta.tar.gz (2016-01-02) was taken from the Internet Archive:
https://web.archive.org/web/2017id_/http://www.payatu.com/wp-content/uploads/2016/01/diva-beta.tar.gz
It holds diva-beta.apk, SHA-256 5cefc51fce9bd760b92ab2340477f4dda84b4ae0c5d04a8c9493e4fe34fab7c5.

The README lists challenge names only. The "Detail" column is taken from the source in
the same repository (activity and provider names in app/src/main), and the CWE column is
our mapping. Both were added for scoring in Step 3.

| ID | Challenge (README) | Detail (from source) | Mapped CWE |
|----|--------------------|----------------------|------------|
| DV-01 | Insecure Logging | LogActivity logs the credit card number | CWE-532 |
| DV-02 | Hardcoding Issues - Part 1 | HardcodeActivity compares input with a hardcoded key in Java | CWE-798 |
| DV-03 | Insecure Data Storage - Part 1 | Credentials in SharedPreferences | CWE-312 |
| DV-04 | Insecure Data Storage - Part 2 | Credentials in a plain SQLite database | CWE-312 |
| DV-05 | Insecure Data Storage - Part 3 | Credentials in a temporary file in app storage | CWE-312 |
| DV-06 | Insecure Data Storage - Part 4 | Credentials in a file on external storage | CWE-921 |
| DV-07 | Input Validation Issues - Part 1 | SQLInjectionActivity builds a raw SQL query from input | CWE-89 |
| DV-08 | Input Validation Issues - Part 2 | InputValidation2URISchemeActivity loads any URL (file://) in a WebView | CWE-939 |
| DV-09 | Access Control Issues - Part 1 | APICredsActivity exported via action VIEW_CREDS | CWE-926 |
| DV-10 | Access Control Issues - Part 2 | APICreds2Activity exported via VIEW_CREDS2, check bypassed with an extra | CWE-926 |
| DV-11 | Access Control Issues - Part 3 | NotesProvider exported with no permission | CWE-926 |
| DV-12 | Hardcoding Issues - Part 2 | Hardcoded key in the native library (DivaJni) | CWE-798 |
| DV-13 | Input Validation Issues - Part 3 | Buffer overflow in native code (InputValidation3Activity) | CWE-120 |
