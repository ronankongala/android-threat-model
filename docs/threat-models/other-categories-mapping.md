# Standards mapping for the other categories

Standards mapping, without a full threat model, for the 31 Ghera benchmarks outside the ICC and Web categories (tag `Jan2019`, commit `6289f39d`). Each subsection follows `docs/threat-models/BATCH-RULES.md`: every statement about an app comes from the benchmark README or source, every ID is in `docs/threat-models/standards-reference.md` with its exact title, and every Fit value points to a line of code. Paths are relative to `benchmarks/ghera/<Category>/<Benchmark>/` unless shown otherwise. Nothing has been run on an emulator; every evidence plan is marked "Not yet run".

## Crypto (5)

### BlockCipher-ECB-InformationExposure-Lean
- **Summary:** An app that encrypts sensitive data with AES in ECB mode (explicitly, or by asking for plain "AES" and getting ECB by default) leaks structure of the plaintext. In the example, an attacker cuts the last blocks out of a token issued for a crafted email address and reuses them as a valid password reset token for another address.
- **Android versions (from README):** "Tested on Android 5.1.1 - Android 8.1"
- **What the code does:** `Benign/app/src/main/java/edu/ksu/cs/benign/ResetPasswordActivity.java` line 63 calls `Cipher.getInstance("AES")`, line 69 builds the key from `R.string.secret_key`, which is the constant `0123456789!@#$%^` in `Benign/app/src/main/res/values/strings.xml` line 3, and line 78 encrypts the typed email address as the token. `Benign/app/src/main/java/edu/ksu/cs/benign/NewPasswordActivity.java` lines 33 to 49 decrypt the `token` extra of any incoming intent with the same cipher and key, and line 55 opens the new password screen if the result equals `anniemaes@gmail.com`. `NewPasswordActivity` is exported through the intent filter for `edu.ksu.cs.benign.NEWPASS` with no permission (`Benign/app/src/main/AndroidManifest.xml` lines 18 to 24). `Malicious/app/src/main/java/edu/ksu/cs/malicious/MainActivity.java` lines 37 to 45 keep only the last 32 bytes of a token and lines 30 to 32 send them to `NewPasswordActivity` with an implicit intent.

| Standard | ID | Title | Confidence | Fit |
|----------|----|-------|------------|-----|
| CWE | CWE-327 | Use of a Broken or Risky Cryptographic Algorithm | Verified | Partial. `ResetPasswordActivity.java` line 63 and `NewPasswordActivity.java` line 36 request `"AES"`, which the README says defaults to ECB; the token blocks are encrypted independently, so Malicious can reuse the last 32 bytes (Malicious `MainActivity.java` lines 41 to 44). Partial because AES itself is standard and the risk comes from the mode. Usage ALLOWED-WITH-REVIEW; review outcome: the mapping notes say this Class may have better Base-level children, and the children one level down (CWE-328, CWE-780, CWE-1240, CWE-916) cover weak hashes, RSA without OAEP, risky primitive implementations and password hash effort, none of which describes a block cipher mode, so CWE-327 is kept as the closest entry. |
| CWE | CWE-321 | Use of Hard-coded Cryptographic Key | Verified | Partial. The AES key is the constant string in `Benign/app/src/main/res/values/strings.xml` line 3, read at `ResetPasswordActivity.java` line 69 and `NewPasswordActivity.java` line 41. The README notes this as a second weakness; the ECB attack does not need the key. Usage ALLOWED. |
| CWE | CWE-926 | Improper Export of Android Application Components | Verified | Partial. `NewPasswordActivity` is exported by its intent filter with no permission (Benign manifest lines 18 to 24), which is how Malicious delivers the forged token. The README does not name the export as the weakness. Usage ALLOWED. |
| OWASP MASVS v2 | MASVS-CRYPTO-1 | The app employs current strong cryptography and uses it according to industry best practices. | Verified | Direct. ECB mode at `ResetPasswordActivity.java` line 63. |
| OWASP MASVS v2 | MASVS-CRYPTO-2 | The app performs key management according to industry best practices. | Verified | Partial. Constant key in `strings.xml` line 3; secondary to the ECB issue. |
| OWASP MASVS v2 | MASVS-PLATFORM-1 | The app uses IPC mechanisms securely. | Verified | Partial. The exploit reaches `NewPasswordActivity` through its exported intent filter (Benign manifest lines 18 to 24). |
| OWASP MASTG test | MASTG-TEST-0364 | Exported And Unprotected Activities That Expose Sensitive Functionality | Verified | Partial. `NewPasswordActivity` is exported without a permission and opens the password reset screen for a decrypted token (`NewPasswordActivity.java` lines 33 to 58). Partial because the activity does check the token; the weakness is that ECB lets an attacker build a valid one. |
| OWASP MASWE | MASWE-0018 | Lack of Authentication or Authorization on App Components | Verified | Partial. Same exported activity (Benign manifest lines 18 to 24), reachable by any app. Partial for the reason given for MASTG-TEST-0364. Controls shown on the page: MASVS-AUTH-1, MASVS-PLATFORM-1, MASVS-STORAGE-2. |

No other MASTG test or MASWE entry in the reference file fits: the remaining ones cover content providers, services, broadcast receivers, intents in general, overlays and untrusted data, and the reference file has no cryptography entry.

MITRE ATT&CK for Mobile: No direct match. No technique on attack.mitre.org was verified that describes forging an encrypted token by reusing ECB ciphertext blocks.

- **Candidates to check:**
  - MASTG-TEST-0232 (Broken Symmetric Encryption Modes, as listed on the MASTG test index): a static test for ECB use such as `ResetPasswordActivity.java` line 63.
  - MASTG-TEST-0350 (Runtime Use of Broken Symmetric Encryption Modes, as listed on the MASTG test index): the runtime form of the same check.
  - MASWE-0007 (Improper Encryption, as listed on the MASWE index): the MASVS-CRYPTO-1 weakness for misused encryption.
  - MASTG-TEST-0212 (Use of Hardcoded Cryptographic Keys in Code, as listed on the MASTG test index): covers the constant key in `strings.xml` line 3.
- **Evidence plan:** On the ghera27 emulator (API 27, inside the README range), install Benign and Malicious, request a token in Benign for `2222222222222222anniemaes@gmail.com`, paste it into Malicious and press *Reset Password*, and check that Benign shows the new password screen for `anniemaes@gmail.com`; then repeat with Secure and Malicious. Not yet run.
- **README vs code differences:**
  - The README says Benign sends the token to the email address; `ResetPasswordActivity.java` lines 88 to 91 only show a toast and log a line, and line 45 puts the token into an on-screen field.
  - The README explains the attack as "if a particular block is encrypted twice, the source message will be returned"; the code relies instead on ECB encrypting each 16-byte block independently, since Malicious keeps the last 32 bytes of the token for the 35-character address (Malicious `MainActivity.java` lines 41 to 44).
  - The README says Malicious "has access to the token"; Malicious ships a fixed token at `MainActivity.java` line 23 (the Testing code replaces it with the token read from Benign).
  - The `Benign-V2` folder (explicit `AES/ECB/PKCS5Padding` at `Benign-V2/app/src/main/java/edu/ksu/cs/benign/NewPasswordActivity.java` line 36) is not mentioned in the README and is not built by `Testing/settings.gradle`.
  - The Secure test looks for `edu.ksu.cs.secure:id/emailView`, but Secure's package is `edu.ksu.cs.benign` (`Secure/app/src/main/AndroidManifest.xml` line 3), so the element is never found and the test passes whether or not the weakness is present (`Testing/secure_app/src/androidTest/java/edu/ksu/cs/secure/Tests.java` lines 74 to 77).
- **Open questions:**
  - Secure keeps `NewPasswordActivity` exported (`Secure/app/src/main/AndroidManifest.xml` lines 19 to 25) and logs the token and the IV (`Secure/app/src/main/java/edu/ksu/cs/benign/ResetPasswordActivity.java` lines 77 and 91); Benign also logs the token (`ResetPasswordActivity.java` line 43). Whether CWE-532 belongs in this model is not decided.
  - Secure no longer checks for a registered address and shows any decrypted email (`Secure/.../NewPasswordActivity.java` lines 70 to 71); whether that is intended is not stated.
  - Secure passes an `IvParameterSpec`, not a `GCMParameterSpec`, to an `AES/GCM/NoPadding` cipher (`Secure/.../NewPasswordActivity.java` lines 56 to 58); whether the API 27 provider accepts it has not been checked.
  - Secure's key is random per process (`Secure/.../ResetPasswordActivity.java` lines 26 to 31), so tokens stop working after the process restarts.

### BlockCipher-NonRandomIV-InformationExposure-Lean
- **Summary:** An app that encrypts records with AES in CBC mode using a fixed IV and key produces identical ciphertext for identical plaintext. An attacker who can insert and read records can confirm a guessed student grade by looking for a duplicate ciphertext.
- **Android versions (from README):** "Tested on Android 5.1.1 - Android 8.1"
- **What the code does:** `Benign/app/src/main/java/edu/ksu/cs/benign/Util/Encrypt.java` lines 20 to 24 encrypt with `AES/CBC/PKCS5PADDING` using a key and IV passed in as strings, and `Benign/app/src/main/java/edu/ksu/cs/benign/GradesContentProvider.java` lines 48 to 51 pass the constants `R.string.secret` and `R.string.IV` (`Benign/app/src/main/res/values/strings.xml` lines 3 and 4) and append the result to `scores.txt`. `GradesContentProvider.query` (lines 79 to 91) returns every stored line, and the provider is exported with no permission (`Benign/app/src/main/AndroidManifest.xml` lines 19 to 23). `Malicious/app/src/main/java/edu/ksu/cs/malicious/MainActivity.java` lines 45 to 50 insert a guessed `name, grade` pair and lines 64 to 72 query all rows and report success when a row repeats.

| Standard | ID | Title | Confidence | Fit |
|----------|----|-------|------------|-----|
| CWE | CWE-329 | Generation of Predictable IV with CBC Mode | Verified | Direct. CBC with the constant IV from `strings.xml` line 4, used at `Encrypt.java` lines 20 to 23. Usage ALLOWED. |
| CWE | CWE-321 | Use of Hard-coded Cryptographic Key | Verified | Partial. The key is the constant in `strings.xml` line 3, passed at `GradesContentProvider.java` line 48. The README notes this as a second weakness; the duplicate-ciphertext attack does not need the key. Usage ALLOWED. |
| CWE | CWE-926 | Improper Export of Android Application Components | Verified | Partial. `GradesContentProvider` has `android:exported="true"` and no permission (Benign manifest lines 19 to 23), which lets Malicious insert and query. The README describes the export as part of the setup, not as the weakness. Usage ALLOWED. |
| OWASP MASVS v2 | MASVS-CRYPTO-1 | The app employs current strong cryptography and uses it according to industry best practices. | Verified | Direct. Fixed IV with CBC at `Encrypt.java` line 22. |
| OWASP MASVS v2 | MASVS-CRYPTO-2 | The app performs key management according to industry best practices. | Verified | Partial. Constant key in `strings.xml` line 3; secondary to the IV issue. |
| OWASP MASVS v2 | MASVS-PLATFORM-1 | The app uses IPC mechanisms securely. | Verified | Partial. The attack uses the exported provider (Benign manifest lines 19 to 23). |
| OWASP MASTG test | MASTG-TEST-0007 | Determining Whether Sensitive Stored Data Has Been Exposed via IPC Mechanisms | Verified | Partial. `GradesContentProvider.query` (lines 79 to 91) returns the stored records to any app. Deprecated, kept for reference only. |
| OWASP MASWE | MASWE-0018 | Lack of Authentication or Authorization on App Components | Verified | Partial. The provider's `insert` and `query` (lines 41 to 102) are open to any app (Benign manifest lines 19 to 23). Partial because the benchmark's weakness is the IV; the open provider is what makes it reachable. Controls shown on the page: MASVS-AUTH-1, MASVS-PLATFORM-1, MASVS-STORAGE-2. |

MASTG-TEST-0355, MASTG-TEST-0356 and MASTG-TEST-0357 were considered and not used: the provider is backed by a plain file read into a `MatrixCursor` (`GradesContentProvider.java` lines 84 to 91), not a database, and it is not a file-sharing provider.

MITRE ATT&CK for Mobile: No direct match. No technique on attack.mitre.org was verified that describes inferring plaintext from repeated CBC ciphertext through another app's content provider.

- **Candidates to check:**
  - MASTG-TEST-0309 (References to Reused Initialization Vectors in Symmetric Encryption, as listed on the MASTG test index, status placeholder): a static test for the constant IV at `Encrypt.java` line 22.
  - MASTG-TEST-0310 (Runtime Use of Reused Initialization Vectors in Symmetric Encryption, as listed on the MASTG test index, status placeholder): the runtime form.
  - MASWE-0007 (Improper Encryption, as listed on the MASWE index): the MASVS-CRYPTO-1 weakness for misused encryption.
  - MASTG-TEST-0212 (Use of Hardcoded Cryptographic Keys in Code, as listed on the MASTG test index): covers the constant key in `strings.xml` line 3.
- **Evidence plan:** On the ghera27 emulator (API 27, inside the README range), install Benign and Malicious, add the student `Jane` with grade `C` in Benign, insert the same pair from Malicious, press *Verify* and check for the success message; then repeat with Secure and Malicious, expecting the default text "Guess result ...". Not yet run.
- **README vs code differences:**
  - The README says the encrypted string is saved "in the database"; `GradesContentProvider.java` line 50 appends it to the file `scores.txt`.
  - The README's expected message is "Congratulations! you guessed the right grade"; the code sets "Congratulations! Your guessed the right grade" (Malicious `MainActivity.java` line 71).
  - The README steps number two different steps as 8 (README lines 56 and 58).
  - The Secure fix is described as a random IV, but Secure also replaces the constant key with a new random key on every call (`Secure/app/src/main/java/edu/ksu/cs/secure/Util/Encrypt.java` lines 20 to 24) and stores neither key nor IV, so the app can never decrypt its own records.
- **Open questions:**
  - Secure keeps the provider exported with no permission (`Secure/app/src/main/AndroidManifest.xml` lines 18 to 22).
  - Secure declares package `edu.ksu.cs.secure` (`Secure/app/src/main/AndroidManifest.xml` line 3) but its `applicationId` is `edu.ksu.cs.benign` (`Secure/app/build.gradle` line 7), and the Secure test selects `edu.ksu.cs.benign:id/...` resources; whether those IDs resolve on the device has not been checked.
  - Benign and Secure share the `applicationId` `edu.ksu.cs.benign`, so installing Secure over Benign may keep Benign's `scores.txt` with its duplicate rows and change the Secure test result.
  - Malicious calls `mCursor.close()` without a null check (`Malicious/.../MainActivity.java` line 75), so it crashes when the provider returns null.
  - Benign logs the student name and grade in plaintext (`Benign/.../AddStudent.java` lines 33 and 34).

### ConstantKey-ForgeryAttack-Lean
- **Summary:** An app that keeps its encryption key in its source code lets anyone who reads the code reuse the key. In the example, a second app uses the same AES key to create a valid password reset token for any email address.
- **Android versions (from README):** "Tested on Android 5.1.1 - Android 8.1"
- **What the code does:** `Benign/app/src/main/java/edu/ksu/cs/benign/ResetPasswordActivity.java` line 26 defines `SECRET_KEY = "0123456789!@#$%^".getBytes()`, and lines 52 to 72 encrypt the typed email with `AES/GCM/NoPadding` under that key. `Benign/app/src/main/java/edu/ksu/cs/benign/NewPasswordActivity.java` lines 43 to 61 decrypt the `generatedToken` extra with the IV from the `initVector` extra and the same key, and show "You can change password for" plus the email. The activity is exported through the `edu.ksu.cs.benign.NEWPASS` intent filter with no permission (`Benign/app/src/main/AndroidManifest.xml` lines 18 to 24). `Malicious/app/src/main/java/edu/ksu/cs/malicious/MainActivity.java` line 26 copies the same key, and lines 43 to 81 encrypt any email and send the token and IV to that action.

| Standard | ID | Title | Confidence | Fit |
|----------|----|-------|------------|-----|
| CWE | CWE-321 | Use of Hard-coded Cryptographic Key | Verified | Direct. `ResetPasswordActivity.java` line 26 hard-codes the AES key, and Malicious line 26 reuses it. Usage ALLOWED. |
| CWE | CWE-926 | Improper Export of Android Application Components | Verified | Partial. `NewPasswordActivity` is exported with no permission (Benign manifest lines 18 to 24). The README's note says the attack "could have been limited by controlling the apps that are serviced by Benign", but also that the key could be abused through other channels, so the export is not the main weakness. Usage ALLOWED. |
| OWASP MASVS v2 | MASVS-CRYPTO-2 | The app performs key management according to industry best practices. | Verified | Direct. Key in code at `ResetPasswordActivity.java` line 26. |
| OWASP MASVS v2 | MASVS-PLATFORM-1 | The app uses IPC mechanisms securely. | Verified | Partial. The forged token reaches Benign through the exported activity (Benign manifest lines 18 to 24). |
| OWASP MASTG test | MASTG-TEST-0364 | Exported And Unprotected Activities That Expose Sensitive Functionality | Verified | Partial. The exported `NewPasswordActivity` grants a password change for any token that decrypts (`NewPasswordActivity.java` lines 59 to 61). Partial because it does check the token; the hard-coded key is what lets an attacker make one. |
| OWASP MASWE | MASWE-0018 | Lack of Authentication or Authorization on App Components | Verified | Partial. Same exported activity, reachable by any app; partial for the reason given for MASTG-TEST-0364. Controls shown on the page: MASVS-AUTH-1, MASVS-PLATFORM-1, MASVS-STORAGE-2. |

No other MASTG test or MASWE entry in the reference file fits: the remaining ones cover content providers, services, broadcast receivers, intents in general, overlays and untrusted data, and the reference file has no cryptography entry.

MITRE ATT&CK for Mobile: No direct match. No technique on attack.mitre.org was verified that describes reusing a key extracted from an app's code to forge tokens for that app.

- **Candidates to check:**
  - MASTG-TEST-0212 (Use of Hardcoded Cryptographic Keys in Code, as listed on the MASTG test index): a direct test for `ResetPasswordActivity.java` line 26.
  - MASWE-0004 (Sensitive Data Hardcoded in the App Package, as listed on the MASWE index): the key is sensitive data shipped in the APK.
  - CWE-798 (Use of Hard-coded Credentials): parent of CWE-321; only needed if a broader entry is wanted.
- **Evidence plan:** On the ghera27 emulator (API 27, inside the README range), install Benign and Malicious, type `good@email.id` in Malicious and press the button, and check that Benign shows "You can change password for good@email.id"; then repeat with Secure and Malicious, expecting "Invalid Token". Not yet run.
- **README vs code differences:**
  - The README says Benign emails the token; `ResetPasswordActivity.java` lines 73 to 75 only log it and show the toast "Token emailed!".
  - Benign's `NewPasswordActivity.java` line 24 uses the log tag `Secure/NewPassword`, a leftover from another app.
  - `Malicious/app/app-debug.apk` is a prebuilt APK inside the source folder, next to `Malicious/ConstantKey-ForgeryAttack-Lean-malicious.apk`.
- **Open questions:**
  - Secure keeps `NewPasswordActivity` exported (`Secure/app/src/main/AndroidManifest.xml` lines 19 to 25), although the README's note suggests limiting which apps Benign serves.
  - Secure's key is random per process (`Secure/app/src/main/java/edu/ksu/cs/benign/ResetPasswordActivity.java` lines 27 to 31), so tokens stop working after a process restart.
  - Benign and Secure log the token and IV (Benign `ResetPasswordActivity.java` lines 73 and 87, Secure lines 77 and 91); whether CWE-532 belongs in this model is not decided.
  - Both apps pass an `IvParameterSpec` to an `AES/GCM/NoPadding` cipher for decryption (Benign `NewPasswordActivity.java` line 49, Secure line 51); whether the API 27 provider accepts it has not been checked.

### ExposedCredentials-InformationExposure-Lean
- **Summary:** An app stores a secret key in a Java keystore entry with no protection parameter and writes the keystore file to external storage. Another app that knows the alias and can read external storage loads the keystore and takes the key.
- **Android versions (from README):** "Tested on Android 5.1.1 - Android 8.1"
- **What the code does:** `Benign/app/src/main/java/edu/ksu/cs/benign/MainActivity.java` lines 33 to 35 generate an AES key, line 44 stores it with `keyStore.setEntry(ALIAS, new KeyStore.SecretKeyEntry(secretKey), null)`, and lines 45 to 47 write the keystore to `getExternalFilesDir(null)/secretKeyStore` with a null store password. `Malicious/app/src/main/java/edu/ksu/cs/malicious/MainActivity.java` lines 56 to 58 build the path to Benign's external files folder, and lines 64 to 69 load the keystore with no password and read the `SECRET_KEY` entry with a null protection parameter; Malicious requests `READ_EXTERNAL_STORAGE` (`Malicious/app/src/main/AndroidManifest.xml` line 5, `MainActivity.java` lines 33 to 37).

| Standard | ID | Title | Confidence | Fit |
|----------|----|-------|------------|-----|
| CWE | CWE-922 | Insecure Storage of Sensitive Information | Verified | Direct. The keystore holding the key is written to external storage (`MainActivity.java` lines 45 to 47) with no entry protection (line 44), so any app with read access to external storage can read it. Usage ALLOWED-WITH-REVIEW; review outcome: the mapping notes say this Class may have better Base-level children. The children one level down are CWE-312 (Cleartext Storage of Sensitive Information) and CWE-921 (Storage of Sensitive Data in a Mechanism without Access Control). CWE-921 matches the external storage location more closely but is not in the reference file and is listed as a candidate; CWE-312 covers only the missing entry protection. CWE-922 is kept because it covers both parts. |
| OWASP MASVS v2 | MASVS-STORAGE-1 | The app securely stores sensitive data. | Verified | Direct. Key written to external storage at `MainActivity.java` lines 45 to 47. |
| OWASP MASVS v2 | MASVS-CRYPTO-2 | The app performs key management according to industry best practices. | Verified | Partial. The key is kept in a file-based keystore with a null protection parameter (line 44) rather than a protected store. |

CWE-522 (Insufficiently Protected Credentials) was considered and not used. Its description is about authentication credentials, the stored item here is an AES encryption key (`MainActivity.java` lines 33 to 35), and its children one level down (CWE-256, CWE-257, CWE-260, CWE-261, CWE-523, CWE-549) are all about passwords or credential transport.

No MASTG test or MASWE entry in the reference file fits: they cover app components, intents, overlays and untrusted data, and this benchmark has no exported component and no IPC.

MITRE ATT&CK for Mobile: No direct match. No technique on attack.mitre.org was verified that describes reading another app's key from a keystore file on external storage.

- **Candidates to check:**
  - CWE-921 (Storage of Sensitive Data in a Mechanism without Access Control): a child of CWE-922 that names storage without access control, such as the external files folder at `MainActivity.java` line 45.
  - MASWE-0003 (Cryptographic Keys Stored Outside of Platform Keystore, as listed on the MASWE index): the key sits in a file keystore, not the platform keystore.
  - MASWE-0002 (Sensitive Data Stored Unencrypted Outside of Private Storage, as listed on the MASWE index): the key file is outside private storage.
  - MASTG-TEST-0200 (Files Written to External Storage, as listed on the MASTG test index): matches the write at lines 45 to 47.
- **Evidence plan:** On the ghera27 emulator (API 27, inside the README range), install Benign and Malicious, launch Benign, then launch Malicious, allow the storage permission prompt, and check for "Successfully retrieved the key."; then repeat with Secure and Malicious, expecting "Failed to retrieve the key.". Not yet run.
- **README vs code differences:**
  - The README steps have two steps numbered 8 and no step 7 (README lines 53 and 55).
  - The README says the issue "can be mitigated by using a password-based implementation of `ProtectionParameter`"; Secure does this with the password `secure` written in its source (`Secure/app/src/main/java/edu/ksu/cs/benign/MainActivity.java` line 47) and still writes the keystore to external storage (lines 49 to 51). The code comment at lines 45 to 46 says this is for demonstration only.
- **Open questions:**
  - Benign declares `WRITE_EXTERNAL_STORAGE` (`Benign/app/src/main/AndroidManifest.xml` line 5) but writes only to `getExternalFilesDir` (`MainActivity.java` line 45); with `minSdkVersion 22` from the shared `Misc/sdkFlavors.gradle`, that folder needs no permission, so the permission looks unused.
  - `KeyStore.getDefaultType()` (line 42) is used without naming the keystore type; which type and provider API 27 uses, and whether it accepts a null entry protection and a null store password, has not been checked.

### PBE-ConstantSalt-InformationExposure-Lean
- **Summary:** An app derives its encryption key from a passphrase with a constant salt, so an attacker can precompute keys for common passphrases. In the example, a second app derives the key for the passphrase `password` and decrypts the student records it reads from Benign.
- **Android versions (from README):** "Tested on Android 5.1.1 - Android 8.1"
- **What the code does:** `Benign/app/src/main/java/edu/ksu/cs/benign/GradesContentProvider.java` line 49 passes `R.string.salt`, the constant `90dujHU*` (`Benign/app/src/main/res/values/strings.xml` line 4), to `Encrypt.encryptGrade`. `Benign/app/src/main/java/edu/ksu/cs/benign/Util/Encrypt.java` lines 25 to 35 derive a 256-bit AES key with `PBKDF2WithHmacSHA1`, 1000 iterations, that salt and the password `Constant.PASS` (`Util/Constant.java` line 4, `"password"`), and lines 37 to 43 encrypt with AES/CBC and a random IV, storing `IV[ciphertext`. The provider is exported with no permission (`Benign/app/src/main/AndroidManifest.xml` lines 19 to 23). `Malicious/app/src/main/java/edu/ksu/cs/malicious/MainActivity.java` lines 101 to 111 derive the key from `password` and the same salt, and lines 60 to 88 query the provider and decrypt each row.

| Standard | ID | Title | Confidence | Fit |
|----------|----|-------|------------|-----|
| CWE | CWE-760 | Use of a One-Way Hash with a Predictable Salt | Verified | Direct. The PBKDF2 derivation at `Encrypt.java` line 33 uses the constant salt from `strings.xml` line 4, and Malicious repeats it with the same salt (`MainActivity.java` lines 102 to 108). Usage ALLOWED. |
| CWE | CWE-926 | Improper Export of Android Application Components | Verified | Partial. `GradesContentProvider` is exported with no permission (Benign manifest lines 19 to 23), which is how Malicious reads the ciphertext. The README does not name the export as the weakness. Usage ALLOWED. |
| OWASP MASVS v2 | MASVS-CRYPTO-1 | The app employs current strong cryptography and uses it according to industry best practices. | Verified | Direct. Constant salt for password-based encryption at `Encrypt.java` line 33. |
| OWASP MASVS v2 | MASVS-CRYPTO-2 | The app performs key management according to industry best practices. | Verified | Partial. The key is derived from a constant salt and the constant password at `Constant.java` line 4. |
| OWASP MASVS v2 | MASVS-PLATFORM-1 | The app uses IPC mechanisms securely. | Verified | Partial. The ciphertext is read through the exported provider (Benign manifest lines 19 to 23). |
| OWASP MASTG test | MASTG-TEST-0007 | Determining Whether Sensitive Stored Data Has Been Exposed via IPC Mechanisms | Verified | Partial. `GradesContentProvider.query` (lines 72 to 101) returns all stored records to any app. Deprecated, kept for reference only. |
| OWASP MASWE | MASWE-0018 | Lack of Authentication or Authorization on App Components | Verified | Partial. The provider is open to any app (Benign manifest lines 19 to 23). Partial because the benchmark's weakness is the constant salt; the open provider is what makes the ciphertext reachable. Controls shown on the page: MASVS-AUTH-1, MASVS-PLATFORM-1, MASVS-STORAGE-2. |

MASTG-TEST-0355, MASTG-TEST-0356 and MASTG-TEST-0357 were considered and not used: the provider is backed by a plain file read into a `MatrixCursor` (`GradesContentProvider.java` lines 79 to 98), not a database, and it is not a file-sharing provider.

MITRE ATT&CK for Mobile: No direct match. No technique on attack.mitre.org was verified that describes a precomputed key dictionary against an app's password-based encryption.

- **Candidates to check:**
  - MASWE-0014 (Improper Cryptographic Key Derivation, as listed on the MASWE index): directly covers the constant-salt derivation at `Encrypt.java` line 33.
  - CWE-916 (Use of Password Hash With Insufficient Computational Effort): a child of CWE-327; 1000 iterations of `PBKDF2WithHmacSHA1` (`Encrypt.java` lines 26 to 27) may count as low effort.
  - CWE-259 (Use of Hard-coded Password): the password is a constant in `Util/Constant.java` line 4.
- **Evidence plan:** On the ghera27 emulator (API 27, inside the README range), install Benign and Malicious, enter passphrase `password` in Benign and add `Jhontu` with grade `A`, then press *Get Student Info* in Malicious and check that it shows `Jhontu` and `A`; then repeat with Secure and Malicious, expecting `null` and `null`. Not yet run.
- **README vs code differences:**
  - The README says the key is derived from the passphrase the user enters; the code derives it from the constant `Constant.PASS` (`Encrypt.java` line 33, `Constant.java` line 4) and uses the typed text only for a comparison (`MainActivity.java` line 31).
  - The README says Malicious has "a list of well-known pass-phrases"; the list has one entry (Malicious `MainActivity.java` line 41).
  - README step 11 says the log shows the decrypted values; Malicious logs only the IV and the ciphertext (`MainActivity.java` lines 66 to 67) and shows the decrypted name and grade on screen (lines 87 to 88), overwritten by each row.
  - `R.string.secret` in `Benign/app/src/main/res/values/strings.xml` line 3 is not used by any Benign code.
- **Open questions:**
  - Secure uses a random salt per record (`Secure/app/src/main/java/edu/ksu/cs/secure/Util/Encrypt.java` lines 33 to 35) but stores only the IV and ciphertext (line 45), so the app cannot rebuild the key to decrypt its own records. Secure keeps the constant password (`Secure/.../Util/Constant.java` line 4) and the exported provider (`Secure/app/src/main/AndroidManifest.xml` lines 19 to 23).
  - `Encrypt.java` lines 42 and 43 call `doFinal` twice and log the IV and ciphertext; Benign also logs the name and grade in plaintext (`AddStudent.java` lines 34 to 35).
  - Secure declares package `edu.ksu.cs.secure` but its `applicationId` is `edu.ksu.cs.benign` (`Secure/app/build.gradle` line 7); whether the Secure test's `edu.ksu.cs.benign:id/...` selectors resolve has not been checked.

