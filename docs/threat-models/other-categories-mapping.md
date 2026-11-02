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

## Networking (8)

### CheckValidity-InformationExposure-Lean
- **Summary:** An app that uses a custom trust manager and does not check whether the server certificate is still within its validity period will connect to a server whose certificate has expired. Benign connects to such a server; Secure checks every certificate in the chain with `checkValidity()`.
- **Android versions (from README):** "Tested on Android 5.1.1 - Android 8.1"
- **What the code does:** `Benign/app/src/main/java/edu/ksu/cs/benign/MyTrustManager.java` lines 16 to 18 implement `checkServerTrusted()` with an empty body, so no certificate is checked at all. `Benign/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` lines 47 to 49 install that trust manager, lines 58 to 63 set a `HostnameVerifier` that always returns true, and lines 64 to 70 read `https://10.0.2.2:5000/test/` and show the response in `ResponseActivity`. `Secure/app/src/main/java/edu/ksu/cs/benign/MyTrustManager.java` lines 20 to 26 call `checkValidity()` on each certificate in the chain, and `Secure/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` lines 72 to 79 show "Expired certificate! SSL Handshake failed." when the handshake fails with a `CertificateExpiredException` cause.

| Standard | ID | Title | Confidence | Fit |
|----------|----|-------|------------|-----|
| CWE | CWE-295 | Improper Certificate Validation | Verified | Direct. `Benign/app/src/main/java/edu/ksu/cs/benign/MyTrustManager.java` lines 16 to 18 leave `checkServerTrusted()` empty, so the expired certificate (and any other certificate) is accepted. Usage ALLOWED. |
| CWE | CWE-297 | Improper Validation of Certificate with Host Mismatch | Verified | Partial. `Benign/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` lines 58 to 63 accept every host name. Partial because the README is about the validity period, and Secure keeps the same verifier (`Secure/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` lines 58 to 63). Usage ALLOWED. |
| OWASP MASVS v2 | MASVS-NETWORK-1 | The app secures all network traffic according to the current best practices. | Verified | Direct. The TLS connection in `Benign/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` lines 47 to 57 uses a trust manager that validates nothing. |
| OWASP MASWE | MASWE-0027 | Insecure Certificate Validation | Verified | Direct. `Benign/app/src/main/java/edu/ksu/cs/benign/MyTrustManager.java` lines 16 to 18 is where the app accepts the connection without the check (see the CWE-295 row); the page covers apps "accepting invalid, expired, self-signed, or untrusted certificates without appropriate verification". Controls shown on the page: MASVS-NETWORK-1. |
| OWASP Mobile Top 10 2024 | M5 | Insecure Communication | Verified | Direct. `Benign/app/src/main/java/edu/ksu/cs/benign/MyTrustManager.java` lines 16 to 18 accept any certificate, including the expired one the README uses; the page lists "Accepting bad ssl certificates" among the flaws it covers, with "self-signed, revoked, expired, wrong host" certificates as its examples. |

CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor) was considered because of the benchmark name and is DISCOURAGED in `standards-reference.md`, so it is not in the table; CWE-295 is used instead.

No OWASP MASTG test in `standards-reference.md` fits: none of the tests in the file covers TLS certificate validation.

MITRE ATT&CK for Mobile: No direct match. No technique on attack.mitre.org was verified that describes a server presenting an expired certificate to an app that does not check it.

- **Candidates to check:**
  - CWE-298 (Improper Validation of Certificate Expiration): the exact weakness the README describes; official page title and Usage ALLOWED read on 2026-11-01, not in the reference file.
  - MASTG-TEST-0282 (Unsafe Custom Trust Evaluation): Android MASVS-NETWORK test on the MASTG index page that targets custom `X509TrustManager` code like `MyTrustManager.java`; not in the reference file.
- **Evidence plan:** On ghera27 (API 27, inside the README range), start `python index_https_expired.py` from `../../Misc/LocalServer` (the `keyExpired` certificate, as in `source-script.sh` line 3), run `./gradlew installApi27Debug` in `Benign` and then in `Secure`, launch each app and check that Benign shows "Response From Server:" and Secure shows "Expired certificate! SSL Handshake failed." as asserted in `Testing/benign_app/src/androidTest/java/edu/ksu/cs/benign/Tests.java` line 70 and `Testing/secure_app/src/androidTest/java/edu/ksu/cs/secure/Tests.java` line 70. Not yet run.
- **README vs code differences:**
  - The README says Benign connects "as a result of improper implementation of the *checkValidity* in *checkServerTrusted()*"; Benign's `checkServerTrusted()` (`Benign/app/src/main/java/edu/ksu/cs/benign/MyTrustManager.java` lines 16 to 18) does not call `checkValidity()` at all and accepts any certificate.
  - README step 1 asks for a server with an expired certificate and links to the LocalServer README, which documents only `index_http.py` and `index_https.py`; the expired server is `index_https_expired.py`, named only in `source-script.sh` line 3.
- **Open questions:**
  - Secure accepts any non-expired certificate from any issuer (`Secure/app/src/main/java/edu/ksu/cs/benign/MyTrustManager.java` lines 16 to 27, and its own comment on line 17) and any host name (`Secure/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` lines 58 to 63). Whether the benchmark intends Secure to show only the expiry check is not stated in the README.
  - The README names no data that is exposed; the information exposure in the folder name is not tied to any specific data in the code.

### IncorrectHostNameVerification-MITM-Lean
- **Summary:** An app that installs a custom `HostnameVerifier` with weak or missing checks can connect to a server that is not the one it meant to reach. Benign's verifier always returns true, so the local server acting as a man in the middle is accepted.
- **Android versions (from README):** "Tested on Android 5.1.1 - Android 8.1"
- **What the code does:** `Benign/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` lines 83 to 88 set a `HostnameVerifier` whose `verify()` returns true, and lines 57 to 74 also install an anonymous `X509TrustManager` whose `checkServerTrusted()` is empty. Lines 89 to 95 read `https://10.0.2.2:5000/test/` and pass the response to `ResponseActivity`. `Secure/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` line 52 initialises the `SSLContext` with the default trust managers, sets no custom verifier, and lines 69 to 74 show "SSL Handshake failed" on `SSLHandshakeException`.

| Standard | ID | Title | Confidence | Fit |
|----------|----|-------|------------|-----|
| CWE | CWE-297 | Improper Validation of Certificate with Host Mismatch | Verified | Direct. `Benign/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` lines 83 to 88 return true for every host name, so a certificate for any host is accepted. Usage ALLOWED. |
| CWE | CWE-295 | Improper Certificate Validation | Verified | Partial. `Benign/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` lines 57 to 74 install a trust manager with an empty `checkServerTrusted()`. Partial because the README describes only the host name check. Usage ALLOWED. |
| OWASP MASVS v2 | MASVS-NETWORK-1 | The app secures all network traffic according to the current best practices. | Verified | Direct. The HTTPS connection in `Benign/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` lines 81 to 89 runs with no host name or certificate checks. |
| OWASP MASWE | MASWE-0027 | Insecure Certificate Validation | Verified | Partial. `Benign/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` lines 57 to 74 is where the app accepts the connection without the check (see the CWE-295 row); the page covers apps "accepting invalid, expired, self-signed, or untrusted certificates without appropriate verification". Partial for the same reason as the CWE-295 row: the README focuses on another check. Controls shown on the page: MASVS-NETWORK-1. |
| OWASP Mobile Top 10 2024 | M5 | Insecure Communication | Verified | Direct. `Benign/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` lines 83 to 88 accept every host name and lines 57 to 74 trust any certificate; the page lists "Accepting bad ssl certificates" among the flaws it covers, with "self-signed, revoked, expired, wrong host" certificates as its examples. |

No OWASP MASTG test in `standards-reference.md` fits: none of the tests in the file covers host name verification.

MITRE ATT&CK for Mobile: No direct match. No technique on attack.mitre.org was verified that describes an app accepting a TLS server for any host name.

- **Candidates to check:**
  - MASTG-TEST-0283 (Incorrect Implementation of Server Hostname Verification): Android MASVS-NETWORK test on the MASTG index page that matches the verifier in lines 83 to 88; not in the reference file.
  - MASTG-TEST-0282 (Unsafe Custom Trust Evaluation): matches the empty trust manager in lines 57 to 74; not in the reference file.
- **Evidence plan:** On ghera27 (API 27, inside the README range), start `python index_https.py` from `../../Misc/LocalServer` (as in `source-script.sh` line 3), run `./gradlew installApi27Debug` in `Benign` and then in `Secure`, launch each app and check that Benign shows "Response From Server:" and Secure shows "SSL Handshake failed" as asserted in the two `Tests.java` files at line 70. Not yet run.
- **README vs code differences:**
  - README step 8 says to read the server response with `adb logcat | grep "System.out"`; the code prints nothing to `System.out` and shows the response in `Benign/app/src/main/java/edu/ksu/cs/benign/ResponseActivity.java` lines 17 to 23.
  - README step 6 says to edit a *url* field in `strings.xml`; `Benign/app/src/main/res/values/strings.xml` has only `app_name` and `url_extension`, and the address comes from `../../Misc/web-config.gradle` lines 13 to 14.
  - The README describes only the always-true `HostnameVerifier`; Benign also disables certificate trust checks (`Benign/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` lines 57 to 74).
- **Open questions:**
  - The LocalServer certificate `keyOne-publickey.crt` is self-signed and has no CN, so Secure's handshake can fail on the untrusted issuer before any host name check. The Secure test (`Testing/secure_app/src/androidTest/java/edu/ksu/cs/secure/Tests.java` line 70) therefore does not isolate host name verification.
  - Secure catches only `SSLHandshakeException` (`Secure/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` line 69); how a host name mismatch alone surfaces on API 27 (`SSLPeerUnverifiedException` or other) is not shown by the code.

### InsecureSSLSocket-MITM-Lean
- **Summary:** Sockets created with `SSLCertificateSocketFactory.createSocket()` and an `InetAddress` as the first argument do not get host name verification, so an app using them can connect to a man in the middle. Secure passes the host as a string so that host name verification applies.
- **Android versions (from README):** "Tested on Android 5.1.1 - Android 8.1"
- **What the code does:** `Benign/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` line 45 gets `SSLCertificateSocketFactory.getDefault(0)`, line 54 installs a trust-all `X509TrustManager` (defined in lines 27 to 42), and line 55 calls `createSocket(InetAddress, int)` for 10.0.2.2:5000 built in lines 50 to 53. Lines 56 to 60 report "SUCCESS" when `isConnected()` is true, which `ResponseActivity` shows as "Connected to Server". `Secure/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` line 48 calls `createSocket(String, int)` instead, with the same trust-all manager on line 46, and lines 53 to 59 show "Failed to connect to server" on `IOException`.

| Standard | ID | Title | Confidence | Fit |
|----------|----|-------|------------|-----|
| CWE | CWE-297 | Improper Validation of Certificate with Host Mismatch | Verified | Direct. `Benign/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` line 55 opens the socket with an `InetAddress`, which per the README performs no host name check. Usage ALLOWED. |
| CWE | CWE-295 | Improper Certificate Validation | Verified | Partial. `Benign/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` line 54 installs a trust manager whose `checkServerTrusted()` is empty (lines 37 to 40). Partial because the README is about host name checks and Secure keeps the same trust manager (`Secure/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` line 46). Usage ALLOWED. |
| OWASP MASVS v2 | MASVS-NETWORK-1 | The app secures all network traffic according to the current best practices. | Verified | Direct. The TLS socket in `Benign/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` lines 45 to 55 has neither host name nor certificate checks. |
| OWASP MASWE | MASWE-0027 | Insecure Certificate Validation | Verified | Partial. `Benign/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` line 54 is where the app accepts the connection without the check (see the CWE-295 row); the page covers apps "accepting invalid, expired, self-signed, or untrusted certificates without appropriate verification". Partial for the same reason as the CWE-295 row: the README focuses on another check. Controls shown on the page: MASVS-NETWORK-1. |
| OWASP Mobile Top 10 2024 | M5 | Insecure Communication | Verified | Direct. `Benign/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` line 55 opens a TLS socket with no host name check and line 54 installs a trust-all manager; the page lists "Accepting bad ssl certificates" among the flaws it covers, with "self-signed, revoked, expired, wrong host" certificates as its examples. |

No OWASP MASTG test in `standards-reference.md` fits: none of the tests in the file covers TLS sockets.

MITRE ATT&CK for Mobile: No direct match. No technique on attack.mitre.org was verified that describes an app opening a TLS socket without host name verification.

- **Candidates to check:**
  - MASTG-TEST-0234 (Missing Implementation of Server Hostname Verification with SSLSockets): Android MASVS-NETWORK test on the MASTG index page that matches line 55; not in the reference file.
  - MASTG-TEST-0282 (Unsafe Custom Trust Evaluation): matches the trust-all manager in lines 27 to 42; not in the reference file.
- **Evidence plan:** On ghera27 (API 27, inside the README range), compile and start `java WriteToSocket 5000` from `../../Misc/LocalServer/java` (as in `source-script.sh` `before_test_vuln`; this is a plain TCP server, not the Flask LocalServer), run `./gradlew installApi27Debug` in `Benign` and then in `Secure`, launch each app and check that Benign shows "Connected to Server" and Secure shows "Failed to connect to server" as asserted in the two `Tests.java` files at line 70. Not yet run.
- **README vs code differences:**
  - The README names `SSLCertificateSocketFactory.getSocket(InetAddress, ...)`; the code calls `createSocket(InetAddress, int)` (`Benign/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` line 55).
  - README step 1 sets up the Flask LocalServer; `source-script.sh` starts `WriteToSocket.java`, a plain TCP server with no TLS.
  - README step 8 says to read the response with `adb logcat | grep "System.out"`; the app reads no response and only shows "Connected to Server" (`Benign/app/src/main/java/edu/ksu/cs/benign/ResponseActivity.java` lines 15 to 18).
  - README step 6 says to edit a *url* field in `strings.xml`; `Benign/app/src/main/res/values/strings.xml` has only `app_name`.
  - The README says the factory "does not perform any SSL security checks"; the code also installs an explicit trust-all manager (`Benign/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` line 54).
- **Open questions:**
  - Benign succeeds when `isConnected()` is true (line 56) and never starts a handshake or reads data, so against the plain TCP `WriteToSocket` server the Benign test may pass on the TCP connection alone.
  - Secure's `createSocket(String, int)` against a non-TLS server would fail for reasons other than host name verification, so the Secure test may pass whatever the host name check does.
  - Secure keeps the trust-all manager (`Secure/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` line 46), so it relies on host name verification alone.

### InsecureSSLSocketFactory-MITM-Lean
- **Summary:** `SSLCertificateSocketFactory.getInsecure()` returns a socket factory that skips TLS checks, so an app using it can connect to a man in the middle. Secure uses `getDefault()` instead.
- **Android versions (from README):** "Tested on Android 5.1.1 - Android 8.1"
- **What the code does:** `Benign/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` line 44 gets `SSLCertificateSocketFactory.getInsecure(0xFFFFFFFF, null)`, line 49 sets it on the `HttpsURLConnection`, and lines 50 to 55 add a `HostnameVerifier` that returns true. Lines 57 to 63 read `https://10.0.2.2:5000/test/` and show the response in `ResponseActivity`. `Secure/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` line 43 uses `getDefault(0xFFFFFFFF, null)`, sets no custom verifier, and lines 60 to 65 show "SSL Handshake failed" on `SSLHandshakeException`.

| Standard | ID | Title | Confidence | Fit |
|----------|----|-------|------------|-----|
| CWE | CWE-295 | Improper Certificate Validation | Verified | Direct. `Benign/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` line 44 uses `getInsecure()`, which the README says "does not perform any SSL security checks", and line 49 applies it to the connection. Usage ALLOWED. |
| CWE | CWE-297 | Improper Validation of Certificate with Host Mismatch | Verified | Partial. `Benign/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` lines 50 to 55 accept any host name. Partial because the README attributes the missing host name check to `getInsecure()`, while in the code it comes from this separate verifier. Usage ALLOWED. |
| OWASP MASVS v2 | MASVS-NETWORK-1 | The app secures all network traffic according to the current best practices. | Verified | Direct. The HTTPS connection in `Benign/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` lines 44 to 57 runs without certificate or host name checks. |
| OWASP MASWE | MASWE-0027 | Insecure Certificate Validation | Verified | Direct. `Benign/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` line 44 is where the app accepts the connection without the check (see the CWE-295 row); the page covers apps "accepting invalid, expired, self-signed, or untrusted certificates without appropriate verification". Controls shown on the page: MASVS-NETWORK-1. |
| OWASP Mobile Top 10 2024 | M5 | Insecure Communication | Verified | Direct. `Benign/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` line 44 uses `getInsecure()` and lines 50 to 55 accept every host name; the page lists "Accepting bad ssl certificates" among the flaws it covers, with "self-signed, revoked, expired, wrong host" certificates as its examples. |

No OWASP MASTG test in `standards-reference.md` fits: none of the tests in the file covers TLS socket factories.

MITRE ATT&CK for Mobile: No direct match. No technique on attack.mitre.org was verified that describes an app using an insecure TLS socket factory.

- **Candidates to check:**
  - MASTG-TEST-0283 (Incorrect Implementation of Server Hostname Verification): matches the verifier in lines 50 to 55; not in the reference file.
  - MASTG-TEST-0282 (Unsafe Custom Trust Evaluation): Android MASVS-NETWORK test on the MASTG index page; whether its scope includes `getInsecure()` needs reading its page; not in the reference file.
- **Evidence plan:** On ghera27 (API 27, inside the README range), start `python index_https.py` from `../../Misc/LocalServer` (as in `source-script.sh` line 3), run `./gradlew installApi27Debug` in `Benign` and then in `Secure`, launch each app and check that Benign shows "Response From Server:" and Secure shows "SSL Handshake failed" as asserted in the two `Tests.java` files at line 70. Not yet run.
- **README vs code differences:**
  - The README says `getInsecure()` is what lets the app accept any host; Benign also sets an always-true `HostnameVerifier` (`Benign/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` lines 50 to 55).
  - README step 6 says to edit a *url* field in `strings.xml`; `Benign/app/src/main/res/values/strings.xml` has only `app_name` and `url_extension`, and the address comes from `../../Misc/web-config.gradle` lines 13 to 14.
- **Open questions:**
  - Both apps pass `0xFFFFFFFF` (the int value -1) as the handshake timeout (Benign line 44, Secure line 43); how `SSLCertificateSocketFactory` treats a negative timeout on API 27 is not shown by the code.
  - The Secure test fails the handshake against the self-signed `keyOne` certificate, so it shows the CA check; it does not separately show host name verification.

### InvalidCertificateAuthority-MITM-Lean
- **Summary:** An app with a custom `X509TrustManager` whose `checkServerTrusted()` is not implemented will trust a server signed by any certificate authority, including a self-signed man in the middle. Secure uses the default trust managers.
- **Android versions (from README):** "Tested on Android 5.1.1 - Android 8.1"
- **What the code does:** `Benign/app/src/main/java/edu/ksu/cs/benign/MyTrustManager.java` lines 16 to 18 leave `checkServerTrusted()` empty and line 22 returns null from `getAcceptedIssuers()`. `Benign/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` lines 54 to 56 install it, lines 65 to 70 set a `HostnameVerifier` that returns true, and lines 71 to 78 read `https://10.0.2.2:5000/test/` and show the response. `Secure/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` line 52 calls `sslContext.init(null, null, null)` and lines 69 to 75 show "SSL Handshake failed" on `SSLHandshakeException`.

| Standard | ID | Title | Confidence | Fit |
|----------|----|-------|------------|-----|
| CWE | CWE-295 | Improper Certificate Validation | Verified | Direct. `Benign/app/src/main/java/edu/ksu/cs/benign/MyTrustManager.java` lines 16 to 18 accept a certificate from any issuer, which is the case the README describes. Usage ALLOWED. |
| CWE | CWE-297 | Improper Validation of Certificate with Host Mismatch | Verified | Partial. `Benign/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` lines 65 to 70 accept any host name. Partial because the README covers only the certificate authority check. Usage ALLOWED. |
| OWASP MASVS v2 | MASVS-NETWORK-1 | The app secures all network traffic according to the current best practices. | Verified | Direct. The HTTPS connection in `Benign/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` lines 54 to 71 trusts any server. |
| OWASP MASWE | MASWE-0027 | Insecure Certificate Validation | Verified | Direct. `Benign/app/src/main/java/edu/ksu/cs/benign/MyTrustManager.java` lines 16 to 18 is where the app accepts the connection without the check (see the CWE-295 row); the page covers apps "accepting invalid, expired, self-signed, or untrusted certificates without appropriate verification". Controls shown on the page: MASVS-NETWORK-1. |
| OWASP Mobile Top 10 2024 | M5 | Insecure Communication | Verified | Direct. `Benign/app/src/main/java/edu/ksu/cs/benign/MyTrustManager.java` lines 16 to 18 accept a certificate from any issuer; the page lists "Accepting bad ssl certificates" among the flaws it covers, with "self-signed, revoked, expired, wrong host" certificates as its examples. |

No OWASP MASTG test in `standards-reference.md` fits: none of the tests in the file covers TLS trust managers.

MITRE ATT&CK for Mobile: No direct match. No technique on attack.mitre.org was verified that describes an app trusting a server signed by an untrusted certificate authority.

- **Candidates to check:**
  - MASTG-TEST-0282 (Unsafe Custom Trust Evaluation): Android MASVS-NETWORK test on the MASTG index page that matches `MyTrustManager.java`; not in the reference file.
- **Evidence plan:** On ghera27 (API 27, inside the README range), start `python index_https.py` from `../../Misc/LocalServer` (as in `source-script.sh` line 3), run `./gradlew installApi27Debug` in `Benign` and then in `Secure`, launch each app and check that Benign shows "Response From Server:" and Secure shows "SSL Handshake failed" as asserted in the two `Tests.java` files at line 70. Not yet run.
- **README vs code differences:**
  - The README names the trust manager methods as *checkClientTrusted()*, *checkServerTrusted()* and *getAcceptedUsers()*; the third method in the code is `getAcceptedIssuers()` (`Benign/app/src/main/java/edu/ksu/cs/benign/MyTrustManager.java` line 21).
  - README step 8 says to read the response with `adb logcat | grep "System.out"`; the code shows the response in `ResponseActivity` and prints nothing to `System.out`.
  - README step 6 says to edit a *url* field in `strings.xml`; `Benign/app/src/main/res/values/strings.xml` has only `app_name` and `url_extension`.
  - The README does not mention the always-true `HostnameVerifier` in `Benign/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` lines 65 to 70.
- **Open questions:**
  - None beyond the shared note that the LocalServer `keyOne` certificate's validity ended on 18 May 2019 (read from `../../Misc/LocalServer/keys/keyOne-publickey.crt`); Benign ignores this because it checks nothing, and Secure would reject the server for expiry as well as for the untrusted issuer.

### OpenSocket-InformationLeak-Lean
- **Summary:** An app that listens on a port and sends data to whoever connects, without checking who the peer is, leaks that data to any connecting party. Malicious connects to Benign's open port and reads the contents of Benign's private file `myInfo.txt`.
- **Android versions (from README):** "Tested on Android 5.1.1 - Android 8.1"
- **What the code does:** `Benign/app/src/main/java/edu/ksu/cs/benign/MainActivity.java` lines 31 to 34 write the TextView text to the private file `myInfo.txt` and start `MyIntentService`. `Benign/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` lines 32 to 41 open `ServerSocket(5000)`, accept the first connection and copy `myInfo.txt` to it with no check of the peer. `Malicious/app/src/main/java/edu/ksu/cs/malicious/MyIntentService.java` lines 24 and 35 to 48 connect to 127.0.0.1:5000 and show what they read in `Result`. `Secure/app/src/main/java/edu/ksu/cs/secure/MyIntentService.java` line 36 sends the file only if `s.getInetAddress().getHostName()` equals "trusted.remote.com" and otherwise writes "Rejected" (lines 45 to 49).

| Standard | ID | Title | Confidence | Fit |
|----------|----|-------|------------|-----|
| CWE | CWE-940 | Improper Verification of Source of a Communication Channel | Verified | Direct. `Benign/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` lines 32 to 41 accept an incoming connection and act on it without verifying that it comes from the expected server, which matches the CWE description ("does not properly verify that the request is coming from the expected origin"). Usage ALLOWED. |
| CWE | CWE-359 | Exposure of Private Personal Information to an Unauthorized Actor | Verified | Partial. The README says `myInfo.txt` "stores sensitive information", and the text written there is "Enter SSN" (`Benign/app/src/main/res/layout/activity_main.xml` line 16), sent to the socket in `MyIntentService.java` lines 39 to 41. Partial because the value is a fixed label, not real personal data entered by a user. Usage ALLOWED. |
| OWASP MASVS v2 | MASVS-NETWORK-1 | The app secures all network traffic according to the current best practices. | Verified | Partial. `Benign/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` line 32 opens an unauthenticated plain TCP listener. Partial because in the code the peer is another app on the same device (`Malicious/app/src/main/java/edu/ksu/cs/malicious/MyIntentService.java` line 24), not a remote network attacker. |
| OWASP MASVS v2 | MASVS-STORAGE-2 | The app prevents leakage of sensitive data. | Verified | Partial. Lines 33 and 39 to 41 of `Benign/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` copy the private file to any connected peer. Partial because the leaked value is a placeholder label. |
| OWASP MASVS v2 | MASVS-PLATFORM-1 | The app uses IPC mechanisms securely. | Verified | Partial. In the code the open port acts as a channel between two apps on the device (Malicious connects to 127.0.0.1). Partial because a TCP socket is not an Android IPC mechanism and the README describes the peer as a remote server. |
| OWASP Mobile Top 10 2024 | M5 | Insecure Communication | Verified | Partial. `Benign/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` lines 32 to 41 send a private file over a plain TCP socket to any peer, which is data going "from point A to point B, but doing it insecurely" in the page's words. Partial because in the code the peer is another app on the same device (`Malicious/app/src/main/java/edu/ksu/cs/malicious/MyIntentService.java` line 24), not an attacker on the network path the page describes. |

CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor), the draft entry in `benchmark-index.md`, was considered and is DISCOURAGED in `standards-reference.md`, so it is not in the table; CWE-940 (root cause) and CWE-359 (data exposed) are used instead.

No OWASP MASTG test or MASWE entry in `standards-reference.md` fits: MASWE-0018 and the MASTG tests in the file cover Android app components (activities, services, receivers, providers), and Benign's listener is a TCP socket, not a component.

MITRE ATT&CK for Mobile: No direct match. No technique on attack.mitre.org was verified that describes one app reading data from another app's open local port.

- **Candidates to check:**
  - CWE-1327 (Binding to an Unrestricted IP Address): `new ServerSocket(PORT)` on line 32 binds to all interfaces; official page title and Usage ALLOWED read on 2026-11-01, not in the reference file.
  - CWE-306 (Missing Authentication for Critical Functionality): the listener sends the file with no authentication; official page title and Usage ALLOWED read on 2026-11-01, not in the reference file.
  - CWE-350 (Reliance on Reverse DNS Resolution for a Security-Critical Action): describes the check in `Secure/app/src/main/java/edu/ksu/cs/secure/MyIntentService.java` line 36, so it is a candidate for the Secure fix's remaining weakness; official page title and Usage ALLOWED read on 2026-11-01, not in the reference file.
- **Evidence plan:** On ghera27 (API 27, inside the README range), run `./gradlew installApi27Debug` in `Benign` and in `Malicious`, tap "Open Port" in Benign, then tap "Connect" in Malicious and check that Malicious shows "Enter SSN"; then replace Benign with `Secure` (same application id `edu.ksu.cs.benign`) and check that Malicious shows "Rejected", as asserted in `Testing/benign_app/src/androidTest/java/edu/ksu/cs/benign/Tests.java` line 80 and `Testing/secure_app/src/androidTest/java/edu/ksu/cs/secure/Tests.java` line 80; this benchmark has no `source-script.sh` and does not use `Misc/LocalServer`. Not yet run.
- **README vs code differences:**
  - The README says Malicious "scans open ports on the device"; Malicious connects to one fixed address and port, 127.0.0.1 (`Malicious/app/src/main/java/edu/ksu/cs/malicious/MyIntentService.java` line 24) and `local_server_port` 5000 (line 32, value from `../../Misc/web-config.gradle` line 14).
  - README step 7 says to set *HOST* in Malicious to the emulator's IP address; the code already uses 127.0.0.1.
  - The README describes `myInfo.txt` as holding sensitive information; Benign writes the fixed TextView label "Enter SSN" (`Benign/app/src/main/res/layout/activity_main.xml` line 16), which the user cannot edit.
- **Open questions:**
  - Secure trusts the peer based on a reverse DNS name (`Secure/app/src/main/java/edu/ksu/cs/secure/MyIntentService.java` line 36). No test or README step shows Secure sending the file to a trusted peer, and whether a reverse lookup name is a sufficient check is not discussed in the README.
  - The Secure listener still binds to all interfaces on port 5000 (line 32).

### UnEncryptedSocketComm-MITM-Lean
- **Summary:** An app that talks to a server over a plain TCP socket can be intercepted, and a man in the middle can pose as the server. Benign connects in cleartext and accepts whatever the `WriteToSocket` program sends.
- **Android versions (from README):** "Tested on Android 5.1.1 - Android 8.1"
- **What the code does:** `Benign/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` lines 36 to 38 open a plain `java.net.Socket` to `local_server_ipv4`:`local_server_port` (10.0.2.2:5000), and lines 41 to 48 read every byte and show it in the `Result` activity. Nothing authenticates the server or encrypts the stream. `Secure/app/src/main/java/edu/ksu/cs/secure/MyIntentService.java` lines 39 to 41 create an `SSLSocket` from `SSLSocketFactory.getDefault()` and then call `connect()` on it, and lines 52 to 54 show the exception text on `IOException`.

| Standard | ID | Title | Confidence | Fit |
|----------|----|-------|------------|-----|
| CWE | CWE-319 | Cleartext Transmission of Sensitive Information | Verified | Partial. `Benign/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` lines 36 to 38 use an unencrypted socket. Partial because the README's stated consequence is server spoofing rather than disclosure, and the data received ("The contents will be written to a socket.", `../../Misc/LocalServer/java/myInfo.txt`) is not described as sensitive. Usage ALLOWED. |
| OWASP MASVS v2 | MASVS-NETWORK-1 | The app secures all network traffic according to the current best practices. | Verified | Direct. All traffic in `Benign/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` lines 36 to 46 is plain TCP with no TLS. |
| OWASP MASWE | MASWE-0026 | Network Traffic Not Encrypted | Verified | Direct. `Benign/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` lines 36 to 38 open an unencrypted socket (see the CWE-319 row); the page covers apps that transmit data "in cleartext, i.e. without encryption" and says this remains a weakness even when no sensitive data is sent. Controls shown on the page: MASVS-NETWORK-1. |
| OWASP Mobile Top 10 2024 | M5 | Insecure Communication | Verified | Direct. `Benign/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` lines 36 to 38 open a plain TCP socket; the page covers data an attacker can "intercept and modify" when "transmitted in plaintext". |

No OWASP MASTG test in `standards-reference.md` fits: none of the tests in the file covers cleartext traffic.

MITRE ATT&CK for Mobile: No direct match. No technique on attack.mitre.org was verified that describes intercepting or spoofing an app's plain TCP connection.

- **Candidates to check:**
  - CWE-923 (Improper Restriction of Communication Channel to Intended Endpoints): covers the missing server authentication that enables spoofing; official page title read on 2026-11-01, Usage ALLOWED-WITH-REVIEW (Reason: Abstraction), so it would need the mapping-notes review before use; not in the reference file.
  - MASTG-TEST-0239 (Using low-level APIs (e.g. Socket) to set up a custom HTTP connection) and MASTG-TEST-0236 (Cleartext Traffic Observed on the Network): Android MASVS-NETWORK tests on the MASTG index page; not in the reference file.
  - CWE-300 (Channel Accessible by Non-Endpoint) was also looked at; its official page gives Usage DISCOURAGED (Frequent Misuse), so it is not proposed.
- **Evidence plan:** On ghera27 (API 27, inside the README range), compile and start `java WriteToSocket 5000` from `../../Misc/LocalServer/java` (as in `source-script.sh` `before_install_vuln`), run `./gradlew installApi27Debug` in `Benign`, tap "Connect" and check that `Result` shows "The contents will be written to a socket" (`Testing/benign_app/src/androidTest/java/edu/ksu/cs/benign/Tests.java` line 72); then install `Secure`, tap "Connect" and check for "Permission denied" (`Testing/secure_app/src/androidTest/java/edu/ksu/cs/secure/Tests.java` line 72). Not yet run.
- **README vs code differences:**
  - README step 6 says *HOST* is an attribute in Benign's `MyIntentService` to be set by hand; the code reads it from the `local_server_ipv4` resource (`Benign/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` line 32), set to 10.0.2.2 in `../../Misc/web-config.gradle` line 13.
  - README step 5 runs `java WriteToSocket` with no argument; `../../Misc/LocalServer/java/WriteToSocket.java` lines 12 to 17 exit with "PORT not found" when no port is given.
- **Open questions:**
  - `Secure/app/src/main/AndroidManifest.xml` declares no `android.permission.INTERNET`, and the Secure test expects "Permission denied". The Secure test therefore appears to pass because the socket is not allowed, not because TLS protects the connection.
  - Secure calls `connect()` (line 41) on a socket that `createSocket(HOST, PORT)` (line 40) already connected. Even with the permission, the TLS path would not be exercised as written.
  - `WriteToSocket` is plain TCP, so a correct TLS client would fail the handshake against it; no TLS server is provided for a positive Secure case.

### UnpinnedCertificates-MITM-Lean
- **Summary:** An app that trusts every server whose certificate chains to a trusted CA, instead of pinning the expected server certificate, will connect to a malicious server that holds a CA-signed certificate. Secure trusts only the bundled `keyTwo` certificate.
- **Android versions (from README):** "Tested on Android 5.1.1 - Android 8.1"
- **What the code does:** `Benign/app/src/main/java/edu/ksu/cs/benign/MyTrustManager.java` lines 49 to 66 accept the chain only if every certificate equals the bundled asset `keyOne-publickey.crt`, which is the LocalServer certificate; the comment on lines 25 to 28 explains this stands in for "a certificate signed by one of the trusted CAs". `Benign/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` lines 52 to 73 use it, with a `HostnameVerifier` that returns `hostname.equals("10.0.2.2")` (lines 64 to 69). `Secure/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` lines 58 to 74 build a `KeyStore` holding only `keyTwo-publickey.crt` and use it as the only trust anchor, and lines 94 to 96 show the exception text on failure.

| Standard | ID | Title | Confidence | Fit |
|----------|----|-------|------------|-----|
| CWE | CWE-295 | Improper Certificate Validation | Verified | Partial. The README's weakness is that Benign accepts any CA-trusted server; the code simulates this with `Benign/app/src/main/java/edu/ksu/cs/benign/MyTrustManager.java` lines 58 to 64, which accept the LocalServer certificate. Partial because CWE-295 is about validation being wrong, while here validation is correct for a CA model and the gap is the missing pin. Usage ALLOWED. |
| CWE | CWE-297 | Improper Validation of Certificate with Host Mismatch | Verified | Partial. `Benign/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` line 67 compares the requested host name with "10.0.2.2" and never checks the certificate in the `SSLSession`. Partial because the README does not discuss host names and Secure has the same check (`Secure/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` line 86). Usage ALLOWED. |
| OWASP MASVS v2 | MASVS-NETWORK-2 | The app performs identity pinning for all remote endpoints under the developer's control. | Verified | Direct. Benign does not pin its intended server, and Secure pins `keyTwo-publickey.crt` (`Secure/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` lines 58 to 65). |
| OWASP MASVS v2 | MASVS-NETWORK-1 | The app secures all network traffic according to the current best practices. | Verified | Partial. TLS is used in both apps; the gap is the trust decision in `Benign/app/src/main/java/edu/ksu/cs/benign/MyTrustManager.java` lines 49 to 66, which NETWORK-2 covers more precisely. |
| OWASP Mobile Top 10 2024 | M5 | Insecure Communication | Verified | Direct. `Benign/app/src/main/java/edu/ksu/cs/benign/MyTrustManager.java` lines 49 to 66 trust the server without a pin, and Secure pins `keyTwo-publickey.crt` (`Secure/app/src/main/java/edu/ksu/cs/benign/MyIntentService.java` lines 58 to 65); the page says "Consider certificate pinning." under prevention. |

No OWASP MASTG test or MASWE entry in `standards-reference.md` fits: the file lists only entries about app components, intents, overlays and untrusted input, and none of them covers certificate pinning.

MITRE ATT&CK for Mobile: No direct match. No technique on attack.mitre.org was verified that describes a man in the middle using a CA-signed certificate against an app without pinning.

- **Candidates to check:**
  - MASWE-0028 (Insecure Identity Pinning): listed under MASVS-NETWORK on the MASWE index page; not in the reference file.
  - MASTG-TEST-0244 (Missing Certificate Pinning in Network Traffic): Android MASVS-NETWORK test on the MASTG index page; not in the reference file.
  - MASTG-TEST-0242 (Missing Certificate Pinning in Network Security Configuration): would fit only partially, because neither app has a network security configuration and pinning is done in code; not in the reference file.
- **Evidence plan:** On ghera27 (API 27, inside the README range), start `python index_https.py` from `../../Misc/LocalServer` (the `keyOne` server, as in `source-script.sh` line 3), run `./gradlew installApi27Debug` in `Benign` and then in `Secure`, launch each app and check that Benign's `serverResponseText` contains "This is a test web page" and Secure's `headingText` contains "SSLHandshakeException" (the two `Tests.java` files at line 70); optionally start `TrustedServer/index_https-Unpinned-Cert.py` (the `keyTwo` server) to see Secure connect. Not yet run.
- **README vs code differences:**
  - The README says Benign "trusts all the servers having certificate signed by trusted CAs"; Benign's trust manager accepts only certificates equal to the bundled `keyOne-publickey.crt` (`Benign/app/src/main/java/edu/ksu/cs/benign/MyTrustManager.java` lines 54 to 64). The code comment on lines 25 to 28 states this is a stand-in.
  - README step 8 says the result "demonstrates that *Benign* does not verify the Certificate Authority", and mentions a console; the benchmark is about pinning, and the response is shown in `ResponseActivity`.
  - README step 6 says to edit a *url* field in `strings.xml`; `Benign/app/src/main/res/values/strings.xml` has only `app_name` and `url_extension`.
- **Open questions:**
  - `keyOne-publickey.crt` (validity ended 18 May 2019) and `keyTwo-publickey.crt` (validity ended 14 May 2019) are expired according to the certificate files. Benign calls `checkValidity()` (`Benign/app/src/main/java/edu/ksu/cs/benign/MyTrustManager.java` line 61), so the Benign case may fail on a current emulator clock; whether the emulator date must be set back is not stated in the README.
  - `source-script.sh` never starts the `TrustedServer`, so no automated test shows Secure connecting to its pinned server; the Secure test passes on any `SSLHandshakeException`.
  - Benign's `checkClientTrusted()` (lines 23 to 45) repeats the server logic and is not used for the server connection.

## NonAPI (2)

### MergeManifest-UnintendedBehavior-Lean
- **Summary:** When an app uses a library that has its own manifest, the build merges that manifest into the app's, so any component the library exports becomes part of the app. In the example, a logging library brings in an exported service that another app can start to acquire a wake lock.
- **Android versions (from README):** "Tested on Android 5.1.1 - Android 8.1"
- **What the code does:** `Benign/app/build.gradle` line 18 adds the `logutil` module, and `Benign/app/src/main/java/edu/ksu/cs/benign/MainActivity.java` line 14 uses only its `LogDebug.d` logging call. The library manifest `Benign/logutil/src/main/AndroidManifest.xml` lines 7 to 13 declare `BackgroundService` with `android:exported="true"` and no permission, and line 5 requests `WAKE_LOCK`; Benign's own manifest declares neither (`Benign/app/src/main/AndroidManifest.xml` lines 5 to 19). `Benign/logutil/src/main/java/edu/ksu/cs/logutil/BackgroundService.java` lines 16 to 23 acquire a partial wake lock, start `DisplayActivity` and release the lock for any non-null intent. `Malicious/app/src/main/java/edu/ksu/cs/malicious/MainActivity.java` lines 22 to 25 start that service by explicit class name in `edu.ksu.cs.benign`.

| Standard | ID | Title | Confidence | Fit |
|----------|----|-------|------------|-----|
| CWE | CWE-926 | Improper Export of Android Application Components | Verified | Direct. `BackgroundService` is exported with no permission in the library manifest (`Benign/logutil/src/main/AndroidManifest.xml` lines 7 to 9) and ends up in Benign through the merge (`Benign/app/build.gradle` line 18). Usage ALLOWED. |
| CWE | CWE-1395 | Dependency on Vulnerable Third-Party Component | Verified | Partial. Benign depends on `logutil` (`Benign/app/build.gradle` line 18), which carries the exported service. Usage ALLOWED-WITH-REVIEW; review outcome: the mapping notes say this Class has no Base-level children and ask for a root cause analysis. Here the original mistake is the library's export, which CWE-926 already names, and the library has no published known vulnerability, so CWE-1395 is kept only as a secondary, partial entry. |
| OWASP MASVS v2 | MASVS-PLATFORM-1 | The app uses IPC mechanisms securely. | Verified | Direct. Exported, unprotected service at `Benign/logutil/src/main/AndroidManifest.xml` lines 7 to 13. |
| OWASP MASVS v2 | MASVS-CODE-3 | The app only uses software components without known vulnerabilities. | Verified | Partial. The weakness comes from the included `logutil` component (`Benign/app/build.gradle` line 18), but the component's flaw is not a published known vulnerability. |
| OWASP MASTG test | MASTG-TEST-0365 | Exported And Unprotected Services That Expose Sensitive Functionality | Verified | Direct. Any app can start `BackgroundService`, which acquires a wake lock and starts an activity (`BackgroundService.java` lines 17 to 22). |
| OWASP MASTG test | MASTG-TEST-0029 | Testing for Sensitive Functionality Exposure Through IPC | Verified | Partial. Deprecated, kept for reference only. |
| OWASP MASWE | MASWE-0018 | Lack of Authentication or Authorization on App Components | Verified | Direct. The merged service has no permission (`Benign/logutil/src/main/AndroidManifest.xml` lines 7 to 9) and Malicious starts it directly (`Malicious/.../MainActivity.java` lines 22 to 25). Controls shown on the page: MASVS-AUTH-1, MASVS-PLATFORM-1, MASVS-STORAGE-2. |

MITRE ATT&CK for Mobile: No direct match. No technique on attack.mitre.org was verified that describes starting a service another app inherited from a library manifest.

- **Candidates to check:**
  - CWE-1357 (Reliance on Insufficiently Trustworthy Component): the parent of CWE-1395 shown on its page; it describes depending on a component without checking what it brings in, as with `logutil` here.
- **Evidence plan:** On the ghera27 emulator (API 27, inside the README range), install Benign and Malicious, launch Benign then Malicious, and check `adb logcat -d | grep LogUtilLib` for "Long running background service" and that `DisplayActivity` shows "Background Service started"; then start the service without Malicious using `adb shell am startservice -n edu.ksu.cs.benign/edu.ksu.cs.logutil.BackgroundService`. There is no Secure app. Not yet run.
- **README vs code differences:**
  - The README says the service "keeps the device screen unlocked"; `BackgroundService.java` line 18 takes a `PARTIAL_WAKE_LOCK`, which keeps the CPU on rather than the screen, and line 23 releases it right after starting `DisplayActivity`.
  - The README says the benchmark has no Secure app, but `Testing/secure_app` exists and its only test is `assert true;` (`Testing/secure_app/src/androidTest/java/edu/ksu/cs/secure/Tests.java` line 29), so it always passes.
- **Open questions:**
  - The README says there is "no way to secure the app against this vulnerability programmatically" and points to the manifest merge documentation; whether a merge rule in Benign's manifest that removes or unexports the service counts as the intended fix is not stated.
  - The merge also adds `WAKE_LOCK` (`Benign/logutil/src/main/AndroidManifest.xml` line 5) to Benign's permissions, which Benign's own code does not use.
  - The library's intent filter uses the action `android.intent.action.BKSERVICE` (`Benign/logutil/src/main/AndroidManifest.xml` line 11), in the platform's action namespace; Malicious does not use it.

### OutdatedLibrary-DirectoryTraversal-Lean
- **Summary:** An app that keeps using an old version of a library inherits the bugs fixed in later versions. In the example, version 1.0 of a file-writing library does not check the file name for `../`, so another app can make Benign write a file into its own cache folder.
- **Android versions (from README):** "Tested on Android 5.1.1 - Android 8.1"
- **What the code does:** `Benign/app/build.gradle` line 18 and `Benign/writetofilelibrary-1.0/build.gradle` line 2 link the version 1.0 AAR. `Benign/app/src/main/java/edu/ksu/cs/benign/MainActivity.java` lines 23 to 35 copy the `fileName` and `fileContent` extras from the incoming intent into an intent for the library's `WriteActivity`; `MainActivity` is the exported launcher activity (`Benign/app/src/main/AndroidManifest.xml` lines 12 to 18). `Library/version1.0/src/main/java/com/example/writetofilelibrary/WriteActivity.java` lines 27 to 41 accept any non-empty name and write the content to `new File(getFilesDir()/custom, fileNm)`; version 1.1 adds `!i.getStringExtra("fileName").contains("..")` (`Library/version1.1/src/main/java/com/example/writetofilelibrary/WriteActivity.java` line 29), and Secure links 1.1 (`Secure/app/build.gradle` line 18). `Malicious/app/src/main/java/edu/ksu/cs/malicious/MainActivity.java` lines 29 to 36 send `../../cache/malicious.txt` to Benign's `MainActivity`.

| Standard | ID | Title | Confidence | Fit |
|----------|----|-------|------------|-----|
| CWE | CWE-1395 | Dependency on Vulnerable Third-Party Component | Verified | Direct. Benign links library 1.0 (`Benign/app/build.gradle` line 18), whose flaw at `WriteActivity.java` line 38 is fixed in 1.1 (line 29), and the README presents the outdated dependency as the weakness. Usage ALLOWED-WITH-REVIEW; review outcome: the mapping notes say this Class has no Base-level children and that, if root cause analysis confirms it, it may be the best available entry. The root cause in Benign is staying on the old version, so CWE-1395 is used, with CWE-22 for the flaw inside the library. |
| CWE | CWE-22 | Improper Limitation of a Pathname to a Restricted Directory | Verified | Partial. `WriteActivity.java` (1.0) line 38 joins the caller's name to `files/custom` with no check, so `../../cache/malicious.txt` (Malicious line 29) escapes it. Usage ALLOWED-WITH-REVIEW; review outcome: the mapping notes suggest CWE-23 for relative path traversal and CWE-36 for absolute. This is a relative traversal, so CWE-23 is the better fit, but it is not in the reference file and is listed as a candidate; CWE-22 is kept as Partial until then. |
| OWASP MASVS v2 | MASVS-CODE-3 | The app only uses software components without known vulnerabilities. | Verified | Direct. Library 1.0 linked at `Benign/app/build.gradle` line 18. |
| OWASP MASVS v2 | MASVS-CODE-4 | The app validates and sanitizes all untrusted inputs. | Verified | Partial. The file name from another app is used unchecked (`MainActivity.java` lines 25 and 33, `WriteActivity.java` line 38). Partial because the README places the fault in the library version. |
| OWASP MASVS v2 | MASVS-PLATFORM-1 | The app uses IPC mechanisms securely. | Verified | Partial. The exported launcher `MainActivity` forwards caller extras to `WriteActivity` (`MainActivity.java` lines 23 to 35). |
| OWASP MASTG test | MASTG-TEST-0364 | Exported And Unprotected Activities That Expose Sensitive Functionality | Verified | Partial. `MainActivity` is exported (Benign manifest lines 12 to 18) and lets any app write a file of its choosing through the library (`MainActivity.java` lines 24 to 35). Partial because a launcher activity has to be exported; the weakness is the unchecked forwarding. |
| OWASP MASWE | MASWE-0032 | Insecure Intents | Verified | Partial. `MainActivity.java` lines 24 to 35 act on extras from an untrusted intent and pass them to `startActivityForResult` without validation, which the page lists. Partial because the target is Benign's own library activity. Controls shown on the page: MASVS-PLATFORM-1, MASVS-STORAGE-2. |
| OWASP MASWE | MASWE-0050 | Unsafe Handling of Untrusted Data | Verified | Partial. The untrusted `fileName` becomes a file path at `WriteActivity.java` line 38. Partial because the benchmark's focus is the outdated library. Controls shown on the page: MASVS-CODE-4. |

CWE-1104 (Use of Unmaintained Third Party Components) was considered and not used: the library is maintained, since version 1.1 exists with the fix (`Library/version1.1/.../WriteActivity.java` line 29); Benign simply does not use it. MASWE-0018 was considered and not used: `WriteActivity` itself is not exported (`Library/version1.0/src/main/AndroidManifest.xml` line 6), and the exposure through the launcher activity is covered by MASTG-TEST-0364 and MASWE-0032.

MITRE ATT&CK for Mobile: No direct match. No technique on attack.mitre.org was verified that describes writing into another app's private folder through a path traversal in a bundled library.

- **Candidates to check:**
  - CWE-23 (Relative Path Traversal): suggested by the CWE-22 mapping notes; matches `../../cache/malicious.txt` (Malicious line 29).
  - MASWE-0044 (Dependencies with Known Vulnerabilities, as listed on the MASWE index): the MASVS-CODE-3 weakness for outdated dependencies.
  - MASTG-TEST-0272 (Identify Dependencies with Known Vulnerabilities in the Android Project, as listed on the MASTG test index): a test for the 1.0 dependency at `Benign/app/build.gradle` line 18.
  - MASTG-TEST-0042 (Checking for Weaknesses in Third Party Libraries, as listed on the MASTG test index, deprecated): the older form of the same test.
- **Evidence plan:** On the ghera27 emulator (API 27, inside the README range), build both library versions, install Benign and Malicious, press "Click for injection" in Malicious and check for "Data injection succeeded." and for `malicious.txt` in Benign's cache folder; then repeat with Secure and Malicious, expecting "Data injection failed."; without Malicious, use `adb shell am start -n edu.ksu.cs.benign/.MainActivity --es fileName ../../cache/malicious.txt --es fileContent test`. Not yet run.
- **README vs code differences:**
  - The README says Malicious sends the file name to the library; Malicious sends it to Benign's `MainActivity` (`Malicious/.../MainActivity.java` line 33), which forwards it (`Benign/.../MainActivity.java` lines 24 to 35), and `WriteActivity` is not exported (`Library/version1.0/src/main/AndroidManifest.xml` line 6).
  - The README steps never build or install Malicious or Secure but step 7 launches Malicious (README line 51).
  - README line 53 contains Unicode replacement characters (U+FFFD) around the expected message.
  - `Library/version1.1/build.gradle` line 27 still sets `versionName "1.0"`.
  - Secure's `MainActivity` sets an `outerCall` flag that is never read (`Secure/app/src/main/java/edu/ksu/cs/benign/MainActivity.java` lines 14 and 26).
  - The Secure test method is named `testPresenceOfVulnerability` although it checks for the failure message (`Testing/secure_app/src/androidTest/java/edu/ksu/cs/secure/Tests.java` line 63).
- **Open questions:**
  - The 1.1 fix rejects any name containing `..` (`Library/version1.1/.../WriteActivity.java` line 29) rather than checking the resolved path; whether other names can still leave `files/custom` has not been checked.
  - Both Benign and Secure build against AARs under `Library/version1.x/build/outputs/aar/` (`Benign/writetofilelibrary-1.0/build.gradle` line 2, `Secure/writetofilelibrary-1.1/build.gradle` line 2), which exist only after the library build in README step 5 or `source-script.sh`.

## Permission (2)

### UnnecesaryPerms-PrivEscalation-Lean

- **Summary:** An app that requests a permission it does not need lets other apps without that permission use it through the app's exported components; here a bundled library's exported service can take a wake lock only because the host app asked for `WAKE_LOCK`.
- **Android versions (from README):** "Tested on Android 5.1.1 - Android 8.1"
- **What the code does:** Benign requests `android.permission.WAKE_LOCK` (`Benign/app/src/main/AndroidManifest.xml` line 5), while its own code only calls the library's logger (`Benign/app/src/main/java/edu/ksu/cs/benign/MainActivity.java` line 14). The bundled `logutil` library declares `BackgroundService` as exported with no permission (`Benign/logutil/src/main/AndroidManifest.xml` lines 6 to 12); for any intent it creates a `PARTIAL_WAKE_LOCK`, acquires it, logs "Long running background service" and releases it (`Benign/logutil/src/main/java/edu/ksu/cs/logutil/BackgroundService.java` lines 24 to 34). Malicious starts that service by explicit class name from `onResume` (`Malicious/app/src/main/java/edu/ksu/cs/malicious/MainActivity.java` lines 22 to 25). Secure drops the `WAKE_LOCK` request (`Secure/app/src/main/AndroidManifest.xml`, no `uses-permission`), so the acquire fails and the service opens `DisplayActivity` ("Permission Denied") instead (`Secure/logutil/src/main/java/edu/ksu/cs/logutil/BackgroundService.java` lines 31 to 33).

| Standard | ID | Title | Confidence | Fit |
|----------|----|-------|------------|-----|
| CWE | CWE-250 | Execution with Unnecessary Privileges | Verified | Direct. Benign holds `WAKE_LOCK` (`Benign/app/src/main/AndroidManifest.xml` line 5) that its own code never needs (`MainActivity.java` line 14 only logs), and the library service runs with it for any caller (`BackgroundService.java` lines 24 to 28). Secure removes the request. Usage ALLOWED. |
| CWE | CWE-926 | Improper Export of Android Application Components | Verified | Partial. `BackgroundService` is `android:exported="true"` with no permission (`Benign/logutil/src/main/AndroidManifest.xml` lines 6 to 8), which is how Malicious reaches it. Partial because the README's fix is removing the permission, and Secure keeps the same export (`Secure/logutil/src/main/AndroidManifest.xml` lines 6 to 8). Usage ALLOWED. |
| CWE | CWE-441 | Unintended Proxy or Intermediary | Verified | Partial. `BackgroundService` takes a request from any app and calls the system `PowerManager` under Benign's identity (`BackgroundService.java` lines 24 to 28), the confused-deputy pattern the page's Relationship note describes. Mapping notes review: the Rationale says this Class might have Base-level children that would be more appropriate and the Comment says to examine them. The children one level down are CWE-918 (Server-Side Request Forgery) and CWE-1021 (Improper Restriction of Rendered UI Layers or Frames); neither fits a service that uses its host's permission, so CWE-441 is kept. Partial because the request goes only to a system service and nothing is passed through to a third party. Usage ALLOWED-WITH-REVIEW. |
| OWASP MASVS v2 | MASVS-PRIVACY-1 | The app minimizes access to sensitive data and resources. | Verified | Partial. The unneeded `WAKE_LOCK` request (manifest line 5) is the access that is not minimized. Partial because the harm in the README comes through the exported service, not from Benign's own use. |
| OWASP MASVS v2 | MASVS-PLATFORM-1 | The app uses IPC mechanisms securely. | Verified | Partial. The exported, unprotected library service (logutil manifest lines 6 to 12) is the entry point; Secure leaves it in place. |
| OWASP MASTG test | MASTG-TEST-0365 | Exported And Unprotected Services That Expose Sensitive Functionality | Verified | Partial. `BackgroundService` is exported with no permission and acquires a wake lock for any caller (`BackgroundService.java` lines 22 to 28). Partial because the exposure matters only while the host app holds `WAKE_LOCK`, and the benchmark's fix keeps the service exported. |
| OWASP MASTG test | MASTG-TEST-0029 | Testing for Sensitive Functionality Exposure Through IPC | Verified | Partial. Deprecated, kept for reference only. |
| OWASP MASWE | MASWE-0018 | Lack of Authentication or Authorization on App Components | Verified | Partial. `BackgroundService` is reachable by any app without access control (logutil manifest lines 6 to 8). Partial because the README's weakness is the unneeded permission. Controls shown on the page: MASVS-AUTH-1, MASVS-PLATFORM-1, MASVS-STORAGE-2. |

CWE-272 (Least Privilege Violation) was considered and not used: it is about not dropping elevated privileges right after the operation that needs them, while here the permission is never needed by Benign at all; CWE-250 is used instead.

MITRE ATT&CK for Mobile: No direct match. No technique was verified on attack.mitre.org that describes using another app's exported service to act with that app's permission.

- **Candidates to check:**
  - MASWE-0066 (Inadequate Permission Management): listed as current on https://mas.owasp.org/MASWE/ (downloaded 2026-11-01), mapped to MASVS-PRIVACY-1; matches the unneeded request at manifest line 5.
  - MASTG-TEST-0255 (Permission Requests Not Minimized): listed with status placeholder on https://mas.owasp.org/MASTG/tests/ (downloaded 2026-11-01).
  - MASTG-TEST-0024 (Testing for App Permissions): listed as deprecated on the same index page.
- **Evidence plan:** On ghera27 (API 27, inside the README range), install Benign and Malicious, launch Malicious and expect `adb logcat -d | grep "LogUtilLib"` to show "Service started" and "Long running background service"; repeat with Secure and expect "Wake Lock Permission not granted" in the log and the "Permission Denied" screen. Not yet run.
- **README vs code differences:**
  - `README.md` line 12 says the service "keeps the device screen unlocked" and that Malicious keeps the device unlocked, "draining the device battery"; the code takes a `PARTIAL_WAKE_LOCK`, which does not keep the screen on, and releases it right after logging (`BackgroundService.java` lines 25, 28 and 34).
- **Open questions:**
  - The Benign test only checks that Malicious shows "Hello World!" (`Testing/benign_app/src/androidTest/java/edu/ksu/cs/benign/Tests.java` line 68), which does not depend on the wake lock; it would pass whether or not the vulnerability is present.
  - In Benign, `wl.release()` runs after the `catch` block (`Benign/logutil/.../BackgroundService.java` line 34), so it also runs when `acquire()` failed; Secure moves it inside the `try` (`Secure/logutil/.../BackgroundService.java` line 30). Whether releasing an unheld wake lock throws on API 27 is not checked; it only matters when the permission is missing.
  - Secure keeps `BackgroundService` exported without a permission (`Secure/logutil/src/main/AndroidManifest.xml` lines 6 to 12), so any app can still start it; only the wake lock fails.

### WeakPermission-UnauthorizedAccess-Lean

- **Summary:** Protecting an exported component with a `normal` permission is about the same as leaving it unprotected, because Android grants a normal permission to any app that requests it at install time.
- **Android versions (from README):** "Tested on Android 5.1.1 - Android 8.1"
- **What the code does:** Benign defines `edu.ksu.cs.benign.MYCP_ACCESS_PERM` with no `protectionLevel` (`Benign/app/src/main/AndroidManifest.xml` line 5) and uses it to guard an exported content provider (lines 20 to 25). The provider's `query`, `insert`, `delete` and `update` only log a message and return `null` or `0` (`Benign/app/src/main/java/edu/ksu/cs/benign/MyContentProvider.java` lines 20 to 23, 31 to 34, 43 to 47 and 50 to 54). Malicious requests the permission (`Malicious/app/src/main/AndroidManifest.xml` line 5) and calls `query`, `insert` and `delete` on `content://edu.ksu.cs.benign.myCP`, opening an "Access Denied" screen only on `SecurityException` (`Malicious/app/src/main/java/edu/ksu/cs/malicious/MainActivity.java` lines 30 to 76). Secure gives the permission `android:protectionLevel="signature"` (`Secure/app/src/main/AndroidManifest.xml` lines 5 to 7).

| Standard | ID | Title | Confidence | Fit |
|----------|----|-------|------------|-----|
| CWE | CWE-926 | Improper Export of Android Application Components | Verified | Direct. The provider is `android:exported="true"` (`Benign/app/src/main/AndroidManifest.xml` line 24) and its only restriction is a permission with no `protectionLevel` (lines 5 and 25), which any app can obtain as Malicious does (`Malicious/app/src/main/AndroidManifest.xml` line 5). Secure restricts it with a `signature` permission (`Secure/app/src/main/AndroidManifest.xml` lines 5 to 7). Usage ALLOWED. |
| CWE | CWE-863 | Incorrect Authorization | Verified | Partial. Android does check `MYCP_ACCESS_PERM` before each provider call (manifest line 25), but the check admits any app that declares the permission because it is normal level (line 5). Mapping notes review: the Rationale says this Class might have Base-level children that would be more appropriate and the Comment says to examine them. The children one level down are CWE-551, CWE-639, CWE-647, CWE-804, CWE-942 and CWE-1244, which cover authorization before canonicalization, user-controlled keys, non-canonical URL paths, guessable CAPTCHA, cross-domain policy and debug access; none describes a permission with too weak a protection level, so CWE-863 is kept. Partial because CWE-926 names the Android-specific form. Usage ALLOWED-WITH-REVIEW. |
| OWASP MASVS v2 | MASVS-PLATFORM-1 | The app uses IPC mechanisms securely. | Verified | Direct. The exported provider and its weak permission (manifest lines 5 and 20 to 25) are the IPC surface. |
| OWASP MASTG test | MASTG-TEST-0355 | References to Unauthorized Database Access through Content Providers | Verified | Partial. The provider is exported and effectively open (manifest lines 20 to 25). Partial because no database is behind it: `query` returns `null` (`MyContentProvider.java` line 46). |
| OWASP MASTG test | MASTG-TEST-0356 | Runtime Verification of Unauthorized Database Access through Content Providers | Verified | Partial. Malicious's calls reach the provider at runtime, which logs them (`MyContentProvider.java` lines 21, 32 and 45). Partial for the same reason: no database data is returned. |
| OWASP MASTG test | MASTG-TEST-0007 | Determining Whether Sensitive Stored Data Has Been Exposed via IPC Mechanisms | Verified | Partial. The README describes the provider as an interface to sensitive data, but the code returns none. Deprecated, kept for reference only. |
| OWASP MASWE | MASWE-0018 | Lack of Authentication or Authorization on App Components | Verified | Direct. The provider is reachable by other apps without adequate access control, since a normal permission is granted on request (manifest lines 5 and 24 to 25). Controls shown on the page: MASVS-AUTH-1, MASVS-PLATFORM-1, MASVS-STORAGE-2. |

CWE-284 (Improper Access Control), the draft value in `benchmark-index.md`, was considered and is DISCOURAGED in `standards-reference.md`, so it is not in the table. Its mapping notes suggest CWE-862, CWE-863, CWE-732, CWE-306, CWE-1390, CWE-286 and CWE-923; CWE-926 and CWE-863 are used instead, and CWE-732 is listed under Candidates. CWE-862 (Missing Authorization) was reviewed and not used, because a permission check does take place; it is only too weak.

MITRE ATT&CK for Mobile: No direct match. No technique was verified on attack.mitre.org that describes obtaining a normal-level custom permission to reach another app's content provider.

- **Candidates to check:**
  - CWE-732 (Incorrect Permission Assignment for Critical Resource): suggested in the CWE-284 mapping notes; matches assigning a normal protection level to the permission that guards the provider (manifest line 5).
  - MASTG-TEST-0024 (Testing for App Permissions): listed as deprecated on https://mas.owasp.org/MASTG/tests/ (downloaded 2026-11-01); covers custom permission protection levels.
- **Evidence plan:** On ghera27 (API 27, inside the README range), install Benign, then Malicious, tap Query Benign CP, Insert Benign CP and Delete Benign CP and expect `adb logcat -d | grep "Benign/MyCP"` to show the query, insert and delete messages; repeat with Secure and expect the "Access Denied" screen after tapping Query Benign CP. Not yet run.
- **README vs code differences:**
  - `README.md` line 20 says the provider gives access to "sensitive information stored in *Benign*" and that Malicious can query, insert and delete it; the provider holds no data and every method only logs and returns `null` or `0` (`MyContentProvider.java` lines 20 to 23, 31 to 34, 43 to 47 and 50 to 54).
- **Open questions:**
  - The Benign test clicks Query Benign CP and then only checks the button's own label (`Testing/benign_app/src/androidTest/java/edu/ksu/cs/benign/Tests.java` line 68). It would also pass if Benign were not installed, since a query to an unknown authority does not raise `SecurityException` in Malicious's code.
  - The README installs Benign before Malicious. Whether Malicious keeps the permission when installed first (before the permission is defined) is not checked.

## Storage (7)

### ExternalStorage-DataInjection-Lean

- **Summary:** An app that reads a file from external storage cannot control that file, even in its own app-specific external directory, so another app with storage permission can replace the content the app later reads.
- **Android versions (from README):** "Tested on Android 5.1.1 - Android 8.1"
- **What the code does:** When the Read bible button is tapped, Benign builds `bible.txt` under `getExternalFilesDir(null)`, writes "This is written by Benign" only if the file does not exist, and otherwise reads and displays whatever the file holds (`Benign/app/src/main/java/edu/ksu/cs/benign/MainActivity.java` lines 44 to 52, read in lines 24 to 30). Malicious takes its own external files path, replaces `edu.ksu.cs.malicious` with `edu.ksu.cs.benign`, and writes its raw resource `bible.txt` to that path using `WRITE_EXTERNAL_STORAGE` (`Malicious/app/src/main/java/edu/ksu/cs/malicious/MalActivity.java` lines 28 to 37; `Malicious/app/src/main/AndroidManifest.xml` line 5). Secure stores and reads the file under `getFilesDir()` instead (`Secure/app/src/main/java/edu/ksu/cs/benign/MainActivity.java` line 43).

| Standard | ID | Title | Confidence | Fit |
|----------|----|-------|------------|-----|
| CWE | CWE-922 | Insecure Storage of Sensitive Information | Verified | Partial. `Benign/.../MainActivity.java` line 44 keeps `bible.txt` in external storage, where `MalActivity.java` lines 33 to 37 overwrite it. Mapping notes review: the Rationale says this Class might have Base-level children that would be more appropriate and the Comment says to examine them. The children one level down are CWE-312 (Cleartext Storage of Sensitive Information) and CWE-921 (Storage of Sensitive Data in a Mechanism without Access Control). CWE-312 does not fit because the problem is write access, not encryption. CWE-921 fits the storage location better (its extended description says Android external storage is typically globally readable and writable), but it is not in the reference file, so it is listed under Candidates. Partial because the README's weakness is that Benign trusts what it reads back (lines 45 to 46), and the file is not described as sensitive. Usage ALLOWED-WITH-REVIEW. |
| OWASP MASVS v2 | MASVS-CODE-4 | The app validates and sanitizes all untrusted inputs. | Verified | Partial. `readFromFile` (`Benign/.../MainActivity.java` lines 26 to 30) shows file content read from attacker-writable storage without any check. Partial because the Secure fix moves the file to internal storage (`Secure/.../MainActivity.java` line 43) rather than validating the content. |
| OWASP MASWE | MASWE-0050 | Unsafe Handling of Untrusted Data | Verified | Partial. Benign reads `bible.txt` from external storage (`Benign/.../MainActivity.java` lines 44 to 46) and uses it as trusted. Partial because the data only reaches a `TextView` (line 30). Controls shown on the page: MASVS-CODE-4. |

CWE-20 (Improper Input Validation) and CWE-345 (Insufficient Verification of Data Authenticity) were considered for reading the file without checks; both are DISCOURAGED in `standards-reference.md`, so CWE-922 is used instead, with CWE-921 as a candidate.

No MASTG test in the reference file fits: all of them cover IPC components (content providers, activities, services, receivers), and this attack goes through a shared file, not an app component.

MITRE ATT&CK for Mobile: No direct match. No technique was verified on attack.mitre.org that describes overwriting a file another app keeps in external storage.

- **Candidates to check:**
  - CWE-921 (Storage of Sensitive Data in a Mechanism without Access Control): Base child of CWE-922, Usage ALLOWED on its page (downloaded 2026-11-01); its extended description names Android external storage as readable and writable by other apps.
  - MASTG-TEST-0002 (Testing Local Storage for Input Validation): listed as deprecated on https://mas.owasp.org/MASTG/tests/ (downloaded 2026-11-01); covers input read back from local storage.
  - MASTG-TEST-0202 (References to APIs and Permissions for Accessing External Storage): listed as current on the same index page; would find the `getExternalFilesDir` call at line 44.
- **Evidence plan:** On ghera27 (API 27, inside the README range), install Benign, tap Read bible and expect "This is written by Benign", then install and launch Malicious (allow storage access), return to Benign, tap Read bible and expect the text from `Malicious/app/src/main/res/raw/bible.txt`; repeat with Secure and expect Malicious to show "Unable to write into file" and Secure to keep showing "This is written by Secure". Not yet run.
- **README vs code differences:** None found.
- **Open questions:**
  - The Secure test (`Testing/secure_app/src/androidTest/java/edu/ksu/cs/secure/Tests.java` line 109) expects Malicious to fail its write. Secure never creates its external files directory, so the failure would come from the missing directory, not from anything Secure enforces; whether the write would succeed if that directory existed is not checked.

### ExternalStorage-InformationLeak-Lean

- **Summary:** An app that writes sensitive data to a file in external storage, even in its app-specific external directory, cannot control who reads it; another app with storage read permission can read the file.
- **Android versions (from README):** "Tested on Android 5.1.1 - Android 8.1"
- **What the code does:** In `onResume`, Benign copies its raw resource `ssn` (an SSN card image, `Benign/app/src/main/res/raw/ssn.png`) to `ssn_bkup.jpg` under `getExternalFilesDir(null)` (`Benign/app/src/main/java/edu/ksu/cs/benign/MainActivity.java` lines 24 to 31). Malicious, holding `READ_EXTERNAL_STORAGE` (`Malicious/app/src/main/AndroidManifest.xml` line 5), rewrites its own external path to Benign's and decodes the image, showing "ImageView loaded with SSN" on success (`Malicious/app/src/main/java/edu/ksu/cs/malicious/MalActivity.java` lines 53 to 63). Secure writes the same file under `getFilesDir()` (`Secure/app/src/main/java/edu/ksu/cs/benign/MainActivity.java` line 24).

| Standard | ID | Title | Confidence | Fit |
|----------|----|-------|------------|-----|
| CWE | CWE-922 | Insecure Storage of Sensitive Information | Verified | Direct. `Benign/.../MainActivity.java` lines 24 to 31 store the SSN image in external storage without limiting read access, and `MalActivity.java` line 57 reads it. Mapping notes review: the Rationale says this Class might have Base-level children that would be more appropriate and the Comment says to examine them. The children one level down are CWE-312 (Cleartext Storage of Sensitive Information) and CWE-921 (Storage of Sensitive Data in a Mechanism without Access Control). CWE-312 is not chosen because the Secure fix changes the location, not the encryption. CWE-921 fits more precisely (its extended description names Android external storage) but is not in the reference file, so CWE-922 is kept and CWE-921 is listed under Candidates. Usage ALLOWED-WITH-REVIEW. |
| CWE | CWE-359 | Exposure of Private Personal Information to an Unauthorized Actor | Verified | Partial. The exposed file is an SSN card image (`Benign/app/src/main/res/raw/ssn.png`, copied at `MainActivity.java` line 27). Partial because the exposure depends on the storage weakness above and on Malicious holding `READ_EXTERNAL_STORAGE`. Usage ALLOWED. |
| OWASP MASVS v2 | MASVS-STORAGE-1 | The app securely stores sensitive data. | Verified | Direct. The sensitive file is written to external storage at `Benign/.../MainActivity.java` line 24; Secure moves it to `getFilesDir()` at `Secure/.../MainActivity.java` line 24. |
| OWASP MASVS v2 | MASVS-STORAGE-2 | The app prevents leakage of sensitive data. | Verified | Partial. The leak to Malicious (`MalActivity.java` lines 55 to 57) follows from the storage location; the control is broader than storage. |

CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor) was considered and is DISCOURAGED in `standards-reference.md`, so it is not in the table; CWE-922 and CWE-359 are used instead.

No MASTG test or MASWE entry in the reference file fits: the MASTG tests cover IPC components and the MASWE entries cover app components, intents, overlays and untrusted input, while this leak goes through a shared file.

MITRE ATT&CK for Mobile: No direct match. No technique was verified on attack.mitre.org that describes reading another app's file from external storage.

- **Candidates to check:**
  - CWE-921 (Storage of Sensitive Data in a Mechanism without Access Control): Base child of CWE-922, Usage ALLOWED; matches line 24 directly.
  - MASWE-0002 (Sensitive Data Stored Unencrypted Outside of Private Storage): listed as current on https://mas.owasp.org/MASWE/ (downloaded 2026-11-01).
  - MASTG-TEST-0200 (Files Written to External Storage): listed as current on https://mas.owasp.org/MASTG/tests/ (downloaded 2026-11-01).
  - MASTG-TEST-0001 (Testing Local Storage for Sensitive Data): listed as deprecated on the same index page.
- **Evidence plan:** On ghera27 (API 27, inside the README range), install and launch Benign, then install and launch Malicious (allow storage access) and expect "ImageView loaded with SSN" with the image shown; repeat with Secure and expect "Unable to load image". Not yet run.
- **README vs code differences:**
  - `README.md` line 16 says Malicious "has write permission to *ExternalStorage*"; `Malicious/app/src/main/AndroidManifest.xml` line 5 requests only `READ_EXTERNAL_STORAGE` (the same README line later says read permission).
- **Open questions:** None.

### InternalStorage-DirectoryTraversal-Lean

- **Summary:** An app that takes a file path from another app and writes that file in its internal storage without sanitizing the path lets the caller write files anywhere in the app's internal file system.
- **Android versions (from README):** "Tested on Android 5.1.1 - Android 8.1"
- **What the code does:** Benign's `MainActivity`, exported through its launcher intent filter (`Benign/app/src/main/AndroidManifest.xml` lines 11 to 16), takes the `fileName` and `fileContent` extras and writes the file as `new File(getFilesDir()/custom, fileName)` with no check on the name, then sets `RESULT_OK` (`Benign/app/src/main/java/edu/ksu/cs/benign/MainActivity.java` lines 25 to 45). Malicious starts it with `fileName` set to `../../cache/malicious.txt` and shows success when `RESULT_OK` comes back (`Malicious/app/src/main/java/edu/ksu/cs/malicious/MainActivity.java` lines 29 to 36 and 45 to 47). Secure accepts the request only when `fileName` equals `demo.txt` and returns `RESULT_CANCELED` otherwise (`Secure/app/src/main/java/edu/ksu/cs/benign/MainActivity.java` lines 27 to 34).

| Standard | ID | Title | Confidence | Fit |
|----------|----|-------|------------|-----|
| CWE | CWE-22 | Improper Limitation of a Pathname to a Restricted Directory | Verified | Direct. `Benign/.../MainActivity.java` lines 28 and 37 use the caller's `fileName` under `files/custom` without limiting it to that directory, and Malicious line 29 escapes it with `../../cache/`. Mapping notes review: the Rationale says this entry might have children that would be more appropriate; the Comment says to consider CWE-23 (or its descendants) for relative path traversal or CWE-36 for absolute path traversal. The children one level down are CWE-23 (Relative Path Traversal) and CWE-36 (Absolute Path Traversal). CWE-23 matches the `../` input better but is not in the reference file, so CWE-22 is kept and CWE-23 is listed under Candidates; CWE-36 does not apply because the input is relative. Usage ALLOWED-WITH-REVIEW. |
| OWASP MASVS v2 | MASVS-CODE-4 | The app validates and sanitizes all untrusted inputs. | Verified | Direct. Benign uses the extra as is (line 28); Secure checks it against a fixed name (`Secure/.../MainActivity.java` line 29). |
| OWASP MASVS v2 | MASVS-PLATFORM-1 | The app uses IPC mechanisms securely. | Verified | Partial. The path arrives as an intent extra to an exported activity (`Benign/.../MainActivity.java` line 25). Partial because the fix is input validation, not a change to the IPC surface. |
| OWASP MASTG test | MASTG-TEST-0364 | Exported And Unprotected Activities That Expose Sensitive Functionality | Verified | Partial. `MainActivity` is exported by its launcher intent filter with no permission (`Benign/app/src/main/AndroidManifest.xml` lines 11 to 16) and writes files named by the caller (lines 37 to 40). Partial because a launcher activity has to be exported and Secure keeps it exported; the fix is in input handling. |
| OWASP MASTG test | MASTG-TEST-0029 | Testing for Sensitive Functionality Exposure Through IPC | Verified | Partial. Deprecated, kept for reference only. |
| OWASP MASWE | MASWE-0050 | Unsafe Handling of Untrusted Data | Verified | Direct. An untrusted intent extra becomes part of a file path (`Benign/.../MainActivity.java` lines 28 and 37). Controls shown on the page: MASVS-CODE-4. |
| OWASP MASWE | MASWE-0032 | Insecure Intents | Verified | Partial. `MainActivity` acts on the incoming intent's extras without validation (lines 25 to 30), which the page covers as acting on untrusted intents. Partial because the harm comes from the file path, not from the intent itself. Controls shown on the page: MASVS-PLATFORM-1, MASVS-STORAGE-2. |

CWE-20 (Improper Input Validation) was considered and is DISCOURAGED in `standards-reference.md`, so it is not in the table; CWE-22 is used instead, with CWE-23 as a candidate.

MITRE ATT&CK for Mobile: No direct match. No technique was verified on attack.mitre.org that describes path traversal through another app's exported activity.

- **Candidates to check:**
  - CWE-23 (Relative Path Traversal): child of CWE-22 named in its mapping notes; matches the `../../cache/malicious.txt` input at Malicious line 29.
- **Evidence plan:** On ghera27 (API 27, inside the README range), install Benign and Malicious, open Malicious, tap its button, press Back and expect "Data injection succeeded", then check `adb shell run-as edu.ksu.cs.benign ls -l cache` for `malicious.txt`; repeat with Secure and expect "Data injection failed" and no `malicious.txt`. Not yet run.
- **README vs code differences:**
  - `README.md` line 52 (step 7) says to launch Malicious and press Back; the request is only sent after tapping the Malicious button (`Malicious/.../MainActivity.java` lines 25 to 37), which the test does before pressing Back.
  - `README.md` line 12 names the file `../../cache/Malicious.txt`; the code uses `../../cache/malicious.txt` (`Malicious/.../MainActivity.java` line 29).
  - `README.md` line 12 says `MainActivity` returns a failure or success result code depending on whether the file was written; Benign throws a `RuntimeException` on an `IOException` instead of returning a failure code (`Benign/.../MainActivity.java` lines 41 to 42).
- **Open questions:**
  - In Secure, the `IOException` handler sets `RESULT_CANCELED` (`Secure/.../MainActivity.java` line 47) but execution continues to `setResult(RESULT_OK)` at line 51, so a failed write would still be reported as success. This does not affect the traversal fix but means the result code is not reliable.

### InternalToExternalStorage-InformationLeak-Lean

- **Summary:** An app component that copies files from internal storage to external storage on request, without telling trusted callers from untrusted ones, lets another app read the app's internal files.
- **Android versions (from README):** "Tested on Android 5.1.1 - Android 8.1"
- **What the code does:** Benign saves the text field to the private file `sensitive_file` (`Benign/app/src/main/java/edu/ksu/cs/benign/MainActivity.java` lines 35 to 38). Its `DownloadService` is exported with no permission (`Benign/app/src/main/AndroidManifest.xml` lines 19 to 27); for any intent with a `filename` extra it reads that internal file, writes it to `getExternalFilesDir(null)`, and broadcasts to the package and action named in the intent (`Benign/app/src/main/java/edu/ksu/cs/benign/DownloadService.java` lines 34 to 62). Malicious starts the service for `sensitive_file`, and its `Result` activity then reads the copy from Benign's external directory (`Malicious/app/src/main/java/edu/ksu/cs/malicious/MainActivity.java` lines 50 to 57; `Malicious/app/src/main/java/edu/ksu/cs/malicious/Result.java` lines 26 to 39). Secure protects the service with a signature-level permission (`Secure/app/src/main/AndroidManifest.xml` lines 5 to 9 and 27); the service code is unchanged.

| Standard | ID | Title | Confidence | Fit |
|----------|----|-------|------------|-----|
| CWE | CWE-926 | Improper Export of Android Application Components | Verified | Direct. `DownloadService` is `android:exported="true"` with no permission (`Benign/app/src/main/AndroidManifest.xml` lines 19 to 21), so any app can make it copy an internal file out. Secure adds `android:permission="edu.ksu.cs.SecurePermission"` with `signature` level (`Secure/app/src/main/AndroidManifest.xml` lines 5 to 8 and 27). Usage ALLOWED. |
| CWE | CWE-922 | Insecure Storage of Sensitive Information | Verified | Partial. `DownloadService.java` lines 36 and 48 to 50 copy the private file to external storage, where any app with storage read permission can read it. Mapping notes review: the Rationale says this Class might have Base-level children that would be more appropriate and the Comment says to examine them. Of the children one level down, CWE-312 (Cleartext Storage of Sensitive Information) is about encryption and does not fit; CWE-921 (Storage of Sensitive Data in a Mechanism without Access Control) fits the external-storage half better but is not in the reference file, so it is listed under Candidates. Partial because the README's weakness is the unrestricted service, and Secure keeps the copy to external storage (`Secure/.../DownloadService.java` lines 47 to 49). Usage ALLOWED-WITH-REVIEW. |
| OWASP MASVS v2 | MASVS-PLATFORM-1 | The app uses IPC mechanisms securely. | Verified | Direct. The exported, unprotected service (manifest lines 19 to 27) is the entry point. |
| OWASP MASVS v2 | MASVS-STORAGE-2 | The app prevents leakage of sensitive data. | Verified | Partial. The private file leaves the sandbox through `DownloadService.java` line 48. Partial because the control is broader than this IPC path. |
| OWASP MASTG test | MASTG-TEST-0365 | Exported And Unprotected Services That Expose Sensitive Functionality | Verified | Direct. `DownloadService` is exported with no permission and copies internal files out on request (`DownloadService.java` lines 34 to 50). |
| OWASP MASTG test | MASTG-TEST-0007 | Determining Whether Sensitive Stored Data Has Been Exposed via IPC Mechanisms | Verified | Partial. Stored data (`sensitive_file`) is exposed through an IPC component. Deprecated, kept for reference only. |
| OWASP MASTG test | MASTG-TEST-0029 | Testing for Sensitive Functionality Exposure Through IPC | Verified | Partial. Deprecated, kept for reference only. |
| OWASP MASWE | MASWE-0018 | Lack of Authentication or Authorization on App Components | Verified | Direct. `DownloadService` is reachable by any app without access control (manifest lines 19 to 21). Controls shown on the page: MASVS-AUTH-1, MASVS-PLATFORM-1, MASVS-STORAGE-2. |

CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor) was considered and is DISCOURAGED in `standards-reference.md`, so it is not in the table; CWE-926 and CWE-922 are used instead.

MITRE ATT&CK for Mobile: No direct match. No technique was verified on attack.mitre.org that describes calling another app's exported service to copy its private files to shared storage.

- **Candidates to check:**
  - CWE-921 (Storage of Sensitive Data in a Mechanism without Access Control): Base child of CWE-922, Usage ALLOWED; matches the copy to external storage at `DownloadService.java` line 48.
  - MASTG-TEST-0200 (Files Written to External Storage): listed as current on https://mas.owasp.org/MASTG/tests/ (downloaded 2026-11-01).
  - MASWE-0002 (Sensitive Data Stored Unencrypted Outside of Private Storage): listed as current on https://mas.owasp.org/MASWE/ (downloaded 2026-11-01).
- **Evidence plan:** On ghera27 (API 27, inside the README range), install Benign and Malicious, type text in Benign and tap Save, open Malicious (allow storage access), tap its service button and expect the `Result` screen to show the typed text and `adb logcat -d | grep "Benign/DownloadService"` to show "Written to external storage in = ..."; repeat with Secure and expect Malicious to show "SecurityException". Not yet run.
- **README vs code differences:**
  - `README.md` step 9 says the log shows that the file was written to external storage "successfully"; the code logs "Written to external storage in = " followed by the path (`Benign/.../DownloadService.java` line 56).
- **Open questions:**
  - `README.md` line 9 calls copying internal files to external storage "inherently insecure", yet Secure keeps the copy and its own "Download to sdcard" button still triggers it (`Secure/app/src/main/java/edu/ksu/cs/benign/MainActivity.java` line 50; `Secure/.../DownloadService.java` lines 47 to 49). After that button is used, any app with storage read permission could read the file the way `Result.java` lines 26 to 29 do. Whether the benchmark intends Secure to cover only the service access is not stated.
  - `DownloadService` broadcasts to a package and action taken from the caller's extras (`Benign/.../DownloadService.java` lines 57 to 62; same in Secure lines 56 to 61). This is not part of the README's description.

### SQLite-execSQL-Lean

- **Summary:** An app that builds a SQL statement from outside input and runs it with `SQLiteDatabase.execSQL()`, without parameters, is open to SQL injection.
- **Android versions (from README):** "Tested on Android 5.1.1 - 8.1"
- **What the code does:** Benign's `MiddleActivity` is exported through an intent filter for action `edu.ksu.cs.benign.DB` with no permission (`Benign/app/src/main/AndroidManifest.xml` lines 23 to 28). When `requestCode` is 100 it reads the `key` and `value` extras, concatenates them into an `UPDATE` statement, runs it with `execSQL`, and returns every row of the table to the caller (`Benign/app/src/main/java/edu/ksu/cs/benign/MiddleActivity.java` lines 28 to 33, 49 to 54 and 73 to 78). Malicious sends `value` set to `666' WHERE 1=1 -- ` so every row is updated (`Malicious/app/src/main/java/edu/ksu/cs/malicious/MainActivity.java` lines 29 to 36). Secure replaces the concatenation with `db.update()` and a `?` placeholder for the key (`Secure/app/src/main/java/edu/ksu/cs/benign/MiddleActivity.java` lines 52 to 55).

| Standard | ID | Title | Confidence | Fit |
|----------|----|-------|------------|-----|
| CWE | CWE-89 | Improper Neutralization of Special Elements used in an SQL Command | Verified | Direct. `MiddleActivity.java` lines 49 to 51 build the `UPDATE` from the `value` and `key` extras and line 54 runs it with `execSQL`; the Malicious payload at line 30 closes the quote and comments out the rest. Usage ALLOWED. |
| CWE | CWE-926 | Improper Export of Android Application Components | Verified | Partial. `MiddleActivity` is exported by its intent filter with no permission (`Benign/app/src/main/AndroidManifest.xml` lines 23 to 28), which lets any app supply the input. Partial because the benchmark's weakness is the injection, and Secure keeps the activity exported (`Secure/app/src/main/AndroidManifest.xml` lines 23 to 30). Usage ALLOWED. |
| OWASP MASVS v2 | MASVS-CODE-4 | The app validates and sanitizes all untrusted inputs. | Verified | Direct. Untrusted extras go into SQL text (lines 49 to 51). |
| OWASP MASVS v2 | MASVS-PLATFORM-1 | The app uses IPC mechanisms securely. | Verified | Partial. The input arrives through an exported activity (manifest lines 23 to 28). Partial because the fix is parameterization, not IPC protection. |
| OWASP MASTG test | MASTG-TEST-0364 | Exported And Unprotected Activities That Expose Sensitive Functionality | Verified | Partial. `MiddleActivity` is exported without a permission, updates the database and returns all rows to the caller (`MiddleActivity.java` lines 73 to 78). Partial because Secure keeps this exposure and only fixes the query. |
| OWASP MASTG test | MASTG-TEST-0029 | Testing for Sensitive Functionality Exposure Through IPC | Verified | Partial. Deprecated, kept for reference only. |
| OWASP MASWE | MASWE-0050 | Unsafe Handling of Untrusted Data | Verified | Direct. Intent extras are used unsanitized in a SQL statement (lines 30 to 31 and 49 to 54). Controls shown on the page: MASVS-CODE-4. |
| OWASP MASWE | MASWE-0018 | Lack of Authentication or Authorization on App Components | Verified | Partial. `MiddleActivity` is reachable by any app without access control (manifest lines 23 to 28). Partial because the README's weakness is the injection. Controls shown on the page: MASVS-AUTH-1, MASVS-PLATFORM-1, MASVS-STORAGE-2. |

CWE-20 (Improper Input Validation) was considered and is DISCOURAGED in `standards-reference.md`, so it is not in the table; CWE-89 is used instead.

The content-provider tests in the reference file (MASTG-TEST-0355, MASTG-TEST-0356, MASTG-TEST-0357) do not fit: this benchmark has no content provider.

MITRE ATT&CK for Mobile: No direct match. No technique was verified on attack.mitre.org that describes SQL injection through another app's exported activity.

- **Candidates to check:**
  - MASTG-TEST-0025 (Testing for Injection Flaws): listed as deprecated on https://mas.owasp.org/MASTG/tests/ (downloaded 2026-11-01); covers SQL injection in general, not only through content providers.
- **Evidence plan:** On ghera27 (API 27, inside the README range), install Benign, tap TRUNCATE TABLE then Insert data, install Malicious, tap Data injection and expect both rows in `MiddleActivity` to show value 666, then press Back and expect "Success"; repeat with Secure and expect values 100 and 200 and "Failure". Not yet run.
- **README vs code differences:**
  - `README.md` line 12 gives the payload as "666 where clause 1=1"; the code sends `666' WHERE 1=1 -- ` (`Malicious/.../MainActivity.java` line 30).
  - `README.md` line 14 names the buttons Truncate Table and Insert Table and line 46 says Insert Data; the layout labels are "TRUNCATE TABLE" and "Insert data" (`Benign/app/src/main/res/layout/activity_main.xml` lines 28 and 33).
  - `README.md` line 62 presents "Success" as the sign of the exploit; Malicious shows "Success" for any `RESULT_OK` (`Malicious/.../MainActivity.java` lines 45 to 46), and `MiddleActivity` returns `RESULT_OK` whenever the table has rows (`Benign/.../MiddleActivity.java` lines 71 to 78), whether or not the injection changed anything.
- **Open questions:**
  - Secure passes `"WHERE " + key + " = ?"` as the `whereClause` of `db.update()` (`Secure/.../MiddleActivity.java` line 55). If `update()` adds its own `WHERE`, as the Android documentation describes, the statement would contain `WHERE WHERE` and fail for every input, ending in `RESULT_CANCELED` (line 61). The Secure test's "Failure" check (`Testing/secure_app/src/androidTest/java/edu/ksu/cs/secure/Tests.java` line 108) would then pass even for a harmless request.
  - Both Benign and Secure declare a `signature` permission `edu.ks.cs.benign.MYCP_READ_PERMISSION` that no component uses (`Benign/app/src/main/AndroidManifest.xml` lines 5 to 7; `Secure/app/src/main/AndroidManifest.xml` lines 5 to 7), and Malicious requests it (`Malicious/app/src/main/AndroidManifest.xml` line 5).
  - Secure still returns every row of the table to any caller (`Secure/.../MiddleActivity.java` lines 75 to 80).

### SQLlite-RawQuery-SQLInjection-Lean

- **Summary:** An app that builds a query from outside input and runs it with `SQLiteDatabase.rawQuery()`, without parameters, is open to SQL injection.
- **Android versions (from README):** "Tested on Android 5.1.1 - Android 8.1"
- **What the code does:** Benign's `MiddleActivity` is exported with no permission (`Benign/app/src/main/AndroidManifest.xml` lines 23 to 30). When `requestCode` is 100 it concatenates the `username` and `password` extras into the `WHERE` clause and runs the query with `rawQuery(query, null)`, then returns all matching usernames and passwords to the caller (`Benign/app/src/main/java/edu/ksu/cs/benign/MiddleActivity.java` lines 28 to 33, 76 to 82 and 40 to 45). Malicious sends `password` set to `"password" OR 1=1` and logs every returned pair (`Malicious/app/src/main/java/edu/ksu/cs/malicious/MainActivity.java` lines 31 to 38 and 49 to 53). Secure uses `?` placeholders and passes the extras as `selectionArgs` (`Secure/app/src/main/java/edu/ksu/cs/benign/MiddleActivity.java` lines 30 to 33 and 81).

| Standard | ID | Title | Confidence | Fit |
|----------|----|-------|------------|-----|
| CWE | CWE-89 | Improper Neutralization of Special Elements used in an SQL Command | Verified | Direct. `MiddleActivity.java` line 31 builds the selection from the extras and line 82 runs it with `rawQuery(query, null)`. Usage ALLOWED. |
| CWE | CWE-926 | Improper Export of Android Application Components | Verified | Partial. `MiddleActivity` is `android:exported="true"` with no permission (`Benign/app/src/main/AndroidManifest.xml` lines 23 to 25). Partial because the weakness is the injection, and Secure keeps the same export (`Secure/app/src/main/AndroidManifest.xml` lines 22 to 24). Usage ALLOWED. |
| OWASP MASVS v2 | MASVS-CODE-4 | The app validates and sanitizes all untrusted inputs. | Verified | Direct. Untrusted extras go into SQL text (line 31). |
| OWASP MASVS v2 | MASVS-PLATFORM-1 | The app uses IPC mechanisms securely. | Verified | Partial. The input arrives through an exported activity (manifest lines 23 to 30). Partial because the fix is parameterization. |
| OWASP MASTG test | MASTG-TEST-0364 | Exported And Unprotected Activities That Expose Sensitive Functionality | Verified | Partial. `MiddleActivity` is exported without a permission and returns usernames and passwords to the caller (`MiddleActivity.java` lines 40 to 45). Partial because Secure keeps this exposure for callers that supply a valid pair. |
| OWASP MASTG test | MASTG-TEST-0029 | Testing for Sensitive Functionality Exposure Through IPC | Verified | Partial. Deprecated, kept for reference only. |
| OWASP MASWE | MASWE-0050 | Unsafe Handling of Untrusted Data | Verified | Direct. Intent extras are used unsanitized in a SQL query (lines 28 to 31 and 82). Controls shown on the page: MASVS-CODE-4. |
| OWASP MASWE | MASWE-0018 | Lack of Authentication or Authorization on App Components | Verified | Partial. `MiddleActivity` is reachable by any app without access control (manifest lines 23 to 25). Partial because the README's weakness is the injection. Controls shown on the page: MASVS-AUTH-1, MASVS-PLATFORM-1, MASVS-STORAGE-2. |

CWE-20 (Improper Input Validation) was considered and is DISCOURAGED in `standards-reference.md`, so it is not in the table; CWE-89 is used instead.

The content-provider tests in the reference file (MASTG-TEST-0355, MASTG-TEST-0356, MASTG-TEST-0357) do not fit: although the README names a content provider, the code has none.

MITRE ATT&CK for Mobile: No direct match. No technique was verified on attack.mitre.org that describes SQL injection through another app's exported activity.

- **Candidates to check:**
  - MASTG-TEST-0025 (Testing for Injection Flaws): listed as deprecated on https://mas.owasp.org/MASTG/tests/ (downloaded 2026-11-01).
- **Evidence plan:** On ghera27 (API 27, inside the README range), install Benign and tap Insert data, install Malicious, tap Data injection, press Back and expect "Success" and `adb logcat -d | grep "Malicious"` to list both username and password pairs; repeat with Secure and expect "Failure". Not yet run.
- **README vs code differences:**
  - `README.md` line 12 says `Benign/MyContentProvider` runs the non-parameterized query and is exported; Benign has no content provider. The query is in `MiddleActivity` (`Benign/.../MiddleActivity.java` lines 31 and 76 to 82), and `MiddleActivity` is the exported component (`Benign/app/src/main/AndroidManifest.xml` lines 23 to 30).
- **Open questions:**
  - Benign and Secure declare a `signature` permission `edu.ks.cs.benign.MYCP_READ_PERMISSION` that no component uses (`Benign/app/src/main/AndroidManifest.xml` lines 5 to 7; `Secure/app/src/main/AndroidManifest.xml` lines 5 to 7), and Malicious requests it (`Malicious/app/src/main/AndroidManifest.xml` line 5). It may be left over from a content-provider version.
  - Benign logs each username and password and the full query text (`Benign/.../MiddleActivity.java` lines 60 and 81); Secure still logs the pairs and the arguments (`Secure/.../MiddleActivity.java` lines 61 and 82). This is outside the README's scope.
  - `Secure/app/src/main/res/layout/activity_middleware.xml` names `edu.ksu.cs.benign.Middleware` as its context (line 7); no such class exists in Secure.

### SQLlite-SQLInjection-Lean

- **Summary:** An app that builds select, update or delete conditions from outside input without using `selectionArgs` is open to SQL injection.
- **Android versions (from README):** "Tested on Android 5.1.1 - Android 8.1"
- **What the code does:** Benign's `MiddleActivity` is exported with no permission (`Benign/app/src/main/AndroidManifest.xml` lines 30 to 37) and concatenates the `username` and `password` extras into a selection string that it passes, with `null` selection arguments, to its own content provider (`Benign/app/src/main/java/edu/ksu/cs/benign/MiddleActivity.java` lines 28 to 34). The provider is not exported and is guarded by a `signature` permission (manifest lines 23 to 28); its `query` passes the selection straight to `db.query` (`Benign/app/src/main/java/edu/ksu/cs/benign/MyContentProvider.java` line 57), and `MiddleActivity` returns all matching pairs to the caller (lines 42 to 47). Malicious sends `"password" OR 1=1` as the password (`Malicious/app/src/main/java/edu/ksu/cs/malicious/MainActivity.java` lines 29 to 36); Secure builds the selection with `?` and passes the extras as `selectionArgs` (`Secure/app/src/main/java/edu/ksu/cs/benign/MiddleActivity.java` lines 30 to 36).

| Standard | ID | Title | Confidence | Fit |
|----------|----|-------|------------|-----|
| CWE | CWE-89 | Improper Neutralization of Special Elements used in an SQL Command | Verified | Direct. `MiddleActivity.java` line 30 builds the selection from the extras and `MyContentProvider.java` line 57 runs it without `selectionArgs`. Usage ALLOWED. |
| CWE | CWE-926 | Improper Export of Android Application Components | Verified | Partial. `MiddleActivity` is `android:exported="true"` with no permission (`Benign/app/src/main/AndroidManifest.xml` lines 30 to 32) and gives other apps indirect access to the unexported provider. Partial because the weakness is the injection, and Secure keeps the same export (`Secure/app/src/main/AndroidManifest.xml` lines 30 to 32). Usage ALLOWED. |
| OWASP MASVS v2 | MASVS-CODE-4 | The app validates and sanitizes all untrusted inputs. | Verified | Direct. Untrusted extras go into the selection (line 30). |
| OWASP MASVS v2 | MASVS-PLATFORM-1 | The app uses IPC mechanisms securely. | Verified | Partial. The input arrives through an exported activity (manifest lines 30 to 37). Partial because the fix is parameterization. |
| OWASP MASTG test | MASTG-TEST-0364 | Exported And Unprotected Activities That Expose Sensitive Functionality | Verified | Partial. `MiddleActivity` is exported without a permission and returns usernames and passwords to the caller (`MiddleActivity.java` lines 42 to 47). Partial because Secure keeps this exposure for callers that supply a valid pair. |
| OWASP MASTG test | MASTG-TEST-0029 | Testing for Sensitive Functionality Exposure Through IPC | Verified | Partial. Deprecated, kept for reference only. |
| OWASP MASWE | MASWE-0050 | Unsafe Handling of Untrusted Data | Verified | Direct. Intent extras are used unsanitized in a SQL selection (lines 28 to 34). Controls shown on the page: MASVS-CODE-4. |
| OWASP MASWE | MASWE-0018 | Lack of Authentication or Authorization on App Components | Verified | Partial. `MiddleActivity` is reachable by any app without access control (manifest lines 30 to 32). Partial because the README's weakness is the injection. Controls shown on the page: MASVS-AUTH-1, MASVS-PLATFORM-1, MASVS-STORAGE-2. |

CWE-20 (Improper Input Validation) was considered and is DISCOURAGED in `standards-reference.md`, so it is not in the table; CWE-89 is used instead.

MASTG-TEST-0355 and MASTG-TEST-0356 do not fit: there is a content provider, but it is `android:exported="false"` and guarded by a `signature` permission (manifest lines 27 to 28), so other apps reach the database only through `MiddleActivity`. MASTG-TEST-0357 does not fit because the provider is not file-based.

MITRE ATT&CK for Mobile: No direct match. No technique was verified on attack.mitre.org that describes SQL injection through another app's exported activity.

- **Candidates to check:**
  - MASTG-TEST-0339 (SQL Injection in Content Providers): named in `standards-reference.md` as filed under MASVS-CODE and not included there; the injectable `db.query` is inside a content provider (`MyContentProvider.java` line 57), but the provider is not exported.
  - MASTG-TEST-0025 (Testing for Injection Flaws): listed as deprecated on https://mas.owasp.org/MASTG/tests/ (downloaded 2026-11-01).
- **Evidence plan:** On ghera27 (API 27, inside the README range), install and launch Benign (which inserts the rows), install Malicious, tap Data injection, press Back and expect "Success" and `adb logcat -d | grep "Malicious"` to list both pairs; repeat with Secure and expect "Failure". Not yet run.
- **README vs code differences:**
  - `README.md` line 2 covers select, update and delete queries; `MyContentProvider` implements only `query`, while `delete` and `update` throw `UnsupportedOperationException` (`MyContentProvider.java` lines 17 to 20 and 61 to 66).
  - `README.md` steps 8 and 9 do not mention pressing Back to return to Malicious; the test presses Back before reading the result (`Testing/benign_app/src/androidTest/java/edu/ksu/cs/benign/Tests.java` lines 74 to 79).
- **Open questions:**
  - The provider is both `exported="false"` and guarded by `edu.ks.cs.benign.MYCP_READ_PERMISSION` (manifest lines 27 to 28); Malicious requests that permission (`Malicious/app/src/main/AndroidManifest.xml` line 5), which has no effect on the attack path.
  - Benign's `MainActivity.onCreate` inserts the two rows on every launch (`Benign/app/src/main/java/edu/ksu/cs/benign/MainActivity.java` line 18, `MyContentProvider.java` lines 33 to 39), so rows repeat over runs.
  - Benign and Secure log each username and password (`Benign/.../MiddleActivity.java` line 62; `Secure/.../MiddleActivity.java` line 64). This is outside the README's scope.

## System (7)

### CheckCallingOrSelfPermission-PrivilegeEscalation-Lean
- **Summary:** An app protects a service with a run-time call to `checkCallingOrSelfPermission`. According to the README, the check passes for every caller once the app's own component has been granted the permission, so a malicious app can start the service.
- **Android versions (from README):** "Tested on Android 5.1.1 - Android 8.1"
- **What the code does:** Benign declares `santos.benign.permission` with no protection level, requests it for itself, and exports `MyService` with no `android:permission` (`Benign/app/src/main/AndroidManifest.xml` lines 5 to 6 and 21 to 24). `MyService.onStartCommand` starts the unexported `SensitiveActivity` with `status_msg=SUCCESS` when `checkCallingOrSelfPermission("santos.benign.permission")` returns granted (`Benign/app/src/main/java/edu/ksu/cs/benign/MyService.java` lines 18 to 23), and `SensitiveActivity` then shows "Activity Started from Service." (`Benign/app/src/main/java/edu/ksu/cs/benign/SensitiveActivity.java` line 19). Malicious starts `edu.ksu.cs.benign.MyService` by explicit class name in `onResume` (`Malicious/app/src/main/java/edu/ksu/cs/malicious/MalActivity.java` lines 20 to 24). Secure drops the in-code check and instead sets `android:protectionLevel="signature"` on the permission and `android:permission` on the service (`Secure/app/src/main/AndroidManifest.xml` lines 5 to 7 and 23 to 27).

| Standard | ID | Title | Confidence | Fit |
|----------|----|-------|------------|-----|
| CWE | CWE-863 | Incorrect Authorization | Verified | Direct. `MyService` performs an authorization check, but the check (`MyService.java` line 18) is satisfied by Benign's own permission (manifest line 6), so a caller without the permission (`MalActivity.java` line 24) gets the sensitive action; the CWE description is a check that is performed but "does not correctly perform the check". Usage ALLOWED-WITH-REVIEW. Mapping notes review: the Rationale and Comment say this is a Class that might have more appropriate Base-level children, so the children should be examined. Children shown on the page: CWE-551 (Incorrect Behavior Order: Authorization Before Parsing and Canonicalization), CWE-639 (Authorization Bypass Through User-Controlled Key), CWE-647 (Use of Non-Canonical URL Paths for Authorization Decisions), CWE-804 (Guessable CAPTCHA), CWE-942 (Permissive Cross-domain Security Policy with Untrusted Domains) and CWE-1244 (Internal Asset Exposed to Unsafe Debug Access Level or State). None fits better: CWE-551 and CWE-647 cover URL parsing and paths, CWE-639 covers a user-supplied key, CWE-804 covers CAPTCHAs, CWE-942 covers cross-domain policy files and CWE-1244 covers hardware debug access. CWE-863 is kept. |
| CWE | CWE-926 | Improper Export of Android Application Components | Verified | Direct. `MyService` is `android:exported="true"` with no `android:permission` (Benign manifest lines 21 to 24), and the Secure fix adds `android:permission` with a signature-level permission (Secure manifest lines 5 to 7 and 27). Usage ALLOWED. |
| CWE | CWE-441 | Unintended Proxy or Intermediary | Verified | Partial. `MyService` starts the unexported `SensitiveActivity` under Benign's identity on behalf of Malicious (`MyService.java` lines 20 to 23), which is the confused deputy pattern named as an alternate term on the CWE page; the root cause is the faulty check, which CWE-863 covers. Usage ALLOWED-WITH-REVIEW. Mapping notes review: the Rationale and Comment say this is a Class that might have more appropriate Base-level children, so the children should be examined. Children shown on the page: CWE-918 (Server-Side Request Forgery) and CWE-1021 (Improper Restriction of Rendered UI Layers or Frames). Neither fits better, because CWE-918 covers a server fetching a URL and CWE-1021 covers UI layers or frames, so CWE-441 is kept. |
| OWASP MASVS v2 | MASVS-PLATFORM-1 | The app uses IPC mechanisms securely. | Verified | Direct. The weakness is an exported service reached through an explicit intent from another app (Benign manifest lines 21 to 24, `MalActivity.java` lines 20 to 24). |
| OWASP MASTG test | MASTG-TEST-0365 | Exported And Unprotected Services That Expose Sensitive Functionality | Verified | Direct. `MyService` is an exported service without a manifest permission (Benign manifest lines 21 to 24) that starts `SensitiveActivity` (`MyService.java` lines 20 to 23). |
| OWASP MASTG test | MASTG-TEST-0029 | Testing for Sensitive Functionality Exposure Through IPC | Verified | Partial. Covers the same exported service (Benign manifest lines 21 to 24), but the page is deprecated and points to MASTG-TEST-0365; kept for reference only. |
| OWASP MASWE | MASWE-0018 | Lack of Authentication or Authorization on App Components | Verified | Direct. The page covers components reachable by other apps without adequate access control, including services; `MyService` is exported with no manifest permission (Benign manifest lines 21 to 24) and its run-time check passes for Malicious (`MyService.java` line 18). |

CWE-862 (Missing Authorization) was considered and not used, because `MyService.java` line 18 does perform an authorization check; CWE-863 is used instead. CWE-284 (DISCOURAGED) was considered; CWE-863 and CWE-926 are used instead.

MITRE ATT&CK for Mobile: No direct match. No technique on attack.mitre.org was verified that describes starting another app's exported service to pass a faulty run-time permission check.

- **Candidates to check:** None.
- **Evidence plan:** On ghera27 (API 27, inside the README range of Android 5.1.1 to 8.1), install Benign and Malicious with `gradlew installApi27Debug`, launch Malicious and check whether Benign's `SensitiveActivity` shows "Activity Started from Service." (`Testing/benign_app/src/androidTest/java/edu/ksu/cs/benign/Tests.java` lines 64 to 69); then replace Benign with Secure, launch Malicious, and check that `MyService` is not started (`Testing/secure_app/src/androidTest/java/edu/ksu/cs/secure/Tests.java` lines 75 to 86). Not yet run.
- **README vs code differences:**
  - README step 7 (`README.md` line 71) expects "Activity started from service."; the code sets "Activity Started from Service." (`Benign/app/src/main/java/edu/ksu/cs/benign/SensitiveActivity.java` line 19), and the test expects the code's text (`Testing/benign_app/src/androidTest/java/edu/ksu/cs/benign/Tests.java` line 69).
  - The README description says the exploit works because the permission "was already granted to *Benign/MainActivity* before" (`README.md` lines 27 to 28), but README steps 5 to 7 and the Testing code (`Tests.java` line 64) launch only Malicious, never Benign first.
  - Secure does not declare `SensitiveActivity` in its manifest (`Secure/app/src/main/AndroidManifest.xml` lines 10 to 29), but Secure `MyService` still starts it (`Secure/app/src/main/java/edu/ksu/cs/benign/MyService.java` lines 17 to 20).
- **Open questions:**
  - The README says the check passes because of an earlier grant to `MainActivity`; the source does not show which identity `checkCallingOrSelfPermission` sees inside `onStartCommand` (`MyService.java` lines 17 to 18 log the calling PID and UID). To confirm from the log on the emulator.
  - `santos.benign.permission` has no protection level (Benign manifest line 5), yet `MainActivity` requests it at run time (`MainActivity.java` line 27). Whether a permission dialog appears on API 27 is not stated in the README.
  - What happens when Secure's own `MainActivity` starts `MyService`, given that `SensitiveActivity` is not declared in the Secure manifest.
  - The Secure test reads `ActivityManager.getRunningServices` from the test app (`Testing/secure_app/src/androidTest/java/edu/ksu/cs/secure/Tests.java` lines 78 to 85). Whether that call lists another app's services on API 27 is not shown in the source; if it does not, the test passes either way.

### CheckPermission-PrivilegeEscalation-Lean
- **Summary:** An app protects a service with `checkPermission` using `Binder.getCallingPid()` and `Binder.getCallingUid()`. The README explains that when these are called on the main thread they return the protected app's own PID and UID, so the check passes for any caller once the app itself holds the permission.
- **Android versions (from README):** "Tested on Android 5.1.1 - Android 8.1"
- **What the code does:** Benign declares `santos.benign.permission` with no protection level, uses it itself, and exports `MyService` with no `android:permission` (`Benign/app/src/main/AndroidManifest.xml` lines 5 to 6 and 22 to 25). `MyService.onStartCommand` calls `checkPermission("santos.benign.permission", Binder.getCallingPid(), Binder.getCallingUid())` and, when granted, starts `SensitiveActivity` with `status_msg=SUCCESS` (`Benign/app/src/main/java/edu/ksu/cs/benign/MyService.java` lines 18 to 23), which shows "Activity Started from Service" (`Benign/app/src/main/java/edu/ksu/cs/benign/SensitiveActivity.java` line 19). Malicious starts the service by explicit class name in `onResume` (`Malicious/app/src/main/java/edu/ksu/cs/malicious/MalActivity.java` lines 21 to 25). Secure removes the in-code check and protects the service with a signature-level permission in the manifest (`Secure/app/src/main/AndroidManifest.xml` lines 5 to 7 and 24 to 28).

| Standard | ID | Title | Confidence | Fit |
|----------|----|-------|------------|-----|
| CWE | CWE-863 | Incorrect Authorization | Verified | Direct. `MyService` performs an authorization check (`MyService.java` line 18), but it passes the identity from `Binder.getCallingPid()` and `Binder.getCallingUid()`, which the README says is Benign's own identity on the main thread, so Malicious (`MalActivity.java` line 25) passes the check; the CWE description is a check that is performed but "does not correctly perform the check". Usage ALLOWED-WITH-REVIEW. Mapping notes review: the Rationale and Comment say this is a Class that might have more appropriate Base-level children, so the children should be examined. Children shown on the page: CWE-551, CWE-639, CWE-647, CWE-804, CWE-942 and CWE-1244. None fits better: CWE-551 and CWE-647 cover URL parsing and paths, CWE-639 covers a user-supplied key, CWE-804 covers CAPTCHAs, CWE-942 covers cross-domain policy files and CWE-1244 covers hardware debug access. CWE-863 is kept. |
| CWE | CWE-926 | Improper Export of Android Application Components | Verified | Direct. `MyService` is exported with no `android:permission` (Benign manifest lines 22 to 25); the Secure fix adds a signature-level `android:permission` (Secure manifest lines 5 to 7 and 28). Usage ALLOWED. |
| CWE | CWE-441 | Unintended Proxy or Intermediary | Verified | Partial. `MyService` starts the unexported `SensitiveActivity` under Benign's identity for Malicious (`MyService.java` lines 20 to 23), the confused deputy pattern named as an alternate term on the CWE page; the root cause is the faulty check, which CWE-863 covers. Usage ALLOWED-WITH-REVIEW. Mapping notes review: the Rationale and Comment say this is a Class that might have more appropriate Base-level children, so the children should be examined. Children shown on the page: CWE-918 (Server-Side Request Forgery) and CWE-1021 (Improper Restriction of Rendered UI Layers or Frames). Neither fits better, because CWE-918 covers a server fetching a URL and CWE-1021 covers UI layers or frames, so CWE-441 is kept. |
| OWASP MASVS v2 | MASVS-PLATFORM-1 | The app uses IPC mechanisms securely. | Verified | Direct. Exported service reached by an explicit intent from another app (Benign manifest lines 22 to 25, `MalActivity.java` lines 21 to 25). |
| OWASP MASTG test | MASTG-TEST-0365 | Exported And Unprotected Services That Expose Sensitive Functionality | Verified | Direct. `MyService` is exported without a manifest permission (Benign manifest lines 22 to 25) and starts `SensitiveActivity` (`MyService.java` lines 20 to 23). |
| OWASP MASTG test | MASTG-TEST-0029 | Testing for Sensitive Functionality Exposure Through IPC | Verified | Partial. Covers the same exported service (Benign manifest lines 22 to 25), but the page is deprecated and points to MASTG-TEST-0365; kept for reference only. |
| OWASP MASWE | MASWE-0018 | Lack of Authentication or Authorization on App Components | Verified | Direct. Exported service with no manifest permission (Benign manifest lines 22 to 25) whose run-time check passes for Malicious (`MyService.java` line 18); the page names services. |

CWE-862 (Missing Authorization) was considered and not used, because `MyService.java` line 18 does perform a check; CWE-863 is used instead. CWE-284 (DISCOURAGED) was considered; CWE-863 and CWE-926 are used instead.

MITRE ATT&CK for Mobile: No direct match. No technique on attack.mitre.org was verified that describes passing another app's faulty `checkPermission` call by starting its exported service.

- **Candidates to check:** None.
- **Evidence plan:** On ghera27 (API 27, inside the README range of Android 5.1.1 to 8.1), install Benign and Malicious with `gradlew installApi27Debug`, launch Malicious and check whether `SensitiveActivity` shows "Activity Started from Service" (`Testing/benign_app/src/androidTest/java/edu/ksu/cs/benign/Tests.java` lines 64 to 69), and read the "Calling PID" log line from `MyService.java` line 16; then replace Benign with Secure, launch Malicious, and check that `MyService` is not started (`Testing/secure_app/src/androidTest/java/edu/ksu/cs/secure/Tests.java` lines 69 to 80). Not yet run.
- **README vs code differences:**
  - README step 7 (`README.md` line 76) expects "Activity started from service."; the code sets "Activity Started from Service" (`Benign/app/src/main/java/edu/ksu/cs/benign/SensitiveActivity.java` line 19), which the test checks (`Testing/benign_app/src/androidTest/java/edu/ksu/cs/benign/Tests.java` line 69).
  - The README names `Binder.getCallingPID()` twice where the second should be the UID method (`README.md` line 26); the code uses `Binder.getCallingPid()` and `Binder.getCallingUid()` (`MyService.java` line 18).
  - The README description says the permission "was already granted to *Benign/MainActivity* before" (`README.md` line 33), but README steps and the Testing code (`Tests.java` line 64) launch only Malicious.
- **Open questions:**
  - Whether `Binder.getCallingPid()` and `Binder.getCallingUid()` inside `onStartCommand` return Benign's own values on API 27, as the README states; to confirm from the log at `MyService.java` line 16.
  - `santos.benign.permission` has no protection level (Benign manifest line 5), yet `MainActivity` requests it at run time (`MainActivity.java` line 33). Whether a dialog appears on API 27 is not stated in the README.
  - The Secure test reads `ActivityManager.getRunningServices` from the test app (`Testing/secure_app/src/androidTest/java/edu/ksu/cs/secure/Tests.java` lines 72 to 79). Whether that call lists another app's services on API 27 is not shown in the source; if it does not, the test passes either way.

### ClipboardUse-InformationExposure-Lean
- **Summary:** An app copies sensitive text to the system clipboard, which every app can read. A malicious app that listens for clipboard changes receives the copied value.
- **Android versions (from README):** "Tested on Android 5.1.1 - Android 8.1"
- **What the code does:** Benign's layout has one `EditText` with id `ssn` and initial text "Enter SSN" and a "Copy-SSN" button (`Benign/app/src/main/res/layout/activity_main.xml` lines 12 to 28). Clicking the button puts the `EditText` contents on the clipboard as plain text labelled "Password" (`Benign/app/src/main/java/edu/ksu/cs/benign/MainActivity.java` lines 28 to 31 and 36 to 38). Malicious registers an `OnPrimaryClipChangedListener` and writes the first clip item's text into its `TextView` (`Malicious/app/src/main/java/edu/ksu/cs/malicious/MainActivity.java` lines 22 to 27 and 31 to 36). Secure sets a selection action mode callback whose `onCreateActionMode` returns false, and its button copies the constant "DummyPass" instead of the field (`Secure/app/src/main/java/edu/ksu/cs/benign/MainActivity.java` lines 28 to 32 and 56).

| Standard | ID | Title | Confidence | Fit |
|----------|----|-------|------------|-----|
| CWE | CWE-359 | Exposure of Private Personal Information to an Unauthorized Actor | Verified | Partial. The copied field is labelled "Enter SSN" (Benign layout line 18) and its text is put on the clipboard (`MainActivity.java` lines 30 to 31), where Malicious reads it (Malicious `MainActivity.java` lines 34 to 35). Partial because the README describes the copied value as a password, not personal information, and the code labels the clip "Password" (line 30). Usage ALLOWED. |
| OWASP MASVS v2 | MASVS-STORAGE-2 | The app prevents leakage of sensitive data. | Verified | Direct. Benign places the field's contents on the shared clipboard (`MainActivity.java` line 31). |
| OWASP MASVS v2 | MASVS-PLATFORM-1 | The app uses IPC mechanisms securely. | Verified | Partial. The clipboard is the shared channel between Benign (`MainActivity.java` line 31) and Malicious (Malicious `MainActivity.java` line 23), and the MASWE clipboard entry listed under Candidates is filed under this control on the MASWE index; it is not a component-level IPC weakness. |

No MASTG test or MASWE entry in the reference file fits: the listed tests and MASWE-0018 and MASWE-0032 cover exported components and intents, and this benchmark has neither (both manifests declare only a launcher activity, `Benign/app/src/main/AndroidManifest.xml` lines 15 to 21).

CWE-200 (DISCOURAGED) was considered, as in the benchmark index draft; CWE-359 is used instead. CWE-522 (Insufficiently Protected Credentials) was considered because the README calls the value a password, and not used because the code field is the SSN field (Benign layout lines 12 to 18) and has no password input type.

MITRE ATT&CK for Mobile: No direct match. No technique on attack.mitre.org was verified for reading clipboard data copied by another app.

- **Candidates to check:**
  - MASWE-0030 (Improper Use of the Clipboard): matches the Benign copy (`MainActivity.java` line 31); title taken from the MASWE index page downloaded on 2026-11-01, not in the reference file.
- **Evidence plan:** On ghera27 (API 27, inside the README range of Android 5.1.1 to 8.1), install Benign and Malicious, launch Malicious, launch Benign, enter "666" in the field and press "Copy-SSN", bring Malicious to the front and check that it shows "666" (`Testing/benign_app/src/androidTest/java/edu/ksu/cs/benign/Tests.java` lines 72 to 84); repeat with Secure, check that Malicious shows "DummyPass" (`Testing/secure_app/src/androidTest/java/edu/ksu/cs/secure/Tests.java` line 84) and that a long press on the field offers no copy option. Not yet run.
- **README vs code differences:**
  - The README describes username and password fields and a "COPY-PASS" button (`README.md` lines 21 to 22 and 73); the code has a single field labelled "Enter SSN" and a "Copy-SSN" button (`Benign/app/src/main/res/layout/activity_main.xml` lines 12 to 28), while the clip label is "Password" (`MainActivity.java` line 30).
  - Benign declares and uses a custom permission `santos.benign.permission` that nothing checks (`Benign/app/src/main/AndroidManifest.xml` lines 5 to 6).
- **Open questions:**
  - Whether the protected data is meant to be an SSN or a password; the source and README disagree.
  - The Secure test only shows that Malicious receives "DummyPass" from the Secure button (`Testing/secure_app/src/androidTest/java/edu/ksu/cs/secure/Tests.java` line 84); it does not test the long-press copy path that the Secure callback blocks (the README note explains UiAutomator cannot reach that dialog). Whether other copy paths remain open on API 27 is untested.

### DynamicCodeLoading-CodeInjection-Lean
- **Summary:** An app loads a jar from external storage at run time and uses a class from it without checking where the jar came from or whether it was changed. Replacing the jar changes the app's behavior.
- **Android versions (from README):** "Tested on Android 5.1.1 - Android 8.1"
- **What the code does:** On a button click, Benign builds the path `greetings.jar` under `getExternalFilesDir(null)`, loads it with a `PathClassLoader`, loads `secureiti.Helper` with `Class.forName` and shows its static `GREETING` field (`Benign/app/src/main/java/edu/ksu/cs/benign/MainActivity.java` lines 24 to 34). `UnsignedHelper` defines `GREETING = "Go to Hell"` (`UnsignedHelper/src/main/java/secureiti/Helper.java` line 4), and the test scripts push its dexed jar to that path (`source-script.sh` lines 10 to 16). Secure first calls `verify()`, which checks that the `classes.dex` entry carries a certificate that verifies against the bundled `keyOne-publickey.cert`, and shows "Hello" or "Hello!" instead of loading when it does not (`Secure/app/src/main/java/edu/ksu/cs/benign/MainActivity.java` lines 40 to 44 and 79 to 108).

| Standard | ID | Title | Confidence | Fit |
|----------|----|-------|------------|-----|
| CWE | CWE-829 | Inclusion of Functionality from Untrusted Control Sphere | Verified | Direct. Benign loads `greetings.jar` from external storage, a location other apps can write, and runs a class from it (`MainActivity.java` lines 24 to 31); the CWE describes importing executable functionality "from a source that is outside of the intended control sphere". Its children on the page (CWE-98 PHP includes, CWE-827 DTDs, CWE-830 web functionality) cover other technologies, so the entry is kept. Usage ALLOWED. |
| CWE | CWE-494 | Download of Code Without Integrity Check | Verified | Partial. Benign executes code from `greetings.jar` without any origin or integrity check (`MainActivity.java` lines 29 to 32). Partial because the CWE describes code downloaded from a remote location, while here the jar is placed on external storage by `adb push` (README step 6, `source-script.sh` lines 13 to 15) and nothing is downloaded. Usage ALLOWED. |
| OWASP MASVS v2 | MASVS-CODE-4 | The app validates and sanitizes all untrusted inputs. | Verified | Partial. The jar from external storage is untrusted input that Benign loads and runs without validation (`MainActivity.java` lines 29 to 32); the MASWE entry on dynamic code loading listed under Candidates is filed under this control on the MASWE index. |
| OWASP MASWE | MASWE-0050 | Unsafe Handling of Untrusted Data | Verified | Partial. Benign treats the externally stored jar as trusted and reads a field from a class loaded out of it (`MainActivity.java` lines 31 to 32). Partial because the entry is about untrusted data in general; the more specific dynamic code loading entry is not in the reference file (see Candidates). Controls shown on the page: MASVS-CODE-4. |

No MASTG test in the reference file fits: the listed tests cover exported components and content providers, and Benign has only a launcher activity (`Benign/app/src/main/AndroidManifest.xml` lines 14 to 23).

CWE-345 (DISCOURAGED) was considered for the missing authenticity check; CWE-494 is used instead. CWE-470 (Use of Externally-Controlled Input to Select Classes or Code) was considered and not used, because the class name is the constant "secureiti.Helper" (`MainActivity.java` line 31) and no external input selects it.

MITRE ATT&CK for Mobile: No direct match. No technique on attack.mitre.org was verified that describes replacing a jar that a benign app loads from its external files directory.

- **Candidates to check:**
  - MASWE-0049 (Unsafe Dynamic Code Loading): matches `PathClassLoader` use on an unverified jar (`MainActivity.java` line 29); title taken from the MASWE index page downloaded on 2026-11-01, not in the reference file.
- **Evidence plan:** On ghera27 (API 27, inside the README range of Android 5.1.1 to 8.1), install Benign, launch and close it, run `gradlew clean dexify` in `UnsignedHelper`, push `build/libs/unsigned-greetings.jar` to `$EXTERNAL_STORAGE/Android/data/edu.ksu.cs.benign/files/greetings.jar`, press "Press Me!!" and check for "Go to Hell" (`Testing/benign_app/src/androidTest/java/edu/ksu/cs/benign/Tests.java` line 75); repeat with Secure and check for "Hello" (`Testing/secure_app/src/androidTest/java/edu/ksu/cs/secure/Tests.java` line 75). Not yet run.
- **README vs code differences:**
  - README step 6 says to run `./gradle clean dexify` and to put an sdk entry in `gradle.properties` (`README.md` lines 65 to 68); `UnsignedHelper` ships `gradlew`, has no `gradle.properties`, and its build fails unless `ANDROID_HOME` is set (`UnsignedHelper/build.gradle` lines 17 to 20).
  - The README names only `UnsignedHelper`; the folder also has `SignedHelper` (greeting "Howdy", `SignedHelper/src/main/java/secureiti/Helper.java` line 4), which no script or test uses and which has no Gradle wrapper.
- **Open questions:**
  - Secure's `verify()` returns null, so the jar is loaded, when the jar has no `classes.dex` entry (`Secure/app/src/main/java/edu/ksu/cs/benign/MainActivity.java` lines 90 to 108); whether a jar without that entry can still supply `secureiti.Helper` to `PathClassLoader` is untested.
  - The Secure accept path (a jar signed with keyOne showing "Howdy") is not tested.
  - Whether the `READ_EXTERNAL_STORAGE` permission (`Benign/app/src/main/AndroidManifest.xml` line 5) is needed to read the app's own external files directory on API 27.

### EnforceCallingOrSelfPermission-PrivilegeEscalation-Lean
- **Summary:** An app protects a service with a run-time call to `enforceCallingOrSelfPermission`. According to the README, the call does not throw for any caller once the app's own component has been granted the permission, so a malicious app can start the service.
- **Android versions (from README):** "Tested on Android 5.1.1 - Android 8.1"
- **What the code does:** Benign declares `santos.benign.permission` with no protection level, uses it itself, and exports `MyService` with no `android:permission` (`Benign/app/src/main/AndroidManifest.xml` lines 5 to 7 and 23 to 26). `MyService.onStartCommand` calls `enforceCallingOrSelfPermission("santos.benign.permission", ...)` and, if it does not throw, starts `SensitiveActivity` with `status_msg=SUCCESS` (`Benign/app/src/main/java/edu/ksu/cs/benign/MyService.java` lines 17 to 22), which shows "Activity Started from Service" (`Benign/app/src/main/java/edu/ksu/cs/benign/SensitiveActivity.java` line 19). Malicious starts the service by explicit class name in `onResume` (`Malicious/app/src/main/java/edu/ksu/cs/malicious/MalActivity.java` lines 24 to 28). Secure removes the in-code check and protects the service with a signature-level permission in the manifest (`Secure/app/src/main/AndroidManifest.xml` lines 5 to 7 and 24 to 28).

| Standard | ID | Title | Confidence | Fit |
|----------|----|-------|------------|-----|
| CWE | CWE-863 | Incorrect Authorization | Verified | Direct. `MyService` performs an authorization check (`MyService.java` line 17), but it is satisfied by Benign's own permission (manifest line 7), so Malicious (`MalActivity.java` line 28) gets the sensitive action; the CWE description is a check that is performed but "does not correctly perform the check". Usage ALLOWED-WITH-REVIEW. Mapping notes review: the Rationale and Comment say this is a Class that might have more appropriate Base-level children, so the children should be examined. Children shown on the page: CWE-551, CWE-639, CWE-647, CWE-804, CWE-942 and CWE-1244. None fits better: CWE-551 and CWE-647 cover URL parsing and paths, CWE-639 covers a user-supplied key, CWE-804 covers CAPTCHAs, CWE-942 covers cross-domain policy files and CWE-1244 covers hardware debug access. CWE-863 is kept. |
| CWE | CWE-926 | Improper Export of Android Application Components | Verified | Direct. `MyService` is exported with no `android:permission` (Benign manifest lines 23 to 26); the Secure fix adds a signature-level `android:permission` (Secure manifest lines 5 to 7 and 28). Usage ALLOWED. |
| CWE | CWE-441 | Unintended Proxy or Intermediary | Verified | Partial. `MyService` starts the unexported `SensitiveActivity` under Benign's identity for Malicious (`MyService.java` lines 19 to 22), the confused deputy pattern named as an alternate term on the CWE page; the root cause is the faulty check, which CWE-863 covers. Usage ALLOWED-WITH-REVIEW. Mapping notes review: the Rationale and Comment say this is a Class that might have more appropriate Base-level children, so the children should be examined. Children shown on the page: CWE-918 (Server-Side Request Forgery) and CWE-1021 (Improper Restriction of Rendered UI Layers or Frames). Neither fits better, because CWE-918 covers a server fetching a URL and CWE-1021 covers UI layers or frames, so CWE-441 is kept. |
| OWASP MASVS v2 | MASVS-PLATFORM-1 | The app uses IPC mechanisms securely. | Verified | Direct. Exported service reached by an explicit intent from another app (Benign manifest lines 23 to 26, `MalActivity.java` lines 24 to 28). |
| OWASP MASTG test | MASTG-TEST-0365 | Exported And Unprotected Services That Expose Sensitive Functionality | Verified | Direct. `MyService` is exported without a manifest permission (Benign manifest lines 23 to 26) and starts `SensitiveActivity` (`MyService.java` lines 19 to 22). |
| OWASP MASTG test | MASTG-TEST-0029 | Testing for Sensitive Functionality Exposure Through IPC | Verified | Partial. Covers the same exported service (Benign manifest lines 23 to 26), but the page is deprecated and points to MASTG-TEST-0365; kept for reference only. |
| OWASP MASWE | MASWE-0018 | Lack of Authentication or Authorization on App Components | Verified | Direct. Exported service with no manifest permission (Benign manifest lines 23 to 26) whose run-time check passes for Malicious (`MyService.java` line 17); the page names services. |

CWE-862 (Missing Authorization) was considered and not used, because `MyService.java` line 17 does perform a check; CWE-863 is used instead. CWE-284 (DISCOURAGED) was considered; CWE-863 and CWE-926 are used instead.

MITRE ATT&CK for Mobile: No direct match. No technique on attack.mitre.org was verified that describes starting another app's exported service to pass a faulty run-time permission check.

- **Candidates to check:** None.
- **Evidence plan:** On ghera27 (API 27, inside the README range of Android 5.1.1 to 8.1), install Benign and Malicious with `gradlew installApi27Debug`, launch Malicious and check whether `SensitiveActivity` shows "Activity Started from Service" (`Testing/benign_app/src/androidTest/java/edu/ksu/cs/benign/Tests.java` lines 64 to 69); then replace Benign with Secure, launch Malicious, and check that `MyService` is not started (`Testing/secure_app/src/androidTest/java/edu/ksu/cs/secure/Tests.java` lines 69 to 80). Not yet run.
- **README vs code differences:**
  - README step 7 (`README.md` line 66) expects "Activity started from service."; the code sets "Activity Started from Service" (`Benign/app/src/main/java/edu/ksu/cs/benign/SensitiveActivity.java` line 19), which the test checks (`Testing/benign_app/src/androidTest/java/edu/ksu/cs/benign/Tests.java` line 69).
  - The README description says the permission "was already granted to *Benign/MainActivity* before" (`README.md` line 23), but README steps and the Testing code (`Tests.java` line 64) launch only Malicious.
- **Open questions:**
  - The README attributes the bypass to an earlier grant to `MainActivity`; the source does not show which identity `enforceCallingOrSelfPermission` sees inside `onStartCommand` (`MyService.java` line 15 logs the calling PID and UID). To confirm from the log on the emulator.
  - `santos.benign.permission` has no protection level (Benign manifest lines 5 to 6), yet `MainActivity` requests it at run time (`MainActivity.java` line 27). Whether a dialog appears on API 27 is not stated in the README.
  - The Secure test reads `ActivityManager.getRunningServices` from the test app (`Testing/secure_app/src/androidTest/java/edu/ksu/cs/secure/Tests.java` lines 72 to 79). Whether that call lists another app's services on API 27 is not shown in the source; if it does not, the test passes either way.

### EnforcePermission-PrivilegeEscalation-Lean
- **Summary:** An app protects a service with `enforcePermission` using `Binder.getCallingPid()` and `Binder.getCallingUid()`. The README explains that on the main thread these return the protected app's own PID and UID, so the call does not throw for any caller once the app itself holds the permission.
- **Android versions (from README):** "Tested on Android 5.1.1 - Android 8.1"
- **What the code does:** Benign declares `santos.benign.permission` with no protection level, uses it itself, and exports `MyService` with no `android:permission` (`Benign/app/src/main/AndroidManifest.xml` lines 5 to 6 and 23 to 26). `MyService.onStartCommand` calls `enforcePermission("santos.benign.permission", Binder.getCallingPid(), Binder.getCallingUid(), ...)` and, if it does not throw, starts `SensitiveActivity` with `status_msg=SUCCESS` (`Benign/app/src/main/java/edu/ksu/cs/benign/MyService.java` lines 17 to 22), which shows "Activity Started from Service" (`Benign/app/src/main/java/edu/ksu/cs/benign/SensitiveActivity.java` line 19). Malicious starts the service by explicit class name from its `MainActivity.onResume` (`Malicious/app/src/main/java/edu/ksu/cs/malicious/MainActivity.java` lines 20 to 24). Secure removes the in-code check and protects the service with a signature-level permission in the manifest (`Secure/app/src/main/AndroidManifest.xml` lines 5 to 7 and 24 to 28).

| Standard | ID | Title | Confidence | Fit |
|----------|----|-------|------------|-----|
| CWE | CWE-863 | Incorrect Authorization | Verified | Direct. `MyService` performs an authorization check (`MyService.java` line 17), but it passes the identity from `Binder.getCallingPid()` and `Binder.getCallingUid()`, which the README says is Benign's own identity on the main thread, so Malicious (`MainActivity.java` line 24) passes; the CWE description is a check that is performed but "does not correctly perform the check". Usage ALLOWED-WITH-REVIEW. Mapping notes review: the Rationale and Comment say this is a Class that might have more appropriate Base-level children, so the children should be examined. Children shown on the page: CWE-551, CWE-639, CWE-647, CWE-804, CWE-942 and CWE-1244. None fits better: CWE-551 and CWE-647 cover URL parsing and paths, CWE-639 covers a user-supplied key, CWE-804 covers CAPTCHAs, CWE-942 covers cross-domain policy files and CWE-1244 covers hardware debug access. CWE-863 is kept. |
| CWE | CWE-926 | Improper Export of Android Application Components | Verified | Direct. `MyService` is exported with no `android:permission` (Benign manifest lines 23 to 26); the Secure fix adds a signature-level `android:permission` (Secure manifest lines 5 to 7 and 28). Usage ALLOWED. |
| CWE | CWE-441 | Unintended Proxy or Intermediary | Verified | Partial. `MyService` starts the unexported `SensitiveActivity` under Benign's identity for Malicious (`MyService.java` lines 19 to 22), the confused deputy pattern named as an alternate term on the CWE page; the root cause is the faulty check, which CWE-863 covers. Usage ALLOWED-WITH-REVIEW. Mapping notes review: the Rationale and Comment say this is a Class that might have more appropriate Base-level children, so the children should be examined. Children shown on the page: CWE-918 (Server-Side Request Forgery) and CWE-1021 (Improper Restriction of Rendered UI Layers or Frames). Neither fits better, because CWE-918 covers a server fetching a URL and CWE-1021 covers UI layers or frames, so CWE-441 is kept. |
| OWASP MASVS v2 | MASVS-PLATFORM-1 | The app uses IPC mechanisms securely. | Verified | Direct. Exported service reached by an explicit intent from another app (Benign manifest lines 23 to 26, Malicious `MainActivity.java` lines 20 to 24). |
| OWASP MASTG test | MASTG-TEST-0365 | Exported And Unprotected Services That Expose Sensitive Functionality | Verified | Direct. `MyService` is exported without a manifest permission (Benign manifest lines 23 to 26) and starts `SensitiveActivity` (`MyService.java` lines 19 to 22). |
| OWASP MASTG test | MASTG-TEST-0029 | Testing for Sensitive Functionality Exposure Through IPC | Verified | Partial. Covers the same exported service (Benign manifest lines 23 to 26), but the page is deprecated and points to MASTG-TEST-0365; kept for reference only. |
| OWASP MASWE | MASWE-0018 | Lack of Authentication or Authorization on App Components | Verified | Direct. Exported service with no manifest permission (Benign manifest lines 23 to 26) whose run-time check passes for Malicious (`MyService.java` line 17); the page names services. |

CWE-862 (Missing Authorization) was considered and not used, because `MyService.java` line 17 does perform a check; CWE-863 is used instead. CWE-284 (DISCOURAGED) was considered; CWE-863 and CWE-926 are used instead.

MITRE ATT&CK for Mobile: No direct match. No technique on attack.mitre.org was verified that describes passing another app's faulty `enforcePermission` call by starting its exported service.

- **Candidates to check:** None.
- **Evidence plan:** On ghera27 (API 27, inside the README range of Android 5.1.1 to 8.1), install Benign and Malicious with `gradlew installApi27Debug`, launch Malicious and check whether `SensitiveActivity` shows "Activity Started from Service" (`Testing/benign_app/src/androidTest/java/edu/ksu/cs/benign/Tests.java` lines 64 to 69), and read the "Calling PID" log line from `MyService.java` line 15; then replace Benign with Secure, launch Malicious, and check that `MyService` is not started (`Testing/secure_app/src/androidTest/java/edu/ksu/cs/secure/Tests.java` lines 69 to 80). Not yet run.
- **README vs code differences:**
  - README step 7 (`README.md` line 78) expects "Activity started from service."; the code sets "Activity Started from Service" (`Benign/app/src/main/java/edu/ksu/cs/benign/SensitiveActivity.java` line 19), which the test checks (`Testing/benign_app/src/androidTest/java/edu/ksu/cs/benign/Tests.java` line 69).
  - The README names `Binder.getCallingPID()` twice where the second should be the UID method (`README.md` line 26); the code uses `Binder.getCallingPid()` and `Binder.getCallingUid()` (`MyService.java` line 17).
  - The README description says the permission "was already granted to *Benign/MainActivity* before" (`README.md` line 34), but README steps and the Testing code (`Tests.java` line 64) launch only Malicious.
- **Open questions:**
  - Whether `Binder.getCallingPid()` and `Binder.getCallingUid()` inside `onStartCommand` return Benign's own values on API 27, as the README states; to confirm from the log at `MyService.java` line 15.
  - `santos.benign.permission` has no protection level (Benign manifest line 5), yet `MainActivity` requests it at run time (`MainActivity.java` line 27). Whether a dialog appears on API 27 is not stated in the README.
  - The Secure test reads `ActivityManager.getRunningServices` from the test app (`Testing/secure_app/src/androidTest/java/edu/ksu/cs/secure/Tests.java` lines 72 to 79). Whether that call lists another app's services on API 27 is not shown in the source; if it does not, the test passes either way.

### UniqueIDs-IdentityLeak-Lean
- **Summary:** An app identifies its installation with the device identifier and stores it where other apps can read it. A malicious app reads the file and learns a value that identifies the device, not just the app instance.
- **Android versions (from README):** "Tested on Android 4.4 - Android 7.1"
- **What the code does:** Benign holds `READ_PHONE_STATE` (`Benign/app/src/main/AndroidManifest.xml` line 5), reads `TelephonyManager.getDeviceId()` and writes "DeviceId :" plus the ID to `UNIQUE_ID.txt` under `getExternalFilesDir(null)`, then shows the file contents (`Benign/app/src/main/java/edu/ksu/cs/benign/MainActivity.java` lines 26 to 30, 51 to 56 and 72 to 77). Malicious, with `READ_EXTERNAL_STORAGE` (`Malicious/app/src/main/AndroidManifest.xml` line 5), takes its own external files path, replaces "malicious" with "benign", reads that `UNIQUE_ID.txt` and shows it (`Malicious/app/src/main/java/edu/ksu/cs/malicious/MalActivity.java` lines 45 to 58). Secure drops `READ_PHONE_STATE` and writes `UUID.randomUUID()` to the same file instead (`Secure/app/src/main/java/edu/ksu/cs/benign/MainActivity.java` lines 26 and 31 to 33 and 49 to 53).

| Standard | ID | Title | Confidence | Fit |
|----------|----|-------|------------|-----|
| CWE | CWE-359 | Exposure of Private Personal Information to an Unauthorized Actor | Verified | Direct. The device ID from `getDeviceId()` (`MainActivity.java` line 55) is written to a file in external storage (lines 74 to 76) and read by an unrelated app (`MalActivity.java` lines 46 to 52). Usage ALLOWED. |
| CWE | CWE-922 | Insecure Storage of Sensitive Information | Verified | Partial. Benign stores the device ID in `UNIQUE_ID.txt` under `getExternalFilesDir(null)` (`MainActivity.java` line 74), which Malicious reads (`MalActivity.java` line 48). Partial because the README's fix changes the stored value, not the storage: Secure still writes to the same file (`Secure/app/src/main/java/edu/ksu/cs/benign/MainActivity.java` lines 51 to 53). Usage ALLOWED-WITH-REVIEW. Mapping notes review: the Rationale and Comment say this is a Class that might have more appropriate Base-level children, so the children should be examined. Children shown on the page: CWE-312 (Cleartext Storage of Sensitive Information) and CWE-921 (Storage of Sensitive Data in a Mechanism without Access Control). CWE-921 fits better, because the problem is that another app can read the file, not that the file is unencrypted; it is not in the reference file, so CWE-922 is kept and CWE-921 is listed under Candidates. CWE-312 covers cleartext only and does not fit better. |
| OWASP MASVS v2 | MASVS-PRIVACY-2 | The app prevents identification of the user. | Verified | Direct. Benign uses the device identifier as its instance ID (`MainActivity.java` lines 51 to 56); Secure uses a random UUID (`Secure/app/src/main/java/edu/ksu/cs/benign/MainActivity.java` line 32). |
| OWASP MASVS v2 | MASVS-STORAGE-2 | The app prevents leakage of sensitive data. | Verified | Partial. The leak path is the external storage file (`MainActivity.java` lines 74 to 76, `MalActivity.java` line 48); the README frames the issue as the identifier choice rather than the storage. |
| OWASP MASVS v2 | MASVS-PRIVACY-1 | The app minimizes access to sensitive data and resources. | Verified | Partial. Benign requests `READ_PHONE_STATE` only to build an instance ID (manifest line 5, `MainActivity.java` lines 26 to 33); Secure declares no permission (`Secure/app/src/main/AndroidManifest.xml` lines 1 to 21). |

No MASTG test or MASWE entry in the reference file fits: the listed tests and MASWE-0018 and MASWE-0032 cover exported components and intents, and neither Benign nor Secure declares anything but a launcher activity (`Benign/app/src/main/AndroidManifest.xml` lines 13 to 19).

CWE-200 (DISCOURAGED) was considered; CWE-359 is used instead.

MITRE ATT&CK for Mobile: No direct match. No technique on attack.mitre.org was verified for reading a device identifier that another app saved to external storage.

- **Candidates to check:**
  - CWE-921 (Storage of Sensitive Data in a Mechanism without Access Control): child of CWE-922 shown on its page; matches the file in external storage that Malicious reads (`MainActivity.java` line 74, `MalActivity.java` line 48). Not in the reference file.
  - MASWE-0068 (Incorrect Use of Identifiers for User Tracking): matches the use of `getDeviceId()` as an instance ID (`MainActivity.java` line 55); title taken from the MASWE index page downloaded on 2026-11-01, not in the reference file.
  - MASWE-0002 (Sensitive Data Stored Unencrypted Outside of Private Storage): matches writing the ID in plain text to external storage (`MainActivity.java` lines 74 to 76); title taken from the same MASWE index page, not in the reference file.
- **Evidence plan:** The README range (Android 4.4 to 7.1) excludes API 27, so a run on ghera27 is outside the tested range, although the Testing code allows API 22 to 27 (`Testing/benign_app/src/androidTest/java/edu/ksu/cs/benign/Tests.java` line 26); on ghera27, install Benign and Malicious, launch Benign and allow the phone permission, launch Malicious and allow the storage permission, and compare the two displayed strings (`Tests.java` lines 86 to 98); repeat with Secure (`Testing/secure_app/src/androidTest/java/edu/ksu/cs/secure/Tests.java` lines 86 to 96). Not yet run.
- **README vs code differences:**
  - The README range starts at Android 4.4 (`README.md` line 5), but the shared build sets `minSdkVersion 22` (`../../Misc/sdkFlavors.gradle` line 5, outside the benchmark folder) and the tests run on API 22 to 27 (`Testing/benign_app/src/androidTest/java/edu/ksu/cs/benign/Tests.java` line 26).
  - README step 7 expects "DeviceId : <ID>" (`README.md` line 63); the code writes "DeviceId :" with no space before the ID (`Benign/app/src/main/java/edu/ksu/cs/benign/MainActivity.java` line 76).
  - The Secure test asserts that Malicious shows the same string as the app (`Testing/secure_app/src/androidTest/java/edu/ksu/cs/secure/Tests.java` line 96), the same assertion as the Benign test (`Testing/benign_app/src/androidTest/java/edu/ksu/cs/benign/Tests.java` line 98), so it does not tell Benign and Secure apart.
- **Open questions:**
  - Whether `getDeviceId()` returns a value on the ghera27 emulator, and whether Benign behaves the same on API 27, which is outside the README range.
  - Secure still writes its identifier, labelled "DeviceId :", to a file other apps can read (`Secure/app/src/main/java/edu/ksu/cs/benign/MainActivity.java` lines 51 to 53); the README accepts this ("only the app may be affected"), so whether the fix is meant to cover storage is open.

