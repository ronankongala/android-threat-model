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

