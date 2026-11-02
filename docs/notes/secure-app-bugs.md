# Permission name mismatches in Ghera Secure apps

## Summary

Two Ghera Secure apps declare a custom signature permission under one name and protect the exported component with a different name. The required permission is defined by no app in the benchmark, so the declared signature permission protects nothing. Both Secure apps still block the benchmark's Malicious app, but only because Malicious does not hold a permission that nobody defines. Any app installed on the device can define the undefined name itself and then pass the check, so the protection works by accident and not by design. The fix in both cases is a one-line manifest change.

Affected benchmarks:

1. ICC/UnprotectedBroadcastRecv-PrivEscalation-Lean
2. ICC/IncorrectHandlingImplicitIntent-UnauthorizedAccess-Lean

## Environment

- Repository: Ghera benchmark repository, tag `Jan2019` (commit `6289f39d`).
- Method: source reading of the Secure, Benign and Malicious apps and of the Testing projects. All paths below are relative to `benchmarks/ghera/`.
- Completeness check: every Secure `AndroidManifest.xml` under `benchmarks/ghera/*/*/Secure*/app/src/main/` (55 Secure folders) was scanned for `<permission android:name>` declarations and for `android:permission`, `android:readPermission` and `android:writePermission` values. Custom permission strings in Secure Java sources were also searched. Only the two benchmarks above have a required name that differs from the declared name.
- Runtime verification: none. The apps were not built, installed or run for this report. Statements about Android behavior are from the platform's documented permission model for the benchmark range (API 22 to 27), not from a device run.

## Bug 1: UnprotectedBroadcastRecv-PrivEscalation-Lean

- Benchmark: `ICC/UnprotectedBroadcastRecv-PrivEscalation-Lean`
- Declared permission: `edu.ksu.cs.benign.permission1`, `protectionLevel="signature"`, at `ICC/UnprotectedBroadcastRecv-PrivEscalation-Lean/Secure/app/src/main/AndroidManifest.xml` lines 5 to 7 (name on line 6).
- Required permission: `edu.ksu.cs.secure.permission1`, as `android:permission` on the exported receiver `edu.ksu.cs.benign.MyReceiver`, at the same file, line 28 (receiver element lines 24 to 33).
- Other apps: the Benign manifest (`Benign/app/src/main/AndroidManifest.xml`) declares no custom permission; the Malicious manifest (`Malicious/app/src/main/AndroidManifest.xml`) declares and requests none. No file in the benchmark defines `edu.ksu.cs.secure.permission1`.
- Effect: the declared signature permission is attached to no component and has no effect. The receiver, which sends an SMS with Secure's `SEND_SMS` permission (`Secure/app/src/main/java/edu/ksu/cs/benign/MyReceiver.java` lines 17 to 21), is guarded by an undefined permission. Malicious sends an explicit broadcast to the receiver (`Malicious/app/src/main/java/edu/ksu/cs/malicious/MainActivity.java` lines 13 to 18) and is blocked because it does not hold `edu.ksu.cs.secure.permission1`. An app that adds `<permission android:name="edu.ksu.cs.secure.permission1" android:protectionLevel="normal"/>` and the matching `<uses-permission>` to its own manifest would be granted the permission at install time and could send SMS through Secure, which is the attack the benchmark is meant to prevent.
- Accidental or by design: accidental. The Secure test (`Testing/secure_app/src/androidTest/java/edu/ksu/cs/secure/Tests.java` lines 86 to 108) checks only that no message starting "Secure:" appears after Malicious runs. It passes with the mismatched name and would also pass with the intended name, so it cannot detect the mismatch.
- Recommended fix: make the receiver require the permission Secure declares.

```xml
<!-- Secure/app/src/main/AndroidManifest.xml, line 28 -->
<receiver
    android:name="edu.ksu.cs.benign.MyReceiver"
    android:enabled="true"
    android:exported="true"
    android:permission="edu.ksu.cs.benign.permission1">
```

- Reference: `docs/notes/benchmark-issues.md` line 25 (and the related entry on line 26, see Not confirmed).

## Bug 2: IncorrectHandlingImplicitIntent-UnauthorizedAccess-Lean

- Benchmark: `ICC/IncorrectHandlingImplicitIntent-UnauthorizedAccess-Lean`
- Declared permission: `edu.ksu.cs.benign.perm`, `protectionLevel="signature"`, at `ICC/IncorrectHandlingImplicitIntent-UnauthorizedAccess-Lean/Secure/app/src/main/AndroidManifest.xml` lines 5 to 7 (name on line 6).
- Required permission: `edu.ksu.cs.secure.perm`, as `android:permission` on `edu.ksu.cs.benign.SensitiveActivity`, at the same file, line 23 (activity element lines 21 to 28).
- Other apps: the Benign and Malicious manifests declare and request no custom permission. No file in the benchmark defines `edu.ksu.cs.secure.perm`.
- Effect: the declared signature permission is attached to no component and has no effect. `SensitiveActivity` returns "sensitive information" to its caller (`Secure/app/src/main/java/edu/ksu/cs/benign/SensitiveActivity.java` lines 19 to 22) and has an intent filter, so it is exported. Malicious starts it with an implicit intent (`Malicious/app/src/main/java/edu/ksu/cs/malicious/MainActivity.java` lines 31 to 37) and receives a `SecurityException` because it does not hold `edu.ksu.cs.secure.perm`. An app that defines `edu.ksu.cs.secure.perm` itself with `protectionLevel="normal"` and requests it would be granted the permission and would receive the sensitive result.
- Accidental or by design: accidental. The Secure test (`Testing/secure_app/src/androidTest/java/edu/ksu/cs/secure/Tests.java` lines 62 to 72) checks only that Malicious shows "SecurityException". It passes with the mismatched name and would also pass with the intended name, so it cannot detect the mismatch.
- Recommended fix: make the activity require the permission Secure declares.

```xml
<!-- Secure/app/src/main/AndroidManifest.xml, line 23 -->
<activity
    android:name="edu.ksu.cs.benign.SensitiveActivity"
    android:permission="edu.ksu.cs.benign.perm">
```

- Reference: `docs/notes/benchmark-issues.md` line 39.

## Suggested test addition (both bugs)

Neither Secure test can tell the intended permission from an undefined one. A check such as the following in each Secure test would catch the mismatch without a device interaction:

```java
PackageManager pm = InstrumentationRegistry.getTargetContext().getPackageManager();
// Throws NameNotFoundException if no installed app defines the permission.
PermissionInfo info = pm.getPermissionInfo("edu.ksu.cs.benign.permission1", 0);
assertEquals(PermissionInfo.PROTECTION_SIGNATURE,
        info.protectionLevel & PermissionInfo.PROTECTION_MASK_BASE);
```

Together with a check that the protected component's `ActivityInfo.permission` equals the declared name, this ties the Secure test to the intended protection.

## Not confirmed

| Entry in benchmark-issues.md | Claim | Finding |
|------------------------------|-------|---------|
| Line 26 (UnprotectedBroadcastRecv-PrivEscalation-Lean) | Secure does not hold the permission its own receiver requires, so Secure's own Send button may stop working. | Not confirmed from source. Secure's `MainActivity` (`Secure/app/src/main/java/edu/ksu/cs/benign/MainActivity.java` lines 58 to 61) sends the broadcast from the same app (same UID) as the receiver. Android grants a component permission check when the caller has the same UID as the component's owner, before it looks at the permission, so Secure's own broadcast should still reach `MyReceiver`. Not verified at runtime. |
| Lines 200 and 203 (SQLite-execSQL-Lean, SQLlite-RawQuery-SQLInjection-Lean) | Benign and Secure declare `edu.ks.cs.benign.MYCP_READ_PERMISSION` but no component uses it. | Confirmed as an unused declaration (`Storage/<Benchmark>/Secure/app/src/main/AndroidManifest.xml` lines 5 to 7; no `android:permission` attribute in the file), but it is not a name mismatch: no Secure component requires any custom permission. The name uses `edu.ks.cs` where the package is `edu.ksu.cs`; the same spelling is used in the Malicious `<uses-permission>` (line 5), so the typo has no functional effect. |
| Line 207 (SQLlite-SQLInjection-Lean) | The provider is guarded by a signature permission that Malicious requests. | No name mismatch. Secure declares `edu.ks.cs.benign.MYCP_READ_PERMISSION` (`Storage/SQLlite-SQLInjection-Lean/Secure/app/src/main/AndroidManifest.xml` line 6) and the provider requires the same string (line 28). The `edu.ks.cs` spelling is consistent across Benign, Secure and Malicious. |
| Lines 10 and 11 (DynamicRegBroadcastReceiver-UnrestrictedAccess-Lean) | Secure protects the receiver with a dangerous permission. | No name mismatch. Secure declares and requests `edu.ksu.cs.perm` (`ICC/DynamicRegBroadcastReceiver-UnrestrictedAccess-Lean/Secure/app/src/main/AndroidManifest.xml` lines 6 and 9) and registers the receiver with the same string (`Secure/app/src/main/java/edu/ksu/cs/benign/MainActivity.java` line 20). The protection-level concern in those entries is separate and is not covered here. |

## Summary table

| Benchmark | Declared permission (file:line) | Required permission (file:line) | Defined anywhere? | Protection | Fix |
|-----------|---------------------------------|---------------------------------|-------------------|------------|-----|
| ICC/UnprotectedBroadcastRecv-PrivEscalation-Lean | `edu.ksu.cs.benign.permission1` (Secure `AndroidManifest.xml`:6) | `edu.ksu.cs.secure.permission1` (Secure `AndroidManifest.xml`:28) | No | Accidental; bypassable by any app that defines the name | Line 28: require `edu.ksu.cs.benign.permission1` |
| ICC/IncorrectHandlingImplicitIntent-UnauthorizedAccess-Lean | `edu.ksu.cs.benign.perm` (Secure `AndroidManifest.xml`:6) | `edu.ksu.cs.secure.perm` (Secure `AndroidManifest.xml`:23) | No | Accidental; bypassable by any app that defines the name | Line 23: require `edu.ksu.cs.benign.perm` |
