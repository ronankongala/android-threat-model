# Email draft to Professor Joydeep Mitra

**To:** Professor Joydeep Mitra
**From:** Ronan (kongala.r@northeastern.edu)
**Subject:** Ghera follow-up: threat models, an evaluated analysis tool, and incomplete fixes in some Secure apps

Dear Professor Mitra,

My name is Ronan, and I am a student at Northeastern University. Over the past months I have built a research project, android-threat-engine, on top of Ghera (tag `Jan2019`, 57 benchmarks) and motivated by your Rekha study with Venkatesh-Prasad Ranganath. The project has three parts: a library of 24 full threat models for the ICC and Web benchmarks (16 ICC, 8 Web), with STRIDE, LINDDUN, attack trees, verified CWE and OWASP MASVS, MASWE and MASTG mappings, 50 Mermaid diagrams, and file and line references for every claim; a ground truth dataset with one row per benchmark; and a layered APK analysis tool (manifest rules, smali code patterns, interprocedural taint analysis, and a dynamic layer that runs the app on an emulator, including a mode that installs the Benign or Secure app together with the Malicious app).

I evaluated the tool on the 53 benchmarks that build for API 27. It finds 37 true positives with 35 false positives, for precision 0.51 and recall 0.70; the static and dynamic runs give the same scores. A Secure APK counts as a false positive when it has any finding, so precision is low largely because many Secure apps still export components or keep code that the rules report. For context only, Rekha reported that all 14 tools together detected 30 of 42 benchmarks and that no single tool detected more than 15, with the best Table 8 entries at precision 0.938 and recall 0.357 (Marvin-SA), 1.000 and 0.333 (QARK) and 1.000 and 0.310 (MobSF). The Ghera version, the tools and the definition of a detection all differ, so I treat this comparison as directional. This round I also added a privacy policy checker that compares a policy's claims with the permissions and SDK packages an APK declares, and I have started a case study on five F-Droid apps (Loop Habit Tracker, Tasks.org, Markor, OpenTracks and drip); that work is in progress.

While writing the threat models I found Secure apps whose fix looks incomplete, summarized below. I would be grateful for 30 minutes of your time, in person or online, to show you the results and ask whether any of this would be useful to you or the Ghera project. The evaluation details are in [evaluation-report.md](evaluation-report.md) and the bug write-up is in [secure-app-bugs.md](secure-app-bugs.md).

**Three questions about possible collaboration**

1. Would you accept fixes for the Secure apps upstream in Ghera, for example the two one-line manifest changes for the permission name mismatches, and if so, would you prefer them as pull requests or as issue reports first?
2. Would a Rekha-style re-run, with current versions of free Android analysis tools against the same 53 benchmarks and the same ground truth, be of interest to you, and would you want it to follow the Rekha detection definition exactly so the results are comparable?
3. I have designed a drift study that records whether each exploit still works on Benign and is still blocked on Secure on API levels 22 to 34, both on newer devices and when rebuilt against newer target SDKs. Would you be open to advising or co-authoring a paper on that study?

Thank you for your time and for making Ghera and Rekha public.

Best regards,
Ronan
Northeastern University
kongala.r@northeastern.edu

## Attachment: summary of the Secure app findings

In several Ghera `Jan2019` benchmarks, the Secure app removes the specific exploit path but leaves the underlying weakness, or its Secure test cannot tell a fixed app from a broken one. The clearest cases are two permission name mismatches: in `UnprotectedBroadcastRecv-PrivEscalation-Lean` and `IncorrectHandlingImplicitIntent-UnauthorizedAccess-Lean`, the Secure manifest declares a signature permission under an `edu.ksu.cs.benign...` name but protects the exported component with an `edu.ksu.cs.secure...` name that no app defines, so the declared permission protects nothing and any app that defines the undefined name itself could pass the check; a scan of all 55 Secure manifests found no other mismatch, and each fix is a one-line change. Other cases include Secure apps that keep a trust-all TrustManager (`InsecureSSLSocket-MITM-Lean`) or an always-true HostnameVerifier (`CheckValidity-InformationExposure-Lean`), still expose a JavaScript bridge (`WebViewInterceptRequest-MITM-Lean`) or still send implicit broadcasts without a permission (`EmptyPendingIntent-PrivEscalation-Lean`, `StickyBroadcast-DataInjection-Lean`); fixes that use a random IV or salt without storing it, so the app cannot decrypt its own data (`BlockCipher-NonRandomIV-InformationExposure-Lean`, `PBE-ConstantSalt-InformationExposure-Lean`); and Secure tests that pass either way (`MergeManifest-UnintendedBehavior-Lean` is `assert true;`, and `UniqueIDs-IdentityLeak-Lean` repeats the Benign assertion). All of these come from reading the source code: in the issues log of 234 entries each is marked "Read in code, not yet run", and the permission mismatch report states that no app was built, installed or run for it. The only runs so far are a smoke test of `DynamicRegBroadcastReceiver-UnrestrictedAccess-Lean` on an API 27 emulator, where the exploit worked on Benign and was blocked on Secure as documented, and a two-app run of `TaskAffinity-ActivityHijack-Lean`, where the tool reported a task hijack for Benign plus Malicious and nothing for Secure plus Malicious. Confirming the Secure findings on an emulator is my next step.
