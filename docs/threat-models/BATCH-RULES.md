# Batch rules

Rules:
1. Every statement about the apps comes from the README or the source code. Anything else goes in Open questions.
2. Follow docs/threat-models/TEMPLATE.md at the same depth as docs/threat-models/ICC-NoValidityCheckOnBroadcastMsg-UnintendedInvocation.md. Mermaid diagrams must use valid syntax.
3. Standards: use only IDs that are in docs/threat-models/standards-reference.md, with the exact titles from that file. Every row needs a Fit value (Direct or Partial) and a reason that points to a line of code. If a CWE you want is not in the reference file, first add it: download the official page, fill the row from the raw HTML, and commit "Extend standards reference: <ids>". If its Usage is ALLOWED-WITH-REVIEW or DISCOURAGED, do the mapping-notes review (Rationale, Comment, children one level down) and record the outcome. Never put a DISCOURAGED ID in a table; add one line under the table saying it was considered. For an ALLOWED-WITH-REVIEW ID, the Fit note holds the outcome of the review, never an instruction to the reader.
4. MASTG and MASWE: only MASTG-TEST-0366, MASTG-TEST-0029 (deprecated, reference only) and MASWE-0063 (beta). Any other candidate goes under "Candidates to check".
5. MITRE ATT&CK for Mobile: "No direct match" with a one-sentence reason unless the ID is verified on attack.mitre.org.
6. Evidence: claim no observed result and reference no screenshots. List the exact steps to run by hand on the ghera27 emulator for both pairs (Benign + Malicious, then Secure + Malicious), the build and install commands, the adb am broadcast line without the Malicious app, and the expected result from the README and the Testing code. Mark everything "Not yet run" and "Not yet observed".
7. Mitigation: diff Benign and Secure with exact files and lines, and assess whether the fix is complete. Any claim about newer Android versions is labeled "Hypothesis, to test in Step 3".
8. Open questions: list README vs code differences, and any Lean vs Fat differences.
9. No em dashes. Commit one model per commit with the message "Add threat model: <benchmark name>". No Co-Authored-By trailer and no mention of Claude, Claude Code, or AI in commit messages, files, or comments.
10. Do not touch anything under benchmarks/.
