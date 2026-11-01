# Ghera Inventory

Folder count per category in the Ghera repository at tag `Jan2019` (commit `6289f39d`).

| Category | Folders |
|----------|--------:|
| Crypto | 5 |
| ICC | 18 |
| Misc | 2 |
| Networking | 8 |
| NonAPI | 2 |
| Permission | 2 |
| Storage | 7 |
| System | 7 |
| TemplateCategory | 1 |
| Web | 8 |
| **Total** | **60** |

## Notes

Verified findings for tag `Jan2019`:

- There are 60 top-level benchmark folders in total, of which 57 are real benchmarks.
- Not benchmarks: `Misc` (`android_keys`, `LocalServer`) and `TemplateCategory` (`TemplateBenchmark`).
- Of the 57 benchmarks, 56 are lean and 1 is fat: `ICC/UnprotectedBroadcastRecv-PrivEscalation-Fat`.
- Lean benchmarks per category:

| Category | Lean benchmarks |
|----------|----------------:|
| Crypto | 5 |
| ICC | 17 |
| Networking | 8 |
| NonAPI | 2 |
| Permission | 2 |
| Storage | 7 |
| System | 7 |
| Web | 8 |
| **Total** | **56** |

- `Web` has 8 of the 12 benchmarks listed on the Ghera website. The other 4 were added after this tag.
