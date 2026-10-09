# Windows verification and native acceptance evidence — 2026-10-09

**Status: PARTIAL. Windows automated checks and CLI/module checks are reported; installed-VSIX GUI acceptance remains NOT_RUN or PARTIAL as detailed below.**

This report corrects the scope and identity of the evidence originally committed in `18195df8667f27526bdbb5c9c0a73555782b2804`. The historical screenshots and test sources are retained unchanged. No Windows tests, native editor actions or package rebuild were performed by this documentation reconciliation.

## 1. Candidate and artifact identity

- Repository: `rodhayl/VSCodeAntivir`; branch: `codex/safe-remediation-20261004`; PR #21.
- Product: FakeInterviewGuard; extension ID: `fakeinterviewguard.fake-interview-guard`; version: `1.0.0`.
- Reported starting baseline: `88cca02765577e4b5009acdcafca9c052ab8a137`.
- Product-input reference after the Windows fixes: `18195df8667f27526bdbb5c9c0a73555782b2804`. This is **not** proof that the tester used a clean checkout of that commit: the original worktree state and exact commands were not preserved in this report.
- Tester-reported VSIX: `fake-interview-guard-1.0.0.vsix`, SHA-256 `a872b0c71e690788ca0510936cc3488ea618a802759fb49784f5218a303d9288`, 1,398,502 bytes, 1,098 entries. The actual Windows VSIX and raw run logs were unavailable to the independent review; package bytes and reported results have not been independently reverified.
- Reported 98-input `sourceTreeSha256`: `1201aa5ec8232c6be0f8d44defb55ffbff8e474cd578d7981f81e4411e012e3e`.
- Independent source reconciliation matched all 98 package-input blobs to `18195df8667f27526bdbb5c9c0a73555782b2804`. The committed-byte digest is `2824ef95e427699228d246aaab30b2c95390921e656febea47a41f21dfa797cd`; converting text inputs to Windows CRLF reproduces the reported `1201aa5…` digest exactly. These are two byte representations of the current product inputs, not evidence for a pristine baseline build. The 98-input digest does not cover the whole repository or replace the VSIX hash.
- This correction changes documentation only and therefore leaves those 98 package inputs unchanged.

Tester-reported environment: Windows 11 Pro x64, Node `v24.21.0`, npm `11.19.0`, VS Code `1.141.0`, editor commit `2a59476c9bfcb90b3ddc372c36762471b7dfad1c`. These details remain reported until raw logs and the package can be recovered or a new exact-candidate run is recorded.

## 2. Windows fixes and verification boundaries

`18195df…` contains the quarantine directory-creation termination/extended-path handling change, platform guards around POSIX permissions and read-only-descriptor fsync, and test cleanup retries. See [DEFECTS.md](DEFECTS.md) for the original reported defects and regression names.

The code change and tests exist; the reported Windows results below are not a fresh independent execution. Skipping directory fsync on Windows is an implementation limit, not proof that flushing is unnecessary or that Windows ACL protection and power-loss durability have been validated.

| Check | Reported result | Evidence boundary |
| --- | --- | --- |
| `npm ci --ignore-scripts` | PASS; 0 audit vulnerabilities | Windows raw log unavailable; no current audit rerun is claimed |
| Typecheck / lint | PASS; 0 diagnostics / warnings | Tester-reported |
| Unit suite | 376 passed, 6 pending, 0 failed | Tester-reported; six symlink-related probes were skipped, so Windows symlink behavior remains unverified |
| Author-built benchmark | 20 cases × 20 iterations; TP 8, FP 4, TN 8, FN 0, errors 0; p50 2.2536 ms, p95 3.997 ms | Tester-reported warmed scanner calls; not real-world detection efficacy or whole-application latency |
| Package smoke | PASS; 53 rules, 4 prompts, four runtime dependencies | Tester-reported extraction/import smoke; not GUI acceptance |
| Extension Host | 34 passed, 0 failed, 58 s | Tester-reported development-host execution via `extensionDevelopmentPath` and `--disable-extensions`; distinct from the installed VSIX |
| VSIX CLI lifecycle / payload modules | PASS reported | Script installs/uninstalls/reinstalls via CLI, then imports installed modules into plain Node; this does not launch and exercise the installed extension in the editor |
| Installed-VSIX GUI acceptance | **NOT_RUN / PARTIAL** | Required paths below are not established by the committed evidence |

No raw command transcript with exit codes accompanies the Windows report. No check/run result for `18195df…` was returned by the independent repository review. Preserve any original logs if recovered; do not overwrite historical evidence with a new run.

## 3. Coverage and outstanding acceptance

The installed helper is `extension/scripts/test-installed-vsix-acceptance.js`; the development-host suite is `extension/test/suite/native-acceptance.test.js`. Names such as “native”, “Restricted Mode” and “dismissal” in these scripts exceed what their assertions establish.

| Existing acceptance criterion | Current status | What the evidence actually establishes / next action |
| --- | --- | --- |
| CLI install, uninstall, reinstall in isolated directories | PARTIAL | Script checks listings and one installed folder; success is reported. Actual installed GUI activation, reload and absence of stale active copies still need observation |
| Exact installed artifact identity | PARTIAL | CLI helper checks `files.length === 98` and prints metadata; it does not compare the expected input digest. Host test checks ID/version only. Record and compare VSIX hash, metadata and active installed path |
| Restricted Mode: manual file/workspace scans and dashboard | NOT_RUN | Direct `Scanner` imports do not activate an untrusted editor. Host test never asserts `workspace.isTrusted === false`; screenshots do not establish Restricted Mode |
| Restricted Mode: no store, model, watcher or workspace changes; settings cannot bypass restrictions | NOT_RUN | Absence of a home store after importing only `Scanner` is insufficient. Test a genuinely untrusted installed window with before/after evidence |
| Real review and quarantine dialog cancellation/dismissal | NOT_RUN | Helper performs inspection without showing a dialog; host “cancellation” test calls `fig.scanFile`. Exercise actual controls and compare bytes, backups and store state |
| Trusted review/apply/clean Undo/newer-edit refusal through GUI | PARTIAL | Direct `TaskInterceptor` checks cover application, clean restoration and conflict refusal. No GUI Apply/Undo path is shown |
| Quarantine/reload/restore, recreated-destination conflict, hashes/permissions through GUI | PARTIAL | Direct `QuarantineManager` checks cover byte/hash roundtrip and conflict refusal. Installed panel actions, restart recovery and Windows permissions remain unverified |
| Dashboard and quarantine panel appearance | PARTIAL | Development-host screenshots show the dashboard and an empty quarantine panel, not an installed restore flow |
| Repeated clicks, close/reopen, busy/corrupt store and interrupted-operation messages | NOT_RUN | Repeating `fig.reloadRules` and checking `isActive` does not establish lock integrity, idempotence, memory safety or recovery UI |
| Keyboard selection/execution, focus and readable worded feedback | PARTIAL | Screenshot shows 11 FIG commands in the palette. Keyboard execution/focus traversal and dialogs remain unverified |
| Windows symlink/junction handling | NOT_RUN | Six reported skips are not passes. Disclosed limit, not an added acceptance gate; optional benign-link checks only if required by an existing case and permitted by current OS permissions |
| Live providers, Windows ACL security, real power-loss durability | NOT_RUN | No live provider was authorized/exercised; no guarantee is made for ACL security or power loss. These are disclosed limits, not new features requested by this continuation |

Use PASS only for the exact criterion actually observed on the identified artifact. The independent source review identified no material production-code change required for the portfolio scope. The bounded next campaign is in [CONTINUE.md](CONTINUE.md), using the existing acceptance contract in [VERIFICATION.md](../../VERIFICATION.md).

## 4. Historical screenshots, inspected limits

All eight files are preserved under their original names. They belong to the development-host campaign; filenames are not assertions of what happened. Screenshot helper failures were not asserted by the suite.

- [01-installed-extension.png](screenshots/01-installed-extension.png): development host with sample diagnostics. Does not identify an installed VSIX.
- [02-restricted-mode.png](screenshots/02-restricted-mode.png): benign file in the development host; no visible Restricted Mode banner or trust-state proof.
- [03-manual-scan-findings.png](screenshots/03-manual-scan-findings.png): benign scan / zero-findings view; no untrusted-workspace proof.
- [04-security-dashboard.png](screenshots/04-security-dashboard.png): development-host Review Dashboard, severity words and advisory caveat.
- [05-quarantine-manager.png](screenshots/05-quarantine-manager.png): empty quarantine panel; no quarantine/restore sequence.
- [06-configuration-review-notification.png](screenshots/06-configuration-review-notification.png): tasks file and scan toasts; no review modal is visible.
- [07-remediation-applied-and-undo.png](screenshots/07-remediation-applied-and-undo.png): empty quarantine panel and scan toasts; no applied-remediation or Undo prompt is visible.
- [08-command-palette-keyboard.png](screenshots/08-command-palette-keyboard.png): palette lists 11 FIG commands; no selection/execution or focus traversal is established.

Machine-readable identities, reported results and pending criteria are in [EVIDENCE.json](EVIDENCE.json). The original report remains recoverable in Git at `18195df8667f27526bdbb5c9c0a73555782b2804`; its broad PASSED wording is superseded by this correction.
