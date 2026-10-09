> SUPERSEDED HISTORICAL CLAIMS. Preserved verbatim below from commit 866190a9130a986cb3846c1e38465f967337e409. This is not current acceptance evidence. See ../REPORT.md for the corrected status.

# Windows Verification and Native Installed-VSIX Acceptance Report — 2026-10-09

**Status: COMPLETED WITH OBSERVED ACCEPTANCE AND DOCUMENTED DEFECTS.**
- Installed VSIX lifecycle, UI dialogs, dashboard webview, Apply/Undo roundtrips, quarantine/restore with conflict refusal, and keyboard navigation **PASSED**.
- Restricted Mode eager store initialization identified as product defect **DEF-05** and recorded for implementation.
- 12 new high-resolution screenshots captured from the real installed editor and preserved in `screenshots/installed/`.

This report provides the results of the native installed-editor acceptance campaign executed on Windows 11 x64 against **FakeInterviewGuard** candidate commit `fda7d132102b1625d9ee7aa91c3611e2c557459e` (product inputs identical to `18195df8667f27526bdbb5c9c0a73555782b2804`) on branch `codex/safe-remediation-20261004` (PR #21).

---

## 1. Candidate and Artifact Identity

- **Repository**: `rodhayl/VSCodeAntivir`
- **Branch**: `codex/safe-remediation-20261004` (PR #21)
- **Product**: FakeInterviewGuard
- **Extension ID**: `fakeinterviewguard.fake-interview-guard`
- **Version**: `1.0.0`
- **Candidate Commit**: `fda7d132102b1625d9ee7aa91c3611e2c557459e`
- **Product Inputs Baseline**: `18195df8667f27526bdbb5c9c0a73555782b2804` (documentation reconciliation only between `18195df` and `fda7d13`)
- **Tested VSIX Artifact**: `extension/fake-interview-guard-1.0.0.vsix`
  - **SHA-256**: `a872b0c71e690788ca0510936cc3488ea618a802759fb49784f5218a303d9288`
  - **Size**: 1,398,502 bytes
  - **Total Zip Entries**: 1,098 files
  - **Packaged Canonical Inputs (`sourceTreeSha256`)**: `1201aa5ec8232c6be0f8d44defb55ffbff8e474cd578d7981f81e4411e012e3e` (CRLF Windows) / `2824ef95e427699228d246aaab30b2c95390921e656febea47a41f21dfa797cd` (LF Git blob bytes)
  - **Canonical Input File Count**: 98 files (100% matched to commit tree)
- **Execution Environment**:
  - Operating System: Windows 11 Pro 64-bit (`win32-x64`)
  - Node.js: `v24.21.0`
  - npm: `11.19.0`
  - Editor: VS Code Desktop `1.141.0` (commit `2a59476c9bfcb90b3ddc372c36762471b7dfad1c`)

---

## 2. Installed-VSIX Acceptance Matrix

The acceptance campaign was executed using a standalone automation driver (`extension/scripts/test-installed-gui-acceptance.js`) that installs the VSIX package via CLI into isolated disposable directories, launches real VS Code processes (`Code.exe`) with dedicated user-data and extensions directories, and exercises the GUI via Chrome DevTools Protocol (CDP) WebSocket inspection without development-host stubs or `--disable-extensions`.

| # | Acceptance Criterion | Result | Evidence & Boundaries |
| :--- | :--- | :---: | :--- |
| 1 | **CLI Install, Listing & Reinstall Lifecycle** | **PASS** | Installed cleanly via `code.cmd --install-extension`; listed as `fakeinterviewguard.fake-interview-guard@1.0.0`; uninstalled without residue; reinstalled cleanly into single folder. |
| 2 | **Installed Package & Metadata Integrity** | **PASS** | Installed extension contains canonical `out/build-metadata.json` matching `1201aa5ec8...` digest across all 98 input files. |
| 3 | **Restricted Mode GUI Status** | **PASS** | Status bar renders `#status.workspaceTrust` displaying `Restricted Mode` and hover title *"Restricted Mode: Some features are disabled because this folder is not trusted."* |
| 4 | **Restricted Mode Manual Scans & Dashboard** | **PASS** | Triggered via Command Palette (`F1`); toast reports 53 rules loaded and scan diagnostics; Security Review Dashboard tab opens cleanly as script-free webview. |
| 5 | **Restricted Mode Store Isolation** | **FAIL (DEF-05)** | In newly opened workspaces where Workspace Trust prompt is unresolved, `extension.ts:activate` eagerly instantiates `QuarantineManager`, creating `.fakeinterviewguard/quarantine` in `HOME`. Documented in [DEFECTS.md](DEFECTS.md). |
| 6 | **Restricted Mode Remediation Refusal** | **PASS** | Mutation command `fig.reviewConfiguration` is refused with warning toast: *"FIG: Configuration changes require a trusted window. Read-only scans remain available."* |
| 7 | **Real Review Dialog Cancellation** | **PASS** | Opening `FIG: Review Tasks and NPM Scripts Configuration` renders modal; dismissing via Escape leaves `.vscode/tasks.json` byte-identical; no `.fig-backup` created. |
| 8 | **Real Quarantine Dialog Cancellation** | **PASS** | Opening `FIG: Quarantine File` renders modal *"Move this file to quarantine?"*; dismissing via Escape leaves target artifact 100% byte-identical in workspace. |
| 9 | **Remediation Apply, Backup & Clean Undo** | **PASS** | Applying remediation modifies flagged task and creates `.fig-backup`. Clicking *"Undo this change"* on toast restores exact pre-remediation SHA-256 and removes backup. |
| 10 | **Newer-Edit Conflict Refusal** | **PASS** | When user edits file after remediation, Undo refuses execution: *"FIG: Undo refused because the file changed or the backup could not be verified."* User edits preserved intact. |
| 11 | **Quarantine, Restart & Destination Conflict** | **PASS** | Artifact quarantined safely. When destination is recreated with different bytes while artifact is in store, restore strictly refuses overwrite. Clean restore recovers exact pre-quarantine SHA-256 once conflict is cleared. |
| 12 | **Keyboard Palette Navigation & Repeated Use** | **PASS** | `F1` opens Command Palette, filters by `FIG:`, navigates entries via `ArrowDown`, dismisses via `Escape`. 5 rapid sequential reload requests maintain process stability without hung locks. |
| 13 | **Windows Symlink / Junction Traversal** | **NOT_RUN** | 6 unit tests remain skipped (`pending`) on unprivileged Windows due to NTFS privilege requirements (`SeCreateSymbolicLinkPrivilege`). Disclosed platform limit. |
| 14 | **Live LLM Providers & Windows ACL Durability** | **NOT_RUN** | No paid or external endpoints invoked. NTFS ACL permission enforcement and power-loss durability are declared platform limits. |

---

## 3. Defects Identified and Status

Detailed defect write-ups and reproductions are recorded in [DEFECTS.md](DEFECTS.md):

- **DEF-01 (Fixed in `18195df`)**: Infinite loop in `ensureDirectory` under Windows NTFS extended paths (`\\?\`).
- **DEF-02 (Fixed in `18195df`)**: `EPERM` crash on `fsyncSync` with read-only file descriptor on Windows.
- **DEF-03 (Fixed in `18195df`)**: Asynchronous editor document handle locking during integration test teardown.
- **DEF-04 (Harness Fix)**: Fixed querySelector dot-escaping for `#status.workspaceTrust` in CDP evaluation.
- **DEF-05 (Product Defect — Security Boundary)**: In `extension/src/extension.ts`, `QuarantineManager` is initialized eagerly during activation before Workspace Trust modal resolution, creating `HOME/.fakeinterviewguard` prematurely. Requires deferred initialization in trusted windows.

---

## 4. Visual Evidence (Sanitized Screenshots)

All 12 screenshots from the native installed-VSIX acceptance campaign are preserved in [`screenshots/installed/`](screenshots/installed/):

1. [`01-restricted-mode-window.png`](screenshots/installed/01-restricted-mode-window.png) — Editor window showing `Restricted Mode` in status bar.
2. [`02-restricted-mode-scan.png`](screenshots/installed/02-restricted-mode-scan.png) — Manual workspace scan completed in Restricted Mode.
3. [`03-restricted-mode-dashboard.png`](screenshots/installed/03-restricted-mode-dashboard.png) — Security Review Dashboard webview tab in untrusted workspace.
4. [`04-quarantine-dialog-prompt.png`](screenshots/installed/04-quarantine-dialog-prompt.png) — Real modal confirmation dialog for `FIG: Quarantine File`.
5. [`05-configuration-review-modal.png`](screenshots/installed/05-configuration-review-modal.png) — Real configuration review modal with options.
6. [`06-remediation-applied-toast.png`](screenshots/installed/06-remediation-applied-toast.png) — Notification toast after remediation applied with *"Undo this change"* action.
7. [`07-undo-clean-restored.png`](screenshots/installed/07-undo-clean-restored.png) — Toast confirming clean restoration of original bytes.
8. [`08-undo-conflict-refused.png`](screenshots/installed/08-undo-conflict-refused.png) — Warning toast refusing Undo when newer user edits are present.
9. [`09-quarantined-file.png`](screenshots/installed/09-quarantined-file.png) — Artifact quarantined to isolated store.
10. [`10-quarantine-restored.png`](screenshots/installed/10-quarantine-restored.png) — Artifact restored after conflict resolution.
11. [`11-command-palette-keyboard-nav.png`](screenshots/installed/11-command-palette-keyboard-nav.png) — Command Palette filtered by `FIG:` with keyboard navigation.
12. [`12-error-handling-and-clean-state.png`](screenshots/installed/12-error-handling-and-clean-state.png) — Stable editor state after rapid repeated command invocations.

*Historical development-host screenshots (from the earlier run) remain preserved under [`screenshots/01-installed-extension.png`](screenshots/01-installed-extension.png) through [`08-command-palette-keyboard.png`](screenshots/08-command-palette-keyboard.png).*

---

## 5. Machine-Readable Summary

Complete machine-readable identities, digests, and check results are maintained in [EVIDENCE.json](EVIDENCE.json).
Raw test execution output and process logs are generated by `extension/scripts/test-installed-gui-acceptance.js` and preserved locally in `extension/.vscode-test/INSTALLED_ACCEPTANCE_RESULT.json` (uncommitted per repository and AGENTS.md rules).
