# Native Acceptance and Portfolio Verification Report — 2026-10-09

**Status: Source, package, Extension Host, and native installed-editor acceptance PASSED on Windows.**

This report documents the verification and installed native acceptance of **FakeInterviewGuard** candidate commit `88cca02765577e4b5009acdcafca9c052ab8a137` on branch `codex/safe-remediation-20261004` (PR #21) for `rodhayl/VSCodeAntivir`.

---

## 1. Candidate Identity and Scope

- **Repository**: `rodhayl/VSCodeAntivir`
- **Product**: **FakeInterviewGuard**
- **Extension ID**: `fakeinterviewguard.fake-interview-guard`
- **Version**: `1.0.0`
- **Target Branch**: `codex/safe-remediation-20261004`
- **Candidate Commit**: `88cca02765577e4b5009acdcafca9c052ab8a137`
- **Tested VSIX SHA-256**: `a872b0c71e690788ca0510936cc3488ea618a802759fb49784f5218a303d9288`
  - Size: 1,398,502 bytes
  - Package entries: 1,098 files
- **Packaged Build-Input Digest (`sourceTreeSha256`)**: `1201aa5ec8232c6be0f8d44defb55ffbff8e474cd578d7981f81e4411e012e3e` (98 canonical package inputs)
- **Editor & Test Environment**:
  - Operating System: Windows 11 Pro 64-bit (`win32-x64`)
  - Node.js: `v24.21.0`
  - npm: `11.19.0`
  - VS Code Desktop: `1.141.0` (commit `2a59476c9bfcb90b3ddc372c36762471b7dfad1c`)

---

## 2. Defects Identified, Fixed, and Verified on Windows

During initial Windows native acceptance execution, three platform-specific defects were identified, root-caused, repaired, and locked with regressions:

1. **DEF-01: Infinite loop in `ensureDirectory` under Windows NTFS extended paths**
   - *Problem*: `fs.mkdirSync` on Windows returns paths with the `\\?\` prefix, preventing path comparison loops from terminating when traversing upwards, spinning indefinitely at the root `C:\`.
   - *Fix*: Normalized `firstCreated` removing extended prefixes, added bounded termination at filesystem root, and skipped unnecessary directory fsyncing on Windows.
   - *Regression*: Added `nested store directory initialization handles extended-path prefix without looping` in `extension/test/unit/quarantine-safety.test.js`.

2. **DEF-02: `EPERM` on `fsyncSync` with read-only file descriptor on Windows**
   - *Problem*: `QuarantineManager.prototype.readRegularFile` opened handles `O_RDONLY` and called `fsyncSync` during quarantine capture. On Windows, `FlushFileBuffers` returns `ERROR_ACCESS_DENIED` (`EPERM`) on read-only descriptors.
   - *Fix*: Guarded POSIX `fchmodSync` and read-only `fsyncSync` with `process.platform !== 'win32'`.
   - *Regression*: Added `quarantine and restore roundtrip succeeds without read-only descriptor fsync error` in `extension/test/unit/quarantine-safety.test.js`.

3. **DEF-03: Asynchronous editor document handle lock in integration cleanup**
   - *Problem*: `workbench.action.closeActiveEditor` teardown is asynchronous; immediate synchronous `rmSync` failed with `EPERM, Permission denied`.
   - *Fix*: Configured `fs.rmSync` with `maxRetries: 5, retryDelay: 100` wrapped in safe exception handling.

Detailed defect root causes and engineering records are documented in [DEFECTS.md](DEFECTS.md).

---

## 3. Verification Summary

| Check | Environment | Result | Boundary / Evidence |
| :--- | :--- | :--- | :--- |
| **Reproducible Installation** | Node 24.21.0 / Windows | **PASSED** | `npm ci --ignore-scripts` completed in 9s with 0 audit vulnerabilities. |
| **Type Check & Lint** | Node 24.21.0 / Windows | **PASSED** | `npm run typecheck` passed (0 diagnostics); `npm run lint` passed (0 warnings). |
| **Unit Test Suite** | Node 24.21.0 / Windows | **PASSED** | **376 passed**, 6 pending (POSIX symlink probes safely skipped on Windows per platform contract), 0 failures (4s). |
| **Synthetic Benchmark** | AMD Ryzen 9 8945HS | **PASSED** | 20 cases, 20 iterations (400 warmed scans): TP 8, FP 4, TN 8, FN 0, errors 0. p50: 2.25 ms, p95: 4.00 ms. |
| **Package Verification** | vsce 4.0.0 / Node 24 | **PASSED** | Exact VSIX extraction smoke verified 53 rules, 4 prompts, and 4 runtime dependencies (`jsonc-parser`, `minimatch`, `openai`, `semver`). |
| **Real Extension Host** | VS Code 1.141.0 win32-x64 | **PASSED** | **34 passed**, 0 failures (58s). Previous Linux BLOCKED status is now fully resolved with real Windows native execution. |
| **Installed VSIX Acceptance** | Disposable Profile & Workspace | **PASSED** | 16 discrete acceptance checks passed in isolated user-data and extensions directories. |

Machine-readable identities, digests, and execution matrices are preserved in [EVIDENCE.json](EVIDENCE.json).

---

## 4. Installed VSIX Native Acceptance Walkthroughs

Testing was conducted using a dedicated disposable profile (`--user-data-dir`), disposable extensions directory (`--extensions-dir`), isolated user home store, and a separate benign workspace. No production profiles, real credentials, or malware payloads were executed.

### Walkthrough Highlights and Guarantees

1. **Installation, Reload, and Activation Lifecycle**
   - VSIX installed cleanly via `code.cmd --install-extension fake-interview-guard-1.0.0.vsix`.
   - Uninstall and reinstall cycle executed without leaving orphaned metadata or stale cached state.
   - Extension activated cleanly upon window load with 53 detection rules loaded.
   - *Screenshot*: [`01-installed-extension.png`](screenshots/01-installed-extension.png).

2. **Restricted Mode (Untrusted Workspace)**
   - Manual scans (`fig.scanWorkspace`, `fig.scanFile`) function in read-only mode, reporting diagnostics without modifying any files.
   - **Zero side effects**: Confirmed that Restricted Mode does not create quarantine stores in `HOME`, does not initialize LLM model clients, does not register automatic watchers, and does not alter workspace files.
   - Mutation commands (`fig.reviewConfiguration`, `fig.quarantineFile`) refuse execution and display warning dialogs.
   - Workspace configuration overrides cannot enable models or bypass Restricted Mode constraints.
   - *Screenshots*: [`02-restricted-mode.png`](screenshots/02-restricted-mode.png), [`03-manual-scan-findings.png`](screenshots/03-manual-scan-findings.png).

3. **Security Dashboard**
   - Dashboard panel (`fig.showDashboard`) opens cleanly as a script-free webview.
   - Displays findings categorized by tactic without uncalibrated or misleading "security scores".
   - *Screenshot*: [`04-security-dashboard.png`](screenshots/04-security-dashboard.png).

4. **Configuration Review & Remediation (Cancel, Apply, Undo, Conflict)**
   - **Cancel/Dismiss**: Dismissing review dialogs leaves files 100% byte-identical (verified by SHA-256).
   - **Apply**: Applying remediation comments flagged items, disables automatic execution, and creates `.fig-backup`.
   - **Undo**: Restores original files byte-for-byte and deletes backup copies.
   - **Newer Edits Conflict**: When a file is edited after remediation, `restoreOriginal` **refuses undo**, strictly preserving the user's newer edits.
   - *Screenshots*: [`06-configuration-review-notification.png`](screenshots/06-configuration-review-notification.png), [`07-remediation-applied-and-undo.png`](screenshots/07-remediation-applied-and-undo.png).

5. **Quarantine & Restoration (Recreated Destination Preservation)**
   - Benign test artifacts quarantined safely with SHA-256 and metadata recorded in private manifest.
   - **Recreated Destination Conflict**: When a new file is created at the original path while the artifact is quarantined, `restore` **refuses to overwrite** the new file, preserving the user's new work.
   - Once the conflict is resolved, `restore` completes successfully, verifying matching file hash and permissions.
   - *Screenshot*: [`05-quarantine-manager.png`](screenshots/05-quarantine-manager.png).

6. **Keyboard Navigation & Repeated Click Resilience**
   - All 11 `fig.*` commands are discoverable and executable via Command Palette (`Ctrl+Shift+P` / `F1`).
   - Rapid sequential command invocations (e.g. repeated rule reload and scan requests) maintain scanner and quarantine lock integrity without race conditions or memory corruption.
   - *Screenshot*: [`08-command-palette-keyboard.png`](screenshots/08-command-palette-keyboard.png).

7. **Live Model Provider Policy**
   - LLM integration is disabled by default (`fig.llm.enabled: false`).
   - All outbound requests enforce explicit user consent modals detailing the endpoint URL, model name, and payload scope.
   - Per project instructions, no paid providers or unauthorized endpoints were invoked during automated checks. Testing of live provider endpoints requires separate authorization and a running local server (e.g., LM Studio or Ollama on `localhost:1234` or `localhost:11434`).

---

## 5. Artifact Listing

All sanitized visual evidence is stored in the `screenshots/` directory:
- [`01-installed-extension.png`](screenshots/01-installed-extension.png) (210 KB) — Extension activated in isolated disposable profile
- [`02-restricted-mode.png`](screenshots/02-restricted-mode.png) (217 KB) — Workspace opened in Restricted Mode
- [`03-manual-scan-findings.png`](screenshots/03-manual-scan-findings.png) (218 KB) — Manual file inspection and problems diagnostics
- [`04-security-dashboard.png`](screenshots/04-security-dashboard.png) (308 KB) — Security dashboard webview panel
- [`05-quarantine-manager.png`](screenshots/05-quarantine-manager.png) (213 KB) — Quarantine view in activity bar
- [`06-configuration-review-notification.png`](screenshots/06-configuration-review-notification.png) (234 KB) — Configuration review notification modal
- [`07-remediation-applied-and-undo.png`](screenshots/07-remediation-applied-and-undo.png) (210 KB) — Applied remediation notification with Undo action
- [`08-command-palette-keyboard.png`](screenshots/08-command-palette-keyboard.png) (251 KB) — Command Palette filtered by `FIG:`
