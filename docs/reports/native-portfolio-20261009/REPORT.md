# Native installed-editor acceptance: verified execution report

Status: **AUTOMATED_SUBSET_PASSED_WITH_DECLARED_LIMITS**. This report records the native Windows execution of FakeInterviewGuard in real VS Code 1.141.0, using disposable profiles, home directories, and workspaces. Historical reports remain preserved under [historical/](historical/).

## 1. Candidate and package identity

- **Repository & branch**: `rodhayl/VSCodeAntivir` on `codex/safe-remediation-20261004`
- **Confirmed ancestor**: `420b133bb06ac49ff12ea13cd1fe4750893d0774`
- **Packaged source tree SHA-256**: `1201aa5ec8232c6be0f8d44defb55ffbff8e474cd578d7981f81e4411e012e3e` (98 files)
- **Built VSIX artifact**: `fake-interview-guard-1.0.0.vsix`
- **VSIX SHA-256**: `2a23e32328cc5c3464e78de1e98585fea4ce406f68c6a3c39536a7aa53a73ba9` (rebuilt digest: `ffa154b35b5ddd86c1a61c95ea22072e75acfaf276f0cb2656ba5e030dfcf920`)
- **Package size**: 1,398,502 bytes (1,098 files, 406 JS files)
- **Runtime dependencies**: `jsonc-parser`, `minimatch`, `openai`, `semver` (pure JS, CommonJS)
- **Extracted package smoke (`npm run verify:package`)**: PASS (53 rules loaded, runtime imports verified)

## 2. Execution environment

- **Operating system**: Windows 11 (`win32` x64)
- **Runtime**: Node `v24.21.0`
- **Editor**: Official VS Code `1.141.0` (`Code.exe` commit `2a59476c9bfcb90b3ddc372c36762471b7dfad1c`)
- **Isolation**: Unique disposable directories per run under `extension/.vscode-test/installed-gui-runs/` with dedicated `User/settings.json`, `--extensions-dir`, `--user-data-dir`, and independent `HOME`/`USERPROFILE`.
- **Sandbox**: Chromium sandbox left active; automatic tasks disabled in disposable profile; benign synthetic fixtures only.

## 3. Installed GUI acceptance matrix

All 17 required checks executed and passed in the official editor via CDP and native Webview automation without product-class workarounds:

| Check ID | Result | Description / Observed Transition |
|---|---|---|
| `installed_identity_lifecycle` | **PASS** | Extension installed via CLI, verified in `--list-extensions`, uninstalled, reinstalled; `out/build-metadata.json` matches candidate metadata. |
| `restricted_state` | **PASS** | Launched with Workspace Trust startup prompt; explicitly selected *"No, I don't trust the authors"*; Workspace Trust status confirmed `restricted`. |
| `restricted_scan` | **PASS** | Executed `fig.scanWorkspace` and `fig.scanFile` on inert fixture `review.js`; reported 1 finding with zero errors/skips. |
| `restricted_dashboard` | **PASS** | Executed `fig.showDashboard`; FIG Security Dashboard webview tab opened cleanly without activation errors. |
| `restricted_refusal_and_storage` | **PASS** | Executed `fig.reviewConfiguration`; toasted *"Configuration changes require a trusted window"*; sample bytes unchanged; `.fakeinterviewguard` home storage absent. |
| `trusted_state_after_reload` | **PASS** | Granted trust in Workspace Trust editor; reloaded editor as required by trust-grant contract; confirmed `trusted` status. |
| `quarantine_cancel` | **PASS** | Executed `fig.quarantineFile` on `quarantine-target.txt`; modal confirmation dialog displayed; cancelled via `Escape`; original file and empty store unchanged. |
| `review_cancel` | **PASS** | Executed `fig.reviewConfiguration` on inert auto-run task fixture; modal dialog displayed; cancelled via `Escape`; task file and backup absent. |
| `review_apply` | **PASS** | Approved configuration review; modified task file to harmless echo, created `.fig-backup` with identical original hash. |
| `review_undo` | **PASS** | Clicked *"Undo this change"* on toast notification; restored original task file byte-for-byte; removed `.fig-backup`. |
| `review_conflict` | **PASS** | Re-applied change; modified task file with newer user edit; clicked *"Undo this change"*; toasted *"Undo refused"*; newer edit preserved alongside backup. |
| `quarantine_capture` | **PASS** | Approved quarantine confirmation; original file removed from workspace; recovery copy stored in `~/.fakeinterviewguard/quarantine/` with matching SHA-256. |
| `quarantine_reload` | **PASS** | Owned editor restarted; opened Quarantine Manager webview; quarantine entry persisted across restart and rendered in webview. |
| `quarantine_conflict` | **PASS** | Created new file at restore destination; clicked Restore in webview; toasted refusal *"The restore destination already exists"*; entry preserved in store. |
| `quarantine_restore` | **PASS** | Preserved conflicting file as evidence; approved restore confirmation; file restored with exact original SHA-256 and file mode; removed from quarantine manifest. |
| `keyboard_navigation` | **PASS** | Opened Command Palette with `F1`; typed `> FIG:`; navigated with `ArrowDown`; active descendant changed from initial row to subsequent row; dismissed with `Escape`. |
| `repeated_reload` | **PASS** | Executed `fig.reloadRules` sequentially 5 times with notifications cleared; toasted *"FakeInterviewGuard: Rules and config reloaded"* each iteration without crashes. |

## 4. Distinct transition captures

All 13 required transition screenshots were captured, individually hashed with SHA-256, and verified to be distinct (zero duplicate hashes). Copies are preserved under [screenshots/verified/](screenshots/verified/):

1. `01-restricted-state.png` (`85f62b02...`): Workspace Trust editor in Restricted Mode
2. `02-restricted-scan.png` (`cce05ac0...`): Manual scan notification toast on inert fixture
3. `03-restricted-dashboard.png` (`2e93f19f...`): FIG Security Dashboard tab in editor
4. `04-trusted-after-reload.png` (`5995e458...`): Workspace Trust granted after editor reload
5. `05-quarantine-cancel-dialog.png` (`28e43986...`): Modal quarantine confirmation dialog with Quarantine file / Cancel buttons
6. `06-review-cancel-dialog.png` (`29863a49...`): Modal task configuration review dialog with Disable flagged tasks
7. `07-apply.png` (`8d4b6ed5...`): Remediation applied toast with Undo action
8. `08-clean-undo.png` (`ae66e77e...`): Clean undo toast notification (*"Original restored."*)
9. `09-undo-conflict.png` (`ba6f964d...`): Refusal notification when task file contains newer edits
10. `10-captured.png` (`c8fea676...`): Quarantine Manager webview showing quarantined file row
11. `11-restore-conflict.png` (`f4f8c663...`): Webview restore refusal toast when destination already exists
12. `12-restored.png` (`f22414b8...`): Restored notification (*"FIG: File restored."*)
13. `13-keyboard-focus.png` (`b8945dcf...`): Command Palette active descendant highlight on `> FIG:` commands

## 5. Local LM Studio integration

- **Endpoint**: `http://127.0.0.1:1234/v1`
- **Confirmed model**: `slm-production-evaluation`
- **Health check**: HTTP 200 OK; models returned: `slm-production-evaluation`, `text-embedding-nomic-embed-text-v1.5`, `gemma-4-12b-it-qat@q4_k_xl`, `gemma-4-12b-it-qat@q4_0`.
- **Synthetic chat**: Executed on an inert benign prompt (`"Synthetic benign test: echo 1."`). Completed with model `slm-production-evaluation`, 29 prompt tokens, 100 completion tokens.
- **Constraints**: No private workspace code sent; no paid cloud providers used; offline/local-only.

## 6. Full standard test suite results

- `npm run typecheck`: PASS (0 errors)
- `npm run lint`: PASS (0 warnings, 0 errors)
- `npm test`: PASS (34 passing in real `@vscode/test-electron` integration environment, 60s)
- `npm run benchmark`: PASS (20 cases x 20 iterations, matrix: 8 TP, 4 FP, 8 TN, 0 FN, 0 errors; p50 per file 1.45ms)
- `npm run package`: PASS (1,098 entries packaged into VSIX)
- `npm run verify:package`: PASS (smoke extraction, imports, 53 rules)

## 7. Defect status and limits

- **DEF-05 remains unproven / not reproduced**: In Restricted Mode, activation does not create quarantine storage, model clients, or watchers. In trusted mode, storage is created intentionally upon activation. No lazy-storage product modification was introduced.
- **Limits declared**:
  - Does not evaluate Windows ACL protection against hostile local admin processes.
  - Does not evaluate power-loss or OS crash durability.
  - Benchmark evaluates author-built characterization with intentional false positives; it does not evaluate live malware detection effectiveness.
  - No product source code was changed; all adjustments were strictly limited to test harnesses and documentation.
