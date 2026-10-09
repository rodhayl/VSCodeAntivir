# Native installed-editor acceptance: verified execution report

Status: **AUTOMATED_SUBSET_PASSED_WITH_DECLARED_LIMITS**. The recoverable [native result](RESULT-VERIFIED.json) and 13 distinct captures support closure of this bounded CV/portfolio demonstration in real Windows VS Code 1.141.0, using disposable profiles, home directories, and workspaces. This is not full release acceptance or a malware-efficacy claim. Historical reports remain preserved under [historical/](historical/).

## 1. Candidate and package identity

- **Repository & branch**: `rodhayl/VSCodeAntivir` on `codex/safe-remediation-20261004`
- **Confirmed ancestor**: `420b133bb06ac49ff12ea13cd1fe4750893d0774`
- **Native-tested candidate**: `35f4de018943709ecfacce5f31810ea7f95158f0`
- **Packaged build-input SHA-256**: `1201aa5ec8232c6be0f8d44defb55ffbff8e474cd578d7981f81e4411e012e3e` (98 files recorded in `out/build-metadata.json`; not a hash of the whole Git tree)
- **Built VSIX artifact**: `fake-interview-guard-1.0.0.vsix`
- **Native-tested VSIX SHA-256**: `2a23e32328cc5c3464e78de1e98585fea4ce406f68c6a3c39536a7aa53a73ba9`
- **Separately reported rebuilt VSIX SHA-256**: `ffa154b35b5ddd86c1a61c95ea22072e75acfaf276f0cb2656ba5e030dfcf920`; no installed-native result for this rebuilt archive is established here.
- **Package size**: 1,398,502 bytes (1,098 files, 406 JS files)
- **Runtime dependencies**: `jsonc-parser`, `minimatch`, `openai`, `semver` (pure JS, CommonJS)
- **Extracted package smoke (`npm run verify:package`)**: PASS (53 rules loaded, runtime imports verified)

The result and screenshots were published in `5b754c65d9c24b16f4c528e1c664a15d0f059298`, a documentation-only child of the native-tested candidate. From the confirmed ancestor through that publication, only the GUI harness and evidence documentation changed; product source, rules and dependency manifests did not. This clarification also changes documentation only and does not retest or relabel a rebuilt archive as the native-tested VSIX.

## 2. Execution environment

- **Operating system**: Windows 11 (`win32` x64)
- **Runtime**: Node `v24.21.0`
- **Editor**: Official VS Code `1.141.0` (`Code.exe` commit `2a59476c9bfcb90b3ddc372c36762471b7dfad1c`)
- **Isolation**: Unique disposable directories per run under `extension/.vscode-test/installed-gui-runs/` with dedicated `User/settings.json`, `--extensions-dir`, `--user-data-dir`, and independent `HOME`/`USERPROFILE`.
- **Sandbox**: Chromium sandbox left active; automatic tasks disabled in disposable profile; benign synthetic fixtures only.

## 3. Installed GUI acceptance matrix

All 17 checks required by this bounded driver passed in the official editor via CDP and native Webview automation without product-class workarounds. The preserved result supports the observations below; it does not cover every release-acceptance criterion:

| Check ID | Result | Description / Observed Transition |
|---|---|---|
| `installed_identity_lifecycle` | **PASS** | Extension installed via CLI, verified in `--list-extensions`, uninstalled, reinstalled; `out/build-metadata.json` matches candidate metadata. |
| `restricted_state` | **PASS** | Launched with Workspace Trust startup prompt; explicitly selected *"No, I don't trust the authors"*; Workspace Trust status confirmed `restricted`. |
| `restricted_scan` | **PASS** | Executed `fig.scanWorkspace` and `fig.scanFile` on inert fixture `review.js`; reported 1 finding with zero errors/skips. |
| `restricted_dashboard` | **PASS** | Executed `fig.showDashboard`; observed the FIG Security Dashboard tab. Dashboard content and rendering correctness were not asserted. |
| `restricted_refusal_and_storage` | **PASS** | Executed `fig.reviewConfiguration`; toasted *"Configuration changes require a trusted window"*; sample bytes unchanged; `.fakeinterviewguard` home storage absent. |
| `trusted_state_after_reload` | **PASS** | Granted trust in Workspace Trust editor; reloaded editor as required by trust-grant contract; confirmed `trusted` status. |
| `quarantine_cancel` | **PASS** | Executed `fig.quarantineFile` on `quarantine-target.txt`; modal confirmation dialog displayed; cancelled via `Escape`; original file and empty store unchanged. |
| `review_cancel` | **PASS** | Executed `fig.reviewConfiguration` on inert auto-run task fixture; modal dialog displayed; cancelled via `Escape`; task file remained unchanged and backup remained absent. |
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

## 5. Separately operator-reported local LM Studio endpoint smoke

The following endpoint/model smoke was reported by the operator, separately from the installed-GUI campaign. Its raw response/log is not included in the recoverable native result. That result explicitly records live LLM providers as NOT RUN by the GUI driver. These observations do not establish extension-mediated consent, rejection with zero requests, approved input transmission, cancellation or late-result suppression.

- **Endpoint**: `http://127.0.0.1:1234/v1`
- **Reported model**: `slm-production-evaluation`
- **Health check**: HTTP 200 OK; models returned: `slm-production-evaluation`, `text-embedding-nomic-embed-text-v1.5`, `gemma-4-12b-it-qat@q4_k_xl`, `gemma-4-12b-it-qat@q4_0`.
- **Synthetic chat**: Executed on an inert benign prompt (`"Synthetic benign test: echo 1."`). Completed with model `slm-production-evaluation`, 29 prompt tokens, 100 completion tokens.
- **Reported constraints**: No private workspace code sent; no paid cloud providers used; loopback endpoint only.

## 6. Operator-reported standard checks

These standard-check results are retained as operator reports; complete command logs and a separate unit-test total for this run are not archived here. They are distinct from the recoverable native-driver JSON and captures, and are not an independently verified full-suite pass.

- `npm run typecheck`: PASS (0 errors)
- `npm run lint`: PASS (0 warnings, 0 errors)
- `npm test`: operator-reported PASS; the supplied count is **34 integration tests** in real `@vscode/test-electron` (60s), not the unit count or combined full-suite total.
- `npm run benchmark`: PASS (20 cases x 20 iterations, matrix: 8 TP, 4 FP, 8 TN, 0 FN, 0 errors; p50 per file 1.45ms)
- `npm run package`: PASS (1,098 entries packaged into VSIX)
- `npm run verify:package`: PASS (smoke extraction, imports, 53 rules)

## 7. Defect status and limits

- **DEF-05 remains unproven / not reproduced**: The native run observed absent quarantine storage and unchanged fixture bytes in Restricted Mode. It did not independently instrument model-client creation/traffic, automatic watchers or custom-rule suppression. Known-false host-stub activation and source inspection provide separate evidence for those gates; they are not native observations. Trusted activation intentionally creates storage in the unchanged product. No lazy-storage product modification was introduced.
- **Limits declared**:
  - Dashboard coverage establishes tab opening only; keyboard coverage is limited to Command Palette navigation.
  - Model-client/traffic absence, automatic-watcher absence and restricted custom-rule suppression are not independently established by this native driver.
  - Extension-mediated live-model consent, rejection, approved transmission, cancellation and late-result suppression remain NOT RUN in this campaign.
  - Broad accessibility, corrupt/busy-store and interrupted-operation GUI coverage are not established by five sequential rule reloads.
  - Does not evaluate Windows ACL protection against hostile local admin processes.
  - Does not evaluate power-loss or OS crash durability.
  - Benchmark evaluates author-built characterization with intentional false positives; it does not evaluate live malware detection effectiveness.
  - No product source code was changed; all adjustments were strictly limited to test harnesses and documentation.
