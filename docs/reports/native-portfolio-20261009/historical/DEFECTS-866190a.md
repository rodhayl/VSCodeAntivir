> SUPERSEDED HISTORICAL CLAIMS. Preserved verbatim below from commit 866190a9130a986cb3846c1e38465f967337e409. This is not current acceptance evidence. See ../REPORT.md for the corrected status.

# Reported Windows defects and implemented fixes

This document preserves the tester-reported Windows findings starting from baseline `88cca02765577e4b5009acdcafca9c052ab8a137` on `codex/safe-remediation-20261004`. The fixes and regression sources were committed in `18195df8667f27526bdbb5c9c0a73555782b2804`. Independent review inspected the source but did not reproduce these Windows failures or rerun the reported results. Reproducibility, severities and causes below are the original engineering report, not a new native execution. The package-input mapping and remaining GUI acceptance gaps are recorded in [REPORT.md](REPORT.md).

---

## 1. DEF-01: Infinite loop in `ensureDirectory` under Windows NTFS extended paths

- **Severity**: Critical (Blocks startup / activation on Windows)
- **Module**: `extension/src/quarantine/quarantine-manager.ts` (`QuarantineManager.prototype.ensureDirectory`)
- **Reproducibility**: 100% on Windows when initializing `QuarantineManager` in trusted mode or with a custom storage path.

### Root Cause
In Node.js on Windows, `fs.mkdirSync(directory, { recursive: true, mode: 0o700 })` returns the first created directory formatted as an extended-length path prefixed with `\\?\` (for example, `\\?\C:\Users\...\.fakeinterviewguard`).
The loop:
```typescript
const existingParent = path.dirname(firstCreated);
let current = directory;
while (current !== existingParent) {
  this.syncDirectory(current);
  current = path.dirname(current);
}
```
compared `current` (which starts with `C:\`) against `existingParent` (which starts with `\\?\C:\`). Because the string paths never matched, `current` climbed up directory ancestors until it reached the drive root `C:\`. Since `path.dirname('C:\\')` returns `'C:\\'`, the loop never terminated and spun at 100% CPU. The implementation already skips directory fsync on Windows (`syncDirectory` returns early on `win32`). This describes the code path, not a Windows durability guarantee.

### Remediation
1. Strip the `\\?\` prefix when normalizing `firstCreated`.
2. Add a boundary check `if (parent === current) break;` to ensure any while traversal terminates unconditionally upon reaching filesystem root.
3. Return early on `process.platform === 'win32'` once the directory is verified, consistent with the existing Windows skip in `syncDirectory`. Windows directory-flush behavior, ACL protection and power-loss durability remain unverified; the skip must not be described as evidence that flushing is unnecessary.

### Regressions Added
- `Cross-platform and Windows quarantine regressions` -> `nested store directory initialization handles extended-path prefix without looping` in `extension/test/unit/quarantine-safety.test.js`.

---

## 2. DEF-02: `EPERM` failure on `fsyncSync` with read-only file descriptor on Windows

- **Severity**: High (Blocks quarantine capture on Windows)
- **Module**: `extension/src/quarantine/quarantine-manager.ts` (`QuarantineManager.prototype.readRegularFile`)
- **Reproducibility**: 100% on Windows during `QuarantineManager.prototype.quarantine` (caused 33 unit test failures).

### Root Cause
When capturing a file to quarantine with `restrictPermissions = true`, `readRegularFile` opened the file descriptor using `O_RDONLY | O_NONBLOCK`. It then executed:
```typescript
if (restrictPermissions) {
  if (stat.nlink !== 1) throw new Error('...');
  fs.fchmodSync(fd, 0o600);
  fs.fsyncSync(fd);
}
```
On Windows:
1. NTFS does not implement POSIX permission bitmasks (`0o600`).
2. The underlying Win32 API for `fsync` (`FlushFileBuffers`) requires `GENERIC_WRITE` access to the file handle. Calling it on a read-only handle fails with `ERROR_ACCESS_DENIED`, which Node.js surfaces as `EPERM: operation not permitted, fsync`.

### Remediation
Guard POSIX `fchmodSync` and read-only `fsyncSync` with `if (process.platform !== 'win32')`, matching the existing platform checks in `syncDirectory`.

### Regressions Added
- `Cross-platform and Windows quarantine regressions` -> `quarantine and restore roundtrip succeeds without read-only descriptor fsync error` in `extension/test/unit/quarantine-safety.test.js`.

---

## 3. DEF-03: Asynchronous editor document file handle lock during integration test cleanup

- **Severity**: Medium (Intermittent integration test failure on Windows)
- **Module**: `extension/test/suite/extension.test.js` (`Clean file should have no threats`)
- **Reproducibility**: Intermittent on Windows when deleting temporary directory immediately after closing text document editor.

### Root Cause
When `workbench.action.closeActiveEditor` is invoked in the VS Code workbench, document teardown and file watcher handle closing occur asynchronously across event loop ticks. Calling `fs.rmSync(root, { recursive: true, force: true })` immediately afterwards in the `finally` block failed with `EPERM, Permission denied` because Windows locks files that have active OS handles.

### Remediation
Configured `fs.rmSync` with Node.js built-in options `{ recursive: true, force: true, maxRetries: 5, retryDelay: 100 }` within a safe try/catch block, allowing Windows time to release the file handle.

### Regressions Added
- Integrated into `extension/test/suite/extension.test.js` and `extension/test/suite/native-acceptance.test.js`.

---

## 4. DEF-04: Test harness status bar element selector failure

- **Severity**: Low (Test harness artifact)
- **Module**: `extension/scripts/test-installed-gui-acceptance.js`
- **Reproducibility**: 100% when using `querySelector('#status\\.workspaceTrust')` within CDP `Runtime.evaluate` string evaluations.

### Root Cause
In Chromium/CDP `Runtime.evaluate`, passing `#status\\.workspaceTrust` inside nested string literals caused JavaScript escape sequences to strip backslashes, leading `querySelector` to parse `.workspaceTrust` as an unescaped CSS class rather than part of the ID `#status.workspaceTrust`.

### Remediation
Replaced `querySelector('#status\\.workspaceTrust')` with direct ID lookup `document.getElementById('status.workspaceTrust')`.

---

## 5. DEF-05: Restricted Mode startup trust race causes quarantine store leakage

- **Severity**: Medium (Product Defect — Security/Isolation Boundary)
- **Module**: `extension/src/extension.ts:activate` (`trustedSession = vscode.workspace.isTrusted`)
- **Reproducibility**: 100% in newly opened workspaces on Windows before the user actively dismisses or selects "Restricted Mode" in the Workspace Trust modal.

### Root Cause
In `extension/src/extension.ts`:
```typescript
trustedSession = vscode.workspace.isTrusted;
quarantineManager = trustedSession ? new QuarantineManager(outputChannel) : undefined;
```
When VS Code opens a new, unconfigured workspace, `vscode.workspace.isTrusted` returns `true` or an indeterminate initial value during early extension host activation ticks before Workspace Trust resolution is completed or if the user prompt is displayed.
Because `trustedSession` evaluates to `true`, `new QuarantineManager(outputChannel)` is called unconditionally.
In `QuarantineManager` constructor:
```typescript
this.ensureDirectory(this.quarantineDir);
```
`ensureDirectory` immediately creates `.fakeinterviewguard/quarantine` in the user's `HOME` directory.
As a result, an untrusted workspace leaks filesystem store initialization into `HOME/.fakeinterviewguard` prior to the user selecting Restricted Mode, violating the contract that Restricted Mode must not touch or initialize home store storage.

### Reproduction
1. Launch clean VS Code with disposable `--user-data-dir` and disposable `--home` pointing to an empty directory.
2. Open an untrusted workspace folder.
3. Observe that before any scan or user action, `.fakeinterviewguard/quarantine` is already created in `HOME`.

### Remediation (For Implementation Agent)
Defer `QuarantineManager` creation until an explicit user action requires quarantine in a confirmed trusted window, or listen to `vscode.workspace.onDidGrantWorkspaceTrust` rather than eagerly creating storage in `activate()`. Do not initialize `quarantineManager` if Workspace Trust is unresolved.

---

## Acceptance boundary

The reported unit/host/helper successes support only their actual assertions. DEF-01 through DEF-03 were fixed in `18195df`. DEF-04 is corrected in test harness. DEF-05 is documented with exact reproduction and evidence for implementation by the product engineer. ACL security, power-loss durability, and native symlink checks under unprivileged Windows accounts remain declared platform limits.

