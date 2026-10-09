# Defects Identified, Fixed, and Verified

This document records the defects encountered during native Windows Extension Host and installed VSIX acceptance of candidate commit `88cca02765577e4b5009acdcafca9c052ab8a137` on branch `codex/safe-remediation-20261004`, along with their root causes, fixes, and regression test suites.

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
compared `current` (which starts with `C:\`) against `existingParent` (which starts with `\\?\C:\`). Because the string paths never matched, `current` climbed up directory ancestors until it reached the drive root `C:\`. Since `path.dirname('C:\\')` returns `'C:\\'`, the loop never terminated and spun at 100% CPU. Furthermore, POSIX directory fsyncing is a no-op on Windows (`syncDirectory` already returns early on `win32`).

### Remediation
1. Strip the `\\?\` prefix when normalizing `firstCreated`.
2. Add a boundary check `if (parent === current) break;` to ensure any while traversal terminates unconditionally upon reaching filesystem root.
3. Return early on `process.platform === 'win32'` once the directory is verified, since directory fsync is not supported or needed on Windows.

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
