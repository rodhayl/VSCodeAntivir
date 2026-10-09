# Recovering files safely

This is the candidate's recovery contract, not a guarantee for every filesystem or crash. Work with copies when investigating. Never execute a suspicious payload to identify it.

## Configuration changes

Approved task/npm/Git remediation retains `<name>.fig-backup` beside the affected file. Immediate “Undo this change” verifies current bytes, file identity and the backup. It refuses to overwrite newer work.

Undo ownership is session-local. After restart or a conflict, copy both the current file and backup, compare their bytes and manually merge the desired content. Do not blindly overwrite the current file. Git review can change several files; if one fails, earlier changes can remain with their backups. Review each target.

`.fig-*.tmp` and `.fig-*.undo` can remain after interruption. Their names are not permission to delete them. Preserve and inspect their contents first. Recovery artifacts are excluded from Git.

## Quarantine contract

The default store is `.fakeinterviewguard/quarantine` under the user's home. It contains `manifest.json`, one directory per entry and payload bytes. POSIX directory modes are 0700; payload/manifest modes are 0600. Windows ACLs need separate verification.

1. A recovery copy and record are persisted before capturing the source.
2. Capture uses a same-filesystem rename. Unsupported paths, hard links and cross-filesystem moves fail conservatively; the source and/or recovery copy remain.
3. Restore validates hash/size, writes and syncs a temporary file beside the destination, then publishes it exclusively. Failed writes do not publish partial originals. Existing destinations and detected concurrent changes are not overwritten.
4. Successful restore removes the active entry/payload after verification and metadata persistence. This is not an atomic transaction across all files, nor universal protection against a hostile same-user process.

## What to do after failure

- Destination exists: preserve the new file. Move it aside only after your own review, then retry. The extension cannot decide which copy to keep.
- Hash mismatch: preserve manifest and payload. Source races, interruption or store modification can cause divergence. Compare bytes without executing them. Do not change the expected hash merely to force restore.
- First metadata write failed: the original should remain; an unlisted recovery payload may also exist. Keep both until reviewed.
- Restore metadata write failed: a complete destination and recovery copy may both remain. Retry refuses an existing destination. Compare and preserve both before manual reconciliation.
- Busy/interrupted lock: another window may still be operating. Close relevant VS Code windows and copy the whole store. Do not remove `.mutation-lock` while a process could be using it. Automatic lock takeover is intentionally absent.
- Corrupt manifest/unlisted payload: preserve the entire store. Do not reset the index or permanently delete entries to “repair” it. Reconcile records to actual bytes and original paths manually.

Permanent deletion has a separate confirmation and is not recoverable by the extension. “Clear all” is not a repair operation. Share sanitized reproductions rather than private payloads or full manifests when asking for help.
