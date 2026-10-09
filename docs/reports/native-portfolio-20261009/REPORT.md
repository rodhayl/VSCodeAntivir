# Native installed-editor acceptance: correction and remaining work

Status: **NOT ACCEPTED. A corrected native rerun is required.** This supersedes the acceptance claims published in `866190a9130a986cb3846c1e38465f967337e409` without deleting their historical reports or screenshots. It does not claim a new Windows execution.

## What the prior campaign does and does not establish

The historical candidate was `fda7d132102b1625d9ee7aa91c3611e2c557459e`; its 98 packaged product inputs were identical to `18195df8667f27526bdbb5c9c0a73555782b2804`. The reported VSIX SHA-256 was `a872b0c71e690788ca0510936cc3488ea618a802759fb49784f5218a303d9288`. Historical unit, helper and development-host results remain reports about those stages. They do not establish installed GUI behavior on this candidate or any later commit.

Independent inspection found material false positives in the GUI driver:

- A missing/broken trust selector was interpreted as trusted. The first workspace screenshots did not positively establish Restricted Mode; the later supposedly trusted screenshots visibly remained restricted.
- Dashboard success contained an unconditional true alternative. Cancellation could pass without a dialog. Apply/Undo/conflict checks did not consistently require the button to exist or be clicked.
- Quarantine and restore invoked the installed `QuarantineManager` directly in the driver process, without native UI actions or the promised restart. Those are helper checks, not installed-editor GUI checks.
- Screenshots 05 through 10 under `screenshots/installed/` share Git blob `0df616f9391286340e835e5c25324a8a492f4d4c`. They cannot independently demonstrate six claimed transitions.
- The driver always exited zero after recorded failures and deleted its temporary evidence.

Accordingly, the previous overall GUI PASS and detailed GUI Apply/Undo/quarantine/reload/resilience claims are withdrawn pending a valid rerun. Preserved reports are under [historical/](historical/); their claims are explicitly superseded. Original screenshots remain at their original paths and are not overwritten.

## DEF-05 is not a reproduced trust race

The previous observation of a home-store directory is insufficient to identify when or why it was created. The harness did not correlate the true workspace-trust state, FIG activation, commands and directory creation. A known-trusted launch followed by incorrect trust setup can also explain it.

The public VS Code API exposes `workspace.isTrusted` as a boolean. No evidence here establishes an indeterminate initial state or a transient true value in a genuinely restricted window. Source/host-stub checks show known-false activation already avoids quarantine storage, model clients and automatic watchers. Known-true activation currently creates quarantine storage by design. A separately evaluated lazy-storage hardening candidate was **not included** in this tests/docs correction. No product fix or native closure of DEF-05 is claimed.

## Corrected driver and its boundaries

`extension/scripts/test-installed-gui-acceptance.js` now:

- Requires positive Workspace Trust editor/status observations; missing, conflicting or failed selectors stop the dependent scenario.
- Requires each real modal, exact command and button, byte transition and expected notification before success. Quarantine actions use the installed editor webview; there is no direct product-class fallback.
- Restarts the owned disposable editor for the trust-grant policy and quarantine recovery, verifies the same entry in the UI, preserves a recreated destination, then checks clean restoration.
- Returns nonzero for failed, blocked, missing or unexecuted required checks. Negative-control unit tests cover its fail-closed behavior.
- Uses unique disposable profiles/HOME/workspaces, records the current clean Git candidate and fresh VSIX metadata, retains per-run logs/JSON/screenshots, hashes images and rejects duplicate transition screenshots.
- Does not disable the Chromium sandbox. Uses an inert echo fixture created after trust/reload and disables automatic tasks in the disposable profile. It never executes sample payloads.

These driver changes have automated tests, not a new native execution. UI selectors can still need a tests-only adjustment on a real supported editor; inability to observe them is BLOCKED/FAIL, never PASS. The driver covers a bounded automated subset. It does not prove absent model traffic/watchers, custom-rule suppression, Windows ACL protection, power-loss durability or broad accessibility. Live models remain NOT RUN.

The obsolete `test-installed-vsix-acceptance.js` helper was removed after checking its complete module, imports, CLI registrations, package exclusions and documentation. It had no current npm or code callers, was not shipped in the VSIX, and duplicated unit, `verify:package` and installed-lifecycle coverage. Its direct class calls were never Workspace Trust, dialog, native GUI or reload evidence. The original script remains recoverable in Git at `866190a`; historical reports are preserved. Use `npm run verify:package` for extracted-package smoke and the corrected GUI driver for its separate native subset.

## Required next evidence

Follow [CONTINUE.md](CONTINUE.md) in an owner-authorized native Windows environment. Rebuild and install the current exact branch candidate; do not reuse the historical VSIX. Archive the driver result even if it fails. Investigate any genuine product defect separately without changing product code in a tests-only campaign. LM Studio is optional, local-only and requires specific owner consent for any input transmission. There is no paid-provider fallback.
