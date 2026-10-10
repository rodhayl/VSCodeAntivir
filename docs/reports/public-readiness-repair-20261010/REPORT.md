# Public-readiness repair: R1–R6

Date: 2026-10-10. Product: FakeInterviewGuard (`fakeinterviewguard.fake-interview-guard`), package 1.0.0. Baseline: `0c89be104552d4895b05bc036074fa1b1d1c8ee3`.

## Result and exact identity

The six bounded repairs and related misleading test/sample descriptions are corrected. Local typecheck, lint, all **585 unit tests**, synthetic corpus, packaging and extracted-package smoke pass. Independent read-only review returned GO with **271 focused tests** passing. **Development Host integration is BLOCKED/NOT_RUN; installed VSIX GUI acceptance is NOT_RUN.** This is not full native release acceptance or a malware-detection certification.

- New VSIX SHA-256: `8b49c92a280bcfc40a5ffd485858be1baa18b9c20f3542375fa9827b82d6adde` (1,403,329 bytes; 1,099 archive entries).
- Packaged source-tree identity: `f2fd1ad0cbae8a07bac6749e1ca0137bed99ba8b96a233a86b2d26cad4b97525` (99 source inputs, listed in EVIDENCE).
- Packaged README SHA-256: `8c3ef78a5978934b3096cbe481fd58bb611661669ece427a043c706d0d3b0ab1`; exact match to canonical README, including sample warnings and task-remediation limits.
- Unchanged package-lock SHA-256: `adb9b1ac961441ef2b81b37949414f2f2d6736d6651e59d144bb552ad808b69b`.
- The changed candidate was not published by this worker. Do not label this new artifact with the baseline commit. The eventual repository commit must be linked to these exact input bytes at publication.

[EVIDENCE.json](EVIDENCE.json) records gates, RED/GREEN, source hashes and limitations. [CHANGES.json](CHANGES.json) lists the 36 changed input paths and exact before/after hashes; this report directory is excluded from its own manifest to avoid self-reference. Build outputs, installed dependencies, logs, caches and VSIX are intentionally not committed.

## Repairs

- **R1:** shared task parsing/inspection covers quoted command/argument objects, all OS variants, global inheritance and platform task lists. Supported shell/default command findings rewrite every variant, clear args/dependencies and disable startup; startup-only findings change runOn while preserving commands/dependencies. Unsupported process/provider/options/global execution configurations visibly require manual editing and refuse all changes before mutation. Scanner reports malformed supported-input shapes as incomplete rather than an empty successful scan. Review, cancellation, backups, conflict-safe undo and unchanged-byte checks remain.
- **R2:** single-pass placeholder callbacks preserve literal input bytes in system/user prompts, including dollar tokens, inserted placeholders, Unicode and CRLF. All templates and actual stubbed Analyze/Explain/Suggest request bodies are covered.
- **R3:** cache identity reflects the effective prompt, filename/language, fallback template and generation parameters, plus full source bytes. Existing model-setting invalidation and cancellation/stale-result checks remain.
- **R4:** filename/path globs no longer widen to an entire extension or discard folder boundaries. Slash-free patterns target basename; path patterns remain anchored, with explicit `**/` for arbitrary depth and support for dot-directories.
- **R5:** invalid rule shapes/types/IDs/references/thresholds/metadata fail loading visibly without suppressing valid siblings. Unknown condition fields are rejected. The two existing nested `and` declarations in artifact-poisoning and pull-request-target are expressed with existing regex alternatives plus `all`, preserving their intended conjunctions without a recursive engine. All 53 bundled rules load. A related inherited-property AST-alias crash is guarded.
- **R6:** automatic save/open/watcher subscriptions update idempotently as settings change, dispose correctly, and remain absent for sessions activated in Restricted Mode. Initial open-document scans honor scanOnOpen.

The former native-acceptance test was renamed development-host.test.js. Unconditional passes, unobserved Restricted Mode/cancellation claims and screenshot writes into historical evidence were removed. The runner opens an isolated workspace with automatic tasks off; samples are read only as text. Existing real consent/recovery tests remain. Seven sample header corrections changed comments only, preserving non-comment bytes and line endings. Historical reports remain clearly historical; broken navigation and public build wording were corrected.

## Verification and retained failures

Run from `extension/`: `npm ci --ignore-scripts`, `npm run typecheck`, `npm run lint`, `npm run test:unit`, `npm run benchmark`, `npm run package`, `npm run verify:package`. Dependencies were installed from the unchanged lockfile. The first npm attempt failed because its default cache location was unavailable; a writable task-local cache resolved that environment issue without changing dependencies or enabling installation scripts.

Each defect has inert failing-before/passing-after regressions. The first aggregate run had **582 passing / 3 failing**: two lifecycle fixtures and one concurrency fixture depended on the old R4 false-positive behavior. Those inputs were corrected to actual applicable high-severity, hex-density or exec-density patterns while retaining the assertions; no detection widening was restored. The final complete suite passed **585/585**. Packaging and smoke were repeated after the final README edit; source/runtime remained unchanged.

The same 20-case author-built corpus still yields **8 TP, 4 FP, 8 TN, 0 FN, 0 errors**, with zero contract failures. Four cases lose inappropriate rule IDs after R4; all differences are listed in EVIDENCE. Timing over 400 file scans: p50 0.9807 ms, p95 1.5047 ms. These timings exclude startup, loading, disk traversal, UI and LLMs. False positives remain visible; this corpus is not independent detection-effectiveness evidence.

## Remaining limits

The cloud environment had no installed/cached VS Code editor, display or Xvfb. Native checks were not launched, no editor was downloaded and no security restriction was bypassed. The historical Windows installed-GUI report belongs only to its original candidate and VSIX. New native integration/installed acceptance must be recorded against this exact rebuilt artifact when a supported authorized environment is available.

No sample program, task, workflow, hook, live model request, remote publication or paid CI was executed by this repair worker. Configuration inspection is advisory text analysis, not a general execution interceptor, task resolver, shell interpreter or guarantee that a workspace is safe.
