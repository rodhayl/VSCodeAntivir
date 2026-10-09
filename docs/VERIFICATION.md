# Verification and acceptance

Every result belongs to an exact commit or source-tree digest. Unit tests, Extension Host tests, a packaged VSIX and installed native acceptance are distinct evidence.

## Repeatable checks

From `extension/`, with Node 22.13+ and the committed lockfile:

```sh
npm ci --ignore-scripts
npm run typecheck
npm run lint
npm run test:unit
npm run compile
node ./test/benchmark.js > benchmark.json
npm run test:integration
npm run package
npm run verify:package
```

Linux integration requires a display or supported `xvfb-run -a`. The test runner downloads VS Code and uses isolated HOME, profile and extension directories. Record the exact editor version/build and exit code. Launch failure, missing fixture or skipped checks are not passes. Standard checks never execute sample payloads or call live models.

Unit tests cover review/cancel/apply/undo, malformed inputs, multi-root diagnostics, Restricted Mode gates, consent/cancellation, links, conflicts, hashes, failed writes/metadata and restart. Mocked editor tests are not native GUI evidence.

The benchmark contains a fixed 20-case corpus, full denominators, known benign challenges and input/source/rule/lockfile hashes. Archive JSON output with the commit. Timings cover warmed scanner calls only, excluding startup, disk traversal, UI and LLMs. `FIG_BENCH_ITERATIONS` accepts 1–1000 (default 20). This is an author-built characterization, not independent malware efficacy evidence.

## Installed VSIX acceptance

Packaging includes generated `out/build-metadata.json`. Record the VSIX SHA-256, metadata, Git commit, uncommitted changes, package version, OS and editor build. Keep logs/package listings outside source control. Packaging does not publish.

Use a disposable profile, benign workspace and separate home/quarantine store. Before release, check:

- Install, reload, activation, command names, uninstall/reinstall without stale copies
- Restricted Mode: both manual scans/dashboard work, with no workspace edits, home-store, model or watcher side effects
- Workspace settings cannot enable models/custom rules or suppress Restricted Mode checks
- Dismiss all review/quarantine dialogs and verify unchanged bytes
- In a deliberately trusted workspace, review/apply/undo a benign task and compare bytes
- Newer edits make undo refuse; quick fixes never perform line-deletion edits
- Quarantine benign bytes, reload, restore and compare hash/permissions; recreated destinations are preserved
- Repeated clicks, closing panels, corrupt/busy store and interrupted-operation messages
- Keyboard focus, readable dialogs and state communicated in words, not color alone
- Separately authorized live-model input/cancellation if that feature is claimed tested

Windows/macOS filesystem behavior, accessibility, real power interruption, installed GUI flows and live providers require separate evidence. Keep incomplete checks BLOCKED or NOT RUN; do not infer completion from Linux units or host activation.

## Claims

Use “workspace inspection with reviewed remediation.” Do not claim antivirus protection, pre-execution blocking, safe repositories, new-threat detection, AST parsing or fixed latency. Legacy `ast` is regex-based; `file-structure` is unsupported. Campaign labels and historic changelog descriptions are not verified current capability contracts.
