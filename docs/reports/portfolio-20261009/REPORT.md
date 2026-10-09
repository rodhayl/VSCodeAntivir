# Portfolio verification report — 2026-10-09

**Historical checkpoint.** The results and blocker below describe this report's original candidate and environment. A [later installed Windows GUI campaign](../native-portfolio-20261009/REPORT.md) established a bounded 17-check subset on candidate `35f4de018943709ecfacce5f31810ea7f95158f0` and its separately identified VSIX. It supports CV/portfolio closure with declared limits; it does not retroactively turn this earlier blocked run into a pass or establish full release acceptance.

**Status: source/package verification passed; native acceptance remains blocked.** This report describes a candidate, not a release or proof that a workspace is safe.

## Identity and scope

- Repository: `rodhayl/VSCodeAntivir`; product: **FakeInterviewGuard**.
- Base commit: `4d8b6cac776fb8ff423622f0f569b607f666333c`, existing branch `codex/safe-remediation-20261004` (PR #21).
- Extension ID/version: `fakeinterviewguard.fake-interview-guard` / `1.0.0`.
- Tested VSIX SHA-256: `4ccae739b2b8ec483234ee2d8ac36f18aae6fc36aec265e522c9a646b392bb0e` (1,398,322 bytes, 1,098 entries).
- Packaged build-input digest: `968fd7a49a26471eab5b526a565c2b2593c0ed678d74da14c19530168af81583`.
- Tested source snapshot digest, excluding this report directory and generated files: `5a8e28f229d5d67a4d4f7b0041d671eea6204d87909084eb94145fb616ed7db0`.

These digests have different scopes. The package digest covers the sorted input list in its `out/build-metadata.json`; it is not the hash of a Git tree or the entire repository. The source snapshot includes test runners and documentation outside this report directory. Adding this report changes the documentation-inclusive source manifest, but does not change packaged inputs. The existing tested VSIX was retained; it was not rebuilt merely to add documentation. [EVIDENCE.json](EVIDENCE.json) records machine-readable identities and counts. The publishing commit identifies the final documentation-inclusive repository state without a self-referential embedded hash.

## Functional changes

- Restricted Mode permits manual, bundled-rule static inspection using user/default settings. It does not initialize quarantine/model clients, custom rules, automatic watchers or remediation. Trust changes require a window reload before enabling those actions.
- Configuration changes use explicit review. Diagnostic actions no longer delete lines directly; the dashboard reports findings without an uncalibrated safety score.
- Restore stages complete bytes and publishes exclusively. Interrupted writes, hash/inode changes, destination conflicts and failed metadata commits retain recoverable payloads. Synthetic RED/GREEN probes reproduced the previous partial-write and concurrent-destination loss cases, then verified preservation.
- Manifest/task/model-response shape validation and local semver handling are stricter. Dependency inspection does not execute `npm audit`, resolve a lockfile or block execution. Legacy `ast` means regex matching; unsupported `file-structure` matchers fail visibly.
- Runtime dependencies are now included in the VSIX. An isolated extraction check loads the packaged entry point, dependencies, 53 rules and four prompts, then runs an inert scan without repository dependency fallback. Development tools, source/tests and editor caches are excluded.
- Documentation, identity and command flow are consistent. Proven unused helpers and obsolete lint configuration were removed after import/call/registration review; historical changelog evidence and inspection samples were preserved. Samples are never executed by these checks.

## Verification results

| Check | Result and boundary |
| --- | --- |
| Reproducible installation | `npm ci --ignore-scripts` passed with the final lockfile on Node 24.19.0/Linux x64. |
| Type check / lint | Passed on Node 24.19.0 and 22.13.0; zero lint warnings. |
| Unit tests | Initial full suite: **376 passed**. After four runner-compatibility regressions were added: **380 passed on each of Node 24.19.0 and 22.13.0**. |
| Synthetic corpus | 20 author-built text cases, 400 warmed scans: TP 8, FP 4, TN 8, FN 0, errors 0. Four of 12 benign challenges are false positives. |
| Package / isolated smoke | vsce 4 packaging passed; exact VSIX import/scanner smoke passed on Node 24.19.0 and 22.13.0. VS Code APIs are stubbed at import, so this is not native activation. |
| Dependency audit | Final production-only and full `npm audit`: **0 reported vulnerabilities** on 2026-10-09. This is a dated advisory result, not a security guarantee. |
| Real Extension Host | **BLOCKED before tests**: VS Code 1.141.0, build `07b4ff1883f94da91f6d698744fc7c3638b59720`, exited with SIGTRAP; missing X server/DISPLAY and socket restrictions. No supported Xvfb installation was available. |
| Installed native acceptance | **NOT RUN**: exact-VSIX installation/lifecycle/GUI, Windows/macOS filesystem behavior, keyboard/accessibility, actual power interruption and live model providers. |

The aggregate `npm test` is **not an overall pass** because Extension Host startup is blocked. No sandbox-disabling flags or security changes were used. The corpus is regression characterization, not independent malware efficacy. Its timings exclude startup, traversal, UI and LLMs; no fixed latency claim is established.

### Tooling compatibility correction

Compatible dependency refreshes followed by vsce 4.0.0 and Mocha 12.0.3 remove the remaining development-tool advisories without forced overrides. The lockfile also advances production minimatch 10.2.5 to 10.2.6; independent artifact comparison found its change limited to package metadata, with runtime JavaScript unchanged.

An independent review raised a minimum-Node compatibility concern. It was reproduced using the official checksum-verified Node 22.13.0 binary: `require('mocha')` returns a namespace with a default constructor, while the previous runner expected a function. Both unit and integration runners now normalize those two shapes, with four regression tests. Mocha's package has `type: module`, `main: ./index.js` and no exports map; compatibility is demonstrated by execution, not inferred from an exports-map claim.

## Independent review and remaining acceptance

A separate reviewer read the changed runtime modules and callers, ran 136 selected safety tests, checked 158 source-file hashes and 98 package inputs, and matched all 37 packaged JavaScript modules to independent in-memory TypeScript emission (zero diagnostics). Additional reviewer-written restore probes covered same-bytes inode replacement, fsync failure/restart and failed metadata rollback. The synthetic counts and isolated package smoke were independently reproduced. This initial review used the prior tooling graph; the subsequent narrow review covers the dependency/runner delta and final source/package linkage rather than claiming another whole-suite execution.

Next acceptance must use an authorized display-capable editor environment and the exact VSIX hash above. Follow [the verification checklist](../../VERIFICATION.md) for install/reload/uninstall, Restricted Mode behavior, review/apply/undo, restore conflicts and accessibility. [Recovery guidance](../../RECOVERY.md) explains interrupted-operation limits. Until that evidence exists, native delivery remains incomplete.

## Official migration references

- [vsce 4.0.0 release](https://github.com/microsoft/vscode-vsce/releases/tag/v4.0.0)
- [Mocha 12.0.0 release](https://github.com/mochajs/mocha/releases/tag/v12.0.0) and [12.0.3 patch](https://github.com/mochajs/mocha/releases/tag/v12.0.3)
- [Node 22.13 CommonJS interoperability](https://nodejs.org/download/release/v22.13.0/docs/api/esm.html#commonjs-namespaces)
