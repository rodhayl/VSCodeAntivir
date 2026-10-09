# Security policy

FakeInterviewGuard is a source-build workspace inspection tool. Findings are advisory. The package version does not certify safety, independent detection performance or a published release.

## Reporting

Use [private vulnerability reporting](https://github.com/rodhayl/VSCodeAntivir/security/advisories/new) when GitHub makes it available. If unavailable, post a minimal issue asking for a private reporting route without exploit details, credentials, private code or sensitive files. No response-time or patch-date guarantee is made.

Include the commit/VSIX hash, OS and VS Code versions, an inert reproduction, expected/observed behavior and whether original/recovery files remain. Sanitized detection suggestions can be ordinary issues; exploitable flaws or sensitive bypasses should be handled privately. Never submit real malware or secrets.

## Threat model

- Static inspection reads text; it does not need to execute a sample, task, install script, hook or suspicious command.
- Restricted Mode permits manual static scans only. Custom rules, automatic scanning, configuration changes, quarantine and model clients are disabled until a trusted window is reloaded.
- Reviewed changes reject stale snapshots, dirty editor files, symlink targets and restoration conflicts where checked. Private permissions and hashes support recovery, not protection against software already running as the same user.
- Quarantine is not a sandbox. Open descriptors, hostile concurrent writers, path-component races, Windows junctions/ACLs, network filesystems and power loss need platform-specific assessment.
- Rules and package indicators are local author-maintained metadata. They do not establish the installed dependency graph, current advisory status or attacker attribution.
- Custom regex rules and synchronous traversal can exhaust resources. A clean or incomplete scan is not evidence that execution is safe.
- Optional model input can leave the device after consent. API keys remain user settings, not SecretStorage; do not sync or commit them. Repository settings cannot enable model traffic.

## Fixtures and dependencies

Treat `samples/` strictly as inspection data. “Simulated” does not mean arbitrary execution is safe. The separate JSON corpus is read as text and never evaluated. Standard tests stub model transport; `extension/test/live/` experiments require deliberate authorization of the endpoint and input.

Use `npm ci --ignore-scripts`. Check current dependency-audit results for the actual lockfile; scheduled automation is not proof of an audit pass. No unevidenced manual audit cadence is promised.

See [recovery](docs/RECOVERY.md) for interrupted operations. Preserve originals, manifests, backups and payloads until ownership and bytes are verified. Manifests may contain private paths and finding details.
