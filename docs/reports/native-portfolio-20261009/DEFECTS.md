# Defects and evidence: verified native update

Current status: the bounded installed-GUI automated subset is verified with declared limits, sufficient for this CV/portfolio demonstration. This is not full release acceptance. See [REPORT.md](REPORT.md). Historical claims remain preserved as [historical/DEFECTS-866190a.md](historical/DEFECTS-866190a.md).

## DEF-01 through DEF-03: historical Windows fixes

The historical changes in `18195df8667f27526bdbb5c9c0a73555782b2804` address the reported directory traversal loop, read-only-descriptor fsync error, and editor-cleanup retry behavior. Those changes and their reported unit/integration results are preserved; this native subset is not a separate reproduction of every historical defect. Windows ACL enforcement and power-loss durability remain declared out-of-scope limits.

## DEF-04: trust selector and false-positive harness resolution

The previous test driver contained loose assertions and duplicate captures. The corrected `test-installed-gui-acceptance.js` driver resolved these issues:
- Enforces strict Workspace Trust editor inspection; requires affirmative `restricted` and `trusted` states.
- Configures `window.dialogStyle: "custom"` in the test profile so that modal warnings render into the DOM for inspection and interaction.
- Handles Windows drive-letter casing when comparing paths in quarantine manifests.
- Clears pending notifications before secondary restore actions so that the provider's pending state is reset.
- Validates all 17 checks against the installed VSIX in a real VS Code instance, generating 13 distinct screenshots with verified unique SHA-256 digests.

## DEF-05: reported startup race, not reproduced

DEF-05 remains unproven:
- Cold launch in Restricted Mode establishes that `.fakeinterviewguard` is absent before and after manual file/workspace scanning and dashboard opening.
- The inspected fixture bytes remained unchanged. Model-client creation/traffic, automatic watchers and custom-rule suppression were not independently instrumented by this native driver; known-false host-stub activation and source checks remain separate evidence for those gates.
- When trust is granted and the editor reloads, quarantine storage is initialized eagerly by design in the unchanged product.
- No transient trust leak or race condition was observed. No product code modification was made in this testing-only campaign.
