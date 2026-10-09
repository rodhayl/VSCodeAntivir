# Defects and evidence correction

Current status: installed GUI acceptance remains open. See [REPORT.md](REPORT.md). The original defect write-up is preserved as [historical/DEFECTS-866190a.md](historical/DEFECTS-866190a.md); descriptions there are historical claims, not newly verified findings.

## DEF-01 through DEF-03: historical Windows fixes

The changes in `18195df8667f27526bdbb5c9c0a73555782b2804` address the reported directory traversal loop, read-only-descriptor fsync error and editor-cleanup retry behavior. This correction changes no product files and does not reproduce their Windows outcomes. Windows ACL enforcement and power-loss durability remain unverified.

## DEF-04: invalid trust-selector and false-positive harness

Confirmed by source inspection at `866190a`: the driver still used the escaped selector while its report claimed `getElementById` was already used. Null was interpreted as trusted; a dashboard condition included `|| true`; dialog presence/clicks were not required; quarantine used direct class calls; reported failures still exited zero. Identical screenshot blobs were presented as separate UI transitions.

The corrected driver requires positive observed trust, actual controls and transitions, a real owned-editor restart and unique hashed captures. Unknown state, evaluation failure and missing mandatory checks fail closed. Regression tests cover null/conflicting trust, missing dialogs/actions, exceptions, duplicate screenshots and nonzero failure exit behavior. A new native run remains necessary to validate all editor selectors and actual flows.

## DEF-05: reported startup race, not established

The observation is only that a home store existed after several actions. The original run did not establish known-untrusted activation or timestamp creation relative to trust/commands. It does not demonstrate a transient or indeterminate API trust value. Known-false host-stub activation already enforces the documented restricted gates; known-true activation eagerly initializes storage in the unchanged product. This is not a reproduced Restricted Mode regression, and no DEF-05 product fix is included here.

Next reproduction must establish actual trust and activation state, observe storage before/after each stage, and distinguish activation from an explicitly authorized quarantine operation. Preserve every result, including negative reproduction and blocked observations. Do not silently convert optional preventive hardening into a security-defect fix.
