# Native harness fixture follow-up — 2026-10-10

After publishing source repairs as `17793193504a5a3abe02dbdf1dd2ae3169d542d2`, a final handoff review found that the installed-GUI driver still used a JavaScript `eval(` comment that only produced a finding through the former over-broad rule matching. With corrected R4 and all 53 rules, the old fixture yields zero findings.

Only the driver fixture and its unit regression changed. The new comment contains a supported suspicious pattern; it is never executed. The regression consumes exactly the exported constant used by the driver and checks file/workspace scanning, one scanned file, zero skipped/error files and unchanged bytes. No GUI assertion was relaxed.

- RED: 0 passing, 1 failing against the previous fixture.
- GREEN: installed-gui-harness.test.js, 33 passing, zero failures; syntax PASS.
- Independent focused verification: 1 passing; GO.
- All 99 product inputs and the VSIX remain unchanged. Package SHA-256: `8b49c92a280bcfc40a5ffd485858be1baa18b9c20f3542375fa9827b82d6adde`.
- The prior full unit result remains 585 passing on its recorded source; the new focused result is separate, not an invented rerun of the aggregate.
- Installed GUI and Development Host remain NOT_RUN/BLOCKED as recorded in REPORT.md. This precondition check is not native acceptance.

This follow-up's containing commit identifies the updated driver. The source repair and package identity are in [REPORT.md](REPORT.md) and [EVIDENCE.json](EVIDENCE.json).
