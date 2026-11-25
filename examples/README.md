# Examples

## gt13-inventory.json

A small operator inventory built around the GT13 campaign (GreyNoise,
23/11/2026): 24 Check Point Security Management servers compromised.
Every asset here is real in the sense that matters - the KEV entries it
matches are the real catalog rows, with real dates:

- `cp-smartconsole-01` - Check Point SmartConsole, unpatched.
  CVE-2026-16232 was listed on KEV 2026-07-22, due 2026-07-25.
  On 2026-11-25 it is 126 days since listing and 123 days past due.
- `citrix-netscaler-01` - Citrix NetScaler ADC and Gateway, unpatched.
  CVE-2025-5777, listed 2025-07-10, due 2025-07-11.
- `ivanti-connect-01` - Ivanti Connect Secure, unpatched.
  CVE-2024-21893, listed 2024-01-31, due 2024-02-02.
- `openssh-01` - OpenBSD OpenSSH, patched 2026-11-13.
  CVE-2026-123158 ("sshole"), listed 2026-11-09, due 2026-11-12.
  Closed window: 4 days after listing, patched 1 day past due.
  The historical gap is reported, not hidden.
- `acme-router-01` - a product with no KEV entry: NOT-LISTED.
- `mystery-01` - same product as the first asset, but no status
  declared: UNKNOWN, never a false pass or false fail.

Run it:

```sh
node dist/cli.js audit examples/gt13-inventory.json
node dist/cli.js check examples/gt13-inventory.json   # exit 1 while anything is overdue
```

## gt13-baseline.json

A previous audit of the same inventory, produced by a real run on
2026-11-18 (`kevgap audit --json` with the date pinned for the
record). Use it with `diff` to see the windows grow:

```sh
node dist/cli.js diff --baseline examples/gt13-baseline.json examples/gt13-inventory.json
```
