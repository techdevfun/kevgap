# Contributing to kevgap

## Bugs and feature requests

Open an issue with:

- the exact command you ran and its full output (or `--json` output),
- your inventory file with any sensitive names replaced (keep the
  structure),
- the snapshot catalog version from the audit header
  (`kevgap audit` prints it on the first lines).

## Pull requests

- Keep the CLI zero-dependency at runtime. Dev dependencies are fine.
- `npm run build` (tsc strict), `npm test`, `npm run lint` and
  `node scripts/preflight.js` must all pass.
- Add a test for every behavior change. Fixtures in `test/` are
  synthetic and labelled as such; the demo and the GT13 example use
  the real bundled KEV snapshot.
- Never invent KEV dates or numbers. If a test needs a KEV row, use
  the real catalog or a clearly synthetic fixture.
- Public content is English only, ASCII only, no em dash (use a
  hyphen). The preflight script enforces this.

## Release process

Releases are cut by the maintainer. The npm package is not published
yet; install from source until that changes.
