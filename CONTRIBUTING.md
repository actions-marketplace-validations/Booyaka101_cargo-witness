# Contributing to cargo-witness

Thanks for your interest in improving cargo-witness. This guide covers how to
get set up, run the tests, and extend the tool.

## Getting Started

```sh
git clone https://github.com/Booyaka101/cargo-witness.git
cd cargo-witness
npm install
npm test
```

Node.js **>= 22** is required. `better-sqlite3` needs it, and on an older Node
the scanner segfaults rather than refusing to start.

## Running the Tests

`npm test` runs the full suite via `test/run.js`, which executes nine test
suites in sequence.

The integration test runs **fully offline**. It spins up a local mock server
that stands in for `static.crates.io`, the crates.io API, and the GitHub
git-trees API, so the suite makes **no network calls** and is deterministic.
Please keep it that way — do not introduce tests that reach the real network.

## Coding Conventions

- **CommonJS** modules (`require`/`module.exports`); the package is
  `"type": "commonjs"`.
- Start each source file with `'use strict';`.
- **Keep the differ pure.** `src/differ.js` should contain no I/O — it takes the
  already-fetched artifact and git-tree data as inputs and returns findings.
  Network access, filesystem work, and side effects belong in the scanner and
  the fetch/cache layers, not the differ. This keeps detection logic easy to
  unit-test.

## Adding a New Detection

1. Define the new flag and its severity (`HIGH`, `MEDIUM`, or `INFO`) alongside
   the existing detection flags.
2. Implement the comparison logic. Pure content/tree comparisons go in
   `src/differ.js`; anything that needs orchestration, fetching, or extra data
   goes in `src/scanner.js`.
3. Add a test case to the suite (extend the offline mock fixtures so the new
   condition is exercised without network access).
4. Update `README.md` and `CHANGELOG.md` to document the new flag.

Keep flags accurate: `HIGH` is reserved for findings that strongly indicate
tampering (injected/modified `build.rs`, unexpected binaries, checksum
mismatch), `MEDIUM` for source divergences that warrant review, and `INFO` for
advisory signals such as yanked versions.

## Rebuilding the Action Bundle

The GitHub Action runs from a committed bundle in `dist/`, produced with
[`@vercel/ncc`](https://github.com/vercel/ncc):

```sh
npm run build:action
```

**`dist/` must be committed** for the Action to work — GitHub runs the bundled
`dist/action.js` directly and does not install dependencies at action runtime.
Whenever you change code that ends up in the Action, rebuild and commit the
updated `dist/`. CI verifies the committed bundle is up to date by rebuilding
and running `git diff --exit-code dist/`.

## Pull Requests

- Ensure `npm test` passes.
- Rebuild `dist/` if your change affects the Action.
- Keep changes focused and describe the detection or behavior you are changing.
