# Contributing to haskoin

## Build and test

See [docs/building.md](docs/building.md) for the toolchain and system libraries. Then:

```bash
cabal build exe:haskoin
cabal test --test-show-details=direct
```

A single suite, or a subset of the main hspec suite, can be run on its own:

```bash
cabal test script-vectors
cabal test haskoin-test --test-options='--match "MuHash"'
```

Keep the style of the module you are editing. Do not reformat code your change does not
otherwise touch.

## Pull requests

- One change per pull request, against `master`.
- Every behaviour change comes with a test that fails before the change and passes after
  it. If an existing test asserts the old behaviour, change that test in the same pull
  request and say why.
- Do not delete or mark pending a test to make the suite pass. If a test pins a known gap,
  keep it pending with a message that names the gap.
- Update the docs in `docs/` when you change an option, a config key or an RPC method.

## Commit messages

Conventional-commit prefixes: `fix:`, `feat:`, `perf:`, `refactor:`, `test:`, `docs:`,
`build:`, `ci:`. The subject says what changed; the body says why, and for a fix, how it
was found and how the test reproduces it.

## Consensus changes

haskoin must accept exactly the blocks and transactions Bitcoin Core accepts. A change to
block, transaction or script validation, the UTXO set, or chain selection needs evidence of
Core equivalence in the pull request: the Core source it follows (file and function), a
test that shows the behaviour on a case where the old code and Core disagreed, and the
result of running Core's own vectors (`cabal test script-vectors sighash-vectors`) or a
regtest comparison against a Core node (see [docs/status.md](docs/status.md)). Also state
what could make a valid block invalid, or an invalid block valid, with your change, and
which test covers that.
