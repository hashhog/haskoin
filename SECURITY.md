# Security Policy — haskoin

haskoin is a from-scratch Bitcoin full-node implementation in Haskell, part of the
[hashhog](https://github.com/hashhog) fleet of ten independent nodes that
cross-validate each other and Bitcoin Core. Security is the entire purpose.

## Project maturity — read this first

haskoin is pre-release. It is intended to be built and run *beside* Bitcoin Core in
watchtower mode with `consensus-diff` as a live divergence alarm. Its genesis→tip
`--assumevalid=0` validation (R4) has not yet been receipted, and it runs
`--connect`-pinned to a trusted Core peer in the fleet deployment.

**It is NOT fund-capable.** Do not custody funds on it. There are no fund-grade
guarantees. Run from a pinned commit.

## Supported versions

| Version | Supported |
|---------|-----------|
| `v0.1.0-beta1` (pinned `b1d1d43`) | Beta — best-effort; no security SLA until the final `v0.1.0` |
| pre-release (`master`) | Best-effort |

Release-signing key fingerprint: to be published with v1.0.0.

## Reporting a vulnerability

**Please do NOT open a public GitHub issue** for anything in the consensus, P2P, or
wallet paths — a public report could put real Bitcoin nodes or funds at risk.

Report privately to the maintainer:

- **Email:** `max@dockyard.navy`  <!-- TODO(max): confirm or replace with a dedicated security alias -->

Include the affected path, a deterministic reproduction (a diff-test corpus entry,
regtest script, or malformed message), impact, and any suggested fix. We coordinate
a fix + disclosure timeline and credit you if you wish.

## In scope (highest priority)

- **Consensus divergence** — haskoin accepting a block/tx Core rejects, or vice-versa.
  This is the core concern (see `../CORE-PARITY-AUDIT/` for receipted fixes).
- **Remotely-triggerable crashes / OOM / resource exhaustion** in the P2P or block/tx
  decode paths.
- **Wallet funds-safety** — silent wrong-key signing, a spend the node reports valid
  that the network rejects, un-recoverable backups, fee miscalculation stranding funds.
- **Chainstate corruption on crash** or on restart (the reload gate is a known
  fragile area; regressions are in scope).

## Custody caveats (not consensus, but real)

- The wallet is not fund-grade. Treat any funded wallet as a canary only, with an
  offline backup of the seed.

## Out of scope

- IBD/sync performance characteristics.
- Issues requiring an already-compromised host.

## Disclosure

Coordinated disclosure. Consensus fixes are verified with `../tools/verify-fix.sh` and
gated through the differential corpus before they are considered landed; a live
watchtower (`../tools/watchtower.sh`) alarms on any haskoin-vs-Core divergence.
