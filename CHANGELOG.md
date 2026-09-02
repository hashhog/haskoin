# Changelog

## v1.0.0 (unreleased)

Changes since `v0.1.0-beta1`:

- 26f71d7 fix(rpc): loadtxoutset answers -8 "Couldn't open file" for an unreadable path
- 01dbc4e test: bring 32 stale expectations up to Core behaviour, unstick fixture-path tests
- 5e06837 docs: LICENSE, SECURITY.md, toolchain versions (release hygiene)
- ccfa0f2 fix(rpc): validate argument COUNT centrally, and list the 31 methods help hid (#103)
- ed1f3e9 tools: db-breakdown — measure which key prefix owns the chainstate bytes
- 6374646 fix(rpc): the integer conversion runs before the lookup, and setban matches Core
- a307605 fix(rpc): read integer arguments at Core's width, and honour the ones we read
- 42c26af fix(rpc): createrawtransaction ignored the `version` argument
- 64b9a53 fix(rpc): submitblock decode failure reports Core's token, not the decoder's own text
- 8782496 fix(rpc): createrawtransaction rejects replaceable=true contradicted by its sequences
- f566ac0 fix(rpc): locktime is range-checked, not silently replaced by 0
- 687db54 fix(rpc): createrawtransaction rejects a malformed input instead of dropping it
- 5c4a327 feat(shim): plumb MTP context into the checkblock op (BIP-68 time locks + BIP-113)
- 92778ae fix(net): serialize sends with a per-connection lock; remove dead outbound queue (audit v1-sendAll row)
- 23b3afe test: work-vs-length pins on the addHeaderAt tip-move guard (#47)
- ae3be7e fix(consensus): header tip never moves onto an invalidated branch (#53b)
- 5d03f3a fix(p2p): requestFromPeer failures are loud; downloadWorker reverts and requeues on dropped getdata (#74)
- e24620b fix(p2p): defuse the evictionLoop single-hash locator landmine
- 9444dc8 fix(consensus): lookupUTXO must not fabricate coin height and coinbase flag
- 624d6b8 test: pin the tombstone defect — a re-created coin must survive the disconnect
- 5e6d0cc fix(consensus): apply both reorg-connect fixes to the submitblock twin
- cabe8e8 fix(consensus): a re-created coin must clear the disconnect phase's tombstone
- bea8d11 fix(consensus): omit unresolvable prevouts in reorg connect, as the live path does

