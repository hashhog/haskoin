# Changelog

## Unreleased

- fix: store an out-of-order body without ConnectBlock against the current UTXO (Core AcceptBlock), and reassign next-needed after BLOCK_STALLING_TIMEOUT (2s) when the assigned peer sends later heights instead. Live 2026-09-24: ahead arrivals were reason=validation Missing UTXO; next-needed stayed already-inflight on one peer because first-byte mute never fired. Discriminator: stored=yes invalid=no (hcInvalidated is RPC-only).
- feat: log the download-stall discriminator. Unconnected arrivals carry the underlying reject (`err=`), including blocks ahead of next-needed that were only tagged `reason=validation`. Each linear getdata window logs every peer's connected-at-send and send outcome, and the next-needed height logs which peer it was assigned to and whether that send left the process. `requestFromPeer` failures name the message type and the peer state. Instrumentation only — refill, inflight accounting, and peer selection are unchanged.
- fix: R5 regtest wallet lane T3 2/16 → 16/16. Core error codes on createwallet/getnewaddress/listunspent/listtransactions/walletcreatefundedpsbt/sendtoaddress/stop; getwalletinfo txcount + blank/flags/lastprocessedblock; getaddressinfo and listunspent descriptor fields; new getbalances, send, walletprocesspsbt, and backupwallet; restorewallet loads a backup file (Core), not a mnemonic.
- feat: name the branch on every linear-download getdata window (`branch=progress|stall|receipt`) and count MBlock bodies that arrive without connecting (`Block arrived unconnected`, with reason + running count). Instrumentation only — e8a03a9 refill/cap behaviour is unchanged. The kicker line keeps the `Block-gap kicker: pipelining` prefix and appends `branch=`; UpdateTip is untouched.
- feat: single `--connect` peer defaults the per-peer in-flight cap to 128 (`HASHHOG_BLOCKS_IN_FLIGHT_PER_PEER` overrides); MBlock refills the pipeline on receipt so a local feeder does not wait for the 0.4s kicker poll

## v1.0.2 — 2026-09-11

- fix: fork-aware download serves historical getdata only to NODE_NETWORK peers and reorgs a downloaded heavier prefix (does not wait for the header tip)
- feat: T2 R5 probe parity (error codes, createpsbt object outputs, WIF sign header, utxoupdatepsbt / descriptorprocesspsbt)
- feat: script-verification counter; getchainstates validated is honest for --load-snapshot
- 30cccf3 fix: dumpTxOutSetFromDB streams one txid group instead of the whole coin set
- 5b59a06 fix: gettxoutsetinfo hashed the set from a materialised list of every coin


## v1.0.2 — 2026-09-11

Changes since `v1.0.0`:

- dumpTxOutSetFromDB streams one txid group at a time (no full coin set in RAM)
- f72a884 docs: say the cited paths are private before the claims that rest on them
- 84a1fd1 fix: stage snapshot coins and hash them before they can touch the live chainstate
- fce0217 fix: UTXO-iterating RPCs must report the validated tip, not the best header
- c2457e8 fix: submitblock must compare against the validated tip, not the best header
- 4a9c082 fix: the snapshot hash gate was dead code
- b10f58b feat: HASHHOG_UNSAFE_SNAPSHOT_HEIGHT — accept an un-anchored UTXO snapshot

