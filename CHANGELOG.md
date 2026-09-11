# Changelog

## v1.0.2 — 2026-09-11

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

