#!/usr/bin/env python3
"""Regtest parity of haskoin against a local bitcoind.

Covers the invalidated-submit / mempool-reorg behaviour:

  * invalidateblock, then reconsiderblock of a block whose body is on disk
  * submitblock of an invalidated block ("duplicate-invalid")
  * submitblock of a block on the active chain ("duplicate")
  * submitblock of a new block whose parent is failed ("bad-prevblk")
  * a low-feerate parent and a high-feerate child in the mempool:
    getrawmempool contents, getblocktemplate tx order and depends

Both nodes stay on 127.0.0.1. Blocks and transactions are fed over RPC.
Exit status is 0 when every compared field matches.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

CORE_RPC_PORT = 18443
CORE_P2P_PORT = 18444
HK_RPC_PORT = 18445
HK_P2P_PORT = 18446
RPC_USER = "parity"
RPC_PASS = "parity"

MISMATCHES: list[str] = []


def note(msg: str) -> None:
    print(msg, flush=True)


def mismatch(what: str, core, haskoin) -> None:
    MISMATCHES.append(what)
    note(f"MISMATCH {what}")
    note(f"  core:    {core!r}")
    note(f"  haskoin: {haskoin!r}")


class Rpc:
    def __init__(self, url: str, user: str, password: str):
        self.url = url
        self.user = user
        self.password = password
        self._id = 0

    def call(self, method: str, params=None):
        self._id += 1
        body = json.dumps(
            {"jsonrpc": "1.0", "id": self._id, "method": method, "params": params or []}
        ).encode()
        req = urllib.request.Request(self.url, data=body, method="POST")
        token = f"{self.user}:{self.password}".encode()
        import base64

        req.add_header("Authorization", "Basic " + base64.b64encode(token).decode())
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                payload = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            raw = e.read().decode()
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                raise RuntimeError(f"{method} HTTP {e.code}: {raw}") from e
        if payload.get("error"):
            err = payload["error"]
            raise RpcError(err.get("code"), err.get("message"), method)
        return payload.get("result")


class RpcError(Exception):
    def __init__(self, code, message, method):
        super().__init__(f"{method}: {code} {message}")
        self.code = code
        self.message = message
        self.method = method


def wait_rpc(rpc: Rpc, label: str, seconds: float = 60) -> None:
    deadline = time.time() + seconds
    last = None
    while time.time() < deadline:
        try:
            rpc.call("getblockcount")
            return
        except Exception as e:  # noqa: BLE001 — startup race
            last = e
            time.sleep(0.25)
    raise RuntimeError(f"{label} RPC did not come up: {last}")


def dsha(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def ser_compact(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def compact_target(bits: int) -> int:
    exp = bits >> 24
    mant = bits & 0xFFFFFF
    if exp <= 3:
        return mant >> (8 * (3 - exp))
    return mant << (8 * (exp - 3))


def bip34_script(height: int) -> bytes:
    if height == 0:
        push = b"\x00"
    else:
        hb = height.to_bytes((height.bit_length() + 7) // 8, "little")
        push = bytes([len(hb)]) + hb
    extra = b"/haskoin-parity/"
    return push + bytes([len(extra)]) + extra


def coinbase_tx(height: int) -> bytes:
    scriptsig = bip34_script(height)
    script_pubkey = b"\x51"  # OP_TRUE
    value = 50 * 100_000_000
    vin = (
        bytes(32)
        + struct.pack("<I", 0xFFFFFFFF)
        + ser_compact(len(scriptsig))
        + scriptsig
        + struct.pack("<I", 0xFFFFFFFF)
    )
    vout = struct.pack("<Q", value) + ser_compact(len(script_pubkey)) + script_pubkey
    return (
        struct.pack("<I", 1)
        + ser_compact(1)
        + vin
        + ser_compact(1)
        + vout
        + struct.pack("<I", 0)
    )


def block_on_parent(prev_hex: str, height: int, bits: int, timestamp: int) -> str:
    """A decodable regtest block whose parent is prev_hex. PoW meets bits."""
    prev = bytes.fromhex(prev_hex)[::-1]
    tx = coinbase_tx(height)
    merkle = dsha(tx)
    base = (
        struct.pack("<I", 0x20000000)
        + prev
        + merkle
        + struct.pack("<II", timestamp, bits)
    )
    target = compact_target(bits)
    for nonce in range(1_000_000):
        hdr = base + struct.pack("<I", nonce)
        if int.from_bytes(dsha(hdr), "little") <= target:
            return (hdr + ser_compact(1) + tx).hex()
    raise RuntimeError("failed to grind regtest nonce")


def result_of(rpc: Rpc, method: str, params) -> object:
    """RPC result, or {'error': code, 'message': ...} when the call errors."""
    try:
        return rpc.call(method, params)
    except RpcError as e:
        return {"error": e.code, "message": e.message}


def compare_result(label: str, core: Rpc, hk: Rpc, method: str, params) -> None:
    c = result_of(core, method, params)
    h = result_of(hk, method, params)
    if c != h:
        mismatch(label, c, h)
    else:
        note(f"match {label}: {c!r}")


def compare_tip(label: str, core: Rpc, hk: Rpc) -> None:
    for method in ("getbestblockhash", "getblockcount"):
        c = core.call(method)
        h = hk.call(method)
        if c != h:
            mismatch(f"{label} {method}", c, h)
        else:
            note(f"match {label} {method}: {c!r}")


def feed_chain(core: Rpc, hk: Rpc, height: int) -> None:
    """Submit Core's blocks 1..height to haskoin. Genesis is shared."""
    cg = core.call("getblockhash", [0])
    hg = hk.call("getblockhash", [0])
    if cg != hg:
        mismatch("genesis hash", cg, hg)
        raise SystemExit(1)
    note(f"match genesis {cg}")
    for h in range(1, height + 1):
        bh = core.call("getblockhash", [h])
        raw = core.call("getblock", [bh, 0])
        res = hk.call("submitblock", [raw])
        if res not in (None,):
            mismatch(f"submitblock height {h}", None, res)
            raise SystemExit(1)
    compare_tip(f"synced to {height}", core, hk)


def gbt_txs(rpc: Rpc) -> list[dict]:
    tmpl = rpc.call("getblocktemplate", [{"rules": ["segwit"]}])
    txs = tmpl.get("transactions") or []
    return [
        {
            "txid": t.get("txid"),
            "depends": t.get("depends"),
            "fee": t.get("fee"),
            "weight": t.get("weight"),
            "sigops": t.get("sigops"),
        }
        for t in txs
    ]


def mempool_parent_child(core: Rpc, hk: Rpc) -> None:
    addr_parent = core.call("getnewaddress")
    addr_child = core.call("getnewaddress")
    # 2 sat/vB parent. Well above both nodes' min relay (Core 1 sat/vB,
    # haskoin 0.1 sat/vB) and far below the child built from it.
    parent = core.call(
        "send",
        [{addr_parent: 1.0}, None, "unset", 2],
    )
    parent_txid = parent["txid"]
    parent_hex = core.call("getrawtransaction", [parent_txid])
    hk_acc = hk.call("sendrawtransaction", [parent_hex])
    if hk_acc != parent_txid:
        mismatch("sendrawtransaction parent txid", parent_txid, hk_acc)

    # Spend the 1 BTC output. Leave a small output so the fee is large.
    decoded = core.call("decoderawtransaction", [parent_hex])
    vout = None
    value = None
    for d in decoded["vout"]:
        spk = d["scriptPubKey"]
        addr = spk.get("address")
        if addr == addr_parent or abs(d["value"] - 1.0) < 1e-8:
            vout = d["n"]
            value = d["value"]
            break
    if vout is None:
        raise RuntimeError(f"parent output not found in {decoded}")

    child_value = round(value - 0.01, 8)  # 0.01 BTC fee, high feerate
    raw = core.call(
        "createrawtransaction",
        [[{"txid": parent_txid, "vout": vout}], {addr_child: child_value}],
    )
    signed = core.call("signrawtransactionwithwallet", [raw])
    if not signed.get("complete"):
        raise RuntimeError(f"child did not sign: {signed}")
    child_hex = signed["hex"]
    child_txid = core.call("sendrawtransaction", [child_hex])
    hk_child = hk.call("sendrawtransaction", [child_hex])
    if hk_child != child_txid:
        mismatch("sendrawtransaction child txid", child_txid, hk_child)
    note(f"parent {parent_txid} (2 sat/vB) child {child_txid} (0.01 BTC fee)")

    c_pool = core.call("getrawmempool")
    h_pool = hk.call("getrawmempool")
    if set(c_pool) != set(h_pool):
        mismatch("getrawmempool txid set", sorted(c_pool), sorted(h_pool))
    else:
        note(f"match getrawmempool txids: {sorted(c_pool)}")
    if c_pool != h_pool:
        mismatch("getrawmempool order", c_pool, h_pool)
    else:
        note(f"match getrawmempool order: {c_pool}")

    c_gbt = gbt_txs(core)
    h_gbt = gbt_txs(hk)
    c_order = [t["txid"] for t in c_gbt]
    h_order = [t["txid"] for t in h_gbt]
    if c_order != h_order:
        mismatch("getblocktemplate tx order", c_order, h_order)
    else:
        note(f"match getblocktemplate tx order: {c_order}")
    c_dep = [(t["txid"], t["depends"]) for t in c_gbt]
    h_dep = [(t["txid"], t["depends"]) for t in h_gbt]
    if c_dep != h_dep:
        mismatch("getblocktemplate depends", c_dep, h_dep)
    else:
        note(f"match getblocktemplate depends: {c_dep}")
    # Parent must precede the child even though the child pays more.
    if parent_txid in c_order and child_txid in c_order:
        if c_order.index(parent_txid) > c_order.index(child_txid):
            mismatch("core parent-before-child", c_order, "child before parent")
    if parent_txid in h_order and child_txid in h_order:
        if h_order.index(parent_txid) > h_order.index(child_txid):
            mismatch("haskoin parent-before-child", h_order, "child before parent")
    # BIP 22 / Core mining.cpp: depends is a 1-based index into the
    # transactions list (the coinbase occupies vtx index 0 and is omitted
    # from the list, so the first template tx is 1). haskoin numbers the
    # same list from 0. Each side must still name the parent.
    for label, rows, base in (("core", c_gbt, 1), ("haskoin", h_gbt, 0)):
        ids = [t["txid"] for t in rows]
        if parent_txid in ids and child_txid in ids:
            expect = [ids.index(parent_txid) + base]
            deps = {t["txid"]: t["depends"] for t in rows}[child_txid]
            if deps != expect:
                mismatch(f"{label} child depends (base {base})", expect, deps)
            else:
                note(f"match {label} child depends on parent: {deps}")

    for field in ("fee", "weight", "sigops"):
        c_f = [(t["txid"], t[field]) for t in c_gbt]
        h_f = [(t["txid"], t[field]) for t in h_gbt]
        if c_f != h_f:
            mismatch(f"getblocktemplate {field}", c_f, h_f)
        else:
            note(f"match getblocktemplate {field}: {c_f}")


def main() -> int:
    note("core parity: starting bitcoind and haskoin")
    bitcoind = os.environ.get("BITCOIND", "/tmp/bitcoind/bitcoin-31.1/bin/bitcoind")
    bitcoin_cli = os.environ.get(
        "BITCOIN_CLI", "/tmp/bitcoind/bitcoin-31.1/bin/bitcoin-cli"
    )
    haskoin = os.environ.get("HASKOIN")
    if not haskoin:
        raise SystemExit("HASKOIN=path to the haskoin binary is required")
    if not Path(bitcoind).is_file():
        raise SystemExit(f"bitcoind not found: {bitcoind}")

    root = Path(os.environ.get("PARITY_DIR", "/tmp/haskoin-core-parity"))
    if root.exists():
        shutil.rmtree(root)
    core_dir = root / "core"
    hk_dir = root / "haskoin"
    core_dir.mkdir(parents=True)
    hk_dir.mkdir(parents=True)

    core_log = open(root / "bitcoind.log", "w")
    hk_log = open(root / "haskoin.log", "w")
    core_proc = subprocess.Popen(
        [
            bitcoind,
            f"-datadir={core_dir}",
            "-regtest",
            f"-port={CORE_P2P_PORT}",
            f"-rpcport={CORE_RPC_PORT}",
            f"-rpcuser={RPC_USER}",
            f"-rpcpassword={RPC_PASS}",
            # RPC only. listen=1 also binds the Tor port (P2P+1), which
            # collides with haskoin's RPC port and aborts startup.
            "-listen=0",
            "-fallbackfee=0.0002",
            "-printtoconsole",
        ],
        stdout=core_log,
        stderr=subprocess.STDOUT,
    )
    hk_proc = subprocess.Popen(
        [
            haskoin,
            "-d",
            str(hk_dir),
            "-n",
            "Regtest",
            "node",
            "--rpcport",
            str(HK_RPC_PORT),
            "--rpcuser",
            RPC_USER,
            "--rpcpassword",
            RPC_PASS,
            "--port",
            str(HK_P2P_PORT),
            "--listen",
            "False",
            "--maxpeers",
            "0",
            "--metricsport",
            "0",
            "--printtoconsole",
        ],
        stdout=hk_log,
        stderr=subprocess.STDOUT,
    )
    core = Rpc(f"http://127.0.0.1:{CORE_RPC_PORT}", RPC_USER, RPC_PASS)
    hk = Rpc(f"http://127.0.0.1:{HK_RPC_PORT}", RPC_USER, RPC_PASS)
    try:
        wait_rpc(core, "bitcoind")
        wait_rpc(hk, "haskoin")
        note(f"bitcoind {subprocess.check_output([bitcoind, '-version'], text=True).splitlines()[0]}")
        # Wallet lives only on Core; haskoin receives the same hex.
        subprocess.check_call(
            [
                bitcoin_cli,
                f"-datadir={core_dir}",
                "-regtest",
                f"-rpcuser={RPC_USER}",
                f"-rpcpassword={RPC_PASS}",
                "createwallet",
                "parity",
            ]
        )
        addr = core.call("getnewaddress")
        core.call("generatetoaddress", [105, addr])
        feed_chain(core, hk, 105)

        # Invalidate a non-tip block whose descendants' bodies are on disk,
        # then reconsider it. Both tips must return to height 105.
        bh103 = core.call("getblockhash", [103])
        tip_before = core.call("getbestblockhash")
        compare_result("invalidateblock 103", core, hk, "invalidateblock", [bh103])
        compare_tip("after invalidate 103", core, hk)
        parent102 = core.call("getblockhash", [102])
        if core.call("getbestblockhash") != parent102:
            mismatch("core tip after invalidate 103", parent102, core.call("getbestblockhash"))
        compare_result("reconsiderblock 103", core, hk, "reconsiderblock", [bh103])
        compare_tip("after reconsider 103", core, hk)
        if core.call("getbestblockhash") != tip_before:
            mismatch("core tip restored", tip_before, core.call("getbestblockhash"))

        # submitblock answers, against the invalidated tip.
        tip = core.call("getbestblockhash")
        tip_hex = core.call("getblock", [tip, 0])
        tip_hdr = core.call("getblockheader", [tip])
        compare_result("invalidateblock tip", core, hk, "invalidateblock", [tip])
        compare_tip("after invalidate tip", core, hk)
        compare_result(
            "submitblock invalidated (duplicate-invalid)",
            core,
            hk,
            "submitblock",
            [tip_hex],
        )
        active = core.call("getbestblockhash")
        active_hex = core.call("getblock", [active, 0])
        compare_result(
            "submitblock active (duplicate)",
            core,
            hk,
            "submitblock",
            [active_hex],
        )
        child_hex = block_on_parent(
            tip,
            int(tip_hdr["height"]) + 1,
            int(tip_hdr["bits"], 16),
            int(tip_hdr["time"]) + 1,
        )
        compare_result(
            "submitblock on failed parent (bad-prevblk)",
            core,
            hk,
            "submitblock",
            [child_hex],
        )
        compare_result("reconsiderblock tip", core, hk, "reconsiderblock", [tip])
        compare_tip("after reconsider tip", core, hk)

        mempool_parent_child(core, hk)
    finally:
        for proc, log in ((hk_proc, hk_log), (core_proc, core_log)):
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    proc.kill()
            log.close()

    note("")
    if MISMATCHES:
        note(f"{len(MISMATCHES)} mismatch(es):")
        for m in MISMATCHES:
            note(f"  - {m}")
        return 1
    note("all compared fields matched")
    return 0


if __name__ == "__main__":
    sys.exit(main())
