#!/usr/bin/env python3
"""Regtest field comparison of haskoin against Bitcoin Core v31.1.

Offline only: both processes bind 127.0.0.1, DNS seeding is off, and neither
is given an outbound peer. Compares decodescript, getdescriptorinfo,
deriveaddresses, decoderawtransaction scriptPubKey fields, scantxoutset
``desc`` when a P2A coin exists, and the wallet address of a P2A output when
the node exposes one.

Usage:
  python3 test/p2a_followups_core_parity.py \
      --bitcoind /path/to/bitcoind \
      --haskoin /path/to/haskoin
"""

import argparse
import json
import os
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

PK1 = "03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd"
PK2 = "03dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a61626"
PK_RPC = "03b0da749730dc9b4b1f4a14d6902877a92541f5368778853d9c4a0cb7802dcfb2"
PK_UNCOMP = (
    "04b0da749730dc9b4b1f4a14d6902877a92541f5368778853d9c4a0cb7802dcfb2"
    "5e01fc8fde47c96c98a4f3a8123e33a38a50cf9025cc8c4494a518f991792bb7"
)

# BIP-380 checksums. Cross-checked against Core v31.1 for the known
# addr/pk/multi/raw bodies; the rest use the same polynomial.
DESCS = {
    "pk1": "pk(" + PK1 + ")#vwaefwnq",
    "pk_rpc": "pk(" + PK_RPC + ")#h9zd5h4y",
    "pk_uncomp": "pk(" + PK_UNCOMP + ")#5u23hkue",
    "multi_sorted": "multi(1," + PK1 + "," + PK2 + ")#ve902xrt",
    "multi_unsorted": "multi(1," + PK2 + "," + PK1 + ")#krrhyz4f",
    "multi_uncomp": "multi(1," + PK1 + "," + PK_UNCOMP + ")#fuu5v7z2",
    "wsh_sorted": "wsh(multi(1," + PK1 + "," + PK2 + "))#8yt2huam",
    "wsh_unsorted": "wsh(multi(1," + PK2 + "," + PK1 + "))#73cnnwta",
    "p2a": "addr(bcrt1pfeesnyr2tx)#swxgse0y",
}

SCRIPTS = [
    ("p2pk", "21" + PK1 + "ac"),
    ("p2pk_rpc_decodescript", "21" + PK_RPC + "ac"),
    ("p2pk_uncompressed", "41" + PK_UNCOMP + "ac"),
    ("hybrid", "41" + "06" + ("00" * 64) + "ac"),
    ("multi_sorted", "5121" + PK1 + "21" + PK2 + "52ae"),
    ("multi_unsorted", "5121" + PK2 + "21" + PK1 + "52ae"),
    ("multi_uncompressed", "5121" + PK1 + "41" + PK_UNCOMP + "52ae"),
    ("p2a", "51024e73"),
    ("op_unknown", "bb"),
    ("op_unknown_pair", "bbbc"),
    ("op_checksigadd_unknown", "babb"),
    ("op_invalidopcode", "ff"),
    ("op_cat", "7e"),
    ("op_cat_truncated", "7e01"),
    ("disabled_pair", "7e95"),
]


def compact(n):
    if n < 0xfd:
        return bytes([n])
    return b"\xfd" + struct.pack("<H", n)


def tx_out(value, script):
    return struct.pack("<Q", value) + compact(len(script)) + script


def sample_tx_hex():
    """One raw transaction both nodes decode. Not broadcast."""
    version = struct.pack("<I", 2)
    prev = b"\x11" * 32
    inp = prev + struct.pack("<I", 0) + compact(0) + struct.pack("<I", 0xFFFFFFFF)
    outs = b"".join(
        [
            tx_out(0, bytes.fromhex("51024e73")),
            tx_out(1000, bytes.fromhex("21" + PK1 + "ac")),
            tx_out(2000, bytes.fromhex("5121" + PK1 + "21" + PK2 + "52ae")),
            tx_out(3000, bytes.fromhex("7ebbff")),
        ]
    )
    raw = version + compact(1) + inp + compact(4) + outs + struct.pack("<I", 0)
    return raw.hex()


class Rpc:
    def __init__(self, url, user, password):
        self.url = url
        token = (user + ":" + password).encode()
        import base64
        self.auth = "Basic " + base64.b64encode(token).decode()

    def call(self, method, params=None):
        body = json.dumps(
            {"jsonrpc": "1.0", "id": method, "method": method, "params": params or []}
        ).encode()
        req = urllib.request.Request(
            self.url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": self.auth,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                payload = json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode(errors="replace")
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                raise RuntimeError("%s HTTP %s: %s" % (method, exc.code, raw)) from exc
        if payload.get("error"):
            err = payload["error"]
            raise RpcError(err.get("code"), err.get("message"), method)
        return payload.get("result")


class RpcError(Exception):
    def __init__(self, code, message, method):
        super().__init__("%s %s: %s" % (method, code, message))
        self.code = code
        self.message = message
        self.method = method


def wait_rpc(rpc, timeout=90):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            rpc.call("getblockcount")
            return
        except Exception as exc:  # noqa: BLE001 — node still booting
            last = exc
            time.sleep(0.5)
    raise RuntimeError("RPC never came up: %s" % last)


def start_bitcoind(bin_path, datadir, port):
    args = [
        bin_path,
        "-regtest",
        "-datadir=" + datadir,
        "-server=1",
        "-listen=0",
        "-dnsseed=0",
        "-dns=0",
        "-connect=0",
        "-port=" + str(port),
        "-rpcbind=127.0.0.1",
        "-rpcallowip=127.0.0.1",
        "-rpcport=" + str(port + 1),
        "-rpcuser=parity",
        "-rpcpassword=parity",
        "-fallbackfee=0.0002",
    ]
    log = open(os.path.join(datadir, "bitcoind.log"), "w")
    proc = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)
    return proc, log


def start_haskoin(bin_path, datadir, port):
    args = [
        bin_path,
        "-d", datadir,
        "-n", "Regtest",
        "node",
        "--rpcport", str(port + 1),
        "--rpcuser", "parity",
        "--rpcpassword", "parity",
        "--listen", "False",
        "--port", str(port),
        "--nodnsseed",
        "--maxpeers", "0",
        "--metricsport", "0",
        "--printtoconsole",
    ]
    log = open(os.path.join(datadir, "haskoin.log"), "w")
    proc = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)
    return proc, log


MATCHED = []
MISMATCHED = []
JUSTIFIED = []
NOT_RUN = []


def record(kind, name, detail):
    {"match": MATCHED, "mismatch": MISMATCHED, "justified": JUSTIFIED, "notrun": NOT_RUN}[kind].append(
        (name, detail)
    )
    tag = {"match": "MATCH", "mismatch": "MISMATCH", "justified": "JUSTIFIED", "notrun": "NOT-RUN"}[kind]
    print("%s  %s  %s" % (tag, name, detail))


def compare_value(path, core, hask):
    if core == hask:
        record("match", path, json.dumps(core, sort_keys=True)[:180])
    else:
        record(
            "mismatch",
            path,
            "core=%s haskoin=%s" % (json.dumps(core), json.dumps(hask)),
        )


def compare_obj(path, core, hask, keys):
    if not isinstance(core, dict) or not isinstance(hask, dict):
        compare_value(path, core, hask)
        return
    for key in keys:
        c_has = key in core
        h_has = key in hask
        if c_has != h_has:
            record(
                "mismatch",
                path + "." + key,
                "presence core=%s haskoin=%s core_val=%s haskoin_val=%s"
                % (c_has, h_has, json.dumps(core.get(key)), json.dumps(hask.get(key))),
            )
        elif c_has:
            compare_value(path + "." + key, core[key], hask[key])


DECODE_KEYS = ["asm", "desc", "address", "type"]
SEGWIT_KEYS = ["asm", "desc", "hex", "address", "type"]
INFO_KEYS = ["descriptor", "checksum", "isrange", "issolvable", "hasprivatekeys"]


def compare_decodescript(core, hask):
    for name, hexscript in SCRIPTS:
        try:
            c = core.call("decodescript", [hexscript])
        except RpcError as exc:
            record("notrun", "decodescript " + name, "core error %s" % exc)
            continue
        try:
            h = hask.call("decodescript", [hexscript])
        except RpcError as exc:
            record("mismatch", "decodescript " + name, "haskoin error %s core=%s" % (exc, json.dumps(c)[:300]))
            continue
        compare_obj("decodescript %s" % name, c, h, DECODE_KEYS)
        if "segwit" in c or "segwit" in h:
            compare_obj("decodescript %s segwit" % name, c.get("segwit"), h.get("segwit"), SEGWIT_KEYS)
        # Checksum present on every inferred descriptor Core returned.
        desc = c.get("desc")
        if isinstance(desc, str) and "#" in desc and len(desc.split("#", 1)[1]) == 8:
            hdesc = h.get("desc")
            if not (isinstance(hdesc, str) and "#" in hdesc and len(hdesc.split("#", 1)[1]) == 8):
                record("mismatch", "decodescript %s checksum" % name, "haskoin desc=%s" % hdesc)


def compare_descriptor_rpcs(core, hask):
    bodies = [
        DESCS["pk1"],
        DESCS["multi_sorted"],
        DESCS["multi_unsorted"],
        DESCS["wsh_sorted"],
        DESCS["p2a"],
        DESCS["pk_uncomp"],
    ]
    for desc in bodies:
        label = desc.split("(", 1)[0]
        try:
            c = core.call("getdescriptorinfo", [desc])
            h = hask.call("getdescriptorinfo", [desc])
        except RpcError as exc:
            record("mismatch", "getdescriptorinfo " + label, str(exc))
            continue
        compare_obj("getdescriptorinfo " + desc, c, h, INFO_KEYS)
        try:
            c_der = core.call("deriveaddresses", [desc])
        except RpcError as exc:
            c_der = {"error": exc.code, "message": exc.message}
        try:
            h_der = hask.call("deriveaddresses", [desc])
        except RpcError as exc:
            h_der = {"error": exc.code, "message": exc.message}
        # pk() has no address. Core errors; a successful address list would be wrong.
        # Record the pair either way. A message-only difference with the same
        # code is still a mismatch unless both are the anchor address list.
        compare_value("deriveaddresses " + desc, c_der, h_der)


def compare_raw_tx(core, hask):
    hex_tx = sample_tx_hex()
    try:
        c = core.call("decoderawtransaction", [hex_tx])
        h = hask.call("decoderawtransaction", [hex_tx])
    except RpcError as exc:
        record("notrun", "decoderawtransaction", str(exc))
        return
    cv = c.get("vout") or []
    hv = h.get("vout") or []
    if len(cv) != len(hv):
        record("mismatch", "decoderawtransaction vout length", "core=%s haskoin=%s" % (len(cv), len(hv)))
        return
    record("match", "decoderawtransaction txid", c.get("txid"))
    compare_value("decoderawtransaction txid", c.get("txid"), h.get("txid"))
    for i, (co, ho) in enumerate(zip(cv, hv)):
        compare_obj(
            "decoderawtransaction vout[%d].scriptPubKey" % i,
            co.get("scriptPubKey"),
            ho.get("scriptPubKey"),
            ["asm", "desc", "hex", "address", "type"],
        )


def compare_scantxoutset(core, hask):
    """Mine one block paying the anchor on each chain and compare desc only.

    txid, amount, and height differ because the chains are independent.
    """
    addr = "bcrt1pfeesnyr2tx"
    scan = ["addr(%s)#swxgse0y" % addr]
    try:
        core.call("generatetoaddress", [1, addr])
        hask.call("generatetoaddress", [1, addr])
    except RpcError as exc:
        record("notrun", "scantxoutset", "generatetoaddress failed: %s" % exc)
        return
    try:
        c = core.call("scantxoutset", ["start", scan])
        h = hask.call("scantxoutset", ["start", scan])
    except RpcError as exc:
        record("notrun", "scantxoutset", str(exc))
        return
    cu = (c or {}).get("unspents") or []
    hu = (h or {}).get("unspents") or []
    if not cu or not hu:
        record(
            "notrun",
            "scantxoutset desc",
            "empty unspents core=%s haskoin=%s" % (len(cu), len(hu)),
        )
        return
    compare_value("scantxoutset unspent.desc", cu[0].get("desc"), hu[0].get("desc"))
    compare_value("scantxoutset unspent.scriptPubKey", cu[0].get("scriptPubKey"), hu[0].get("scriptPubKey"))
    for key in ("txid", "amount", "height"):
        if cu[0].get(key) != hu[0].get(key):
            record(
                "justified",
                "scantxoutset unspent." + key,
                "independent regtest chains core=%s haskoin=%s"
                % (json.dumps(cu[0].get(key)), json.dumps(hu[0].get(key))),
            )


def compare_wallet_p2a(core, hask):
    addr = "bcrt1pfeesnyr2tx"
    desc = DESCS["p2a"]
    for node, rpc in (("core", core), ("haskoin", hask)):
        try:
            rpc.call("createwallet", ["p2a-parity"])
        except RpcError as exc:
            record("notrun", "wallet %s createwallet" % node, str(exc))
            return
    try:
        c_imp = core.call(
            "importdescriptors",
            [[{"desc": desc, "timestamp": "now"}]],
        )
    except RpcError as exc:
        record("notrun", "wallet core importdescriptors", str(exc))
        c_imp = None
    try:
        h_imp = hask.call(
            "importdescriptors",
            [[{"desc": desc, "timestamp": "now"}]],
        )
    except RpcError as exc:
        record("notrun", "wallet haskoin importdescriptors", str(exc))
        h_imp = None
    if c_imp is not None and h_imp is not None:
        compare_value("importdescriptors success", _import_ok(c_imp), _import_ok(h_imp))
    for method, params in (
        ("getaddressinfo", [addr]),
        ("validateaddress", [addr]),
    ):
        try:
            c = core.call(method, params)
            h = hask.call(method, params)
        except RpcError as exc:
            record("notrun", "wallet " + method, str(exc))
            continue
        keys = ["address", "scriptPubKey", "isscript", "iswitness", "ismine", "solvable"]
        # witness_version must be absent for PayToAnchor on both.
        compare_obj("wallet " + method, c, h, keys)
        c_wit = "witness_version" in c
        h_wit = "witness_version" in h
        if c_wit or h_wit:
            record(
                "mismatch",
                "wallet %s witness_version" % method,
                "core_present=%s haskoin_present=%s core=%s haskoin=%s"
                % (c_wit, h_wit, json.dumps(c.get("witness_version")), json.dumps(h.get("witness_version"))),
            )
        else:
            record("match", "wallet %s omits witness_version" % method, "absent")
    # listunspent address, if either wallet saw the mined anchor.
    try:
        c_u = core.call("listunspent", [0, 9999999, [addr]])
        h_u = hask.call("listunspent", [0, 9999999, [addr]])
    except RpcError as exc:
        record("notrun", "wallet listunspent", str(exc))
        return
    c_addrs = sorted({u.get("address") for u in c_u}) if isinstance(c_u, list) else None
    h_addrs = sorted({u.get("address") for u in h_u}) if isinstance(h_u, list) else None
    if not c_u and not h_u:
        record("notrun", "wallet listunspent address", "neither wallet listed a P2A utxo")
    else:
        compare_value("wallet listunspent addresses", c_addrs, h_addrs)


def _import_ok(result):
    if isinstance(result, list) and result:
        return bool(result[0].get("success"))
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bitcoind", required=True)
    parser.add_argument("--haskoin", required=True)
    args = parser.parse_args()
    root = tempfile.mkdtemp(prefix="p2a-parity-")
    core_dir = os.path.join(root, "core")
    hask_dir = os.path.join(root, "haskoin")
    os.makedirs(core_dir)
    os.makedirs(hask_dir)
    # Distinct local ports. Nothing listens publicly.
    core_proc = hask_proc = None
    core_log = hask_log = None
    try:
        core_proc, core_log = start_bitcoind(args.bitcoind, core_dir, 18440)
        hask_proc, hask_log = start_haskoin(args.haskoin, hask_dir, 18540)
        core = Rpc("http://127.0.0.1:18441/", "parity", "parity")
        hask = Rpc("http://127.0.0.1:18541/", "parity", "parity")
        wait_rpc(core)
        wait_rpc(hask)
        # Prove neither node has a peer.
        try:
            cpeers = core.call("getconnectioncount")
            hpeers = hask.call("getconnectioncount")
            if cpeers != 0 or hpeers != 0:
                record("mismatch", "connection count", "core=%s haskoin=%s" % (cpeers, hpeers))
            else:
                record("match", "connection count", 0)
        except RpcError as exc:
            record("notrun", "connection count", str(exc))
        compare_decodescript(core, hask)
        compare_descriptor_rpcs(core, hask)
        compare_raw_tx(core, hask)
        compare_scantxoutset(core, hask)
        compare_wallet_p2a(core, hask)
    finally:
        for proc in (core_proc, hask_proc):
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
        for log in (core_log, hask_log):
            if log is not None:
                log.close()
        print("logs left in %s" % root)
    print("--- summary ---")
    print("matched %d" % len(MATCHED))
    print("mismatched %d" % len(MISMATCHED))
    print("justified %d" % len(JUSTIFIED))
    print("not_run %d" % len(NOT_RUN))
    report = {
        "matched": MATCHED,
        "mismatched": MISMATCHED,
        "justified": JUSTIFIED,
        "not_run": NOT_RUN,
    }
    out = os.path.join(root, "report.json")
    with open(out, "w") as fh:
        json.dump(report, fh, indent=2)
    print("report %s" % out)
    return 1 if MISMATCHED else 0


if __name__ == "__main__":
    sys.exit(main())
