#!/usr/bin/env python3
"""What a snapshot-started haskoin tells peers and RPC clients about the
blocks it does not have.

A node started with --load-snapshot holds the UTXO set at the snapshot base
but none of the block bodies at or below it. Bitcoin Core v31.1, measured on
regtest after loadtxoutset (history not downloaded):

  * localservices / the services field of the version message it sends:
    NODE_NETWORK is cleared, NODE_NETWORK_LIMITED kept (0xc08 with BIP-324 on),
    and it stays cleared after a restart
    (rpc/blockchain.cpp loadtxoutset RemoveLocalServices(NODE_NETWORK);
    init.cpp only sets NODE_NETWORK when there is no historical chainstate).
  * getblock of a block whose header is known but whose body was never
    downloaded (including the snapshot base itself), at verbosity 0/1/2:
    -1 "Block not available (not fully downloaded)"
    (rpc/blockchain.cpp CheckBlockDataAvailability; "pruned data" only when
    the node really pruned). An unknown hash stays -5 "Block not found".
  * getblockheader of such a block works (printed, not asserted here: haskoin
    answers -5 for a header learned over submitheader -- a separate gap).
  * getblockchaininfo: pruned false, no pruneheight.
  * getchainstates: the chainstate carries snapshot_blockhash and
    validated false.

A node synced from genesis keeps advertising NODE_NETWORK (control).

The fixture (fixtures/utxo-299.dat + fixtures/headers-1-299.hex) is the
deterministic chain Core's feature_assumeutxo.py builds; its base matches the
regtest assumeutxo entry at height 299 that haskoin carries.

Usage:
  python3 test/regtest/snapshot_history_floor.py --binary PATH [--workdir DIR]

Each test prints PASS/FAIL with its name. Exit status 0 iff all pass.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
SNAPSHOT = HERE / "fixtures" / "utxo-299.dat"
HEADERS = HERE / "fixtures" / "headers-1-299.hex"
BASE_HEIGHT = 299
BASE_HASH = "7cc695046fec709f8c9394b6f928f81e81fd3ac20977bb68760fa1faa7916ea2"
REGTEST_MAGIC = bytes.fromhex("fabfb5da")

NODE_NETWORK = 0x1
NODE_WITNESS = 0x8
NODE_NETWORK_LIMITED = 0x400
NODE_P2P_V2 = 0x800

NOT_DOWNLOADED = "Block not available (not fully downloaded)"
RPC_USER = "floor"
RPC_PASS = "floor"


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def dsha256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def header_hash(hex80: str) -> str:
    return dsha256(bytes.fromhex(hex80))[::-1].hex()


class RpcError(Exception):
    def __init__(self, code, message):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class Node:
    def __init__(self, binary: Path, datadir: Path, snapshot: Path | None,
                 extra: list[str] | None = None):
        self.extra = extra or []
        self.binary = binary
        self.datadir = datadir
        self.snapshot = snapshot
        self.rpcport = free_port()
        self.p2pport = free_port()
        self.proc: subprocess.Popen | None = None
        self.log = datadir.parent / (datadir.name + ".log")

    def start(self, load_snapshot: bool) -> None:
        args = [
            str(self.binary),
            f"--datadir={self.datadir}",
            "--network=Regtest",
            "node",
            f"--rpcport={self.rpcport}",
            f"--rpcuser={RPC_USER}",
            f"--rpcpassword={RPC_PASS}",
            f"--port={self.p2pport}",
            "--listen=True",
            "--bind=127.0.0.1",
            "--nodnsseed",
            "--discover=False",
            "--connect=127.0.0.1:1",
            "--metricsport=0",
            "--printtoconsole",
        ]
        if load_snapshot:
            args.append(f"--load-snapshot={self.snapshot}")
        args += self.extra
        env = dict(os.environ)
        # BIP-324 is on by default; keep the test independent of the caller.
        env.pop("HASKOIN_BIP324_V2", None)
        env.pop("HASKOIN_BIP324_V2_OUTBOUND", None)
        logf = open(self.log, "ab")
        logf.write(f"\n==== start {' '.join(args)}\n".encode())
        logf.flush()
        self.proc = subprocess.Popen(args, stdout=logf, stderr=subprocess.STDOUT, env=env)
        deadline = time.time() + 120
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"haskoin exited with {self.proc.returncode}; see {self.log}")
            try:
                self.rpc("getblockcount")
                return
            except (OSError, RpcError, urllib.error.URLError):
                time.sleep(0.5)
        raise RuntimeError(f"haskoin RPC did not come up; see {self.log}")

    def stop(self) -> None:
        if self.proc is None or self.proc.poll() is not None:
            return
        try:
            self.rpc("stop")
        except Exception:
            pass
        try:
            self.proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()

    def rpc(self, method: str, *params):
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method,
                           "params": list(params)}).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{self.rpcport}/", data=body,
                                     method="POST")
        tok = base64.b64encode(f"{RPC_USER}:{RPC_PASS}".encode()).decode()
        req.add_header("Authorization", "Basic " + tok)
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                payload = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            payload = json.loads(e.read().decode())
        if payload.get("error"):
            raise RpcError(payload["error"].get("code"), payload["error"].get("message"))
        return payload["result"]

    def rpc_error(self, method: str, *params) -> tuple:
        try:
            r = self.rpc(method, *params)
        except RpcError as e:
            return (e.code, e.message)
        return ("no error", r)

    def localservices(self) -> int:
        return int(self.rpc("getnetworkinfo")["localservices"], 16)

    def version_services(self) -> int:
        """Connect inbound over v1 and return the services field of the
        version message the node sends back."""
        def msg(cmd: bytes, payload: bytes) -> bytes:
            return (REGTEST_MAGIC + cmd.ljust(12, b"\0") + struct.pack("<I", len(payload))
                    + dsha256(payload)[:4] + payload)

        def netaddr() -> bytes:
            return struct.pack("<Q", 0) + bytes(10) + b"\xff\xff" + bytes([127, 0, 0, 1]) \
                + struct.pack(">H", 0)

        ua = b"/floor-test/"
        payload = (struct.pack("<iQq", 70016, 0, int(time.time())) + netaddr() + netaddr()
                   + struct.pack("<Q", 0x5eed) + bytes([len(ua)]) + ua
                   + struct.pack("<i", 0) + b"\x00")
        with socket.create_connection(("127.0.0.1", self.p2pport), timeout=30) as s:
            s.sendall(msg(b"version", payload))
            buf = b""
            deadline = time.time() + 30
            while time.time() < deadline:
                while len(buf) >= 24:
                    if buf[:4] != REGTEST_MAGIC:
                        raise RuntimeError(f"bad magic from node: {buf[:4].hex()}")
                    cmd = buf[4:16].rstrip(b"\0")
                    ln = struct.unpack("<I", buf[16:20])[0]
                    if len(buf) < 24 + ln:
                        break
                    body = buf[24:24 + ln]
                    buf = buf[24 + ln:]
                    if cmd == b"version":
                        return struct.unpack("<Q", body[4:12])[0]
                chunk = s.recv(65536)
                if not chunk:
                    raise RuntimeError("node closed the connection before sending version")
                buf += chunk
        raise RuntimeError("no version message from node")


def feed_headers(node: Node) -> list[str]:
    hashes = []
    for line in HEADERS.read_text().split():
        r = node.rpc("submitheader", line)
        if r is not None:
            raise RuntimeError(f"submitheader returned {r!r}")
        hashes.append(header_hash(line))
    return hashes


RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, cond: bool, detail: str) -> None:
    RESULTS.append((name, cond, detail))
    print(f"{'PASS' if cond else 'FAIL'} {name}: {detail}", flush=True)


def run(binary: Path, workdir: Path) -> None:
    # ---- control: a node that never loaded a snapshot ------------------
    genesis = Node(binary, workdir / "genesis", None)
    genesis.start(load_snapshot=False)
    try:
        ls = genesis.localservices()
        check("test_genesis_node_localservices_has_network",
              ls & NODE_NETWORK != 0 and ls & NODE_NETWORK_LIMITED != 0,
              f"localservices=0x{ls:x}")
        vs = genesis.version_services()
        check("test_genesis_node_version_services_has_network",
              vs & NODE_NETWORK != 0, f"version.services=0x{vs:x}")
    finally:
        genesis.stop()

    # ---- snapshot-started node ----------------------------------------
    snap = Node(binary, workdir / "snapshot", SNAPSHOT)
    snap.start(load_snapshot=True)
    try:
        # haskoin rebuilds the header chain genesis->base after the import
        # (normally over P2P); ferry it in over submitheader.
        hashes = feed_headers(snap)
        count = snap.rpc("getblockcount")
        if count != BASE_HEIGHT:
            raise RuntimeError(f"snapshot did not load: getblockcount={count}")

        ls = snap.localservices()
        names = snap.rpc("getnetworkinfo")["localservicesnames"]
        check("test_snapshot_node_localservices_drops_network",
              ls == NODE_WITNESS | NODE_NETWORK_LIMITED | NODE_P2P_V2 and "NETWORK" not in names,
              f"localservices=0x{ls:x} names={names} (Core: 0xc08)")
        vs = snap.version_services()
        check("test_snapshot_node_version_services_drops_network",
              vs & NODE_NETWORK == 0 and vs & NODE_NETWORK_LIMITED != 0 and vs == ls,
              f"version.services=0x{vs:x} localservices=0x{ls:x}")

        block1, base = hashes[0], hashes[-1]
        if base != BASE_HASH:
            raise RuntimeError(f"fixture header 299 hashes to {base}, expected {BASE_HASH}")
        for name, h in (("block1", block1), ("base", base)):
            got = [snap.rpc_error("getblock", h, v) for v in (0, 1, 2)]
            check(f"test_snapshot_getblock_{name}_not_fully_downloaded",
                  all(g == (-1, NOT_DOWNLOADED) for g in got),
                  f"verbosity 0/1/2 -> {got}")
        # Core serves getblockheader for these blocks. haskoin answers -5 for
        # a header learned over submitheader below the base; that is a
        # separate getblockheader gap outside this test's scope, so it is
        # printed, not asserted.
        print(f"INFO getblockheader(block1): {snap.rpc_error('getblockheader', block1)}",
              flush=True)
        unknown = snap.rpc_error("getblock", "00" * 32)
        check("test_snapshot_getblock_unknown_hash_not_found",
              unknown == (-5, "Block not found"), f"{unknown}")

        bci = snap.rpc("getblockchaininfo")
        check("test_snapshot_blockchaininfo_not_pruned",
              bci.get("pruned") is False and "pruneheight" not in bci,
              f"pruned={bci.get('pruned')} pruneheight={bci.get('pruneheight', '<absent>')}")

        cs = snap.rpc("getchainstates")["chainstates"]
        active = cs[-1]
        check("test_snapshot_getchainstates_unvalidated_snapshot",
              active.get("snapshot_blockhash") == BASE_HASH and active.get("validated") is False,
              f"snapshot_blockhash={active.get('snapshot_blockhash')} "
              f"validated={active.get('validated')}")
    finally:
        snap.stop()

    # ---- restart: still no history below the base ----------------------
    snap.start(load_snapshot=False)
    try:
        ls = snap.localservices()
        vs = snap.version_services()
        check("test_snapshot_node_restart_keeps_network_off",
              ls & NODE_NETWORK == 0 and vs & NODE_NETWORK == 0,
              f"localservices=0x{ls:x} version.services=0x{vs:x} (Core: 0xc08)")
    finally:
        snap.stop()

    # ---- snapshot + prune: blocks below the base were never held, so they
    # are "not fully downloaded", not "pruned data" (Core IsBlockPruned needs
    # nTx > 0, which a never-downloaded block does not have). -------------
    pruned = Node(binary, workdir / "snapshot-prune", SNAPSHOT, extra=["--prune=1"])
    pruned.start(load_snapshot=True)
    try:
        hashes = feed_headers(pruned)
        bci = pruned.rpc("getblockchaininfo")
        if bci.get("pruned") is not True:
            raise RuntimeError(f"--prune=1 did not enable prune mode: {bci.get('pruned')}")
        got = [pruned.rpc_error("getblock", h, 1) for h in (hashes[0], hashes[-1])]
        check("test_snapshot_prune_getblock_below_base_not_fully_downloaded",
              all(g == (-1, NOT_DOWNLOADED) for g in got),
              f"block1/base -> {got}")
        ls = pruned.localservices()
        check("test_snapshot_prune_localservices_drops_network",
              ls & NODE_NETWORK == 0, f"localservices=0x{ls:x}")
    finally:
        pruned.stop()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default=os.environ.get("HASKOIN_BIN"),
                    help="haskoin executable (or HASKOIN_BIN)")
    ap.add_argument("--workdir", help="scratch dir (kept); default: a fresh temp dir, removed")
    a = ap.parse_args()
    if not a.binary:
        ap.error("--binary or HASKOIN_BIN is required")
    binary = Path(a.binary).resolve()
    if a.workdir:
        workdir = Path(a.workdir).resolve()
        if workdir.exists():
            shutil.rmtree(workdir)
        workdir.mkdir(parents=True)
    else:
        workdir = Path(tempfile.mkdtemp(prefix="haskoin-floor-"))
    print(f"binary: {binary}\nworkdir: {workdir}", flush=True)
    try:
        run(binary, workdir)
    except Exception:
        traceback.print_exc()
        RESULTS.append(("harness", False, "aborted"))
    finally:
        if not a.workdir:
            shutil.rmtree(workdir, ignore_errors=True)
    failed = [n for n, ok, _ in RESULTS if not ok]
    print(f"\n{len(RESULTS)} checks, {len(RESULTS) - len(failed)} passed, {len(failed)} failed")
    for n in failed:
        print(f"  FAILED: {n}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
