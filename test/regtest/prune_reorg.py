#!/usr/bin/env python3
"""A pruned node prunes, keeps 288 blocks, and still reorgs 288 deep (regtest).

Runs the same steps against haskoin or Bitcoin Core v31.1:

  1. start in manual prune mode (haskoin --prune=1; Core -prune=1
     -fastprune, so Core's 64 KiB test block files can be pruned at all),
     mine 1100 blocks;
  2. pruneblockchain(1100): clamped to tip-288 = 812.  Core prunes whole
     block files, so it answers the last height of the last whole file at or
     below 812; haskoin prunes per block and answers 812;
  3. getblock of a pruned block: -1 "Block not available (pruned data)";
     block 813 is still served; getblockchaininfo pruneheight = answer + 1;
  4. 288-block reorg: invalidateblock(813) -> tip 812, mine 289 blocks on
     812 -> tip 1101 on the new branch; reconsiderblock(813) leaves the tip
     there (288 < 289 blocks of work);
  5. restart with prune: pruneheight is kept;
  6. restart WITHOUT prune: refused ("You need to rebuild the database
     using -reindex to go back to unpruned mode");
  7. restart with prune and -txindex: refused ("Prune mode is incompatible
     with -txindex.").

Usage:
  python3 test/regtest/prune_reorg.py --impl haskoin --binary PATH [--workdir DIR]
  python3 test/regtest/prune_reorg.py --impl core --binary PATH/bitcoind

Each step prints PASS/FAIL with its name. Exit status 0 iff all pass.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

RPC_USER = "prune"
RPC_PASS = "prune"
ADDR = "bcrt1qlfglp2xalgefyyy8hdh3h6wg8ceqn006jdyp89"
# The new branch pays elsewhere: a block mined on 812 to ADDR in the same
# second as the invalidated 813 would BE that block (duplicate-invalid).
ADDR2 = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
CHAIN = 1100
KEEP = 288

FAILS: list[str] = []


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class RpcError(Exception):
    def __init__(self, code, message):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class Node:
    def __init__(self, impl: str, binary: Path, datadir: Path):
        self.impl = impl
        self.binary = binary
        self.datadir = datadir
        self.rpcport = free_port()
        self.p2pport = free_port()
        self.proc: subprocess.Popen | None = None
        self.log = datadir.parent / (datadir.name + ".log")
        datadir.mkdir(parents=True, exist_ok=True)

    def args(self, prune: bool, txindex: bool) -> list[str]:
        if self.impl == "haskoin":
            a = [str(self.binary), f"--datadir={self.datadir}", "--network=Regtest",
                 "node", f"--rpcport={self.rpcport}", f"--rpcuser={RPC_USER}",
                 f"--rpcpassword={RPC_PASS}", f"--port={self.p2pport}",
                 "--listen=False", "--nodnsseed", "--discover=False",
                 "--connect=127.0.0.1:1", "--metricsport=0", "--printtoconsole"]
            if prune:
                a.append("--prune=1")
            if txindex:
                a.append("--txindex")
        else:
            a = [str(self.binary), "-regtest", f"-datadir={self.datadir}",
                 f"-rpcport={self.rpcport}", f"-rpcuser={RPC_USER}",
                 f"-rpcpassword={RPC_PASS}", f"-port={self.p2pport}", "-listen=0",
                 "-connect=0", "-dnsseed=0", "-printtoconsole", "-fastprune"]
            if prune:
                a.append("-prune=1")
            if txindex:
                a.append("-txindex=1")
        return a

    def start(self, prune: bool = True, txindex: bool = False,
              expect_fail: bool = False) -> int | None:
        args = self.args(prune, txindex)
        logf = open(self.log, "ab")
        logf.write(f"\n==== start {' '.join(args)}\n".encode())
        logf.flush()
        self.proc = subprocess.Popen(args, stdout=logf, stderr=subprocess.STDOUT)
        deadline = time.time() + 120
        while time.time() < deadline:
            rc = self.proc.poll()
            if rc is not None:
                if expect_fail:
                    return rc
                raise RuntimeError(f"{self.impl} exited with {rc}; see {self.log}")
            if not expect_fail:
                try:
                    self.rpc("getblockcount")
                    return None
                except (OSError, RpcError, urllib.error.URLError):
                    pass
            time.sleep(0.5)
        if expect_fail:
            self.stop()
            return None
        raise RuntimeError(f"{self.impl} RPC did not come up; see {self.log}")

    def stop(self) -> None:
        if self.proc is None or self.proc.poll() is not None:
            return
        try:
            self.rpc("stop")
        except Exception:
            pass
        try:
            self.proc.wait(timeout=90)
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
            with urllib.request.urlopen(req, timeout=600) as resp:
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
        return ("no error", str(r)[:80])

    def mine(self, n: int, addr: str = ADDR) -> list[str]:
        out: list[str] = []
        while n > 0:
            k = min(n, 100)
            out += self.rpc("generatetoaddress", k, addr)
            n -= k
        return out

    def log_tail(self, nbytes: int = 4000) -> str:
        data = self.log.read_bytes()
        return data[-nbytes:].decode(errors="replace")


def check(name: str, cond: bool, detail: str) -> None:
    print(("PASS " if cond else "FAIL ") + name + " -- " + detail, flush=True)
    if not cond:
        FAILS.append(name)


def run(impl: str, binary: Path, workdir: Path) -> None:
    node = Node(impl, binary, workdir / f"{impl}-pruned")
    node.start(prune=True)
    try:
        hashes = [None] + node.mine(CHAIN)   # hashes[h] = block at height h
        check("mined", node.rpc("getblockcount") == CHAIN, f"tip {node.rpc('getblockcount')}")
        info0 = node.rpc("getblockchaininfo")
        print(f"     size_on_disk before prune: {info0.get('size_on_disk')}", flush=True)

        r = node.rpc("pruneblockchain", CHAIN)
        if impl == "haskoin":
            ok = r == CHAIN - KEEP
        else:
            ok = isinstance(r, int) and 0 < r <= CHAIN - KEEP
        check("pruneblockchain(tip) clamps to tip-288", ok,
              f"answered {r} (tip-288 = {CHAIN - KEEP})")
        pruned_to = r if isinstance(r, int) else 0

        e1 = node.rpc_error("getblock", hashes[1])
        check("getblock(1) is pruned data", e1 == (-1, "Block not available (pruned data)"), str(e1))
        if pruned_to > 1:
            e2 = node.rpc_error("getblock", hashes[pruned_to])
            check("getblock(last pruned) is pruned data",
                  e2 == (-1, "Block not available (pruned data)"), f"height {pruned_to}: {e2}")
        b813 = node.rpc_error("getblock", hashes[CHAIN - KEEP + 1])
        check("getblock(tip-287) is still served", b813[0] == "no error", str(b813))

        svc = int(node.rpc("getnetworkinfo")["localservices"], 16)
        check("pruned node does not advertise NODE_NETWORK, keeps NODE_NETWORK_LIMITED",
              svc & 0x1 == 0 and svc & 0x400 == 0x400, f"localservices=0x{svc:x}")

        info = node.rpc("getblockchaininfo")
        check("getblockchaininfo pruned + pruneheight",
              info.get("pruned") is True and info.get("pruneheight") == pruned_to + 1,
              f"pruned={info.get('pruned')} pruneheight={info.get('pruneheight')}")
        print(f"     size_on_disk after prune: {info.get('size_on_disk')}", flush=True)

        # 288-block reorg on the pruned node.
        fork = CHAIN - KEEP + 1          # 813: first block above the prune window
        node.rpc("invalidateblock", hashes[fork])
        c = node.rpc("getblockcount")
        check("invalidateblock(813) disconnects 288 blocks", c == fork - 1, f"tip {c}")
        new = node.mine(KEEP + 1, ADDR2)
        best = node.rpc("getbestblockhash")
        check("289 new blocks on 812 become the tip",
              best == new[-1] and node.rpc("getblockcount") == CHAIN + 1,
              f"tip {node.rpc('getblockcount')} best==new[-1] {best == new[-1]}")
        node.rpc("reconsiderblock", hashes[fork])
        best2 = node.rpc("getbestblockhash")
        check("reconsiderblock(813) keeps the heavier new branch", best2 == new[-1],
              f"best==new[-1] {best2 == new[-1]}")
        tips = node.rpc("getchaintips")
        old_tip = [t for t in tips if t["hash"] == hashes[CHAIN]]
        check("old 1100 tip is a 288-block valid fork",
              len(old_tip) == 1 and old_tip[0]["branchlen"] == KEEP,
              json.dumps(old_tip))
    finally:
        node.stop()

    # Restart keeps the prune height, and the connected tip.
    log_before = node.log.stat().st_size
    node.start(prune=True)
    try:
        boot = node.log.read_bytes()[log_before:].decode(errors="replace")
        low = [ln for ln in boot.splitlines()
               if "connected-block tip is height" in ln
               and not ln.split("connected-block tip is height ")[1].startswith(f"{CHAIN + 1},")]
        check("restart: boot reconciliation keeps the connected tip (no rewind to a pruned height)",
              not low, low[0][:160] if low else "no low connected-tip line")
        cnt = node.rpc("getblockcount")
        check("restart: getblockcount is the tip", cnt == CHAIN + 1, f"tip {cnt}")
        info = node.rpc("getblockchaininfo")
        check("restart keeps pruneheight", info.get("pruneheight") == pruned_to + 1,
              f"pruneheight={info.get('pruneheight')}")
        e1 = node.rpc_error("getblock", hashes[1])
        check("restart: getblock(1) still pruned data",
              e1 == (-1, "Block not available (pruned data)"), str(e1))
    finally:
        node.stop()

    rc = node.start(prune=False, expect_fail=True)
    tail = node.log_tail()
    check("restart without prune is refused",
          rc not in (None, 0) and "go back to unpruned mode" in tail, f"rc={rc}")

    rc = node.start(prune=True, txindex=True, expect_fail=True)
    tail = node.log_tail()
    check("prune with -txindex is refused",
          rc not in (None, 0) and "Prune mode is incompatible with -txindex." in tail,
          f"rc={rc}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--impl", choices=["haskoin", "core"], required=True)
    ap.add_argument("--binary", required=True, type=Path)
    ap.add_argument("--workdir", type=Path)
    ap.add_argument("--keep", action="store_true")
    a = ap.parse_args()
    workdir = a.workdir or Path(tempfile.mkdtemp(prefix="haskoin-prune-reorg-"))
    workdir.mkdir(parents=True, exist_ok=True)
    try:
        run(a.impl, a.binary.resolve(), workdir)
    except Exception as e:  # a crash is a failure, not a pass
        print(f"FAIL run -- {type(e).__name__}: {e}", flush=True)
        FAILS.append("run")
    finally:
        if not a.keep and a.workdir is None:
            shutil.rmtree(workdir, ignore_errors=True)
    print(f"{a.impl}: {'ALL PASS' if not FAILS else 'FAILED: ' + ', '.join(FAILS)}", flush=True)
    return 0 if not FAILS else 1


if __name__ == "__main__":
    sys.exit(main())
