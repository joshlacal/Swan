#!/usr/bin/env python3
"""End-to-end proof of the WAL-shipping durability model against a real SQLite.

1. Start swan-vault on a temp root.
2. Create a WAL-mode SQLite database with autocheckpoint disabled, upload the
   empty image as the snapshot.
3. Commit N transactions; after each COMMIT read the new frames straight out of
   the -wal file (exactly what the Swift shipper on the Apple TV will do) and
   POST them as one segment. Include a mid-run wal_checkpoint(TRUNCATE) so the
   salt/reset path is exercised.
4. Ask the vault to compact, download the snapshot, open it with SQLite,
   run integrity_check and compare every row against the live database.
5. Negative checks: a stale generation is refused; a corrupted segment is
   refused; a replayed segment is idempotent.

Usage: wal_ship_selftest.py [path-to-swan-vault-binary]
"""
import json
import os
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

WAL_HEADER = 32
FRAME_HEADER = 24


def wal_checksum(big_endian, data, seed):
    s0, s1 = seed
    fmt = ">II" if big_endian else "<II"
    for i in range(0, len(data) - len(data) % 8, 8):
        x, y = struct.unpack_from(fmt, data, i)
        s0 = (s0 + x + s1) & 0xFFFFFFFF
        s1 = (s1 + y + s0) & 0xFFFFFFFF
    return s0, s1


class Shipper:
    """Tracks what has been shipped for one database's -wal file."""

    def __init__(self, base, token, name, gen, db_path):
        self.base, self.token, self.name, self.gen = base, token, name, gen
        self.wal_path = db_path + "-wal"
        self.salt = None
        self.next_frame = 1
        self.seq = 1

    def request(self, method, path, body=None, headers=None):
        req = urllib.request.Request(f"{self.base}{path}", data=body, method=method)
        req.add_header("Authorization", f"Bearer {self.token}")
        for k, v in (headers or {}).items():
            req.add_header(k, str(v))
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def ship(self):
        with open(self.wal_path, "rb") as f:
            wal = f.read()
        if len(wal) < WAL_HEADER:
            return None
        magic, version, page_size, ckpt, salt = struct.unpack(">IIII8s", wal[:24])
        big_endian = magic == 0x377F0683
        header_checksum = wal_checksum(big_endian, wal[:24], (0, 0))
        assert header_checksum == struct.unpack(">II", wal[24:32]), "WAL header checksum mismatch: algorithm wrong"
        reset = salt != self.salt
        if reset:
            self.salt = salt
            self.next_frame = 1
        frame_len = FRAME_HEADER + page_size
        total = (len(wal) - WAL_HEADER) // frame_len
        # Only ship frames that carry the current salt and stop at the last commit frame.
        last_commit = None
        for i in range(self.next_frame - 1, total):
            off = WAL_HEADER + i * frame_len
            _, commit, fsalt = struct.unpack_from(">II8s", wal, off)
            if fsalt != salt:
                break
            if commit:
                last_commit = i + 1
        if last_commit is None or last_commit < self.next_frame:
            return None
        start = WAL_HEADER + (self.next_frame - 1) * frame_len
        end = WAL_HEADER + last_commit * frame_len
        headers = {
            "X-Wal-Seq": self.seq, "X-Wal-Page-Size": page_size, "X-Wal-First-Frame": self.next_frame,
            "X-Wal-Frame-Count": last_commit - self.next_frame + 1, "X-Wal-Salt": salt.hex(),
            "X-Wal-Big-Endian": 1 if big_endian else 0,
        }
        if reset:
            headers["X-Wal-Reset"] = 1
            headers["X-Wal-Header-Checksum"] = f"{header_checksum[0]},{header_checksum[1]}"
        status, body = self.request("POST", f"/v1/db/{self.name}/wal?gen={self.gen}", wal[start:end], headers)
        if status != 200:
            raise SystemExit(f"segment {self.seq} rejected: {status} {body!r}")
        self.seq += 1
        self.next_frame = last_commit + 1
        return json.loads(body)


def main():
    binary = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "target", "release", "swan-vault")
    root = tempfile.mkdtemp(prefix="swan-vault-test-")
    token = "t" * 48
    token_path = os.path.join(root, "token")
    with open(token_path, "w") as f:
        f.write(token)
    port = 17180
    proc = subprocess.Popen([binary, "--root", os.path.join(root, "vault"), "--listen", f"127.0.0.1:{port}", "--token-file", token_path])
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(50):
            try:
                urllib.request.urlopen(f"{base}/v1/health", timeout=1).read()
                break
            except Exception:
                time.sleep(0.1)
        db_path = os.path.join(root, "live.sqlite")
        con = sqlite3.connect(db_path, isolation_level=None)
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=NORMAL")
        con.execute("PRAGMA wal_autocheckpoint=0")
        con.execute("CREATE TABLE records(id INTEGER PRIMARY KEY, payload BLOB NOT NULL)")
        con.execute("PRAGMA wal_checkpoint(TRUNCATE)")

        # Lease + snapshot of the checkpointed image.
        req = urllib.request.Request(f"{base}/v1/lease", data=json.dumps({"holder": "selftest"}).encode(), method="POST")
        req.add_header("Authorization", f"Bearer {token}")
        gen = json.loads(urllib.request.urlopen(req).read())["generation"]
        shipper = Shipper(base, token, "live", gen, db_path)
        with open(db_path, "rb") as f:
            status, body = shipper.request("PUT", f"/v1/db/live/snapshot?gen={gen}", f.read())
        assert status == 200, (status, body)

        # Stale generation must be refused before anything is written.
        status, _ = shipper.request("PUT", f"/v1/db/live/snapshot?gen={gen + 5}", b"SQLite format 3\0" + b"\0" * 200)
        assert status == 409, status

        shipped = 0
        for i in range(1, 41):
            con.execute("BEGIN IMMEDIATE")
            con.execute("INSERT INTO records(payload) VALUES (?)", (os.urandom(3000 + i * 50),))
            if i % 7 == 0:
                con.execute("DELETE FROM records WHERE id = ?", (i - 3,))
            con.execute("COMMIT")
            if shipper.ship():
                shipped += 1
            if i == 20:
                # Reader-free moment: truncate the WAL, salt changes, next ship is a reset.
                res = con.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
                assert res[0] == 0, f"checkpoint blocked: {res}"
        assert shipped == 40, shipped

        # Replay of the last segment must be idempotent.
        shipper.seq -= 1
        with open(db_path + "-wal", "rb") as f:
            wal = f.read()
        page_size = struct.unpack(">I", wal[8:12])[0]
        frame_len = FRAME_HEADER + page_size
        total = (len(wal) - WAL_HEADER) // frame_len
        manifest = json.loads(shipper.request("GET", "/v1/db/live/manifest")[1])
        last = manifest["segments"][-1]
        start = WAL_HEADER + (last["first_frame"] - 1) * frame_len
        end = start + last["frames"] * frame_len
        headers = {"X-Wal-Seq": last["seq"], "X-Wal-Page-Size": page_size, "X-Wal-First-Frame": last["first_frame"],
                   "X-Wal-Frame-Count": last["frames"], "X-Wal-Salt": last["salt"]}
        status, _ = shipper.request("POST", f"/v1/db/live/wal?gen={gen}", wal[start:end], headers)
        assert status == 200, status
        # Corrupt replay with the same seq must be refused, not overwrite.
        bad = bytearray(wal[start:end]); bad[FRAME_HEADER + 5] ^= 0xFF
        status, _ = shipper.request("POST", f"/v1/db/live/wal?gen={gen}", bytes(bad), headers)
        assert status in (409, 422), status
        del total

        # Compact remotely and verify the restored image equals the live DB.
        status, body = shipper.request("POST", f"/v1/db/live/compact?gen={gen}")
        assert status == 200, (status, body)
        status, image = shipper.request("GET", "/v1/db/live/snapshot")
        assert status == 200
        restored_path = os.path.join(root, "restored.sqlite")
        with open(restored_path, "wb") as f:
            f.write(image)
        r = sqlite3.connect(restored_path)
        assert r.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        live_rows = con.execute("SELECT id, payload FROM records ORDER BY id").fetchall()
        restored_rows = r.execute("SELECT id, payload FROM records ORDER BY id").fetchall()
        assert live_rows == restored_rows, f"row mismatch: {len(live_rows)} vs {len(restored_rows)}"
        assert len(live_rows) == 40 - 5

        # Objects: content addressed, digest verified, idempotent.
        import hashlib
        blob = os.urandom(70000)
        sha = hashlib.sha256(blob).hexdigest()
        assert shipper.request("PUT", f"/v1/objects/{sha}?gen={gen}", blob)[0] == 201
        assert shipper.request("PUT", f"/v1/objects/{sha}?gen={gen}", blob)[0] == 200
        assert shipper.request("PUT", f"/v1/objects/{'0' * 64}?gen={gen}", blob)[0] == 422
        assert shipper.request("GET", f"/v1/objects/{sha}")[1] == blob

        # A new lease fences the old writer.
        req = urllib.request.Request(f"{base}/v1/lease", data=json.dumps({"holder": "second-apple-tv"}).encode(), method="POST")
        req.add_header("Authorization", f"Bearer {token}")
        urllib.request.urlopen(req).read()
        status, _ = shipper.request("PUT", f"/v1/objects/{sha}?gen={gen}", blob)
        assert status == 409, status

        # Restart the daemon: manifest and objects must survive.
        proc.terminate(); proc.wait()
        proc = subprocess.Popen([binary, "--root", os.path.join(root, "vault"), "--listen", f"127.0.0.1:{port}", "--token-file", token_path])
        for _ in range(50):
            try:
                urllib.request.urlopen(f"{base}/v1/health", timeout=1).read(); break
            except Exception:
                time.sleep(0.1)
        status, image2 = shipper.request("GET", "/v1/db/live/snapshot")
        assert status == 200 and image2 == image
        print(f"PASS: 40 commits shipped as {manifest['next_seq'] - 1} segments incl. one WAL reset; restored image matches live DB; fencing, digest, replay checks ok")
    finally:
        proc.terminate()
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    main()
