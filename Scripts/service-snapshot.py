#!/usr/bin/env python3
"""Authenticated offline whole-service snapshots; never modifies source databases.

Portable/operator account exports are content transfers. This tool retains the
complete local operational state, including authority policies and durable
queues. Stop the local server before use; this tool never stops any service.
"""
import argparse
import contextlib
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import subprocess
import sys
import uuid

FORMAT = "swan-offline-service-snapshot-v1"
LOCK = ".swan-service.lock"


def secure_regular(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("owner-only regular file required")
    return info


def key(path):
    secure_regular(path)
    value = path.read_bytes()
    if len(value) != 32:
        raise ValueError("integrity key must contain exactly 32 bytes")
    return value


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(65536), b""):
            value.update(chunk)
    return value.hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def tree(root):
    root_info = root.lstat()
    if not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != os.geteuid() or root_info.st_mode & 0o077:
        raise ValueError("unsafe snapshot root")
    entries = []
    for base, dirs, files in os.walk(root, followlinks=False):
        dirs.sort()
        files.sort()
        for name in dirs:
            item = Path(base) / name
            info = item.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise ValueError("snapshot contains an unsafe directory")
        for name in files:
            item = Path(base) / name
            relative = item.relative_to(root).as_posix()
            if relative == LOCK:
                continue
            info = secure_regular(item)
            entries.append((relative, info.st_size, info.st_mtime_ns, info.st_ino))
    return entries


def ensure_offline(root):
    executable = shutil.which("lsof")
    if not executable:
        raise ValueError("lsof is required to verify offline state")
    result = subprocess.run([executable, "-nP", "-F", "pn", "+D", str(root)], capture_output=True, text=True)
    if result.returncode not in (0, 1) or result.stderr.strip():
        raise ValueError("unable to verify offline state")
    pid = None
    for line in result.stdout.splitlines():
        if line.startswith("p"):
            pid = int(line[1:])
        elif line.startswith("n") and pid != os.getpid():
            if line[1:] != str(root / LOCK):
                raise ValueError("source directory is in use; stop the local server first")


@contextlib.contextmanager
def offline_lock(root):
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("owner-only source directory required")
    fd = os.open(root / LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        ensure_offline(root)
        yield
    finally:
        os.close(fd)


def sqlite_check(path):
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as db:
        if db.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
            raise ValueError("SQLite integrity check failed")
        if db.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise ValueError("SQLite foreign-key check failed")


def destination_stage(destination):
    if destination.exists() or destination.is_symlink():
        raise ValueError("destination must be absent")
    if not destination.parent.is_dir():
        raise ValueError("destination parent must exist")
    staging = destination.parent / (destination.name + ".partial-" + uuid.uuid4().hex)
    staging.mkdir(mode=0o700)
    return staging


def snapshot(source, destination, integrity_key, build_id, profile_id):
    if source == destination or source in destination.parents:
        raise ValueError("snapshot must be outside the source directory")
    with offline_lock(source), contextlib.ExitStack() as locks:
        before = tree(source)
        databases = [name for name, *_ in before if name.endswith(".sqlite")]
        if "control.sqlite" not in databases:
            raise ValueError("source is not a complete Swan service directory")
        # Hold every database write lock simultaneously. Old tooling that does
        # not participate in the directory lease cannot write a mixed snapshot.
        for name in databases:
            db = sqlite3.connect(source / name, timeout=0)
            locks.callback(db.close)
            db.execute("BEGIN IMMEDIATE")
        staging = destination_stage(destination)
        data = staging / "data"
        data.mkdir(mode=0o700)
        try:
            entries = []
            for name, *_ in before:
                if name.endswith((".sqlite-wal", ".sqlite-shm", ".sqlite-journal")):
                    continue
                origin, target = source / name, data / name
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                if name in databases:
                    read = sqlite3.connect(f"file:{origin}?mode=ro", uri=True)
                    write = sqlite3.connect(target)
                    try:
                        read.backup(write, pages=128)
                    finally:
                        write.close()
                        read.close()
                    os.chmod(target, 0o600)
                    sqlite_check(target)
                else:
                    with origin.open("rb") as src, target.open("xb") as dst:
                        os.chmod(target, 0o600)
                        shutil.copyfileobj(src, dst, 65536)
                        dst.flush()
                        os.fsync(dst.fileno())
                entries.append({"path": name, "bytes": target.stat().st_size, "sha256": digest(target), "sqlite": name in databases})
            # Locks may create/update WAL bookkeeping. All durable source data
            # and key/blob bytes must retain their identity throughout copying.
            stable = lambda rows: [item for item in rows if not item[0].endswith((".sqlite-wal", ".sqlite-shm", ".sqlite-journal"))]
            if stable(before) != stable(tree(source)):
                raise ValueError("source changed during snapshot")
            ensure_offline(source)
            manifest = {"format": FORMAT, "buildID": build_id, "profileID": profile_id,
                        "scope": "full-service", "externalSecrets": "Original mounted KEK, OAuth and operator secret files and runtime configuration are required separately.",
                        "files": entries}
            payload = canonical(manifest)
            (staging / "manifest.json").write_bytes(payload)
            (staging / "manifest.hmac").write_text(hmac.new(integrity_key, payload, hashlib.sha256).hexdigest() + "\n")
            os.chmod(staging / "manifest.json", 0o600)
            os.chmod(staging / "manifest.hmac", 0o600)
            os.rename(staging, destination)
        except Exception:
            # Preserve partial output for diagnosis/recovery. Never destroy it.
            raise
    return {"operation": "snapshot", "format": FORMAT, "files": len(entries), "databases": len(databases)}


def restore(snapshot_root, destination, integrity_key):
    secure_regular(snapshot_root / "manifest.json")
    secure_regular(snapshot_root / "manifest.hmac")
    payload = (snapshot_root / "manifest.json").read_bytes()
    expected = hmac.new(integrity_key, payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, (snapshot_root / "manifest.hmac").read_text().strip()):
        raise ValueError("snapshot manifest authentication failed")
    manifest = json.loads(payload)
    if manifest.get("format") != FORMAT or manifest.get("scope") != "full-service":
        raise ValueError("unsupported snapshot format")
    data = snapshot_root / "data"
    files = manifest["files"]
    paths = [item["path"] for item in files]
    if len(set(paths)) != len(paths) or "control.sqlite" not in paths:
        raise ValueError("invalid snapshot inventory")
    for name in paths:
        path = Path(name)
        if path.is_absolute() or any(part in (".", "..", "") for part in path.parts) or str(path) != name:
            raise ValueError("unsafe snapshot path")
    if sorted(paths) != sorted(name for name, *_ in tree(data)):
        raise ValueError("snapshot inventory mismatch")
    staging = destination_stage(destination)
    for item in files:
        origin, target = data / item["path"], staging / item["path"]
        secure_regular(origin)
        if origin.stat().st_size != item["bytes"] or digest(origin) != item["sha256"]:
            raise ValueError("snapshot file integrity check failed")
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with origin.open("rb") as src, target.open("xb") as dst:
            os.chmod(target, 0o600)
            shutil.copyfileobj(src, dst, 65536)
        if digest(target) != item["sha256"]:
            raise ValueError("restored file integrity check failed")
        if item["sqlite"]:
            sqlite_check(target)
    os.rename(staging, destination)
    return {"operation": "restore", "format": FORMAT, "files": len(files),
            "buildID": manifest["buildID"], "profileID": manifest["profileID"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    for name in ("snapshot", "restore"):
        command = sub.add_parser(name)
        command.add_argument("--source", type=Path, required=True)
        command.add_argument("--destination", type=Path, required=True)
        command.add_argument("--integrity-key-file", type=Path, required=True)
        if name == "snapshot":
            command.add_argument("--build-id", required=True)
            command.add_argument("--profile-id", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        source = args.source.absolute()
        destination = args.destination.absolute()
        integrity_key = key(args.integrity_key_file)
        if args.operation == "snapshot":
            result = snapshot(source, destination, integrity_key, args.build_id, args.profile_id)
        else:
            result = restore(source, destination, integrity_key)
        print(json.dumps(result, sort_keys=True))
    except (ValueError, OSError, sqlite3.Error, KeyError, TypeError) as error:
        print("Offline service snapshot refused: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
