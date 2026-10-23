import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[2] / "Scripts" / "service-snapshot.py"


class ServiceSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.original_umask = os.umask(0o077)
        self.temporary = tempfile.TemporaryDirectory(prefix="swan-snapshot-test-")
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir(mode=0o700)
        self.secret = self.root / "integrity-key"
        self.secret.write_bytes(os.urandom(32))
        self.secret.chmod(0o600)
        for relative in ["control.sqlite", "firehose.sqlite", "actors/aa/account.sqlite"]:
            target = self.source / relative
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with sqlite3.connect(target) as db:
                db.executescript("""
                    CREATE TABLE authority_policy(space TEXT PRIMARY KEY, policy TEXT);
                    CREATE TABLE members(space TEXT, did TEXT);
                    CREATE TABLE writers(space TEXT, rev TEXT, data BLOB);
                    CREATE TABLE registrations(space TEXT, service TEXT, expires INTEGER);
                    CREATE TABLE outbox(id TEXT, action TEXT, attempts INTEGER, retry_at INTEGER);
                    INSERT INTO authority_policy VALUES('space', 'memberList');
                    INSERT INTO members VALUES('space', 'member');
                    INSERT INTO writers VALUES('space', '2222222222222', x'1234');
                    INSERT INTO registrations VALUES('space', 'service', 100);
                    INSERT INTO outbox VALUES('pending-delete', 'deleted', 2, 42);
                """)
            db.close()
            target.chmod(0o600)
        for relative, contents in [("keys/account-signing", b"encrypted-signing"),
                                   ("keys/account-kem", b"encrypted-kem"),
                                   ("blobs/private-content", b"private-content")]:
            path = self.source / relative
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.write_bytes(contents)
            path.chmod(0o600)

    def tearDown(self):
        self.temporary.cleanup()
        os.umask(self.original_umask)

    def run_tool(self, operation, source, destination):
        args = ["python3", str(SCRIPT), operation, "--source", str(source), "--destination", str(destination),
                "--integrity-key-file", str(self.secret)]
        if operation == "snapshot":
            args += ["--build-id", "test-fixture-build", "--profile-id", "test-fixture-profile"]
        return subprocess.run(args, capture_output=True, text=True, timeout=30)

    def test_restores_operational_tables_keys_and_pending_deliveries(self):
        archive, restored = self.root / "archive", self.root / "restored"
        result = self.run_tool("snapshot", self.source, archive)
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.run_tool("restore", archive, restored)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((restored / "keys/account-kem").read_bytes(), b"encrypted-kem")
        for relative in ["control.sqlite", "firehose.sqlite", "actors/aa/account.sqlite"]:
            with sqlite3.connect(self.source / relative) as before, sqlite3.connect(restored / relative) as after:
                self.assertEqual(list(before.iterdump()), list(after.iterdump()))
                self.assertEqual(after.execute("SELECT attempts, retry_at FROM outbox").fetchone(), (2, 42))
        self.assertEqual(restored.stat().st_mode & 0o777, 0o700)
        self.assertEqual((restored / "keys/account-kem").stat().st_mode & 0o777, 0o600)

    def test_refuses_active_source(self):
        with sqlite3.connect(self.source / "control.sqlite") as live:
            live.execute("BEGIN IMMEDIATE")
            result = self.run_tool("snapshot", self.source, self.root / "active-archive")
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((self.root / "active-archive").exists())

    def test_refuses_changed_file_and_manifest_and_existing_restore(self):
        archive = self.root / "archive"
        result = self.run_tool("snapshot", self.source, archive)
        self.assertEqual(result.returncode, 0, result.stderr)
        target = archive / "data/keys/account-kem"
        target.write_bytes(b"changed")
        result = self.run_tool("restore", archive, self.root / "corrupt-restore")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "corrupt-restore").exists())
        (archive / "manifest.json").write_bytes(b"{}")
        result = self.run_tool("restore", archive, self.root / "bad-manifest")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "bad-manifest").exists())
        result = self.run_tool("restore", archive, self.source)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.source / "keys/account-kem").read_bytes(), b"encrypted-kem")

    def test_refuses_symlink_and_public_private_material(self):
        (self.source / "keys/link").symlink_to(self.secret)
        result = self.run_tool("snapshot", self.source, self.root / "symlink-archive")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "symlink-archive").exists())


if __name__ == "__main__":
    unittest.main()
