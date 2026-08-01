#!/usr/bin/env python3
"""Validate the intentionally narrow Task 47 replacement-recovery artifact."""

import json
import os
import re
import stat
import sys


EXPECTED_SCENARIO = "permissioned-retention-recovery"
EXPECTED_PROFILE = "permissioned-data-0016-2026-07-30"
EXPECTED_POLICY = (
    "semantic-summary-only; no DIDs, space URIs, paths, request identities, "
    "verifier material, credentials, tokens, DPoP proofs, record values, or raw LtHash state"
)


def fail(code: str) -> None:
    print(code)
    raise SystemExit(1)


def main(path: str) -> None:
    if stat.S_IMODE(os.stat(path).st_mode) != 0o600:
        fail("mode")
    with open(path, encoding="utf-8") as source:
        artifact = json.load(source)
    if not isinstance(artifact, dict):
        fail("fields")
    expected = {
        "scenario", "profileID", "gapStatus", "gapErrorCode",
        "priorHeadGeneration", "priorHeadRevision", "priorCommitment",
        "replacementHeadGeneration", "replacementHeadRevision", "replacementCommitment",
        "replacementRecordCount", "replacementCASAdvanced",
        "corruptionRejected", "corruptErrorCode", "finalHeadGeneration", "finalHeadRevision",
        "finalCommitment", "lastValidHeadPreserved", "status", "errorCode", "fixturePolicy",
    }
    required = {
        "scenario", "profileID", "priorHeadGeneration", "priorHeadRevision",
        "priorCommitment", "replacementHeadGeneration", "replacementHeadRevision",
        "replacementCommitment", "replacementRecordCount", "replacementCASAdvanced",
        "corruptionRejected", "lastValidHeadPreserved", "finalHeadGeneration",
        "status", "fixturePolicy",
    }
    if not set(artifact).issubset(expected) or not required.issubset(artifact):
        fail("fields")
    if artifact["scenario"] != EXPECTED_SCENARIO:
        fail("scenario")
    if artifact["profileID"] != EXPECTED_PROFILE:
        fail("profile")
    if artifact["status"] != "passed" or artifact.get("gapStatus") != 409:
        fail("status")
    if artifact.get("gapErrorCode") != "full_repo_recovery_required":
        fail("gap")
    if artifact.get("corruptErrorCode") != "CARBlockCIDMismatch" \
            or artifact["corruptionRejected"] is not True:
        fail("corruption")
    if artifact["lastValidHeadPreserved"] is not True:
        fail("preserved")
    for field in ("priorHeadGeneration", "replacementHeadGeneration", "finalHeadGeneration"):
        if not isinstance(artifact[field], int) \
                or isinstance(artifact[field], bool) \
                or artifact[field] <= 0:
            fail("generation")
    if artifact.get("replacementHeadGeneration") != artifact.get("finalHeadGeneration") \
            or artifact.get("replacementHeadRevision") != artifact.get("finalHeadRevision") \
            or artifact.get("replacementCommitment") != artifact.get("finalCommitment"):
        fail("head")
    if artifact["replacementHeadGeneration"] != artifact["priorHeadGeneration"] + 1 \
            or artifact["replacementHeadRevision"] == artifact["priorHeadRevision"] \
            or artifact["replacementCommitment"] == artifact["priorCommitment"] \
            or artifact["replacementCASAdvanced"] is not True:
        fail("replacement")
    if not isinstance(artifact.get("replacementRecordCount"), int) \
            or isinstance(artifact["replacementRecordCount"], bool) \
            or artifact["replacementRecordCount"] < 1:
        fail("records")
    for field in ("priorCommitment", "replacementCommitment"):
        if not isinstance(artifact.get(field), str) \
                or re.fullmatch(r"[0-9a-f]{64}", artifact[field]) is None:
            fail("commitment")
    for field in ("priorHeadRevision", "replacementHeadRevision"):
        if not isinstance(artifact.get(field), str) \
                or re.fullmatch(r"[a-z2-7]{13}", artifact[field]) is None:
            fail("revision")
    if not isinstance(artifact.get("finalCommitment"), str) \
            or re.fullmatch(r"[0-9a-f]{64}", artifact["finalCommitment"]) is None:
        fail("commitment")
    if not isinstance(artifact.get("finalHeadRevision"), str) \
            or re.fullmatch(r"[a-z2-7]{13}", artifact["finalHeadRevision"]) is None:
        fail("revision")
    if artifact.get("errorCode") is not None:
        fail("error")
    if artifact["fixturePolicy"] != EXPECTED_POLICY:
        fail("policy")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: validate-permissioned-recovery-artifact.py ARTIFACT")
    main(sys.argv[1])
