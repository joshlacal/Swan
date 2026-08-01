#!/usr/bin/env python3
"""Validate the intentionally narrow Task 45 recovery acceptance artifact."""

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
        "scenario", "profileID", "gapStatus", "gapErrorCode", "priorHeadPresent",
        "validHeadGeneration", "validHeadRevision", "validCommitment", "validRecordCount",
        "corruptionRejected", "corruptErrorCode", "finalHeadGeneration", "finalHeadRevision",
        "finalCommitment", "lastValidHeadPreserved", "status", "errorCode", "fixturePolicy",
    }
    required = {
        "scenario", "profileID", "priorHeadPresent", "corruptionRejected",
        "lastValidHeadPreserved", "validHeadGeneration", "finalHeadGeneration",
        "status", "fixturePolicy",
    }
    if not set(artifact).issubset(expected) or not required.issubset(artifact):
        fail("fields")
    if artifact["scenario"] != EXPECTED_SCENARIO:
        fail("scenario")
    if artifact["profileID"] != EXPECTED_PROFILE:
        fail("profile")
    if not isinstance(artifact["priorHeadPresent"], bool):
        fail("prior")
    if artifact["status"] != "passed" or artifact.get("gapStatus") != 409:
        fail("status")
    if artifact.get("gapErrorCode") != "full_repo_recovery_required":
        fail("gap")
    if artifact.get("corruptErrorCode") != "CARBlockCIDMismatch" \
            or artifact["corruptionRejected"] is not True:
        fail("corruption")
    if artifact["lastValidHeadPreserved"] is not True:
        fail("preserved")
    for field in ("validHeadGeneration", "finalHeadGeneration"):
        if not isinstance(artifact[field], int) \
                or isinstance(artifact[field], bool) \
                or artifact[field] <= 0:
            fail("generation")
    if artifact.get("validHeadGeneration") != artifact.get("finalHeadGeneration") \
            or artifact.get("validHeadRevision") != artifact.get("finalHeadRevision") \
            or artifact.get("validCommitment") != artifact.get("finalCommitment"):
        fail("head")
    if not isinstance(artifact.get("validRecordCount"), int) \
            or isinstance(artifact["validRecordCount"], bool) \
            or artifact["validRecordCount"] < 1:
        fail("records")
    if not isinstance(artifact.get("validCommitment"), str) \
            or re.fullmatch(r"[0-9a-f]{64}", artifact["validCommitment"]) is None:
        fail("commitment")
    if not isinstance(artifact.get("validHeadRevision"), str) \
            or re.fullmatch(r"[a-z2-7]{13}", artifact["validHeadRevision"]) is None:
        fail("revision")
    if artifact.get("errorCode") is not None:
        fail("error")
    if artifact["fixturePolicy"] != EXPECTED_POLICY:
        fail("policy")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: validate-permissioned-recovery-artifact.py ARTIFACT")
    main(sys.argv[1])
