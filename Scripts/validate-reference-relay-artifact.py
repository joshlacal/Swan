#!/usr/bin/env python3
"""Validate one aggregate-only Swan reference-relay acceptance artifact."""

from __future__ import annotations

import json
import os
import pathlib
import re
import stat
import sys


EXPECTED_STEPS = [
    "fresh_state",
    "crawl",
    "subscription_open",
    "account_activation",
    "activation_lifecycle",
    "first_commit",
    "offline_five_commit_recovery",
    "manual_sync",
]
EXPECTED_CHECKS = [
    "canonical_frames",
    "ordered_lifecycle",
    "cursor_recovery",
    "repository_commits",
    "get_repo_mode",
    "final_mst_equality",
]
EXPECTED_KEYS = {
    "schemaVersion", "scenario", "status", "swanHead", "indigo",
    "freshState", "orderedSteps", "connectionObservations", "account",
    "lifecycleKinds", "firstCommit", "offlineRecovery", "finalRepository",
    "manualSync", "verifier", "cleanup", "artifactPolicy", "successMarker",
}
FORBIDDEN_KEY = re.compile(
    r"(?:password|credential|oauth|token|proof|private|secret|recordvalue|rawlog|requestbody)",
    re.IGNORECASE,
)
HEX64 = re.compile(r"[0-9a-f]{64}")
HEX40 = re.compile(r"[0-9a-f]{40}")
REVISION = re.compile(r"[234567abcdefghij][234567abcdefghijklmnopqrstuvwxyz]{12}")
CID = re.compile(r"b[a-z2-7]{20,120}")


def fail(code: str) -> "NoReturn":
    print(code)
    raise SystemExit(1)


def integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def exact_dict(value: object, keys: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == keys


def scan_keys(value: object) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str) or FORBIDDEN_KEY.search(key):
                fail("forbidden-field")
            scan_keys(child)
    elif isinstance(value, list):
        for child in value:
            scan_keys(child)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: validate-reference-relay-artifact.py ARTIFACT", file=sys.stderr)
        return 64
    path = pathlib.Path(sys.argv[1])
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError:
        fail("artifact-unavailable")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        fail("artifact-type")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        fail("artifact-mode")
    if metadata.st_size <= 0 or metadata.st_size > 256 * 1024:
        fail("artifact-size")
    try:
        with path.open(encoding="utf-8") as handle:
            artifact = json.load(handle)
    except (OSError, UnicodeError, ValueError):
        fail("artifact-json")
    if not exact_dict(artifact, EXPECTED_KEYS):
        fail("artifact-layout")
    scan_keys(artifact)
    if artifact["schemaVersion"] != 1 or artifact["scenario"] != "swan-reference-relay-phase5":
        fail("scenario")
    if artifact["status"] != "passed" or artifact["successMarker"] != "REFERENCE RELAY ACCEPTANCE OK":
        fail("status-marker")
    if artifact["artifactPolicy"] != "aggregate-digest-only":
        fail("artifact-policy")
    if not isinstance(artifact["swanHead"], str) or not HEX40.fullmatch(artifact["swanHead"]):
        fail("swan-head")

    indigo = artifact["indigo"]
    if not exact_dict(indigo, {"commit", "sourceSHA256", "vendorSHA256", "imageID"}):
        fail("indigo-layout")
    if indigo["commit"] != "8b43a326dbbb394f63b6d68761553cdfe25532de":
        fail("indigo-commit")
    if not all(isinstance(indigo[key], str) and HEX64.fullmatch(indigo[key]) for key in ("sourceSHA256", "vendorSHA256", "imageID")):
        fail("indigo-digest")

    fresh = artifact["freshState"]
    if not exact_dict(fresh, {"volume", "removed", "listHostsCount"}) \
            or fresh["volume"] != "swan-interop-alpha_reference-relay-data" \
            or fresh["removed"] is not True or fresh["listHostsCount"] != 0:
        fail("fresh-state")
    if artifact["orderedSteps"] != EXPECTED_STEPS:
        fail("ordered-steps")

    observations = artifact["connectionObservations"]
    if not isinstance(observations, list) or len(observations) < 2:
        fail("connection-observations")
    for index, observation in enumerate(observations, start=1):
        if not exact_dict(observation, {"ordinal", "cursorMode", "upstreamCursor"}) \
                or observation["ordinal"] != index \
                or observation["cursorMode"] not in {"live", "full_window", "backfill"} \
                or (observation["upstreamCursor"] is not None and not integer(observation["upstreamCursor"])):
            fail("connection-observations")
    if observations[0] != {"ordinal": 1, "cursorMode": "live", "upstreamCursor": None}:
        fail("initial-connection")
    if not any(item["cursorMode"] == "backfill" for item in observations[1:]):
        fail("recovery-connection")

    account = artifact["account"]
    if not exact_dict(account, {"didDigest", "fresh"}) \
            or not isinstance(account["didDigest"], str) \
            or not HEX64.fullmatch(account["didDigest"]) or account["fresh"] is not True:
        fail("account")
    if artifact["lifecycleKinds"] != ["identity", "account", "sync"]:
        fail("lifecycle-order")

    first = artifact["firstCommit"]
    if not exact_dict(first, {"observed", "sequence"}) or first["observed"] is not True \
            or not integer(first["sequence"]) or first["sequence"] <= 0:
        fail("first-commit")
    recovery = artifact["offlineRecovery"]
    recovery_keys = {
        "expectedCommitCount", "observedCommitCount", "relaySequenceStart", "relaySequenceEnd",
        "upstreamCursor", "firstDeliveredRelaySequence", "duplicateCount", "gapCount", "queryMode",
    }
    if not exact_dict(recovery, recovery_keys):
        fail("recovery-layout")
    if recovery["expectedCommitCount"] != 5 or recovery["observedCommitCount"] != 5:
        fail("recovery-count")
    if not all(integer(recovery[key]) for key in (
        "relaySequenceStart", "relaySequenceEnd", "upstreamCursor", "firstDeliveredRelaySequence",
        "duplicateCount", "gapCount",
    )):
        fail("recovery-integer")
    if recovery["relaySequenceStart"] <= first["sequence"] \
            or recovery["relaySequenceEnd"] != recovery["relaySequenceStart"] + 4 \
            or recovery["upstreamCursor"] < 0 \
            or recovery["firstDeliveredRelaySequence"] != recovery["relaySequenceStart"] \
            or recovery["duplicateCount"] != 0 or recovery["gapCount"] != 0:
        fail("recovery-sequence")
    backfills = [item for item in observations[1:] if item["cursorMode"] == "backfill"]
    if not any(item["upstreamCursor"] == recovery["upstreamCursor"] for item in backfills):
        fail("recovery-observation")
    if recovery["queryMode"] != "subscribe_repos_cursor_only":
        fail("recovery-mode")

    final = artifact["finalRepository"]
    final_keys = {
        "relayRevision", "swanRevision", "relayCommitCID", "swanCommitCID",
        "relayDataCID", "swanDataCID", "relayMSTDigest", "swanMSTDigest",
        "projectionDigest", "equal",
    }
    if not exact_dict(final, final_keys) or final["equal"] is not True:
        fail("final-layout")
    if not all(isinstance(final[key], str) and REVISION.fullmatch(final[key]) for key in ("relayRevision", "swanRevision")):
        fail("final-revision")
    if not all(isinstance(final[key], str) and CID.fullmatch(final[key]) for key in ("relayCommitCID", "swanCommitCID", "relayDataCID", "swanDataCID")):
        fail("final-cid")
    if not all(isinstance(final[key], str) and HEX64.fullmatch(final[key]) for key in ("relayMSTDigest", "swanMSTDigest", "projectionDigest")):
        fail("final-digest")
    if final["relayRevision"] != final["swanRevision"] \
            or final["relayCommitCID"] != final["swanCommitCID"] \
            or final["relayDataCID"] != final["swanDataCID"] \
            or final["relayMSTDigest"] != final["swanMSTDigest"]:
        fail("final-mismatch")

    if artifact["manualSync"] != {"observed": True, "clean": True}:
        fail("manual-sync")
    verifier = artifact["verifier"]
    if verifier != {"status": "passed", "checks": EXPECTED_CHECKS}:
        fail("verifier")
    if artifact["cleanup"] != {"toxiproxyEnabled": True, "disposableContainersRemaining": 0}:
        fail("cleanup")
    print("REFERENCE RELAY ARTIFACT VALIDATION OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
