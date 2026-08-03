#!/usr/bin/env python3
"""Project sanitized recovery evidence into stateful fault head witnesses."""

import json
import os
import re
import sys
import tempfile


TID = re.compile(r"^[234567abcdefghij][234567abcdefghijklmnopqrstuvwxyz]{12}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def recovery_head(artifact, prefix):
    generation = artifact.get(f"{prefix}HeadGeneration")
    revision = artifact.get(f"{prefix}HeadRevision")
    commitment = artifact.get(f"{prefix}Commitment")
    if (
        not isinstance(generation, int)
        or isinstance(generation, bool)
        or generation <= 0
        or not isinstance(revision, str)
        or TID.fullmatch(revision) is None
        or not isinstance(commitment, str)
        or SHA256.fullmatch(commitment) is None
    ):
        raise SystemExit(f"invalid {prefix} recovery head")
    return {
        "generation": generation,
        "revision": revision,
        "commitment": commitment,
    }


def write_head(path, head):
    directory = os.path.dirname(path) or "."
    descriptor, temporary = tempfile.mkstemp(
        prefix=".corruption-head.", dir=directory, text=True
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(
                {"head": head}, handle, sort_keys=True, separators=(",", ":")
            )
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


if len(sys.argv) != 6:
    raise SystemExit(
        "usage: project-corruption-recovery-witness.py "
        "RECOVERY BEFORE INTENDED AFTER_FAULT AFTER_HEAL"
    )

with open(sys.argv[1], encoding="utf-8") as handle:
    artifact = json.load(handle)

if (
    artifact.get("status") != "passed"
    or artifact.get("corruptionRejected") is not True
    or artifact.get("lastValidHeadPreserved") is not True
):
    raise SystemExit("recovery artifact does not prove corruption rejection")

replacement = recovery_head(artifact, "replacement")
final = recovery_head(artifact, "final")
if replacement != final:
    raise SystemExit("corrupted recovery changed the last valid head")

# The replacement is the last-good state immediately before the injected
# corrupt retry and the intended terminal state. The final head is a separate
# database read performed after that retry. Preserve those distinct evidence
# sources even though a successful rejection makes their values equal.
write_head(sys.argv[2], replacement)
write_head(sys.argv[3], replacement)
write_head(sys.argv[4], final)
write_head(sys.argv[5], final)
