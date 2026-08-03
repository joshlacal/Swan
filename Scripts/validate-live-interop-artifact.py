#!/usr/bin/env python3
"""Require one semantically passing live-interoperability artifact."""

import json
import pathlib
import re
import sys


MODES = {
    "normal", "offline", "disconnected", "delayed",
    "duplicated", "reordered", "corrupted",
}


def valid_head(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"generation", "revision", "commitment"}
        and isinstance(value["generation"], int)
        and not isinstance(value["generation"], bool)
        and 0 < value["generation"] <= sys.maxsize
        and isinstance(value["revision"], str)
        and re.fullmatch(r"[234567abcdefghij][234567abcdefghijklmnopqrstuvwxyz]{12}", value["revision"])
        is not None
        and isinstance(value["commitment"], str)
        and re.fullmatch(r"[0-9a-f]{64}", value["commitment"]) is not None
    )


def valid_fault_witness(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "mode", "before", "intended", "afterFault", "afterHeal",
        "faultObserved", "invalidDeliveryRejected",
    }:
        return False
    mode = value["mode"]
    before = value["before"]
    intended = value["intended"]
    after_fault = value["afterFault"]
    after_heal = value["afterHeal"]
    observed = value["faultObserved"]
    rejected = value["invalidDeliveryRejected"]
    if (
        mode not in MODES
        or not valid_head(intended)
        or (before is not None and not valid_head(before))
        or (after_fault is not None and not valid_head(after_fault))
        or (after_heal is not None and not valid_head(after_heal))
        or not isinstance(observed, bool)
        or not isinstance(rejected, bool)
    ):
        return False
    reaches_intended = after_fault == intended
    heals = after_heal == intended
    preserves_before = before is not None and after_fault == before
    if mode == "normal":
        return reaches_intended and heals
    if mode == "delayed":
        return observed and reaches_intended and heals
    if mode in {"offline", "disconnected"}:
        return observed and preserves_before and heals
    if mode == "duplicated":
        return (
            observed and rejected and before is not None and reaches_intended
            and heals and after_fault["generation"] == before["generation"]
            and after_fault["revision"] != before["revision"]
            and after_fault["commitment"] != before["commitment"]
        )
    return observed and rejected and preserves_before and heals


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: validate-live-interop-artifact.py ARTIFACT", file=sys.stderr)
        return 64
    try:
        with pathlib.Path(sys.argv[1]).open(encoding="utf-8") as handle:
            artifact = json.load(handle)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"live interop artifact is not valid JSON: {error}", file=sys.stderr)
        return 1
    if (
        not isinstance(artifact, dict)
        or artifact.get("status") != "passed"
        or not isinstance(artifact.get("scenario"), str)
        or not artifact["scenario"]
    ):
        print("live interop artifact lacks passing scenario evidence", file=sys.stderr)
        return 1
    if "faultWitness" in artifact and not valid_fault_witness(artifact["faultWitness"]):
        print("live interop artifact fault witness is not semantically passing", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
