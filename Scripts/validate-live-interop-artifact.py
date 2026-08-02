#!/usr/bin/env python3
"""Require one JSON object whose root status is exactly ``passed``."""

import json
import pathlib
import sys


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
    if not isinstance(artifact, dict) or artifact.get("status") != "passed":
        print("live interop artifact root status is not passed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
