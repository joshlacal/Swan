#!/usr/bin/env python3
"""Emit one safe failure code from a bounded Swan live artifact."""

import json
import sys


MAX_ARTIFACT_BYTES = 64 * 1024
ALLOWED_CODES = {
    "AuthMissing", "CARBlockCIDMismatch", "CARByteLimitExceeded",
    "CARCommitmentMismatch", "CARInvalidCID", "CARInvalidChunk",
    "CARInvalidExpectedWitness", "CARInvalidLimits", "CARMalformedFrame",
    "CARMalformedHeader", "CARMalformedIndex", "CARMalformedVarint",
    "CARRecordBodyLimitExceeded", "CARStagingUnavailable",
    "CARUniqueBlockLimitExceeded", "CommitmentMismatch", "CommitMissing",
    "ContentBindingMismatch", "ContextSignatureMismatch", "FileFailure",
    "HTTP400", "HTTP401", "HTTP403", "HTTP404", "HTTP409", "HTTP429",
    "HTTP500", "HTTP502", "HTTP503", "HTTP504", "InteropFailure",
    "InvalidCommit", "InvalidOperation", "InvalidRequest", "InvalidResponse",
    "MissingCommitKey", "MissingCredential", "MissingJwt", "OperationMismatch",
    "RecoveryBindingMismatch", "RecoveryCASConflict", "RecoveryCorruptReplica",
    "RecoveryEquivocation", "RecoveryFailed", "RecoveryFreshnessMismatch",
    "RecoveryInvalidBinding", "RecoveryInvalidStatus", "RecoveryReceiverMismatch",
    "RecoveryStale", "ResponseTooLarge", "SpaceNotFound", "TransportFailure",
    "Unauthorized", "UnexpectedContentType", "UnexpectedRedirect", "ValueCIDMismatch",
    "ValueMissing", "full_repo_recovery_required", "temporarily_unavailable",
    "use_dpop_nonce",
}


def main(path: str) -> None:
    with open(path, "rb") as source:
        payload = source.read(MAX_ARTIFACT_BYTES + 1)
    if len(payload) > MAX_ARTIFACT_BYTES:
        raise SystemExit(1)
    try:
        artifact = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise SystemExit(1)
    if not isinstance(artifact, dict):
        raise SystemExit(1)
    code = artifact.get("errorCode")
    if not isinstance(code, str) or code not in ALLOWED_CODES:
        raise SystemExit(1)
    print(code)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(2)
    main(sys.argv[1])
