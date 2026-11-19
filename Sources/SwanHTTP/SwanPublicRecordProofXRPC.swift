import Foundation
import Hummingbird
import HTTPTypes
import NIOCore
import Petrel
import PetrelRepo
import SwanStorage

/// `com.atproto.sync.getRecord`, spelled as a literal because no public
/// profile's wire registry declares it — see
/// ``SwanPublicRouteSurface/outOfProfilePublicMethods``.
let publicRecordProofNSID = "com.atproto.sync.getRecord"

/// `commit` is the reference lexicon's deprecated parameter. It is accepted so
/// a client that still sends it is not refused, and it selects nothing: the
/// proof is always relative to the current signed commit.
private let recordProofQuerySchema = StrictQuerySchema(
    required: ["did", "collection", "rkey"],
    optional: ["commit"]
)

/// Unauthenticated `com.atproto.sync.getRecord`: the CAR a consumer verifies
/// to learn, from the account's own signature, whether a record exists.
///
/// The response is a CARv1 whose root is the signed commit and whose blocks
/// are that commit, the MST nodes on the search path for
/// `<collection>/<rkey>`, and the record block when the key is present. An
/// absent key is still `200`: the same path proves the key is not in the
/// commit, which is what the reference PDS returns and what a verifier needs
/// in order to tell "not declared" from "withheld". Only an unhosted or
/// non-active repository is an error, with the mapping `sync.getRepo` uses.
///
/// It reserves the same lease class as `com.atproto.repo.getRecord` from the
/// shared read admission and holds it until the body is written. A proof is
/// bounded by ``PublicRepositoryRecordProofLimits/maximumProofCARBytes``, so
/// it is answered from memory with an exact `Content-Length` and never takes
/// the disk spool `getRepo` streams through.
func registerPublicRecordProofEndpoint(
    on router: Router<BasicRequestContext>,
    directory: any PublicRepositoryReadDirectory,
    servedMethods: Set<String>,
    jsonReadAdmission: PublicRepositoryJSONReadAdmission
) {
    router.getIfServed(
        publicRecordProofNSID, in: servedMethods
    ) { request, _ async -> Response in
        var selector: String?
        do {
            let query = try publicReadQuery(
                request, schema: recordProofQuerySchema
            )
            // Canonical-only, as `getBlob` parses its `did`: the account the
            // proof is built for is the account the caller literally named.
            // A handle is refused here — the lexicon's parameter is `did`.
            guard let rawDID = query["did"],
                  rawDID.utf8.count <= 2_048,
                  let did = try? DID(didString: rawDID),
                  did.didString() == rawDID,
                  let collection = query["collection"],
                  let recordKey = query["rkey"],
                  query["commit"].map({ (try? CID.parse($0)) != nil })
                    ?? true else {
                return publicReadError(.badRequest, "InvalidRequest")
            }
            selector = rawDID
            let path = try PublicRepositoryPath(
                collection: collection, recordKey: recordKey
            )
            // Reserved before storage is touched. A cache miss or a drifted
            // generation pin sends this call into a full admission, exactly as
            // it does for `getLatestCommit`, and unleased each small anonymous
            // GET would buy one of those plus an MST descent.
            guard let lease = jsonReadAdmission.reserve(
                maximumResponseBytes: PublicRepositoryRecordProofLimits
                    .maximumProofCARBytes
            ) else {
                return publicReadUnavailable(
                    reason: PublicReadHandlerGuard
                        .responseAdmissionExhausted.rawValue,
                    method: publicRecordProofNSID,
                    selector: selector
                )
            }
            let proof: PublicRepositoryReadRecordProof
            do {
                switch try await directory.publicRepositoryRecordProofOutcome(
                    did: rawDID, path: path
                ) {
                case .notFound:
                    lease.release()
                    return publicReadError(.badRequest, "RepoNotFound")
                case let .lifecycle(status):
                    lease.release()
                    return publicLifecycleError(status.status)
                case let .active(resolved):
                    // Defence in depth, as on `getBlob`: the directory is
                    // asked for one exact DID, and an implementation that
                    // answered with another account's commit would serve one
                    // account's signed data under another's name.
                    guard resolved.did == rawDID else {
                        lease.release()
                        return publicReadError(.badRequest, "RepoNotFound")
                    }
                    proof = resolved
                }
            } catch {
                lease.release()
                throw error
            }
            return publicRecordProofCARResponse(proof.car, lease: lease)
        } catch PublicRepositoryReadError.invalidSelector {
            return publicReadError(.badRequest, "InvalidRequest")
        } catch PublicRepositoryDomainError.invalidCollection,
                PublicRepositoryDomainError.invalidRecordKey,
                PublicRepositoryDomainError.pathTooLong {
            return publicReadError(.badRequest, "InvalidRequest")
        } catch {
            return publicReadUnavailable(
                error,
                method: publicRecordProofNSID,
                selector: selector
            )
        }
    }
}

/// The proof body, with the read lease held until the writer finishes — a
/// stalled reader must not hold bytes outside the admission that bounds them.
/// The headers match `sync.getRepo`'s CAR response.
private func publicRecordProofCARResponse(
    _ car: Data,
    lease: PublicRepositoryJSONReadLease
) -> Response {
    Response(
        status: .ok,
        headers: [
            .contentType: "application/vnd.ipld.car",
            .cacheControl: "no-store",
        ],
        body: .init(contentLength: car.count) { writer in
            defer { lease.release() }
            try await writer.write(ByteBuffer(data: car))
            try await writer.finish(nil)
        }
    )
}
