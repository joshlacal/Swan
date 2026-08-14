import Foundation
import XCTest
@testable import SwanCore
@testable import SwanHTTP
@testable import SwanOAuth
import SwanSQLite
@testable import SwanSpaces

/// **§9-D23 — BLOCKER.** Provenance is durable state, not parser metadata.
///
/// The whole point of this file is its *shape*. A parse → matcher test passes
/// with the defect present, because the defect is not in the matcher: it is in
/// what survives the round trip through storage. Every test here therefore runs
/// the full sequence
///
///     request → MINT → PERSIST → **RELOAD FROM STORAGE** → fence
///
/// with a real close/reopen of the control database in the middle, and asserts
/// the fence's answer on the far side.
///
/// Both directions matter, and they fail in opposite ways:
///
///  * **Provenance invented.** `space:x.y.z?skey=*&action=read` has `authority`
///    *defaulted*, so the delegation fence must refuse. Mint resolves `self` to
///    the subject DID and persists a string in which all three values look
///    literal. Re-parsed at request time, the fence flips false → true — exactly
///    the amplification the provenance machinery exists to prevent.
///  * **Provenance destroyed.** Canonical serialisation deletes values equal to
///    their defaults; the golden corpus confirms `space:g?skey=*` canonicalises
///    to bare `space:g`. A fence requiring a *literal* `skey=*` can then never
///    fire again, silently disabling the listing fence.
///
/// Neither is visible without the reload.
final class ScopeProvenanceDurabilityTests: XCTestCase, @unchecked Sendable {
    private static let spaceType = "app.example.forum"

    // MARK: - Isolating the layer: facade vs. seam

    /// **Control for the two failing end-to-end tests below.** It answers the
    /// only question that matters when they go red: is the *facade* wrong, or is
    /// provenance simply not reaching it?
    ///
    /// Pure unit, no HTTP, no storage — the same permissions value constructed
    /// twice, once with the durable `statedKeys` and once without. If the
    /// with-provenance case passes and the without case fails, the matcher is
    /// correct and the defect is at the plumbing seam. That is a different bug,
    /// with a different owner, than "the fence logic is wrong".
    func testFacadeHonoursDurableProvenanceWhenItIsSupplied() throws {
        let stated = "space:\(Self.spaceType)?authority=\(PermissionedScopeFixture.subject)&skey=*&action=read"

        // WITHOUT provenance: both fences must refuse. This is the fail-closed
        // posture, and it is what the resource plane currently produces.
        let blind = SwanScopePermissions(
            rawScopes: [stated],
            subject: PermissionedScopeFixture.subject
        )
        XCTAssertFalse(
            blind.allowsSpace(
                SpaceScopeTarget(
                    type: Self.spaceType,
                    authority: PermissionedScopeFixture.subject,
                    skey: "*",
                    operation: .delegationExchange
                )
            ),
            "with no provenance the delegation fence must refuse — fail closed, not open"
        )

        // WITH provenance: the same grant, plus the bits saying the client
        // literally wrote all three keys. Both fences must now allow.
        let witnessed = SwanScopePermissions(
            rawScopes: [stated],
            subject: PermissionedScopeFixture.subject,
            statedKeys: [stated: ["authority", "skey", "action"]]
        )
        XCTAssertTrue(
            witnessed.allowsSpace(
                SpaceScopeTarget(
                    type: Self.spaceType,
                    authority: PermissionedScopeFixture.subject,
                    skey: "*",
                    operation: .delegationExchange
                )
            ),
            """
            The FACADE is the wrong suspect if this fails: given durable \
            provenance, `isExactReadOnlyDelegationGrant` must accept a grant whose \
            `authority`, `skey` and single `action=read` were all literally \
            written. If this passes while the end-to-end tests fail, the matcher \
            is fine and provenance is not reaching it.
            """
        )
        let wildcard = "space:\(Self.spaceType)?authority=*&skey=*&action=read"
        XCTAssertTrue(
            SwanScopePermissions(
                rawScopes: [wildcard],
                subject: PermissionedScopeFixture.subject,
                statedKeys: [wildcard: ["authority", "skey", "action"]]
            ).allowsSpaceListing(type: Self.spaceType, authority: nil),
            "same for the listing fence (§7.3 W8)"
        )
    }

    // MARK: - Direction 1: minting must not INVENT provenance

    /// The exact example §9-D23 names. `authority` is never written by the
    /// client; mint resolves it; the delegation fence must still refuse on the
    /// far side of storage.
    func testDelegationFenceRefusesAResolvedAuthorityThatWasNeverStated() async throws {
        let requested = "space:\(Self.spaceType)?skey=*&action=read"
        let client = try PermissionedScopeClient(scopes: [requested])
        let minting = try await PermissionedScopeFixture.make()
        let issued: OAuthTokenGrantResult
        do {
            issued = try await minting.mint(client: client, proofID: "d23-invented-mint")
        } catch {
            await minting.tearDown()
            throw error
        }

        // Precondition, not decoration: if mint did NOT resolve `self`, this test
        // would pass for the wrong reason — the fence would refuse an unresolved
        // authority rather than a defaulted one, and the defect would be invisible.
        // §6.4 removed the layer at which an unresolved `self` fails closed for a
        // minted token, so this assertion is what keeps the test honest.
        XCTAssertTrue(
            issued.scopes.contains { $0.contains("authority=\(PermissionedScopeFixture.subject)") },
            """
            mint did not resolve `self` to the subject DID, so this test is not \
            exercising §9-D23's "provenance invented" direction at all (§6.4)
            """
        )

        let reloaded = try await minting.reopeningStorage()
        defer { Task { await reloaded.tearDown() } }

        let permissions = try await reloaded.permissions(
            accessToken: issued.accessToken,
            client: client,
            jti: "d23-invented-authorize"
        )

        // The grant reads as fully literal now. The fence must still refuse,
        // because provenance came out of storage beside the grant rather than
        // being re-derived from it.
        XCTAssertFalse(
            permissions.allowsSpace(
                SpaceScopeTarget(
                    type: Self.spaceType,
                    authority: PermissionedScopeFixture.subject,
                    skey: "*",
                    operation: .delegationExchange
                )
            ),
            """
            DELEGATION WIDENING (§9-D23, direction "provenance invented"). The \
            client never wrote `authority`; mint resolved it; the reloaded grant \
            now reads as three literal values and the fence accepted it. \
            `isExactReadOnlyDelegationGrant` must consult PERSISTED provenance \
            (§5.6.3), never `wasStated` re-derived from the stored string.
            """
        )

        // ... while ordinary matching on the same grant is unaffected: resolution
        // is supposed to make the grant usable. If this went false too, the fix
        // would have been "stop resolving", which breaks every `self` grant (M22).
        XCTAssertTrue(
            permissions.allowsSpace(
                SpaceScopeTarget(
                    type: Self.spaceType,
                    authority: PermissionedScopeFixture.subject,
                    skey: "anything",
                    // NOT aggregate: this probes an ordinary read of one named
                    // space, which is what must survive `self` resolution. An
                    // aggregate read carries the §6.5.5 hardening and would fail
                    // here for a reason unrelated to provenance, turning a
                    // positive control into a false alarm.
                    operation: .read(aggregate: false, collection: nil)
                )
            ),
            "resolution must still make the grant match ordinary reads (§6.4)"
        )
    }

    /// `withResolvedAuthority` changes the VALUE, never the statedness. A grant
    /// whose `authority` *was* written by the client keeps the delegation
    /// exchange after the same round trip — otherwise the fix for the row above
    /// would be "refuse everything", which regresses W7, the one positive vector
    /// in the §7.3 widening fence.
    func testDelegationFenceStillAllowsAFullyStatedReadOnlyGrant() async throws {
        let requested =
            "space:\(Self.spaceType)?authority=\(PermissionedScopeFixture.subject)&skey=*&action=read"
        let client = try PermissionedScopeClient(scopes: [requested])
        let minting = try await PermissionedScopeFixture.make()
        let issued: OAuthTokenGrantResult
        do {
            issued = try await minting.mint(client: client, proofID: "d23-stated-mint")
        } catch {
            await minting.tearDown()
            throw error
        }
        let reloaded = try await minting.reopeningStorage()
        defer { Task { await reloaded.tearDown() } }

        let permissions = try await reloaded.permissions(
            accessToken: issued.accessToken,
            client: client,
            jti: "d23-stated-authorize"
        )
        XCTAssertTrue(
            permissions.allowsSpace(
                SpaceScopeTarget(
                    type: Self.spaceType,
                    authority: PermissionedScopeFixture.subject,
                    skey: "*",
                    operation: .delegationExchange
                )
            ),
            """
            W7 regression: the one positive delegation vector. Every parameter \
            here was literally written by the client and survived storage; if \
            this is denied, delegation is broken and the §9-D23 fix over-corrected.
            """
        )
    }

    // MARK: - Direction 2: canonicalisation must not DESTROY provenance

    /// The mirror case §9-D23 requires. The golden corpus proves
    /// `space:com.example.group?skey=*` canonicalises to bare
    /// `space:com.example.group` — a stated `skey=*` is deleted because it equals
    /// its default. If persistence stores a canonical string and the listing
    /// fence re-derives `wasStated` from it, the fence can never fire again.
    func testListingFenceStillFiresForAStatedSkeyWildcardAfterStorage() async throws {
        // Exactly §7.3's W8: literal `*` in both aggregate dimensions, stated
        // `skey=*`, stated single `action=read`.
        let requested = "space:\(Self.spaceType)?authority=*&skey=*&action=read"
        let client = try PermissionedScopeClient(scopes: [requested])
        let minting = try await PermissionedScopeFixture.make()
        let issued: OAuthTokenGrantResult
        do {
            issued = try await minting.mint(client: client, proofID: "d23-listing-mint")
        } catch {
            await minting.tearDown()
            throw error
        }
        let reloaded = try await minting.reopeningStorage()
        defer { Task { await reloaded.tearDown() } }

        let permissions = try await reloaded.permissions(
            accessToken: issued.accessToken,
            client: client,
            jti: "d23-listing-authorize"
        )
        XCTAssertTrue(
            permissions.allowsSpaceListing(type: Self.spaceType, authority: nil),
            """
            LISTING FENCE SILENTLY DISABLED (§9-D23, direction "provenance \
            destroyed"). The client stated `skey=*` and `action=read`; canonical \
            serialisation deletes a value equal to its default, so a fence that \
            re-derives `wasStated` from the stored string sees neither and refuses \
            forever. Provenance must be persisted beside the grant.
            """
        )
    }

    /// The negative half of the same fence, after the same round trip: a **bare**
    /// grant states nothing, so it must not satisfy the listing (§7.3 W2). Held
    /// beside the row above, the pair proves the fence is reading provenance
    /// rather than having been widened into an unconditional yes.
    func testListingFenceRefusesABareGrantAfterStorage() async throws {
        let client = try PermissionedScopeClient(scopes: ["space:\(Self.spaceType)"])
        let minting = try await PermissionedScopeFixture.make()
        let issued: OAuthTokenGrantResult
        do {
            issued = try await minting.mint(client: client, proofID: "d23-bare-mint")
        } catch {
            await minting.tearDown()
            throw error
        }
        let reloaded = try await minting.reopeningStorage()
        defer { Task { await reloaded.tearDown() } }

        let permissions = try await reloaded.permissions(
            accessToken: issued.accessToken,
            client: client,
            jti: "d23-bare-authorize"
        )
        XCTAssertFalse(
            permissions.allowsSpaceListing(type: Self.spaceType, authority: nil),
            "W2: a bare `space:<type>` defaults `skey` and `action`; defaults are not literals"
        )
        XCTAssertFalse(
            permissions.allowsSpace(
                SpaceScopeTarget(
                    type: Self.spaceType,
                    authority: PermissionedScopeFixture.subject,
                    skey: "*",
                    operation: .delegationExchange
                )
            ),
            "W1: a bare grant's `action` is defaulted, not stated"
        )
    }
}
