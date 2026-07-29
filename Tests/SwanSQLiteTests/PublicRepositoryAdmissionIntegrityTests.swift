import Crypto
import Foundation
import Petrel
import SQLiteNIO
import SwanAccounts
import SwanCore
import SwanPublicRepository
@testable import SwanSQLite
import SwanStorage
import XCTest

final class PublicRepositoryAdmissionIntegrityTests: XCTestCase {
    private let alice = "did:plc:abcdefghijklmnopqrstuvwx"
    private let bob = "did:plc:bcdefghijklmnopqrstuvwxy"

    // Production mutation caught: a configured public-read runtime treats an
    // active control row with neither PLC genesis nor an empty repository as a
    // valid account and installs it with a nil public generation.
    func testConfiguredPublicVerifierRejectsActiveAccountWithoutGenesisAndRepository()
        async throws
    {
        let root = try temporaryDirectory(label: "missing-public-genesis")
        defer { try? FileManager.default.removeItem(at: root) }
        try await installEmptyDatabase(root: root, did: alice)
        let control = try await activeControlStore(
            root: root,
            did: alice,
            handle: "alice.example.com",
            genesisCID: nil
        )

        do {
            let unexpected = try await SQLitePreMigratedAccountDirectory
                .bootstrap(
                    dataDirectory: root,
                    controlStore: control,
                    publicIdentityVerifier: SwanPublicPLCGenesisVerifier()
                )
            try? await unexpected.close()
            XCTFail(
                "public-read-enabled startup admitted an active account without public identity or repository truth"
            )
        } catch let error as SwanError {
            guard case .unavailable = error else {
                XCTFail("expected unavailable, got \(error)")
                try await control.close()
                return
            }
        } catch {
            XCTFail("expected SwanError.unavailable, got \(error)")
        }
        try await control.close()
    }

    // Production mutation caught: the explicit nil-verifier mode accidentally
    // publishes a nil/nil account through a public read outcome. This mode is
    // retained only for isolated permissioned-data tests and must never create
    // a public generation.
    func testExplicitNilVerifierModeCannotServePublicRepositoryReads()
        async throws
    {
        let root = try temporaryDirectory(label: "public-reads-disabled")
        defer { try? FileManager.default.removeItem(at: root) }
        try await installEmptyDatabase(root: root, did: alice)
        let control = try await activeControlStore(
            root: root,
            did: alice,
            handle: "alice.example.com",
            genesisCID: nil
        )
        let directory = try await SQLitePreMigratedAccountDirectory.bootstrap(
            dataDirectory: root,
            controlStore: control,
            publicIdentityVerifier: nil
        )

        do {
            _ = try await directory.publicRepositoryDescriptionOutcome(
                selector: alice
            )
            XCTFail("nil-verifier mode exposed a public repository outcome")
        } catch let error as PublicRepositoryReadError {
            XCTAssertEqual(error, .unavailable)
        } catch {
            XCTFail("expected public read unavailable, got \(error)")
        }

        try await directory.close()
        try await control.close()
    }

    // Production mutation caught: bootstrap authenticates only the canonical
    // commit schema/CID and accepts a structurally coherent current commit
    // whose fixed-width P-256 signature was not made by the account key.
    func testBootstrapRejectsCanonicalFakeSignatureOnCoherentCurrentCommitBeforeExposure()
        async throws
    {
        let root = try temporaryDirectory(label: "fake-current-signature")
        defer { try? FileManager.default.removeItem(at: root) }
        let accountKey = try P256.Signing.PrivateKey(
            rawRepresentation: Data(repeating: 0x11, count: 32)
        )
        let rotationKey = try P256.Signing.PrivateKey(
            rawRepresentation: Data(repeating: 0x33, count: 32)
        )
        let handle = "alice.example.com"
        let pdsOrigin = "https://swan.example"
        let repositoryRevision = "3jzfcijpj2z2a"
        let preparationRequestID = "authenticated-current-signature"
        let plcGenesis = try PLCOperationCodec.sign(
            .regular(
                try PLCATProfile.regularOperation(
                    handle: handle,
                    signingPublicKey: accountKey.publicKey,
                    rotationPublicKeys: [rotationKey.publicKey],
                    pdsOrigin: try XCTUnwrap(URL(string: pdsOrigin)),
                    prev: nil
                )
            ),
            using: rotationKey
        )
        let plcRegular = try XCTUnwrap(plcGenesis.regular)
        let did = try PLCOperationCodec.genesisDID(for: plcGenesis)
        let plcOperationCID = try plcGenesis.cid.string
        let installed = try await installRepository(
            root: root,
            did: did,
            key: accountKey,
            revision: repositoryRevision,
            recordKey: "signed"
        )
        try await installSubmittedPLCJournal(
            root: root,
            did: did,
            handle: handle,
            pdsOrigin: pdsOrigin,
            repositoryRevision: repositoryRevision,
            repositoryGenesisCID: installed.genesisCID,
            preparationRequestID: preparationRequestID,
            signingDIDKey: try XCTUnwrap(
                plcRegular.verificationMethods["atproto"]
            ),
            rotationDIDKey: try XCTUnwrap(plcRegular.rotationKeys.first),
            operationSignature: plcRegular.signature
        )
        let control = try await activeControlStore(
            root: root,
            did: did,
            handle: handle,
            genesisCID: installed.genesisCID
        )
        try await installSubmittedPLCIntent(
            control: control,
            did: did,
            handle: handle,
            pdsOrigin: pdsOrigin,
            repositoryRevision: repositoryRevision,
            preparationRequestID: preparationRequestID,
            operationCID: plcOperationCID
        )
        let identityVerifier = SwanPublicPLCGenesisVerifier()
        let validDirectory = try await SQLitePreMigratedAccountDirectory
            .bootstrap(
                dataDirectory: root,
                controlStore: control,
                publicIdentityVerifier: identityVerifier
            )
        let validStore = await validDirectory.preopenedPublicMutationStore(
            did: did
        )
        XCTAssertNotNil(
            validStore,
            "the positive-control repository must be admitted"
        )
        let validDescription = try await validDirectory
            .describePublicRepository(selector: did)
        XCTAssertEqual(
            validDescription?.identity.signingDIDKey,
            P256DIDKey(publicKey: accountKey.publicKey).value
        )
        try await validDirectory.close()

        let attackerKey = try P256.Signing.PrivateKey(
            rawRepresentation: Data(repeating: 0x22, count: 32)
        )
        let unsignedCommit = try PublicRepositoryCommitCodec.encodeUnsigned(
            did: installed.state.did,
            revision: installed.state.revision,
            dataCID: installed.state.dataCID
        )
        let fakeSignature = try P256WireSignature.sign(
            unsignedCommit,
            using: attackerKey
        )
        XCTAssertEqual(fakeSignature.count, P256WireSignature.rawByteCount)
        XCTAssertTrue(P256WireSignature.isCanonicalLowS(fakeSignature))
        let fakeCommit = try canonicalSignedCommit(
            state: installed.state,
            signature: fakeSignature
        )
        let fakeCommitCID = CID.fromDAGCBOR(fakeCommit)
        let structural = try PublicRepositoryCommitCodec.structurallyValidate(
            signedCommitBytes: fakeCommit,
            expectedCommitCID: fakeCommitCID
        )
        XCTAssertEqual(structural.signature, fakeSignature)
        XCTAssertEqual(structural.descriptor.did, installed.state.did)
        XCTAssertEqual(
            structural.descriptor.revision.value,
            installed.state.revision
        )
        XCTAssertEqual(
            structural.descriptor.dataCID,
            installed.state.dataCID
        )
        do {
            _ = try await PublicRepositoryCommitCodec.verify(
                signedCommitBytes: fakeCommit,
                expectedCommitCID: fakeCommitCID,
                verifier: P256PublicRepositoryCommitVerifier(
                    publicKey: accountKey.publicKey
                )
            )
            XCTFail("the adversarial signature unexpectedly verified")
        } catch let error as PublicRepositoryCommitError {
            XCTAssertEqual(error, .invalidSignature)
        }
        try await replaceCurrentCommit(
            root: root,
            did: did,
            commitCID: fakeCommitCID,
            commitBytes: fakeCommit
        )

        do {
            let unexpected = try await SQLitePreMigratedAccountDirectory
                .bootstrap(
                    dataDirectory: root,
                    controlStore: control,
                    publicIdentityVerifier: identityVerifier
                )
            let exposed = await unexpected.preopenedPublicMutationStore(
                did: did
            )
            XCTAssertNil(
                exposed,
                "a commit with an unauthenticated signature became reachable"
            )
            try? await unexpected.close()
            XCTFail(
                "bootstrap must reject the unauthenticated current commit before exposure"
            )
        } catch let error as SwanError {
            guard case .unavailable = error else {
                XCTFail("expected unavailable, got \(error)")
                try await control.close()
                return
            }
        } catch {
            XCTFail("expected SwanError.unavailable, got \(error)")
        }
        try await control.close()
    }

    // Production mutation caught: replaying the same opaque transfer reaches
    // the duplicate-DID branch, which closes the actor already installed in
    // the live directory.
    func testReplayedActivatedAccountAdmissionDoesNotCloseInstalledLiveDatabase()
        async throws
    {
        let root = try temporaryDirectory(label: "replayed-admission")
        defer { try? FileManager.default.removeItem(at: root) }
        // Keep this replay test independent of PLC/head authentication. The
        // transferred empty account database is sufficient to prove that a
        // repeated opaque admission must not close the live actor.
        try await installEmptyDatabase(root: root, did: alice)
        let control = try await inactiveControlStore(
            root: root,
            did: alice,
            handle: "alice.example.com",
            genesisCID: nil
        )
        let directory = try await SQLitePreMigratedAccountDirectory.bootstrap(
            dataDirectory: root,
            controlStore: control,
            publicIdentityVerifier: nil
        )
        _ = try await control.transitionStatus(
            did: alice,
            to: .active,
            declaration: .init(),
            now: Date(timeIntervalSince1970: 1_750_000_002)
        )
        let database = try await SQLiteAccountDatabase(
            dataDirectory: root,
            did: alice
        )
        let admission = SQLiteActivatedAccountAdmission(
            did: alice,
            database: database
        )
        try await directory.admitActivatedAccount(admission)
        let firstStore = await directory.preopenedPublicMutationStore(did: alice)
        let firstDatabase = try XCTUnwrap(firstStore as? SQLiteAccountDatabase)
        XCTAssertTrue(firstDatabase === database)

        // A replay may be reported as unavailable, but it must never revoke
        // or close the already-installed live actor.
        try? await directory.admitActivatedAccount(admission)
        let replayedStore = await directory.preopenedPublicMutationStore(
            did: alice
        )
        let replayedDatabase = try XCTUnwrap(
            replayedStore as? SQLiteAccountDatabase
        )
        XCTAssertTrue(replayedDatabase === database)
        let stateResult: Result<PublicRepositoryState?, Error>
        do {
            stateResult = .success(
                try await replayedDatabase.loadPublicRepositoryState()
            )
        } catch {
            stateResult = .failure(error)
        }

        try? await directory.close()
        try? await database.close()
        try await control.close()

        switch stateResult {
        case let .success(state):
            XCTAssertNil(state)
        case let .failure(error):
            XCTFail(
                "replayed transfer closed the installed live database: \(error)"
            )
        }
    }

    // Production mutation caught: activation validates the supplied database
    // internally but never binds its account DID to the admission DID.
    func testActivatedAccountAdmissionRejectsDatabaseBoundToDifferentDID()
        async throws
    {
        let liveRoot = try temporaryDirectory(label: "wrong-did-live")
        defer { try? FileManager.default.removeItem(at: liveRoot) }
        try await installEmptyDatabase(root: liveRoot, did: alice)
        try await installEmptyDatabase(root: liveRoot, did: bob)
        let control = try await inactiveControlStore(
            root: liveRoot,
            did: alice,
            handle: "alice.example.com",
            genesisCID: nil
        )
        let directory = try await SQLitePreMigratedAccountDirectory.bootstrap(
            dataDirectory: liveRoot,
            controlStore: control,
            publicIdentityVerifier: nil
        )
        _ = try await control.transitionStatus(
            did: alice,
            to: .active,
            declaration: .init(),
            now: Date(timeIntervalSince1970: 1_750_000_002)
        )
        let foreign = try await SQLiteAccountDatabase(
            dataDirectory: liveRoot,
            did: bob
        )

        let rejection = await admissionResult(
            directory: directory,
            admission: SQLiteActivatedAccountAdmission(
                did: alice,
                database: foreign
            )
        )
        let exposed = await directory.preopenedPublicMutationStore(did: alice)

        try? await directory.close()
        try? await foreign.close()
        try await control.close()

        assertUnavailable(rejection)
        XCTAssertNil(
            exposed,
            "a database bound to a different DID was installed for the account"
        )
    }

    // Production mutation caught: activation checks that the expected local
    // path exists but accepts an exact same-DID database copy opened from a
    // different physical data root.
    func testActivatedAccountAdmissionRejectsSameDIDDatabaseFromDifferentRoot()
        async throws
    {
        let liveRoot = try temporaryDirectory(label: "wrong-root-live")
        let foreignRoot = try temporaryDirectory(label: "wrong-root-foreign")
        defer {
            try? FileManager.default.removeItem(at: liveRoot)
            try? FileManager.default.removeItem(at: foreignRoot)
        }
        let local = try await installRepository(
            root: liveRoot,
            did: alice,
            key: P256.Signing.PrivateKey(),
            revision: "3jzfcijpj2z2a"
        )
        try await cloneAccountDatabase(
            sourceRoot: liveRoot,
            destinationRoot: foreignRoot,
            did: alice
        )
        let control = try await inactiveControlStore(
            root: liveRoot,
            did: alice,
            handle: "alice.example.com",
            genesisCID: local.genesisCID
        )
        let directory = try await SQLitePreMigratedAccountDirectory.bootstrap(
            dataDirectory: liveRoot,
            controlStore: control,
            publicIdentityVerifier: nil
        )
        _ = try await control.transitionStatus(
            did: alice,
            to: .active,
            declaration: .init(),
            now: Date(timeIntervalSince1970: 1_750_000_002)
        )
        let foreignDatabase = try await SQLiteAccountDatabase(
            dataDirectory: foreignRoot,
            did: alice
        )
        let copiedState = try await foreignDatabase.loadPublicRepositoryState()
        XCTAssertEqual(copiedState, local.state)

        let rejection = await admissionResult(
            directory: directory,
            admission: SQLiteActivatedAccountAdmission(
                did: alice,
                database: foreignDatabase
            )
        )
        let exposed = await directory.preopenedPublicMutationStore(did: alice)

        try? await directory.close()
        try? await foreignDatabase.close()
        try await control.close()

        assertUnavailable(rejection)
        XCTAssertNil(
            exposed,
            "a same-DID database from a different data root was installed"
        )
    }

    // Production mutation caught: activation checks terminal revocation only
    // before awaiting public commit authentication, allowing permanent
    // deletion to win and then have the stale activation reinsert its database.
    func testRevocationWhilePublicAuthenticationIsSuspendedPreventsActivationReinsert()
        async throws
    {
        let root = try temporaryDirectory(label: "revocation-activation-race")
        defer { try? FileManager.default.removeItem(at: root) }
        let signingKey = P256.Signing.PrivateKey()
        let rotationKey = P256.Signing.PrivateKey()
        let handle = "alice.example.com"
        let pdsOrigin = "https://swan.example"
        let revision = "3jzfcijpj2z2a"
        let requestID = "revocation-activation-race"
        let genesisOperation = try PLCOperationCodec.sign(
            .regular(
                try PLCATProfile.regularOperation(
                    handle: handle,
                    signingPublicKey: signingKey.publicKey,
                    rotationPublicKeys: [rotationKey.publicKey],
                    pdsOrigin: try XCTUnwrap(URL(string: pdsOrigin)),
                    prev: nil
                )
            ),
            using: rotationKey
        )
        let regular = try XCTUnwrap(genesisOperation.regular)
        let did = try PLCOperationCodec.genesisDID(for: genesisOperation)
        let installed = try await installRepository(
            root: root,
            did: did,
            key: signingKey,
            revision: revision
        )
        try await installSubmittedPLCJournal(
            root: root,
            did: did,
            handle: handle,
            pdsOrigin: pdsOrigin,
            repositoryRevision: revision,
            repositoryGenesisCID: installed.genesisCID,
            preparationRequestID: requestID,
            signingDIDKey: try XCTUnwrap(
                regular.verificationMethods["atproto"]
            ),
            rotationDIDKey: try XCTUnwrap(regular.rotationKeys.first),
            operationSignature: regular.signature
        )
        let control = try await inactiveControlStore(
            root: root,
            did: did,
            handle: handle,
            genesisCID: installed.genesisCID
        )
        try await installSubmittedPLCIntent(
            control: control,
            did: did,
            handle: handle,
            pdsOrigin: pdsOrigin,
            repositoryRevision: revision,
            preparationRequestID: requestID,
            operationCID: try genesisOperation.cid.string
        )
        let barrier = PublicAdmissionAuthenticationBarrier()
        let verifier = BlockingPublicAdmissionVerifier(barrier: barrier)
        let directory = try await SQLitePreMigratedAccountDirectory.bootstrap(
            dataDirectory: root,
            controlStore: control,
            publicIdentityVerifier: verifier
        )
        _ = try await control.transitionStatus(
            did: did,
            to: .active,
            declaration: .init(),
            now: Date(timeIntervalSince1970: 1_750_000_002)
        )
        let database = try await SQLiteAccountDatabase(
            dataDirectory: root,
            did: did
        )

        let rejected = try await withThrowingTaskGroup(of: Bool.self) {
            group in
            group.addTask {
                do {
                    try await directory.admitActivatedAccount(
                        SQLiteActivatedAccountAdmission(
                            did: did,
                            database: database
                        )
                    )
                    return false
                } catch let error as SwanError {
                    guard case .unavailable = error else { return false }
                    return true
                } catch {
                    return false
                }
            }
            await barrier.waitUntilAuthenticationEntered()
            do {
                try await directory.revokeAndDrainAccount(did: did)
            } catch {
                await barrier.releaseAuthentication()
                throw error
            }
            await barrier.releaseAuthentication()
            let result = try await group.next()
            return try XCTUnwrap(result)
        }

        XCTAssertTrue(rejected)
        let exposed = await directory.preopenedPublicMutationStore(did: did)
        XCTAssertNil(exposed)
        try await directory.close()
        try? await database.close()
        try await control.close()
    }
}

private extension PublicRepositoryAdmissionIntegrityTests {
    struct InstalledRepository {
        let genesisCID: String
        let state: PublicRepositoryState
    }

    func temporaryDirectory(label: String) throws -> URL {
        let root = FileManager.default.temporaryDirectory.appending(
            path: "SwanPublicAdmission-\(label)-\(UUID().uuidString)"
        )
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true
        )
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700],
            ofItemAtPath: root.path
        )
        return root
    }

    func installRepository(
        root: URL,
        did: String,
        key: P256.Signing.PrivateKey,
        revision: String,
        recordKey: String? = nil
    ) async throws -> InstalledRepository {
        let database = try await SQLiteAccountDatabase(
            dataDirectory: root,
            did: did
        )
        do {
            let genesis = try PublicRepositoryGenesisCodec.create(
                did: did,
                revision: revision,
                signingKey: key
            )
            _ = try await database.installPublicRepositoryGenesis(
                genesis,
                signingPublicKey: key.publicKey,
                installedAt: Date(timeIntervalSince1970: 1_750_000_000)
            )
            let maybeState = try await database.loadPublicRepositoryState()
            var state = try XCTUnwrap(maybeState)
            if let recordKey {
                let request = try PublicRepositoryMutationRequest(
                    id: "admission-\(recordKey)",
                    canonicalDigest: Data(repeating: 0xa7, count: 32),
                    baseCommitCID: state.commitCID
                )
                guard case let .reserved(reservation) =
                    try await database.reservePublicRepositoryRevision(
                        request,
                        wallClockMicroseconds: 1_750_000_001_000_000
                    ) else {
                    throw PublicRepositoryMutationStoreError
                        .conflictingRequestReuse
                }
                let path = try PublicRepositoryPath(
                    collection: "app.bsky.feed.post",
                    recordKey: recordKey
                )
                let prepared = try await PublicRepositoryEngine.apply(
                    repositoryDID: did,
                    currentState: state,
                    blocks: database,
                    revision: reservation.nextRevision,
                    batch: try PublicRepositoryWriteBatch(
                        writes: [
                            .create(
                                path: path,
                                record: [
                                    "$type": .string("app.bsky.feed.post"),
                                    "text": .string("admission integrity"),
                                ]
                            ),
                        ],
                        expectedCommitCID: state.commitCID
                    ),
                    signer: P256PublicRepositoryCommitSigner(privateKey: key)
                )
                state = try await database.applyPublicRepositoryMutation(
                    reservation: reservation,
                    prepared: prepared
                ).state
            }
            try await database.close()
            return InstalledRepository(
                genesisCID: genesis.commitCID.string,
                state: state
            )
        } catch {
            try? await database.close()
            throw error
        }
    }

    func activeControlStore(
        root: URL,
        did: String,
        handle: String,
        genesisCID: String?
    ) async throws -> SQLiteControlDatabase {
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        _ = try await control.createAccount(
            try registration(
                did: did,
                handle: handle,
                genesisCID: genesisCID
            )
        )
        return control
    }

    func inactiveControlStore(
        root: URL,
        did: String,
        handle: String,
        genesisCID: String?
    ) async throws -> SQLiteControlDatabase {
        let control = try await activeControlStore(
            root: root,
            did: did,
            handle: handle,
            genesisCID: genesisCID
        )
        _ = try await control.transitionStatus(
            did: did,
            to: .deactivated,
            declaration: .init(),
            now: Date(timeIntervalSince1970: 1_750_000_001)
        )
        return control
    }

    func registration(
        did: String,
        handle: String,
        genesisCID: String?
    ) throws -> AccountControlRegistration {
        try AccountControlRegistration(
            did: did,
            canonicalHandle: handle,
            passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
            signingKey: AccountControlKeyReference(
                purpose: .signing,
                generation: 1
            ),
            rotationKey: AccountControlKeyReference(
                purpose: .rotation,
                generation: 1
            ),
            publicGenesisCommitCID: genesisCID,
            createdAt: Date(timeIntervalSince1970: 1_750_000_000)
        )
    }

    func canonicalSignedCommit(
        state: PublicRepositoryState,
        signature: Data
    ) throws -> Data {
        try DAGCBOR.encodeValue(
            OrderedCBORMap(entries: [
                (key: "did", value: state.did),
                (key: "version", value: 3),
                (key: "data", value: ATProtoLink(cid: state.dataCID)),
                (key: "rev", value: state.revision),
                (key: "prev", value: NSNull()),
                (key: "sig", value: signature),
            ])
        )
    }

    func replaceCurrentCommit(
        root: URL,
        did: String,
        commitCID: CID,
        commitBytes: Data
    ) async throws {
        let connection = try await SQLiteConnection.open(
            storage: .file(
                path: SQLiteLayout.accountDatabase(in: root, did: did).path
            )
        )
        do {
            _ = try await connection.query(
                """
                INSERT INTO public_repository_blocks(cid, bytes)
                VALUES (?, ?)
                """,
                [.text(commitCID.string), commitBytes.sqliteData!]
            )
            let updated = try await connection.query(
                """
                UPDATE public_repository_state
                SET commit_cid = ?
                WHERE singleton = 1 AND did = ?
                RETURNING singleton
                """,
                [.text(commitCID.string), .text(did)]
            )
            guard updated.count == 1 else {
                throw PublicRepositoryMutationStoreError.corruptRepository
            }
            try await connection.close()
        } catch {
            try? await connection.close()
            throw error
        }
    }

    func installEmptyDatabase(root: URL, did: String) async throws {
        let database = try await SQLiteAccountDatabase(
            dataDirectory: root,
            did: did
        )
        try await database.close()
    }

    func installSubmittedPLCJournal(
        root: URL,
        did: String,
        handle: String,
        pdsOrigin: String,
        repositoryRevision: String,
        repositoryGenesisCID: String,
        preparationRequestID: String,
        signingDIDKey: String,
        rotationDIDKey: String,
        operationSignature: String
    ) async throws {
        let database = try await SQLiteAccountDatabase(
            dataDirectory: root,
            did: did
        )
        do {
            let journal = try PLCAccountPreparationJournal(
                requestID: preparationRequestID,
                canonicalHandle: handle,
                pdsOrigin: pdsOrigin,
                repositoryRevision: repositoryRevision,
                operation: PLCAccountPreparationOperationFacts(
                    signingDIDKey: signingDIDKey,
                    rotationDIDKey: rotationDIDKey,
                    signature: operationSignature
                ),
                signingKey: AccountControlKeyReference(
                    purpose: .signing,
                    generation: 1
                ),
                rotationKey: AccountControlKeyReference(
                    purpose: .rotation,
                    generation: 1
                ),
                publicGenesisCommitCID: nil,
                stage: .keysStored
            )
            _ = try await database.installPLCAccountPreparationJournal(journal)
            _ = try await database.advancePLCAccountPreparationJournal(
                requestID: preparationRequestID,
                expectedStage: .keysStored,
                to: .repositoryInstalled,
                publicGenesisCommitCID: repositoryGenesisCID
            )
            _ = try await database.advancePLCAccountPreparationJournal(
                requestID: preparationRequestID,
                expectedStage: .repositoryInstalled,
                to: .submissionPending,
                publicGenesisCommitCID: nil
            )
            _ = try await database.advancePLCAccountPreparationJournal(
                requestID: preparationRequestID,
                expectedStage: .submissionPending,
                to: .submitted,
                publicGenesisCommitCID: nil
            )
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }
    }

    func installSubmittedPLCIntent(
        control: SQLiteControlDatabase,
        did: String,
        handle: String,
        pdsOrigin: String,
        repositoryRevision: String,
        preparationRequestID: String,
        operationCID: String
    ) async throws {
        var intent = try PLCAccountPreparationIntent(
            requestID: preparationRequestID,
            did: did,
            canonicalHandle: handle,
            pdsOrigin: pdsOrigin,
            repositoryRevision: repositoryRevision,
            operationCID: operationCID,
            stage: .keysStored
        )
        _ = try await control.reservePLCAccountPreparationIntent(intent)
        for next in [
            PLCAccountPreparationStage.repositoryInstalled,
            .submissionPending,
            .submitted,
        ] {
            intent = try await control.advancePLCAccountPreparationIntent(
                requestID: preparationRequestID,
                expectedStage: intent.stage,
                to: next
            )
        }
    }

    func cloneAccountDatabase(
        sourceRoot: URL,
        destinationRoot: URL,
        did: String
    ) async throws {
        let placeholder = try await SQLiteAccountDatabase(
            dataDirectory: destinationRoot,
            did: did
        )
        try await placeholder.close()
        let source = SQLiteLayout.accountDatabase(in: sourceRoot, did: did)
        let destination = SQLiteLayout.accountDatabase(
            in: destinationRoot,
            did: did
        )
        for path in [
            destination.path,
            destination.path + "-wal",
            destination.path + "-shm",
        ] where FileManager.default.fileExists(atPath: path) {
            try FileManager.default.removeItem(atPath: path)
        }
        try FileManager.default.copyItem(at: source, to: destination)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: destination.path
        )
    }

    func admissionResult(
        directory: SQLitePreMigratedAccountDirectory,
        admission: SQLiteActivatedAccountAdmission
    ) async -> Result<Void, Error> {
        do {
            try await directory.admitActivatedAccount(admission)
            return .success(())
        } catch {
            return .failure(error)
        }
    }

    func assertUnavailable(
        _ result: Result<Void, Error>,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        switch result {
        case .success:
            XCTFail("expected SwanError.unavailable", file: file, line: line)
        case let .failure(error):
            guard let swanError = error as? SwanError else {
                XCTFail(
                    "expected SwanError.unavailable, got \(error)",
                    file: file,
                    line: line
                )
                return
            }
            guard case .unavailable = swanError else {
                XCTFail(
                    "expected unavailable, got \(swanError)",
                    file: file,
                    line: line
                )
                return
            }
        }
    }
}

private struct BlockingPublicAdmissionVerifier:
    PublicPLCGenesisVerifying,
    PublicPLCRepositoryAuthenticating
{
    let barrier: PublicAdmissionAuthenticationBarrier
    private let base = SwanPublicPLCGenesisVerifier()

    func verifyGenesis(
        facts: PublicPLCGenesisFacts,
        expectedDID: String
    ) throws -> String {
        try base.verifyGenesis(facts: facts, expectedDID: expectedDID)
    }

    func authenticateRepositoryCommit(
        signedCommitBytes: Data,
        expectedCommitCID: CID,
        expectedDID: String,
        signingDIDKey: String
    ) async throws -> PublicRepositoryCommitAuthentication {
        await barrier.authenticationEnteredAndWait()
        return try await base.authenticateRepositoryCommit(
            signedCommitBytes: signedCommitBytes,
            expectedCommitCID: expectedCommitCID,
            expectedDID: expectedDID,
            signingDIDKey: signingDIDKey
        )
    }
}

private actor PublicAdmissionAuthenticationBarrier {
    private var entered = false
    private var released = false
    private var entryWaiters: [CheckedContinuation<Void, Never>] = []
    private var releaseWaiters: [CheckedContinuation<Void, Never>] = []

    func authenticationEnteredAndWait() async {
        guard !released else { return }
        entered = true
        let waitingForEntry = entryWaiters
        entryWaiters.removeAll()
        waitingForEntry.forEach { $0.resume() }
        await withCheckedContinuation { continuation in
            if released {
                continuation.resume()
            } else {
                releaseWaiters.append(continuation)
            }
        }
    }

    func waitUntilAuthenticationEntered() async {
        guard !entered else { return }
        await withCheckedContinuation { entryWaiters.append($0) }
    }

    func releaseAuthentication() {
        guard !released else { return }
        released = true
        let waitingForRelease = releaseWaiters
        releaseWaiters.removeAll()
        waitingForRelease.forEach { $0.resume() }
    }
}
