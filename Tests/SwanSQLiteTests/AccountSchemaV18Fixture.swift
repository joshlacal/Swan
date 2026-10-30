// Exact account-store schema written by Swan 481f2f8 (August 24, 2026), the
// last layout before migration v19: `sqlite_master` of a fresh account store
// opened by that revision, in creation order. Production swan.place account
// stores were still at this layout (migrations 1-18) on October 30, 2026.
// Regenerate only from a binary built at that revision, never by hand.
enum AccountSchemaV18Fixture {
    static let appliedMigrationVersions = Array(1...18)

    static let statements: [String] = [
        #"""
        CREATE TABLE public_records (uri TEXT PRIMARY KEY, value BLOB NOT NULL, revision INTEGER NOT NULL)
        """#,
        #"""
        CREATE TABLE space_records (space_uri TEXT NOT NULL, uri TEXT NOT NULL, value BLOB NOT NULL, revision INTEGER NOT NULL, PRIMARY KEY(space_uri, uri))
        """#,
        #"""
        CREATE TABLE space_oplog (space_uri TEXT NOT NULL, revision INTEGER NOT NULL, operation BLOB NOT NULL, commitment BLOB NOT NULL, PRIMARY KEY(space_uri, revision))
        """#,
        #"""
        CREATE TABLE space_outbox (id TEXT PRIMARY KEY, space_uri TEXT NOT NULL, revision INTEGER NOT NULL, payload BLOB NOT NULL, attempts INTEGER NOT NULL DEFAULT 0)
        """#,
        #"""
        CREATE TABLE blob_refs (cid TEXT NOT NULL, namespace TEXT NOT NULL, PRIMARY KEY(cid, namespace))
        """#,
        #"""
        CREATE TABLE public_repository_records (
            uri TEXT PRIMARY KEY,
            value BLOB NOT NULL,
            cid TEXT NOT NULL,
            revision INTEGER NOT NULL CHECK(revision >= 0)
        )
        """#,
        #"""
        CREATE TABLE public_repository_genesis (
            did TEXT PRIMARY KEY,
            revision TEXT NOT NULL,
            commit_cid TEXT NOT NULL,
            car BLOB NOT NULL,
            installed_at INTEGER NOT NULL CHECK(installed_at >= 0)
        )
        """#,
        #"""
        CREATE TABLE public_repository_state (
            singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
            did TEXT NOT NULL UNIQUE,
            revision TEXT NOT NULL,
            commit_cid TEXT NOT NULL,
            data_cid TEXT NOT NULL
        )
        """#,
        #"""
        CREATE TABLE public_repository_blocks (
            cid TEXT PRIMARY KEY,
            bytes BLOB NOT NULL
        )
        """#,
        #"""
        CREATE TABLE public_repository_record_index (
            collection TEXT NOT NULL,
            rkey TEXT NOT NULL,
            record_cid TEXT NOT NULL,
            PRIMARY KEY(collection, rkey)
        )
        """#,
        #"""
        CREATE TABLE public_repository_mutation_requests (
            request_id TEXT PRIMARY KEY,
            request_digest BLOB NOT NULL CHECK(length(request_digest) = 32),
            base_commit_cid TEXT NOT NULL,
            base_revision TEXT NOT NULL,
            next_revision TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL CHECK(status IN ('reserved', 'committed', 'abandoned')),
            committed_commit_cid TEXT,
            committed_data_cid TEXT,
            committed_projection BLOB,
            committed_projection_digest BLOB CHECK(
                committed_projection_digest IS NULL
                OR length(committed_projection_digest) = 32
            ),
            integrity_digest BLOB NOT NULL CHECK(length(integrity_digest) = 32),
            CHECK(
                    (status IN ('reserved', 'abandoned') AND committed_commit_cid IS NULL
                    AND committed_data_cid IS NULL AND committed_projection IS NULL
                    AND committed_projection_digest IS NULL)
                OR
                (status = 'committed' AND committed_commit_cid IS NOT NULL
                    AND committed_data_cid IS NOT NULL AND committed_projection IS NOT NULL
                    AND committed_projection_digest IS NOT NULL)
            )
        )
        """#,
        #"""
        CREATE TABLE public_repository_revision_allocator (
            singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
            highest_value INTEGER NOT NULL CHECK(highest_value >= 0)
        )
        """#,
        #"""
        CREATE TABLE public_repository_import_sessions (
            session_id TEXT PRIMARY KEY,
            request_id TEXT NOT NULL UNIQUE,
            request_digest BLOB NOT NULL CHECK(length(request_digest) = 32),
            account_did TEXT NOT NULL,
            expected_base_commit_cid TEXT NOT NULL,
            verifier_identity TEXT NOT NULL,
            maximum_record_block_bytes INTEGER NOT NULL CHECK(maximum_record_block_bytes > 0),
            maximum_car_bytes INTEGER NOT NULL CHECK(maximum_car_bytes > 0),
            maximum_car_blocks INTEGER NOT NULL CHECK(maximum_car_blocks > 0),
            maximum_mst_nodes INTEGER NOT NULL CHECK(maximum_mst_nodes > 0),
            maximum_mst_entries_per_node INTEGER NOT NULL CHECK(maximum_mst_entries_per_node > 0),
            maximum_cbor_nesting_depth INTEGER NOT NULL CHECK(maximum_cbor_nesting_depth > 0),
            created_at INTEGER NOT NULL CHECK(created_at >= 0),
            expires_at INTEGER NOT NULL CHECK(expires_at >= created_at),
            status TEXT NOT NULL CHECK(status IN ('receiving', 'verifying', 'verified', 'poisoned', 'consumed')),
            root_cid TEXT,
            received_byte_count INTEGER NOT NULL DEFAULT 0 CHECK(received_byte_count >= 0),
            frame_count INTEGER NOT NULL DEFAULT 0 CHECK(frame_count >= 0),
            verified_commit_cid TEXT,
            verified_data_cid TEXT,
            verified_revision TEXT,
            reachable_block_count INTEGER,
            record_count INTEGER,
            commit_block_count INTEGER,
            mst_block_count INTEGER,
            record_block_count INTEGER,
            index_count INTEGER,
            verified_projection_digest BLOB
                CHECK(verified_projection_digest IS NULL
                    OR length(verified_projection_digest) = 32)
        )
        """#,
        #"""
        CREATE TABLE public_repository_import_blocks (
            session_id TEXT NOT NULL REFERENCES public_repository_import_sessions(session_id) ON DELETE CASCADE,
            cid TEXT NOT NULL,
            bytes BLOB NOT NULL,
            PRIMARY KEY(session_id, cid)
        )
        """#,
        #"""
        CREATE TABLE public_repository_import_reachable (
            session_id TEXT NOT NULL REFERENCES public_repository_import_sessions(session_id) ON DELETE CASCADE,
            cid TEXT NOT NULL,
            kind TEXT NOT NULL CHECK(kind IN ('commit', 'mst', 'record')),
            PRIMARY KEY(session_id, cid)
        )
        """#,
        #"""
        CREATE TABLE public_repository_import_record_index (
            session_id TEXT NOT NULL REFERENCES public_repository_import_sessions(session_id) ON DELETE CASCADE,
            collection TEXT NOT NULL,
            rkey TEXT NOT NULL,
            record_cid TEXT NOT NULL,
            PRIMARY KEY(session_id, collection, rkey)
        )
        """#,
        #"""
        CREATE TABLE public_repository_import_results (
            request_id TEXT PRIMARY KEY,
            request_digest BLOB NOT NULL CHECK(length(request_digest) = 32),
            account_did TEXT NOT NULL,
            expected_base_commit_cid TEXT NOT NULL,
            verifier_identity TEXT NOT NULL,
            maximum_record_block_bytes INTEGER NOT NULL,
            maximum_car_bytes INTEGER NOT NULL,
            maximum_car_blocks INTEGER NOT NULL,
            maximum_mst_nodes INTEGER NOT NULL,
            maximum_mst_entries_per_node INTEGER NOT NULL,
            maximum_cbor_nesting_depth INTEGER NOT NULL,
            revision TEXT NOT NULL,
            commit_cid TEXT NOT NULL,
            data_cid TEXT NOT NULL,
            reachable_block_count INTEGER NOT NULL CHECK(reachable_block_count > 0),
            record_count INTEGER NOT NULL CHECK(record_count >= 0),
            consumed_at INTEGER NOT NULL CHECK(consumed_at >= 0),
            integrity_digest BLOB NOT NULL CHECK(length(integrity_digest) = 32)
        )
        """#,
        #"""
        CREATE INDEX public_repository_import_expiry
        ON public_repository_import_sessions(status, expires_at)
        """#,
        #"""
        CREATE TABLE permissioned_remote_replica_state (
            receiver_did TEXT NOT NULL,
            space_uri TEXT NOT NULL,
            repository_did TEXT NOT NULL,
            generation INTEGER NOT NULL CHECK(generation > 0),
            wire_revision TEXT NOT NULL,
            history_floor_wire_revision TEXT NOT NULL,
            lthash BLOB NOT NULL CHECK(length(lthash) = 2048),
            commitment BLOB NOT NULL CHECK(length(commitment) = 32),
            state_marker BLOB NOT NULL CHECK(length(state_marker) > 0),
            installed_at INTEGER NOT NULL CHECK(installed_at >= 0),
            PRIMARY KEY(space_uri, repository_did)
        )
        """#,
        #"""
        CREATE TABLE permissioned_remote_replica_blocks (
            space_uri TEXT NOT NULL,
            repository_did TEXT NOT NULL,
            cid TEXT NOT NULL,
            byte_count INTEGER NOT NULL
                CHECK(byte_count BETWEEN 1 AND 1048576),
            chunk_count INTEGER NOT NULL CHECK(chunk_count BETWEEN 1 AND 16),
            generation INTEGER NOT NULL CHECK(generation > 0),
            PRIMARY KEY(space_uri, repository_did, generation, cid)
        )
        """#,
        #"""
        CREATE TABLE permissioned_remote_replica_block_chunks (
            space_uri TEXT NOT NULL,
            repository_did TEXT NOT NULL,
            generation INTEGER NOT NULL CHECK(generation > 0),
            cid TEXT NOT NULL,
            chunk_index INTEGER NOT NULL CHECK(chunk_index BETWEEN 0 AND 15),
            bytes BLOB NOT NULL CHECK(length(bytes) BETWEEN 1 AND 65536),
            PRIMARY KEY(
                space_uri, repository_did, generation, cid, chunk_index
            ),
            FOREIGN KEY(space_uri, repository_did, generation, cid)
                REFERENCES permissioned_remote_replica_blocks(
                    space_uri, repository_did, generation, cid
                ) ON DELETE CASCADE
        )
        """#,
        #"""
        CREATE TABLE permissioned_remote_replica_records (
            space_uri TEXT NOT NULL,
            repository_did TEXT NOT NULL,
            collection TEXT NOT NULL,
            rkey TEXT NOT NULL,
            cid TEXT NOT NULL,
            generation INTEGER NOT NULL CHECK(generation > 0),
            PRIMARY KEY(
                space_uri, repository_did, generation, collection, rkey
            ),
            FOREIGN KEY(space_uri, repository_did, generation, cid)
                REFERENCES permissioned_remote_replica_blocks(
                    space_uri, repository_did, generation, cid
                )
        )
        """#,
        #"""
        CREATE TABLE permissioned_remote_replica_import_sessions (
            session_id TEXT PRIMARY KEY,
            request_id TEXT NOT NULL UNIQUE,
            request_digest BLOB NOT NULL CHECK(length(request_digest) = 32),
            source_origin TEXT NOT NULL,
            receiver_did TEXT NOT NULL,
            space_uri TEXT NOT NULL,
            repository_did TEXT NOT NULL,
            expected_base_generation INTEGER,
            expected_base_wire_revision TEXT,
            expected_base_history_floor TEXT,
            expected_base_lthash BLOB,
            expected_base_commitment BLOB,
            expected_base_marker BLOB,
            freshness_wire_revision TEXT,
            freshness_commitment BLOB,
            verifier_identity TEXT NOT NULL,
            profile_id TEXT NOT NULL,
            maximum_car_bytes INTEGER NOT NULL,
            maximum_record_bytes INTEGER NOT NULL,
            maximum_index_entries INTEGER NOT NULL,
            maximum_unique_blocks INTEGER NOT NULL,
            maximum_logical_restored_bytes INTEGER NOT NULL
                CHECK(maximum_logical_restored_bytes BETWEEN 1 AND 268435456),
            status TEXT NOT NULL CHECK(
                status IN (
                    'receiving', 'verifying', 'verified',
                    'preparing', 'poisoned', 'consumed'
                )
            ),
            created_at INTEGER NOT NULL CHECK(created_at >= 0),
            expires_at INTEGER NOT NULL CHECK(expires_at > created_at),
            commit_root_cid TEXT,
            index_root_cid TEXT,
            verified_commit_body BLOB
                CHECK(verified_commit_body IS NULL
                    OR length(verified_commit_body) <= 65536),
            verified_commit_body_digest BLOB
                CHECK(verified_commit_body_digest IS NULL
                    OR length(verified_commit_body_digest) = 32),
            verified_wire_revision TEXT,
            verified_lthash BLOB
                CHECK(verified_lthash IS NULL
                    OR length(verified_lthash) = 2048),
            verified_commitment BLOB
                CHECK(verified_commitment IS NULL
                    OR length(verified_commitment) = 32),
            verified_record_count INTEGER,
            verified_unique_block_count INTEGER,
            verified_received_byte_count INTEGER,
            verified_projection_digest BLOB
                CHECK(verified_projection_digest IS NULL
                    OR length(verified_projection_digest) = 32),
            prepared_generation INTEGER CHECK(
                prepared_generation IS NULL OR prepared_generation > 0
            ),
            prepared_projection_digest BLOB CHECK(
                prepared_projection_digest IS NULL
                    OR length(prepared_projection_digest) = 32
            ),
            CHECK(
                (expected_base_generation IS NULL
                    AND expected_base_wire_revision IS NULL
                    AND expected_base_history_floor IS NULL
                    AND expected_base_lthash IS NULL
                    AND expected_base_commitment IS NULL
                    AND expected_base_marker IS NULL)
                OR
                (expected_base_generation IS NOT NULL
                    AND expected_base_wire_revision IS NOT NULL
                    AND expected_base_history_floor IS NOT NULL
                    AND length(expected_base_lthash) = 2048
                    AND length(expected_base_commitment) = 32
                    AND expected_base_marker IS NOT NULL)
            ),
            CHECK(
                (freshness_wire_revision IS NULL
                    AND freshness_commitment IS NULL)
                OR
                (freshness_wire_revision IS NOT NULL
                    AND length(freshness_commitment) = 32)
            )
        )
        """#,
        #"""
        CREATE TABLE permissioned_remote_replica_import_index (
            session_id TEXT NOT NULL REFERENCES
                permissioned_remote_replica_import_sessions(session_id)
                ON DELETE CASCADE,
            path BLOB NOT NULL,
            collection TEXT NOT NULL,
            rkey TEXT NOT NULL,
            cid TEXT NOT NULL,
            consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed IN (0, 1)),
            PRIMARY KEY(session_id, path),
            UNIQUE(session_id, collection, rkey)
        )
        """#,
        #"""
        CREATE TABLE permissioned_remote_replica_import_blocks (
            session_id TEXT NOT NULL REFERENCES
                permissioned_remote_replica_import_sessions(session_id)
                ON DELETE CASCADE,
            cid TEXT NOT NULL,
            byte_count INTEGER NOT NULL
                CHECK(byte_count BETWEEN 1 AND 1048576),
            chunk_count INTEGER NOT NULL DEFAULT 0
                CHECK(chunk_count BETWEEN 0 AND 16),
            complete INTEGER NOT NULL DEFAULT 0 CHECK(complete IN (0, 1)),
            PRIMARY KEY(session_id, cid)
        )
        """#,
        #"""
        CREATE TABLE permissioned_remote_replica_import_block_chunks (
            session_id TEXT NOT NULL,
            cid TEXT NOT NULL,
            chunk_index INTEGER NOT NULL CHECK(chunk_index BETWEEN 0 AND 15),
            bytes BLOB NOT NULL CHECK(length(bytes) BETWEEN 1 AND 65536),
            PRIMARY KEY(session_id, cid, chunk_index),
            FOREIGN KEY(session_id, cid)
                REFERENCES permissioned_remote_replica_import_blocks(
                    session_id, cid
                ) ON DELETE CASCADE
        )
        """#,
        #"""
        CREATE TABLE permissioned_remote_replica_import_results (
            request_id TEXT PRIMARY KEY,
            request_digest BLOB NOT NULL CHECK(length(request_digest) = 32),
            -- This is computed by the storage boundary from the complete
            -- import binding.  It is intentionally separate from the
            -- caller-supplied request digest: a low-level caller must not be
            -- able to replay a request while changing the expected base,
            -- freshness witness, or resource limits.
            binding_digest BLOB CHECK(
                binding_digest IS NULL OR length(binding_digest) = 32
            ),
            source_origin TEXT NOT NULL,
            receiver_did TEXT NOT NULL,
            space_uri TEXT NOT NULL,
            repository_did TEXT NOT NULL,
            base_generation INTEGER,
            installed_generation INTEGER NOT NULL CHECK(installed_generation > 0),
            installed_wire_revision TEXT NOT NULL,
            installed_history_floor TEXT NOT NULL,
            installed_lthash BLOB NOT NULL CHECK(length(installed_lthash) = 2048),
            installed_commitment BLOB NOT NULL
                CHECK(length(installed_commitment) = 32),
            installed_marker BLOB NOT NULL,
            commit_root_cid TEXT NOT NULL,
            index_root_cid TEXT NOT NULL,
            record_count INTEGER NOT NULL CHECK(record_count >= 0),
            unique_block_count INTEGER NOT NULL CHECK(unique_block_count >= 0),
            verifier_identity TEXT NOT NULL,
            profile_id TEXT NOT NULL,
            maximum_logical_restored_bytes INTEGER NOT NULL
                CHECK(maximum_logical_restored_bytes BETWEEN 1 AND 268435456),
            committed_at INTEGER NOT NULL CHECK(committed_at >= 0),
            integrity_digest BLOB NOT NULL CHECK(length(integrity_digest) = 32)
        )
        """#,
        #"""
        CREATE TABLE permissioned_remote_replica_incremental_results (
            request_id TEXT NOT NULL
                CHECK(length(request_id) BETWEEN 1 AND 512),
            request_sequence BLOB NOT NULL CHECK(length(request_sequence) = 8),
            request_digest BLOB NOT NULL CHECK(length(request_digest) = 32),
            batch_digest BLOB NOT NULL CHECK(length(batch_digest) = 32),
            receiver_did TEXT NOT NULL,
            space_uri TEXT NOT NULL,
            repository_did TEXT NOT NULL,
            expected_generation INTEGER NOT NULL
                CHECK(expected_generation > 0),
            expected_wire_revision TEXT NOT NULL,
            expected_commitment BLOB NOT NULL
                CHECK(length(expected_commitment) = 32),
            expected_marker BLOB NOT NULL CHECK(length(expected_marker) > 0),
            installed_generation INTEGER NOT NULL
                CHECK(installed_generation > 0),
            installed_wire_revision TEXT NOT NULL,
            installed_history_floor TEXT NOT NULL,
            installed_lthash BLOB NOT NULL CHECK(length(installed_lthash) = 2048),
            installed_commitment BLOB NOT NULL
                CHECK(length(installed_commitment) = 32),
            installed_marker BLOB NOT NULL CHECK(length(installed_marker) > 0),
            record_count INTEGER NOT NULL CHECK(record_count >= 0),
            operation_count INTEGER NOT NULL
                CHECK(operation_count BETWEEN 1 AND 4096),
            applied_at INTEGER NOT NULL CHECK(applied_at >= 0),
            integrity_digest BLOB NOT NULL CHECK(length(integrity_digest) = 32),
            PRIMARY KEY(receiver_did, space_uri, repository_did, request_id),
            UNIQUE(receiver_did, space_uri, repository_did, request_sequence)
        )
        """#,
        #"""
        CREATE TABLE permissioned_remote_replica_incremental_progress (
            receiver_did TEXT NOT NULL,
            space_uri TEXT NOT NULL,
            repository_did TEXT NOT NULL,
            replay_floor BLOB NOT NULL CHECK(length(replay_floor) = 8),
            high_watermark BLOB NOT NULL CHECK(length(high_watermark) = 8),
            PRIMARY KEY(receiver_did, space_uri, repository_did)
        )
        """#,
        #"""
        CREATE INDEX permissioned_remote_replica_incremental_results_retention
        ON permissioned_remote_replica_incremental_results(
            receiver_did, space_uri, repository_did, request_sequence
        )
        """#,
        #"""
        CREATE INDEX permissioned_remote_replica_import_expiry
        ON permissioned_remote_replica_import_sessions(status, expires_at)
        """#,
        #"""
        CREATE INDEX permissioned_remote_replica_import_index_canonical_page
        ON permissioned_remote_replica_import_index(
            session_id, length(path), path
        )
        """#,
        #"""
        CREATE INDEX permissioned_remote_replica_import_index_cid
        ON permissioned_remote_replica_import_index(session_id, cid)
        """#,
        #"""
        CREATE INDEX permissioned_remote_replica_records_page
        ON permissioned_remote_replica_records(
            space_uri, repository_did, generation, collection, rkey
        )
        """#,
        #"""
        CREATE INDEX permissioned_remote_replica_records_cid
        ON permissioned_remote_replica_records(
            space_uri, repository_did, generation, cid
        )
        """#,
        #"""
        CREATE INDEX permissioned_remote_replica_records_canonical_page
        ON permissioned_remote_replica_records(
            space_uri,
            repository_did,
            generation,
            length(CAST(collection || '/' || rkey AS BLOB)),
            CAST(collection || '/' || rkey AS BLOB)
        )
        """#,
        #"""
        CREATE UNIQUE INDEX permissioned_remote_replica_one_active_import
        ON permissioned_remote_replica_import_sessions(
            receiver_did, space_uri, repository_did
        )
        WHERE status IN ('receiving', 'verifying', 'verified', 'preparing')
        """#,
        #"""
        CREATE UNIQUE INDEX permissioned_remote_replica_one_active_import_v2
        ON permissioned_remote_replica_import_sessions(
            receiver_did, space_uri, repository_did
        )
        WHERE status IN ('receiving', 'verifying', 'verified', 'preparing')
           OR (status = 'poisoned' AND prepared_generation IS NOT NULL)
        """#,
        #"""
        CREATE TABLE plc_account_preparation_journal (
            singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
            request_id TEXT NOT NULL UNIQUE,
            canonical_handle TEXT NOT NULL,
            pds_origin TEXT NOT NULL,
            repository_revision TEXT NOT NULL,
            operation_signing_did_key TEXT NOT NULL,
            operation_rotation_did_key TEXT NOT NULL,
            operation_signature TEXT NOT NULL,
            signing_key_reference TEXT NOT NULL,
            rotation_key_reference TEXT NOT NULL,
            public_genesis_commit_cid TEXT,
            stage INTEGER NOT NULL CHECK(stage BETWEEN 1 AND 4),
            CHECK(
                (stage = 1 AND public_genesis_commit_cid IS NULL)
                OR (stage > 1 AND public_genesis_commit_cid IS NOT NULL)
            )
        )
        """#,
        #"""
        CREATE TABLE plc_identity_operations (
            sequence INTEGER PRIMARY KEY CHECK(sequence > 0),
            cid TEXT NOT NULL UNIQUE,
            previous_cid TEXT,
            canonical_json BLOB NOT NULL CHECK(length(canonical_json) > 0 AND length(canonical_json) <= 32768),
            created_at INTEGER NOT NULL CHECK(created_at >= 0),
            signing_key_generation INTEGER NOT NULL CHECK(signing_key_generation > 0),
            rotation_key_generation INTEGER NOT NULL CHECK(rotation_key_generation = signing_key_generation)
        )
        """#,
        #"""
        CREATE TABLE permissioned_repository_state (
            space_uri TEXT NOT NULL,
            author_did TEXT NOT NULL,
            revision INTEGER NOT NULL CHECK(revision >= 0),
            wire_revision TEXT NOT NULL,
            lthash BLOB NOT NULL CHECK(length(lthash) = 2048),
            current_commit BLOB NOT NULL,
            oplog_entry_count INTEGER NOT NULL DEFAULT 0 CHECK(oplog_entry_count >= 0),
            request_entry_count INTEGER NOT NULL DEFAULT 0 CHECK(request_entry_count >= 0),
            PRIMARY KEY(space_uri, author_did)
        )
        """#,
        #"""
        CREATE TABLE permissioned_restored_repository_closures (
            space_uri TEXT NOT NULL,
            author_did TEXT NOT NULL,
            reason TEXT NOT NULL CHECK(reason = 'missing-authority-policy-v1'),
            PRIMARY KEY(space_uri, author_did)
        )
        """#,
        #"""
        CREATE TABLE permissioned_repository_migrations (
            version INTEGER PRIMARY KEY CHECK(version > 0),
            applied_at INTEGER NOT NULL CHECK(applied_at >= 0)
        )
        """#,
        #"""
        CREATE TABLE permissioned_space_records (
            space_uri TEXT NOT NULL,
            author_did TEXT NOT NULL,
            collection TEXT NOT NULL,
            rkey TEXT NOT NULL,
            value BLOB NOT NULL,
            cid TEXT NOT NULL,
            revision INTEGER NOT NULL CHECK(revision > 0),
            PRIMARY KEY(space_uri, author_did, collection, rkey)
        )
        """#,
        #"""
        CREATE TABLE permissioned_space_record_blobs (
            space_uri TEXT NOT NULL,
            author_did TEXT NOT NULL,
            collection TEXT NOT NULL,
            rkey TEXT NOT NULL,
            blob_cid TEXT NOT NULL,
            -- The wire TID of the record's last write. listBlobs' `since`
            -- compares against this lexically, exactly as the reference
            -- compares space_record.repoRev.
            wire_revision TEXT NOT NULL CHECK(length(wire_revision) = 13),
            PRIMARY KEY(space_uri, author_did, collection, rkey, blob_cid)
        )
        """#,
        #"""
        CREATE INDEX permissioned_space_record_blobs_page
        ON permissioned_space_record_blobs(space_uri, author_did, blob_cid)
        """#,
        #"""
        CREATE TABLE permissioned_space_oplog (
            space_uri TEXT NOT NULL,
            author_did TEXT NOT NULL,
            revision INTEGER NOT NULL CHECK(revision > 0),
            operation_index INTEGER NOT NULL CHECK(operation_index >= 0),
            wire_revision TEXT NOT NULL,
            action TEXT NOT NULL CHECK(action IN ('create', 'update', 'delete')),
            collection TEXT NOT NULL,
            rkey TEXT NOT NULL,
            value BLOB,
            cid TEXT,
            previous_cid TEXT,
            commitment BLOB NOT NULL,
            PRIMARY KEY(space_uri, author_did, revision, operation_index),
            CHECK(
                (action IN ('create', 'update') AND value IS NOT NULL AND cid IS NOT NULL)
                OR (action = 'delete' AND value IS NULL AND cid IS NULL)
            ),
            CHECK(
                (action = 'create' AND previous_cid IS NULL)
                OR (action IN ('update', 'delete') AND previous_cid IS NOT NULL)
            )
        )
        """#,
        #"""
        CREATE TABLE permissioned_space_requests (
            request_id TEXT PRIMARY KEY,
            space_uri TEXT NOT NULL,
            author_did TEXT NOT NULL,
            base_revision INTEGER NOT NULL CHECK(base_revision >= 0),
            final_revision INTEGER NOT NULL CHECK(final_revision >= base_revision),
            event_id TEXT NOT NULL UNIQUE,
            -- Receipts are retained to the same depth as the oplog. Rows
            -- written before this column existed carry the zero default and
            -- are therefore evicted before any stamped row.
            created_at INTEGER NOT NULL DEFAULT 0 CHECK(created_at >= 0)
        )
        """#,
        #"""
        CREATE INDEX permissioned_space_requests_retention
        ON permissioned_space_requests(space_uri, author_did, final_revision)
        """#,
        #"""
        CREATE TABLE permissioned_space_outbox (
            id TEXT PRIMARY KEY,
            space_uri TEXT NOT NULL,
            author_did TEXT NOT NULL,
            revision INTEGER NOT NULL CHECK(revision >= 0),
            payload BLOB NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
            created_at INTEGER NOT NULL CHECK(created_at >= 0),
            available_at INTEGER NOT NULL CHECK(available_at >= 0),
            lease_token TEXT,
            lease_expires_at INTEGER,
            CHECK(
                (lease_token IS NULL AND lease_expires_at IS NULL)
                OR (lease_token IS NOT NULL AND lease_expires_at IS NOT NULL
                    AND lease_expires_at >= 0)
            )
        )
        """#,
        #"""
        CREATE INDEX permissioned_space_outbox_pending
        ON permissioned_space_outbox(created_at, id)
        """#,
        #"""
        CREATE TABLE blob_payloads (
            cid TEXT PRIMARY KEY,
            -- `payload` is retained only to migrate pre-CAS rows. New rows
            -- carry a zero-length marker and are read from a private file.
            payload BLOB NOT NULL,
            storage_kind TEXT NOT NULL DEFAULT 'legacy-sqlite'
                CHECK(storage_kind IN ('legacy-sqlite', 'cas-v1')),
            -- Physical CAS lifecycle/reclamation is keyed by this digest,
            -- not the logical CID. A legacy sha256 label and CIDv1/raw label
            -- can legitimately name the same immutable file.
            cas_digest TEXT CHECK(cas_digest IS NULL OR length(cas_digest) = 64),
            byte_count INTEGER CHECK(byte_count >= 0),
            mime_type TEXT
        )
        """#,
        #"""
        CREATE TABLE blob_namespace_references (
            cid TEXT NOT NULL REFERENCES blob_payloads(cid) ON DELETE CASCADE,
            -- `staged` is an uploaded blob no commit has claimed yet. Only
            -- `public` is served to an anonymous reader; a staged edge is
            -- consumed by the public or permissioned commit that promotes it,
            -- or it expires.
            namespace_kind TEXT NOT NULL
                CHECK(namespace_kind IN ('public', 'space', 'staged')),
            space_uri TEXT NOT NULL,
            -- Unix seconds this edge was created, and the only input to both
            -- sweeps: staged expiry, and garbage collection of a public edge
            -- no repository record justifies. A NULL is never swept, so a
            -- writer that forgets to stamp an edge leaks storage rather than
            -- deleting a live blob.
            created_at INTEGER CHECK(created_at IS NULL OR created_at >= 0),
            PRIMARY KEY(cid, namespace_kind, space_uri),
            CHECK(
                (namespace_kind = 'public' AND space_uri = '')
                OR (namespace_kind = 'space' AND length(space_uri) > 0)
                OR (namespace_kind = 'staged' AND space_uri = '')
            )
        )
        """#,
        #"""
        CREATE INDEX permissioned_space_outbox_available
        ON permissioned_space_outbox(available_at, created_at, id)
        """#,
        #"""
        CREATE TABLE "blob_cas_lifecycle" (
            digest_hex TEXT PRIMARY KEY CHECK(length(digest_hex) = 64),
            state TEXT NOT NULL CHECK(state IN ('creating', 'ready', 'reclaiming')),
            updated_at INTEGER NOT NULL CHECK(updated_at >= 0)
        )
        """#,
        #"""
        CREATE INDEX blob_namespace_references_sweep
        ON blob_namespace_references(namespace_kind, created_at)
        """#,
        #"""
        CREATE TABLE public_event_outbox (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_key TEXT NOT NULL UNIQUE,
            kind TEXT NOT NULL CHECK(kind IN ('commit', 'sync')),
            lifecycle_generation INTEGER NOT NULL DEFAULT 0
                CHECK(lifecycle_generation >= 0),
            payload BLOB NOT NULL CHECK(length(payload) > 0),
            car_bytes BLOB NOT NULL CHECK(length(car_bytes) > 0),
            attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
            created_at INTEGER NOT NULL CHECK(created_at >= 0),
            available_at INTEGER NOT NULL CHECK(available_at >= 0),
            lease_token TEXT,
            lease_expires_at INTEGER, completed INTEGER NOT NULL DEFAULT 0 CHECK(completed IN (0, 1)),
            CHECK(
                (lease_token IS NULL AND lease_expires_at IS NULL)
                OR (
                    lease_token IS NOT NULL
                    AND lease_expires_at IS NOT NULL
                    AND lease_expires_at >= 0
                )
            )
        )
        """#,
        #"""
        CREATE TABLE permissioned_simple_space_authorities (
            space_uri TEXT PRIMARY KEY,
            owner_did TEXT NOT NULL,
            policy TEXT NOT NULL CHECK(policy IN ('public', 'member-list', 'managing-app')),
            app_access TEXT NOT NULL CHECK(app_access IN ('open', 'allow-list')),
            managing_app TEXT,
            is_deleted INTEGER NOT NULL CHECK(is_deleted IN (0, 1)),
            revision INTEGER NOT NULL CHECK(revision > 0),
            created_at INTEGER NOT NULL CHECK(created_at >= 0),
            updated_at INTEGER NOT NULL CHECK(updated_at >= created_at),
            CHECK(managing_app IS NULL OR length(managing_app) > 0)
        )
        """#,
        #"""
        CREATE TABLE permissioned_simple_space_members (
            space_uri TEXT NOT NULL REFERENCES permissioned_simple_space_authorities(space_uri) ON DELETE CASCADE,
            member_did TEXT NOT NULL,
            PRIMARY KEY(space_uri, member_did)
        )
        """#,
        #"""
        CREATE TABLE permissioned_simple_space_clients (
            space_uri TEXT NOT NULL REFERENCES permissioned_simple_space_authorities(space_uri) ON DELETE CASCADE,
            client_id TEXT NOT NULL,
            PRIMARY KEY(space_uri, client_id)
        )
        """#,
        #"""
        CREATE TABLE permissioned_simple_space_managing_app_decisions (
            space_uri TEXT NOT NULL REFERENCES permissioned_simple_space_authorities(space_uri) ON DELETE CASCADE,
            user_did TEXT NOT NULL,
            PRIMARY KEY(space_uri, user_did)
        )
        """#,
        #"""
        CREATE TABLE permissioned_space_writers (
            space_uri TEXT NOT NULL REFERENCES permissioned_simple_space_authorities(space_uri) ON DELETE CASCADE,
            repo_did TEXT NOT NULL,
            wire_revision TEXT NOT NULL,
            commitment BLOB NOT NULL CHECK(length(commitment) = 32),
            updated_at INTEGER NOT NULL CHECK(updated_at >= 0),
            PRIMARY KEY(space_uri, repo_did)
        )
        """#,
        #"""
        CREATE TABLE permissioned_space_notification_registrations (
            space_uri TEXT NOT NULL REFERENCES permissioned_simple_space_authorities(space_uri) ON DELETE CASCADE,
            endpoint TEXT NOT NULL,
            repo_did TEXT,
            expires_at INTEGER NOT NULL CHECK(expires_at >= 0),
            updated_at INTEGER NOT NULL CHECK(updated_at >= 0),
            service_did TEXT,
            PRIMARY KEY(space_uri, endpoint),
            CHECK(length(endpoint) > 0)
        )
        """#,
        #"""
        CREATE TABLE permissioned_space_recipient_tombstones (
            space_uri TEXT PRIMARY KEY,
            authority_did TEXT NOT NULL,
            deletion_event_id TEXT NOT NULL,
            closed_at INTEGER NOT NULL CHECK(closed_at >= 0)
        )
        """#,
        #"""
        CREATE TABLE permissioned_space_notification_fanout (
            id TEXT PRIMARY KEY,
            source_issuer TEXT NOT NULL,
            source_event_id TEXT NOT NULL,
            kind TEXT NOT NULL CHECK(kind IN ('write', 'deleted')),
            space_uri TEXT NOT NULL,
            repo_did TEXT,
            wire_revision TEXT,
            commitment BLOB,
            endpoint TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
            created_at INTEGER NOT NULL CHECK(created_at >= 0),
            available_at INTEGER NOT NULL CHECK(available_at >= 0),
            lease_token TEXT,
            lease_expires_at INTEGER,
            UNIQUE(source_issuer, source_event_id, kind, endpoint),
            CHECK(
                (kind = 'write' AND repo_did IS NOT NULL AND wire_revision IS NOT NULL
                    AND commitment IS NOT NULL AND length(commitment) = 32)
                OR (kind = 'deleted' AND repo_did IS NULL AND wire_revision IS NULL
                    AND commitment IS NULL)
            ),
            CHECK(
                (lease_token IS NULL AND lease_expires_at IS NULL)
                OR (lease_token IS NOT NULL AND lease_expires_at IS NOT NULL
                    AND lease_expires_at >= 0)
            )
        )
        """#,
        #"""
        CREATE INDEX permissioned_space_writers_page
        ON permissioned_space_writers(space_uri, repo_did)
        """#,
        #"""
        CREATE INDEX permissioned_space_notification_fanout_available
        ON permissioned_space_notification_fanout(available_at, created_at, id)
        """#,
        #"""
        CREATE TABLE permissioned_space_notification_receipts (
            issuer TEXT NOT NULL,
            event_id TEXT NOT NULL,
            space_uri TEXT NOT NULL,
            received_at INTEGER NOT NULL CHECK(received_at >= 0),
            PRIMARY KEY(issuer, event_id, space_uri)
        )
        """#,
    ]
}
