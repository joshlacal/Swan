import Foundation
import Petrel
import SwanSpaces

/// One decoded forum post or reply record from a permissioned space.
///
/// This is the pure, testable domain value for the `swan lab forum` thread
/// merger. It deliberately carries no credentials, tokens, or proof material:
/// the syncer keeps those in the network layer and hands only record facts to
/// the merger.
public struct ForumRecord: Sendable, Equatable, Hashable {
    public let uri: SpaceRecordURI
    public let cid: String
    public let revision: UInt64
    public let text: String
    public let createdAt: Date?
    /// Full `at:space/` record URI of the thread root, or nil for a root post.
    public let replyRoot: String?
    /// Full `at:space/` record URI of the immediate parent, or nil for a root post.
    public let replyParent: String?

    public init(
        uri: SpaceRecordURI,
        cid: String,
        revision: UInt64,
        text: String,
        createdAt: Date?,
        replyRoot: String?,
        replyParent: String?
    ) {
        self.uri = uri
        self.cid = cid
        self.revision = revision
        self.text = text
        self.createdAt = createdAt
        self.replyRoot = replyRoot
        self.replyParent = replyParent
    }

    /// The writer DID that authored this record.
    public var authorDID: String { uri.author }

    /// The collection this record belongs to (`blue.catbird.lab.post` or
    /// `blue.catbird.lab.reply`).
    public var collection: String { uri.collection }

    /// Full record URI, e.g. `at:space/did:plc:.../.../.../did:plc:.../.../...`.
    public var recordURI: String { uri.rawValue }

    /// Whether this record is a root post: no reply reference, or a reply
    /// whose root is itself (a self-anchored root).
    public var isRoot: Bool {
        guard let root = replyRoot else { return true }
        return root == recordURI
    }
}

/// Decodes forum record values from canonical DAG-CBOR. The space layer is
/// collection-agnostic, so this implements the tiny `{text, reply, createdAt}`
/// shape directly instead of requiring a new lexicon.
public enum ForumRecordDecoding {
    public enum Error: Swift.Error, Sendable, Equatable {
        case malformedValue
        case invalidText
        case invalidReplyReference
        case invalidCreatedAt
    }

    private struct ForumReplyValue: Decodable, DAGCBORDecodable {
        let root: String
        let parent: String
    }

    private struct ForumRecordValue: Decodable, DAGCBORDecodable {
        let text: String
        let reply: ForumReplyValue?
        let createdAt: String?
    }

    /// Decodes one DAG-CBOR record value into a `ForumRecord`.
    public static func decode(
        uri: SpaceRecordURI,
        cid: String,
        revision: UInt64,
        value: Data
    ) throws -> ForumRecord {
        let decoded: ForumRecordValue
        do {
            decoded = try DAGCBOR.decode(value)
        } catch {
            throw Error.malformedValue
        }
        let text = decoded.text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, text.utf8.count <= 4_096 else {
            throw Error.invalidText
        }
        let createdAt: Date?
        if let raw = decoded.createdAt {
            let formatter = ISO8601DateFormatter()
            formatter.formatOptions = [.withInternetDateTime]
            guard let parsed = formatter.date(from: raw) else {
                throw Error.invalidCreatedAt
            }
            createdAt = parsed
        } else {
            createdAt = nil
        }
        var replyRoot: String?
        var replyParent: String?
        if let reply = decoded.reply {
            // Reply refs are record values (covered by the record CID), so
            // ones written during the spaces alpha keep the `at://.../space/`
            // form. Read them leniently and compare in the current form.
            // TODO: remove before beta, with SpaceURI.fromLegacySpaceURI.
            replyRoot = SpaceURI.fromLegacySpaceURI(reply.root) ?? reply.root
            replyParent = SpaceURI.fromLegacySpaceURI(reply.parent) ?? reply.parent
            guard !reply.root.isEmpty, reply.root.utf8.count <= 4_096,
                  !reply.parent.isEmpty, reply.parent.utf8.count <= 4_096 else {
                throw Error.invalidReplyReference
            }
        }
        return ForumRecord(
            uri: uri,
            cid: cid,
            revision: revision,
            text: text,
            createdAt: createdAt,
            replyRoot: replyRoot,
            replyParent: replyParent
        )
    }
}

/// One node in the merged thread tree.
public struct ForumThreadNode: Sendable, Equatable {
    public let record: ForumRecord
    public let replies: [ForumThreadNode]

    public init(record: ForumRecord, replies: [ForumThreadNode]) {
        self.record = record
        self.replies = replies
    }
}

/// A merged thread: root posts with their reply subtrees, plus an
/// `unlinked` section for replies whose parent record is not present in the
/// synchronized set.
public struct ForumThread: Sendable, Equatable {
    public let roots: [ForumThreadNode]
    public let unlinked: [ForumThreadNode]

    public init(roots: [ForumThreadNode], unlinked: [ForumThreadNode]) {
        self.roots = roots
        self.unlinked = unlinked
    }

    public var postCount: Int { roots.count }
    public var replyCount: Int {
        roots.reduce(0) { $0 + Self.descendantCount($1) } + unlinked.count
    }
    public var recordCount: Int { postCount + replyCount }

    private static func descendantCount(_ node: ForumThreadNode) -> Int {
        node.replies.reduce(0) { $0 + 1 + descendantCount($1) }
    }
}

/// Pure deterministic merge of forum records into one thread tree.
///
/// Semantics:
/// - A record whose `reply.root` is nil or equal to its own URI is a root.
/// - Every other record is a reply attached under the record addressed by its
///   `reply.parent`.
/// - A reply whose parent record is absent from the input is placed in the
///   `unlinked` section (the orphaned-reply rule).
/// - Ordering is by record time (`createdAt` when present, otherwise the rkey
///   TID timestamp), then revision, then record URI, ascending, at every
///   level. Roots and siblings are ordered the same way.
/// - Records authored by different writer DIDs merge into the same tree.
public enum ForumThreadMerger {
    /// Merges a batch of records from any number of writers into one thread.
    public static func merge(_ records: [ForumRecord]) -> ForumThread {
        guard !records.isEmpty else {
            return ForumThread(roots: [], unlinked: [])
        }
        let byURI = Dictionary(
            records.map { ($0.recordURI, $0) },
            uniquingKeysWith: { first, _ in first }
        )
        var nodes = Dictionary(
            uniqueKeysWithValues: records.map { ($0.recordURI, ForumThreadNode(record: $0, replies: [])) }
        )
        let sorted = records.sorted(by: Self.orderedBefore)
        var placed = Set<String>()
        var roots: [ForumThreadNode] = []
        var unlinked: [ForumThreadNode] = []
        for record in sorted where record.isRoot && !placed.contains(record.recordURI) {
            var node = nodes[record.recordURI]!
            node = Self.attachDescendants(
                of: node,
                nodes: &nodes,
                byURI: byURI,
                placed: &placed,
                visited: []
            )
            nodes[record.recordURI] = node
            roots.append(node)
            placed.insert(record.recordURI)
        }
        // Remaining records are replies whose parent was absent or whose
        // parent chain never reached a root (a broken or cyclic chain). They
        // all land in the unlinked section, in the same deterministic order.
        for record in sorted where !placed.contains(record.recordURI) {
            unlinked.append(nodes[record.recordURI]!)
            placed.insert(record.recordURI)
        }
        return ForumThread(roots: roots, unlinked: unlinked)
    }

    private static func attachDescendants(
        of root: ForumThreadNode,
        nodes: inout [String: ForumThreadNode],
        byURI: [String: ForumRecord],
        placed: inout Set<String>,
        visited: Set<String>
    ) -> ForumThreadNode {
        var node = root
        var visited = visited
        visited.insert(root.record.recordURI)
        let children = byURI.values
            .filter { $0.replyParent == root.record.recordURI }
            .sorted(by: Self.orderedBefore)
        var childNodes: [ForumThreadNode] = []
        for child in children {
            guard !visited.contains(child.recordURI),
                  !placed.contains(child.recordURI),
                  var childNode = nodes[child.recordURI] else { continue }
            placed.insert(child.recordURI)
            childNode = attachDescendants(
                of: childNode,
                nodes: &nodes,
                byURI: byURI,
                placed: &placed,
                visited: visited
            )
            nodes[child.recordURI] = childNode
            childNodes.append(childNode)
        }
        node = ForumThreadNode(record: node.record, replies: childNodes)
        return node
    }

    /// Deterministic ordering key: time, then revision, then URI.
    private static func orderedBefore(_ lhs: ForumRecord, _ rhs: ForumRecord) -> Bool {
        let lhsTime = lhs.createdAt ?? Self.tidDate(lhs.uri.rkey)
        let rhsTime = rhs.createdAt ?? Self.tidDate(rhs.uri.rkey)
        if lhsTime != rhsTime { return lhsTime < rhsTime }
        if lhs.revision != rhs.revision { return lhs.revision < rhs.revision }
        return lhs.recordURI < rhs.recordURI
    }

    private static func tidDate(_ rkey: String) -> Date {
        guard let tid = try? TID(tidString: rkey) else {
            return Date(timeIntervalSince1970: 0)
        }
        return tid.date
    }
}

/// Plain-text rendering of a merged thread (the deliberately ugly forum).
public enum ForumThreadRender {
    public static func render(_ thread: ForumThread) -> String {
        var lines: [String] = []
        for (index, node) in thread.roots.enumerated() {
            if index > 0 { lines.append("") }
            render(node, depth: 0, into: &lines)
        }
        if !thread.unlinked.isEmpty {
            lines.append("")
            lines.append("-- unlinked replies (parent record absent) --")
            for node in thread.unlinked {
                render(node, depth: 1, into: &lines)
            }
        }
        return lines.joined(separator: "\n")
    }

    private static func render(
        _ node: ForumThreadNode,
        depth: Int,
        into lines: inout [String]
    ) {
        let record = node.record
        let timestamp = record.createdAt.map(Self.timestampFormatter.string) ?? ""
        let indent = String(repeating: "  ", count: depth)
        lines.append("\(indent)@\(record.authorDID): \(record.text)")
        if !timestamp.isEmpty {
            lines.append("\(indent)  (at \(timestamp) uri=\(record.recordURI) cid=\(record.cid))")
        }
        for reply in node.replies {
            render(reply, depth: depth + 1, into: &lines)
        }
    }

    private static let timestampFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
        formatter.timeZone = TimeZone(identifier: "UTC")
        return formatter
    }()
}

/// Sanitized JSON artifact for one forum thread sync. It contains only
/// counts, DIDs, CIDs, revision/commitment summaries, and post text; it never
/// contains credentials, tokens, or DPoP proofs.
public struct ForumThreadArtifact: Codable, Sendable, Equatable {
    public let profileID: String
    public let space: String
    public let status: String
    public let errorCode: String?
    public let writers: [ForumWriterStatus]
    public let recordCount: Int
    public let postCount: Int
    public let replyCount: Int
    public let unlinkedCount: Int
    public let thread: [ForumThreadNodeArtifact]
    public let fixturePolicy: String

    public init(
        profileID: String,
        space: String,
        status: String,
        errorCode: String?,
        writers: [ForumWriterStatus],
        recordCount: Int,
        postCount: Int,
        replyCount: Int,
        unlinkedCount: Int,
        thread: [ForumThreadNodeArtifact]
    ) {
        self.profileID = profileID
        self.space = space
        self.status = status
        self.errorCode = errorCode
        self.writers = writers
        self.recordCount = recordCount
        self.postCount = postCount
        self.replyCount = replyCount
        self.unlinkedCount = unlinkedCount
        self.thread = thread
        fixturePolicy = "counts, DIDs, CIDs, and thread text only; no credentials, tokens, or DPoP proofs"
    }
}

public struct ForumWriterStatus: Codable, Sendable, Equatable {
    public let did: String
    public let host: String
    public let outcome: String
    public let revision: String?
    public let commitment: String?
    public let recordCount: Int

    public init(
        did: String,
        host: String,
        outcome: String,
        revision: String?,
        commitment: String?,
        recordCount: Int
    ) {
        self.did = did
        self.host = host
        self.outcome = outcome
        self.revision = revision
        self.commitment = commitment
        self.recordCount = recordCount
    }
}

public struct ForumThreadNodeArtifact: Codable, Sendable, Equatable {
    public let uri: String
    public let authorDID: String
    public let cid: String
    public let text: String
    public let replies: [ForumThreadNodeArtifact]

    public init(
        uri: String,
        authorDID: String,
        cid: String,
        text: String,
        replies: [ForumThreadNodeArtifact]
    ) {
        self.uri = uri
        self.authorDID = authorDID
        self.cid = cid
        self.text = text
        self.replies = replies
    }
}

public enum ForumThreadArtifactBuilder {
    public static func artifact(
        profileID: String,
        space: String,
        status: String,
        errorCode: String?,
        writers: [ForumWriterStatus],
        thread: ForumThread
    ) -> ForumThreadArtifact {
        ForumThreadArtifact(
            profileID: profileID,
            space: space,
            status: status,
            errorCode: errorCode,
            writers: writers,
            recordCount: thread.recordCount,
            postCount: thread.postCount,
            replyCount: thread.replyCount,
            unlinkedCount: thread.unlinked.count,
            thread: thread.roots.map(Self.node) + thread.unlinked.map(Self.node)
        )
    }

    public static func node(_ threadNode: ForumThreadNode) -> ForumThreadNodeArtifact {
        ForumThreadNodeArtifact(
            uri: threadNode.record.recordURI,
            authorDID: threadNode.record.authorDID,
            cid: threadNode.record.cid,
            text: threadNode.record.text,
            replies: threadNode.replies.map(node)
        )
    }
}
