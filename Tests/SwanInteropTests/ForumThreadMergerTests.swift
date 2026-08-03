import Foundation
import SwanInterop
import SwanSpaces
import XCTest

final class ForumThreadMergerTests: XCTestCase {
    private let authority = "did:plc:abcdefghijklmnopqrstuvwx"
    private let alice = "did:plc:aliceaaaaaaaaaaaaaaaaaaa"
    private let bob = "did:plc:boobbbbbbbbbbbbbbbbbbbbb"
    private let carol = "did:plc:carolccccccccccccccccccc"

    private var space: SpaceURI {
        try! SpaceURI(
            authority: authority,
            spaceType: "blue.catbird.lab.forum",
            skey: "lab-1"
        )
    }

    private func record(
        author: String,
        collection: String = "blue.catbird.lab.post",
        rkey: String,
        text: String,
        revision: UInt64 = 1,
        replyRoot: String? = nil,
        replyParent: String? = nil
    ) -> ForumRecord {
        ForumRecord(
            uri: try! SpaceRecordURI(
                space: space,
                author: author,
                collection: collection,
                rkey: rkey
            ),
            cid: "bafkreigh2akiscaildcqabsyg3dfr6yo3e5gjr4wzrfpz6k5j5v7aqp2mse",
            revision: revision,
            text: text,
            createdAt: nil,
            replyRoot: replyRoot,
            replyParent: replyParent
        )
    }

    private func uri(_ record: ForumRecord) -> String { record.recordURI }

    func testEmptyInputProducesEmptyThread() {
        let thread = ForumThreadMerger.merge([])
        XCTAssertTrue(thread.roots.isEmpty)
        XCTAssertTrue(thread.unlinked.isEmpty)
        XCTAssertEqual(thread.recordCount, 0)
    }

    func testSingleRootPost() {
        let post = record(author: alice, rkey: "2222222222222", text: "hello")
        let thread = ForumThreadMerger.merge([post])
        XCTAssertEqual(thread.roots.count, 1)
        XCTAssertEqual(thread.roots[0].record, post)
        XCTAssertTrue(thread.roots[0].replies.isEmpty)
        XCTAssertTrue(thread.unlinked.isEmpty)
        XCTAssertEqual(thread.postCount, 1)
        XCTAssertEqual(thread.replyCount, 0)
    }

    func testNestedRepliesAttachUnderParent() {
        let root = record(author: alice, rkey: "2222222222222", text: "root")
        let reply1 = record(
            author: bob,
            rkey: "2222222222223",
            text: "first reply",
            replyRoot: uri(root),
            replyParent: uri(root)
        )
        let reply2 = record(
            author: carol,
            rkey: "2222222222224",
            text: "second level",
            replyRoot: uri(root),
            replyParent: uri(reply1)
        )
        let thread = ForumThreadMerger.merge([reply1, root, reply2])
        XCTAssertEqual(thread.roots.count, 1)
        XCTAssertEqual(thread.roots[0].record, root)
        XCTAssertEqual(thread.roots[0].replies.count, 1)
        XCTAssertEqual(thread.roots[0].replies[0].record, reply1)
        XCTAssertEqual(thread.roots[0].replies[0].replies.count, 1)
        XCTAssertEqual(thread.roots[0].replies[0].replies[0].record, reply2)
        XCTAssertTrue(thread.unlinked.isEmpty)
        XCTAssertEqual(thread.replyCount, 2)
    }

    func testOrphanedReplyGoesToUnlinkedSection() {
        let root = record(author: alice, rkey: "2222222222222", text: "root")
        let orphan = record(
            author: bob,
            rkey: "2222222222223",
            text: "parent is missing",
            replyRoot: uri(root),
            replyParent: "at://did:plc:ghostggggggggggggggggggg/space/blue.catbird.lab.forum/lab-1/did:plc:ghostggggggggggggggggggg/blue.catbird.lab.post/2222222222229"
        )
        let thread = ForumThreadMerger.merge([root, orphan])
        XCTAssertEqual(thread.roots.count, 1)
        XCTAssertTrue(thread.roots[0].replies.isEmpty)
        XCTAssertEqual(thread.unlinked.count, 1)
        XCTAssertEqual(thread.unlinked[0].record, orphan)
        XCTAssertEqual(thread.replyCount, 1)
        XCTAssertEqual(thread.unlinked.count, 1)
    }

    func testTwoWritersMergeIntoOneThread() {
        let root = record(author: alice, rkey: "2222222222222", text: "from alice")
        let reply = record(
            author: bob,
            rkey: "2222222222223",
            text: "from bob",
            replyRoot: uri(root),
            replyParent: uri(root)
        )
        let thread = ForumThreadMerger.merge([reply, root])
        XCTAssertEqual(thread.roots.count, 1)
        XCTAssertEqual(thread.roots[0].record.authorDID, alice)
        XCTAssertEqual(thread.roots[0].replies.count, 1)
        XCTAssertEqual(thread.roots[0].replies[0].record.authorDID, bob)
        XCTAssertEqual(thread.roots[0].replies[0].record.replyParent, uri(root))
    }

    func testRootsAndSiblingsAreTimeOrdered() {
        let older = ForumRecord(
            uri: record(author: alice, rkey: "2222222222222", text: "older root").uri,
            cid: "bafkreigh2akiscaildcqabsyg3dfr6yo3e5gjr4wzrfpz6k5j5v7aqp2mse",
            revision: 1,
            text: "older root",
            createdAt: Date(timeIntervalSince1970: 1_000),
            replyRoot: nil,
            replyParent: nil
        )
        let newer = ForumRecord(
            uri: record(author: bob, rkey: "2222222222227", text: "newer root").uri,
            cid: "bafkreigh2akiscaildcqabsyg3dfr6yo3e5gjr4wzrfpz6k5j5v7aqp2mse",
            revision: 1,
            text: "newer root",
            createdAt: Date(timeIntervalSince1970: 2_000),
            replyRoot: nil,
            replyParent: nil
        )
        let thread = ForumThreadMerger.merge([newer, older])
        XCTAssertEqual(thread.roots.map(\.record.text), ["older root", "newer root"])

        let root = record(author: alice, rkey: "2222222222222", text: "root")
        let lateSibling = ForumRecord(
            uri: record(author: bob, rkey: "2222222222229", text: "late sibling").uri,
            cid: "bafkreigh2akiscaildcqabsyg3dfr6yo3e5gjr4wzrfpz6k5j5v7aqp2mse",
            revision: 1,
            text: "late sibling",
            createdAt: Date(timeIntervalSince1970: 2_000),
            replyRoot: uri(root),
            replyParent: uri(root)
        )
        let earlySibling = ForumRecord(
            uri: record(author: carol, rkey: "2222222222225", text: "early sibling").uri,
            cid: "bafkreigh2akiscaildcqabsyg3dfr6yo3e5gjr4wzrfpz6k5j5v7aqp2mse",
            revision: 1,
            text: "early sibling",
            createdAt: Date(timeIntervalSince1970: 1_000),
            replyRoot: uri(root),
            replyParent: uri(root)
        )
        let threaded = ForumThreadMerger.merge([root, lateSibling, earlySibling])
        XCTAssertEqual(
            threaded.roots[0].replies.map(\.record.text),
            ["early sibling", "late sibling"]
        )
    }

    func testExplicitCreatedAtBeatsRkeyOrdering() {
        let oldTid = record(author: alice, rkey: "2222222222222", text: "old tid, new date")
        let newTid = record(author: bob, rkey: "2222222222227", text: "new tid, old date")
        let old = ForumRecord(
            uri: oldTid.uri,
            cid: oldTid.cid,
            revision: 1,
            text: oldTid.text,
            createdAt: Date(timeIntervalSince1970: 2_000),
            replyRoot: nil,
            replyParent: nil
        )
        let fresh = ForumRecord(
            uri: newTid.uri,
            cid: newTid.cid,
            revision: 1,
            text: newTid.text,
            createdAt: Date(timeIntervalSince1970: 1_000),
            replyRoot: nil,
            replyParent: nil
        )
        let thread = ForumThreadMerger.merge([old, fresh])
        XCTAssertEqual(thread.roots.map(\.record.text), ["new tid, old date", "old tid, new date"])
    }

    func testSelfAnchoredReplyIsARoot() {
        let anchorURI = "at://did:plc:abcdefghijklmnopqrstuvwx/space/blue.catbird.lab.forum/lab-1/did:plc:aliceaaaaaaaaaaaaaaaaaaa/blue.catbird.lab.post/2222222222222"
        let selfAnchored = record(
            author: alice,
            rkey: "2222222222222",
            text: "self anchored",
            replyRoot: anchorURI,
            replyParent: anchorURI
        )
        let thread = ForumThreadMerger.merge([selfAnchored])
        XCTAssertEqual(thread.roots.count, 1)
        XCTAssertEqual(thread.roots[0].record, selfAnchored)
        XCTAssertTrue(thread.unlinked.isEmpty)
    }

    func testMutualReplyCycleLandsBothInUnlinked() {
        let a = record(
            author: alice,
            rkey: "2222222222222",
            text: "a",
            replyRoot: uri(record(author: alice, rkey: "2222222222223", text: "b")),
            replyParent: uri(record(author: alice, rkey: "2222222222223", text: "b"))
        )
        let b = record(
            author: alice,
            rkey: "2222222222223",
            text: "b",
            replyRoot: uri(a),
            replyParent: uri(a)
        )
        let thread = ForumThreadMerger.merge([a, b])
        XCTAssertTrue(thread.roots.isEmpty)
        XCTAssertEqual(thread.unlinked.count, 2)
    }

    func testRepliesOfBrokenParentChainLandInUnlinked() {
        let root = record(author: alice, rkey: "2222222222222", text: "root")
        let middle = record(
            author: bob,
            rkey: "2222222222223",
            text: "middle",
            replyRoot: uri(root),
            replyParent: uri(root)
        )
        let broken = record(
            author: carol,
            rkey: "2222222222224",
            text: "broken chain",
            replyRoot: uri(root),
            replyParent: uri(middle)
        )
        // middle is deleted from the synchronized set, so broken has no parent.
        let thread = ForumThreadMerger.merge([root, broken])
        XCTAssertEqual(thread.roots.count, 1)
        XCTAssertTrue(thread.roots[0].replies.isEmpty)
        XCTAssertEqual(thread.unlinked.count, 1)
        XCTAssertEqual(thread.unlinked[0].record, broken)
    }

    func testReplyCollectionRecordsStillMerge() {
        let root = record(
            author: alice,
            collection: "blue.catbird.lab.reply",
            rkey: "2222222222222",
            text: "root in reply collection"
        )
        let child = record(
            author: bob,
            collection: "blue.catbird.lab.reply",
            rkey: "2222222222223",
            text: "child",
            replyRoot: uri(root),
            replyParent: uri(root)
        )
        let thread = ForumThreadMerger.merge([root, child])
        XCTAssertEqual(thread.roots.count, 1)
        XCTAssertEqual(thread.roots[0].replies.count, 1)
    }

    func testRenderProducesIndentedPlainText() {
        let root = record(author: alice, rkey: "2222222222222", text: "hello")
        let reply = record(
            author: bob,
            rkey: "2222222222223",
            text: "hi",
            replyRoot: uri(root),
            replyParent: uri(root)
        )
        let thread = ForumThreadMerger.merge([root, reply])
        let rendered = ForumThreadRender.render(thread)
        XCTAssertTrue(rendered.contains("@\(alice): hello"))
        XCTAssertTrue(rendered.contains("  @\(bob): hi"))
        XCTAssertFalse(rendered.contains("unlinked"))
    }

    func testRenderMarksUnlinkedSection() {
        let orphan = record(
            author: alice,
            rkey: "2222222222222",
            text: "lost",
            replyRoot: "at://did:plc:ghostggggggggggggggggggg/space/blue.catbird.lab.forum/lab-1/did:plc:ghostggggggggggggggggggg/blue.catbird.lab.post/2222222222229",
            replyParent: "at://did:plc:ghostggggggggggggggggggg/space/blue.catbird.lab.forum/lab-1/did:plc:ghostggggggggggggggggggg/blue.catbird.lab.post/2222222222229"
        )
        let thread = ForumThreadMerger.merge([orphan])
        let rendered = ForumThreadRender.render(thread)
        XCTAssertTrue(rendered.contains("unlinked"))
        XCTAssertTrue(rendered.contains("@\(alice): lost"))
    }
}
