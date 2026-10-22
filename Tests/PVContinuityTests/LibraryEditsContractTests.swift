// Copyright 2026 iCube Project
// SPDX-License-Identifier: GPL-2.0-or-later
import XCTest
import PVLibraryMetadata
@testable import PVContinuity

final class LibraryEditsContractTests: XCTestCase {
    private let snapshot = UUID(uuidString: "aabbccdd-0011-2233-4455-66778899aabb")!
    private let prefix = "v1:aabbccdd-0011-2233-4455-66778899aabb:"

    func testCursorRoundTripsCanonicalOffsetsIncludingIntegerBoundary() throws {
        for offset in [0, 1, 128, Int.max] {
            let cursor = try ContinuityLibraryEditsCursor(snapshotID: snapshot, offset: offset)
            XCTAssertEqual(cursor.rawValue, prefix + String(offset))
            XCTAssertEqual(cursor.snapshotID, snapshot)
            XCTAssertEqual(cursor.offset, offset)
            XCTAssertEqual(ContinuityLibraryEditsCursor.parse(cursor.rawValue), cursor)
            XCTAssertLessThan(cursor.rawValue.utf8.count, LibraryEditsManifestPage.maxCursorBytes)
        }
        XCTAssertThrowsError(try ContinuityLibraryEditsCursor(snapshotID: snapshot, offset: -1))
    }

    func testCursorRejectsNoncanonicalAndMalformedValues() {
        let invalid = ["", "v2:" + String(prefix.dropFirst(3)) + "0", prefix + "-1", prefix + "-0", prefix + "+1",
            prefix + "00", prefix + "01", prefix + "", prefix + "1 ", prefix + " 1", prefix + "1:2",
            prefix + String(Int.max) + "0", prefix + "١", "v1:" + snapshot.uuidString + ":0",
            "v1:aabbccdd00112233445566778899aabb:0", "v1:{aabbccdd-0011-2233-4455-66778899aabb}:0"]
        for raw in invalid { XCTAssertNil(ContinuityLibraryEditsCursor.parse(raw), raw) }
    }

    func testRouteBuildersKeepDecodedQueryMeaningAndFixedPaths() throws {
        let base = URL(string: "http://host:1234/")!
        // Canonical disc identities can contain base64 /, + and =.
        for gameID in ["A?🦀", "~~~", "A?"] {
            let identity = try XCTUnwrap(LibraryMetadataStore.Identity.game(gameID: gameID, discNumber: 0, revision: 0)).rawValue
            let document = try ContinuityRoutes.libraryEditsDocumentURL(base: base, identity: identity)
            XCTAssertEqual(document.path, "/api/continuity/library/edits/document")
            XCTAssertEqual(URLComponents(url: document, resolvingAgainstBaseURL: false)?.queryItems,
                           [URLQueryItem(name: "identity", value: identity)])
        }
        for limit in [1, 128] {
            let url = try ContinuityRoutes.libraryEditsManifestURL(base: base, after: prefix + "128", limit: limit)
            XCTAssertEqual(url.path, "/api/continuity/library/edits/manifest")
            XCTAssertEqual(URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems,
                           [URLQueryItem(name: "after", value: prefix + "128"), URLQueryItem(name: "limit", value: String(limit))])
        }
        let first = try ContinuityRoutes.libraryEditsManifestURL(base: base, after: nil, limit: 1)
        XCTAssertEqual(URLComponents(url: first, resolvingAgainstBaseURL: false)?.queryItems,
                       [URLQueryItem(name: "limit", value: "1")])
        XCTAssertEqual(ContinuityRoutes.libraryEditsAuthStartURL(base: base).absoluteString, "http://host:1234/api/continuity/library/edits/auth/start")
        XCTAssertEqual(ContinuityRoutes.libraryEditsAuthCompleteURL(base: base).absoluteString, "http://host:1234/api/continuity/library/edits/auth/complete")
        XCTAssertEqual(ContinuityRoutes.libraryEditsMergeURL(base: base).absoluteString, "http://host:1234/api/continuity/library/edits/merge")
        XCTAssertEqual(ContinuityLibraryEdits.nonceHeader, "X-ICube-Edits-Nonce")
        XCTAssertEqual(ContinuityLibraryEdits.signatureHeader, "X-ICube-Edits-Signature")
    }

    func testRoutesRejectBadCursorIdentityAndLimitsBeforeBuilding() {
        let base = URL(string: "http://host/")!
        for limit in [Int.min, -1, 0, 129, Int.max] {
            XCTAssertThrowsError(try ContinuityRoutes.libraryEditsManifestURL(base: base, after: nil, limit: limit))
        }
        for cursor in ["", prefix + "01", "bad&token=secret"] {
            XCTAssertThrowsError(try ContinuityRoutes.libraryEditsManifestURL(base: base, after: cursor, limit: 1))
        }
        for identity in ["", "<UNKNOWN>", "game:R0FMRTAx:00:0", "sha256:" + String(repeating: "A", count: 64), "bad&token=secret"] {
            XCTAssertThrowsError(try ContinuityRoutes.libraryEditsDocumentURL(base: base, identity: identity))
        }
    }

    func testLegacyURLBuildersStayUnchanged() {
        let base = URL(string: "http://host:1234/")!
        XCTAssertEqual(ContinuityRoutes.manifestURL(base: base).absoluteString, "http://host:1234/api/continuity/manifest")
        XCTAssertEqual(ContinuityRoutes.mintURL(base: base).absoluteString, "http://host:1234/api/continuity/mint")
        XCTAssertEqual(ContinuityRoutes.libraryCatalogURL(base: base).absoluteString, "http://host:1234/api/continuity/library/catalog")
        XCTAssertEqual(ContinuityRoutes.fileURL(base: base, relativePath: "a&b").absoluteString, "http://host:1234/api/continuity/file?path=a%26b")
        XCTAssertEqual(ContinuityRoutes.libraryFileURL(base: base, key: "a&b", relativePath: "c=d").absoluteString,
                       "http://host:1234/api/continuity/library/file?key=a%26b&path=c%3Dd")
    }

    func testContextComposesActualMergeAndInvalidationPreventsFileGateEntry() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let fileLock = NSLock()
        var fileEntries = 0
        var writes = 0
        let store = try LibraryMetadataStore(directoryURL: dir, withFileAccess: { operation in
            fileLock.lock(); defer { fileLock.unlock() }
            fileEntries += 1
            try operation()
        }, write: { data, url in
            writes += 1
            try data.write(to: url, options: .atomic)
        })
        let identity = LibraryMetadataStore.Identity.game(gameID: "GALE01", discNumber: 0, revision: 0)!
        let data = try JSONSerialization.data(withJSONObject: [identity.rawValue + ":title": ["updatedAt": 123, "value": "Custom title"]])
        let provider: any ContinuityLibraryEditsProviding = StoreProvider(store: store)
        let peer = TrustedPeer(id: "peer", name: "TV", publicKey: Data(repeating: 1, count: 32))
        let gate = LibraryMetadataCommitGate()
        let context = ContinuityLibraryEditsCommitContext(peer: peer, gate: gate)
        XCTAssertEqual(context.peer, peer)
        let merged = try await provider.merge(identity: identity.rawValue, document: data, context: context)
        XCTAssertEqual(fileEntries, 1)
        XCTAssertEqual(writes, 1)
        XCTAssertEqual(try Data(contentsOf: dir.appendingPathComponent(identity.fileName)), merged)
        gate.invalidate()
        do {
            _ = try await provider.merge(identity: identity.rawValue, document: data, context: context)
            XCTFail("Revoked context admitted merge")
        } catch { XCTAssertTrue(error is LibraryMetadataCommitGate.GateError) }
        XCTAssertEqual(fileEntries, 1)
        XCTAssertEqual(writes, 1)
        let fresh = ContinuityLibraryEditsCommitContext(peer: peer, gate: gate)
        _ = try await provider.merge(identity: identity.rawValue, document: data, context: fresh)
        XCTAssertEqual(fileEntries, 2)
        XCTAssertEqual(writes, 1) // Identical document is idempotent.
    }

    func testThrowReleasesContextGateForRevocationAndFreshAdmission() throws {
        let gate = LibraryMetadataCommitGate()
        let peer = TrustedPeer(id: "peer", name: "TV", publicKey: Data())
        let context = ContinuityLibraryEditsCommitContext(peer: peer, gate: gate)
        XCTAssertThrowsError(try context.withPermit { throw ContinuityLibraryEditsProviderError.unavailable }) { error in
            XCTAssertEqual(error as? ContinuityLibraryEditsProviderError, .unavailable)
        }
        gate.invalidate()
        let fresh = ContinuityLibraryEditsCommitContext(peer: peer, gate: gate)
        XCTAssertEqual(try fresh.withPermit { 42 }, 42)
    }
}

/// A consumer supplies binding/preparation before entering the synchronous context.
private struct StoreProvider: ContinuityLibraryEditsProviding {
    let store: LibraryMetadataStore
    func manifest(after: String?, limit: Int) async throws -> LibraryEditsManifestPage {
        if after != nil { throw ContinuityLibraryEditsProviderError.staleCursor }
        return try LibraryEditsManifestPage(entries: [], nextCursor: nil)
    }
    func read(identity: String) async throws -> Data {
        guard let bound = LibraryMetadataStore.Identity.parseCanonical(identity) else {
            throw ContinuityLibraryEditsProviderError.identityUnavailable
        }
        return try store.exportDocument(for: bound)
    }
    func merge(identity: String, document: Data, context: ContinuityLibraryEditsCommitContext) async throws -> Data {
        guard let bound = LibraryMetadataStore.Identity.parseCanonical(identity) else {
            throw ContinuityLibraryEditsProviderError.identityUnavailable
        }
        return try context.withPermit { try store.mergeDocument(document, for: bound) }
    }
}
