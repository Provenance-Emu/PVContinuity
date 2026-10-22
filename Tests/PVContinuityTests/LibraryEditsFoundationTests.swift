// Copyright 2026 iCube Project
// SPDX-License-Identifier: GPL-2.0-or-later

import XCTest
import PVContinuity

final class LibraryEditsCapabilityTests: XCTestCase {
    private let legacyTXT = ["v": "1", "sid": "session", "tok": "secret", "name": "Melee", "plat": "gc", "gid": "GALE01", "lib": "1", "pid": "peer", "dt": "tv", "stem": "GALE01", "u0": "http://host/"]
    private let legacyJSON = #"{"deviceType":"tv","game":{"displayName":"Melee","gameID":"GALE01","platform":"gc"},"payloadVersion":1,"peerId":"peer","saveStateStem":"GALE01","sessionId":"session","sharesLibrary":true,"token":"secret","urlCandidates":["http:\/\/host\/"]}"#

    func testExactLegacyFixturesRemainUnchangedWithNoCapability() throws {
        let ad = try XCTUnwrap(ContinuityTXTRecord.decode(legacyTXT))
        XCTAssertNil(ad.libraryEditsVersion)
        XCTAssertFalse(ad.supportsLibraryEdits)
        XCTAssertEqual(ContinuityTXTRecord.encode(ad), legacyTXT)
        let data = Data(legacyJSON.utf8)
        XCTAssertEqual(try JSONDecoder().decode(ContinuityAdvertisement.self, from: data), ad)
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        XCTAssertEqual(try encoder.encode(ad), data)
        XCTAssertEqual(ContinuityAdvertisement(userInfo: ["continuityAdvertisement": data]), ad)
        XCTAssertEqual(ContinuityAdvertisement.activityType, "com.joemattiello.icube.continuity.play")
        XCTAssertEqual(ad.payloadVersion, 1)
    }

    func testOnlyKnownVersionEnablesCapabilityWithoutLosingROMOrHandoff() throws {
        for value in [nil, "1", "2", "garbage", "", "1.0"] as [String?] {
            var txt = legacyTXT
            txt["le"] = value
            txt["future-key"] = "ignored"
            let ad = try XCTUnwrap(ContinuityTXTRecord.decode(txt))
            XCTAssertEqual(ad.supportsLibraryEdits, value == "1")
            XCTAssertEqual(ad.game?.gameID, "GALE01")
            XCTAssertEqual(ad.token, "secret")
            XCTAssertTrue(ad.sharesLibrary)
            XCTAssertEqual(ad.saveStateStem, "GALE01")
            XCTAssertEqual(ad.urlCandidates, [URL(string: "http://host/")!])
        }
    }

    func testNoncanonicalVersionTextDoesNotEnableCapability() throws {
        for value in ["+1", "01", " 1", "1 ", "-1"] {
            var txt = legacyTXT
            txt["le"] = value
            let ad = try XCTUnwrap(ContinuityTXTRecord.decode(txt))
            XCTAssertFalse(ad.supportsLibraryEdits, "noncanonical capability: \(value)")
            XCTAssertEqual(ad.game?.gameID, "GALE01")
        }
    }

    func testCapabilitySurvivesActivityAndTokenRedaction() throws {
        let ad = ContinuityAdvertisement(sessionId: "s", token: "secret", game: nil, urlCandidates: [], libraryEditsVersion: 1)
        XCTAssertEqual(ContinuityLibraryEdits.currentVersion, 1)
        XCTAssertEqual(ContinuityAdvertisement(userInfo: ad.userInfoRepresentation), ad)
        let redacted = ad.redactedForBonjour()
        XCTAssertTrue(redacted.supportsLibraryEdits)
        XCTAssertEqual(redacted.token, "")
        XCTAssertEqual(ContinuityTXTRecord.encode(redacted)["le"], "1")
        XCTAssertNil(ContinuityTXTRecord.encode(redacted)["tok"])
        var unknown = ad
        unknown.libraryEditsVersion = 2
        XCTAssertFalse(unknown.supportsLibraryEdits)
        XCTAssertNil(ContinuityTXTRecord.encode(unknown)["le"])
    }
}

final class LibraryEditsGrantTests: XCTestCase {
    private func directory() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: url) }
        return url
    }

    private func peer(_ id: String = "peer", key: UInt8 = 1) -> TrustedPeer {
        TrustedPeer(id: id, name: "TV", publicKey: Data(repeating: key, count: 32), addedAt: Date(timeIntervalSince1970: 0))
    }

    func testAbsentDefaultDeniesAndPairingAloneDoesNotGrant() async throws {
        let dir = try directory()
        let trust = FileTrustStore(fileURL: dir.appendingPathComponent("trust.json"))
        await trust.add(peer())
        let store = FileLibraryEditsGrantStore(fileURL: dir.appendingPathComponent("edits.json"), trustStore: trust)
        let grant = try await store.grant(forPeerId: "peer")
        let all = try await store.allGrants()
        XCTAssertEqual(grant, .denied)
        XCTAssertTrue(all.isEmpty)
    }

    func testOptInRejectsUnpairedAndReplacedKeys() async throws {
        let dir = try directory()
        let trust = FileTrustStore(fileURL: dir.appendingPathComponent("trust.json"))
        let store = FileLibraryEditsGrantStore(fileURL: dir.appendingPathComponent("edits.json"), trustStore: trust)
        do { try await store.setGrant(.enabled, for: peer()); XCTFail("unpaired opt-in") }
        catch { XCTAssertEqual(error as? ContinuityLibraryEditsGrantError, .peerNotTrusted) }
        await trust.add(peer(key: 2))
        do { try await store.setGrant(.enabled, for: peer()); XCTFail("stale key opt-in") }
        catch { XCTAssertEqual(error as? ContinuityLibraryEditsGrantError, .peerNotTrusted) }
        let all = try await store.allGrants()
        XCTAssertTrue(all.isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.appendingPathComponent("edits.json").path))
    }

    func testPersistedOptInDoesNotSurviveKeyReplacementOrTrustRemoval() async throws {
        let dir = try directory()
        let trust = FileTrustStore(fileURL: dir.appendingPathComponent("trust.json"))
        await trust.add(peer())
        let url = dir.appendingPathComponent("edits.json")
        let store = FileLibraryEditsGrantStore(fileURL: url, trustStore: trust)
        try await store.setGrant(.enabled, for: peer())
        await trust.add(peer(key: 2))
        let stale = try await store.grant(forPeerId: "peer")
        XCTAssertEqual(stale, .denied)
        let reopened = FileLibraryEditsGrantStore(fileURL: url, trustStore: trust)
        let restarted = try await reopened.grant(forPeerId: "peer")
        let listed = try await reopened.allGrants()
        XCTAssertEqual(restarted, .denied)
        XCTAssertEqual(listed, ["peer": .denied])
        do { try await reopened.setGrant(.enabled, for: peer()); XCTFail("stale key opt-in") }
        catch { XCTAssertEqual(error as? ContinuityLibraryEditsGrantError, .peerNotTrusted) }
        try await reopened.setGrant(.enabled, for: peer(key: 2))
        let renewed = try await reopened.grant(forPeerId: "peer")
        XCTAssertEqual(renewed, .enabled)
        await trust.removePeer(withId: "peer")
        let unpaired = try await reopened.grant(forPeerId: "peer")
        let unpairedRestart = try await FileLibraryEditsGrantStore(fileURL: url, trustStore: trust).grant(forPeerId: "peer")
        XCTAssertEqual(unpaired, .denied)
        XCTAssertEqual(unpairedRestart, .denied)
    }

    func testPersistenceListingRemovalAndExplicitDenial() async throws {
        let dir = try directory()
        let trust = FileTrustStore(fileURL: dir.appendingPathComponent("trust.json"))
        await trust.add(peer())
        let url = dir.appendingPathComponent("edits.json")
        let store = FileLibraryEditsGrantStore(fileURL: url, trustStore: trust)
        try await store.setGrant(.enabled, for: peer())
        try await store.setGrant(.denied, for: peer("other"))
        let reopened = FileLibraryEditsGrantStore(fileURL: url, trustStore: trust)
        let all = try await reopened.allGrants()
        XCTAssertEqual(all, ["peer": .enabled, "other": .denied])
        try await reopened.removeGrant(forPeerId: "peer")
        let removed = try await reopened.grant(forPeerId: "peer")
        XCTAssertEqual(removed, .denied)
        try await reopened.removeAll()
        let empty = try await FileLibraryEditsGrantStore(fileURL: url, trustStore: trust).allGrants()
        XCTAssertTrue(empty.isEmpty)
    }

    func testFailedWriteLeavesMemoryAndExistingFileUnchanged() async throws {
        let dir = try directory()
        let trust = FileTrustStore(fileURL: dir.appendingPathComponent("trust.json"))
        await trust.add(peer())
        let url = dir.appendingPathComponent("edits.json")
        let store = FileLibraryEditsGrantStore(fileURL: url, trustStore: trust)
        try await store.setGrant(.denied, for: peer())
        let original = try Data(contentsOf: url)
        // A readable immutable file lets load succeed and makes atomic replacement fail.
        try FileManager.default.setAttributes([.immutable: true], ofItemAtPath: url.path)
        defer { try? FileManager.default.setAttributes([.immutable: false], ofItemAtPath: url.path) }
        do { try await store.setGrant(.enabled, for: peer()); XCTFail("write should fail") } catch {}
        XCTAssertEqual(try Data(contentsOf: url), original)
        let grant = try await store.grant(forPeerId: "peer")
        XCTAssertEqual(grant, .denied)
    }

    func testFailedRemovalLeavesMemoryAndFileUnchanged() async throws {
        let dir = try directory()
        let trust = FileTrustStore(fileURL: dir.appendingPathComponent("trust.json"))
        await trust.add(peer())
        let url = dir.appendingPathComponent("edits.json")
        let store = FileLibraryEditsGrantStore(fileURL: url, trustStore: trust)
        try await store.setGrant(.enabled, for: peer())
        let original = try Data(contentsOf: url)
        try FileManager.default.setAttributes([.immutable: true], ofItemAtPath: url.path)
        defer { try? FileManager.default.setAttributes([.immutable: false], ofItemAtPath: url.path) }
        do { try await store.removeGrant(forPeerId: "peer"); XCTFail("remove should fail") } catch {}
        do { try await store.removeAll(); XCTFail("clear should fail") } catch {}
        XCTAssertEqual(try Data(contentsOf: url), original)
        let grant = try await store.grant(forPeerId: "peer")
        XCTAssertEqual(grant, .enabled)
    }

    func testCorruptionAfterSuccessfulLoadCannotReuseOrOverwriteCachedConsent() async throws {
        let dir = try directory()
        let trust = FileTrustStore(fileURL: dir.appendingPathComponent("trust.json"))
        await trust.add(peer())
        let url = dir.appendingPathComponent("edits.json")
        let store = FileLibraryEditsGrantStore(fileURL: url, trustStore: trust)
        try await store.setGrant(.enabled, for: peer())
        let corrupt = Data("corrupt evidence".utf8)
        try corrupt.write(to: url)
        do { _ = try await store.grant(forPeerId: "peer"); XCTFail("cached consent must not hide corrupt storage") } catch {}
        do { try await store.setGrant(.enabled, for: peer()); XCTFail("must not overwrite corrupt storage") } catch {}
        do { try await store.removeAll(); XCTFail("must not erase corrupt storage") } catch {}
        XCTAssertEqual(try Data(contentsOf: url), corrupt)
    }

    func testCorruptFutureAndUnreadableFilesThrowWithoutOverwritingEvidence() async throws {
        let dir = try directory()
        let trust = FileTrustStore(fileURL: dir.appendingPathComponent("trust.json"))
        await trust.add(peer())
        let url = dir.appendingPathComponent("edits.json")
        for raw in [
            "corrupt",
            #"{"version":1,"grants":{"peer":{"grant":"future-grant","publicKey":"AQ=="}}}"#,
            #"{"version":1,"grants":{"peer":{"grant":"enabled","publicKey":"AQ==","future":true}}}"#,
            #"{"version":1,"grants":{"peer":{"grant":"enabled"}}}"#,
            #"{"version":1,"grants":{"peer":{"grant":"enabled","publicKey":"bad-base64"}}}"#,
            #"{"version":1,"grants":{},"future":true}"#,
            #"{"version":2,"grants":{}}"#
        ] {
            let data = Data(raw.utf8)
            try data.write(to: url)
            let store = FileLibraryEditsGrantStore(fileURL: url, trustStore: trust)
            do { _ = try await store.grant(forPeerId: "peer"); XCTFail("invalid read") } catch {}
            do { try await store.setGrant(.enabled, for: peer()); XCTFail("invalid update") } catch {}
            do { try await store.removeAll(); XCTFail("invalid clear") } catch {}
            XCTAssertEqual(try Data(contentsOf: url), data)
        }
        try FileManager.default.removeItem(at: url)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
        let store = FileLibraryEditsGrantStore(fileURL: url, trustStore: trust)
        do { _ = try await store.allGrants(); XCTFail("directory is not readable JSON") } catch {}
        do { try await store.setGrant(.enabled, for: peer()); XCTFail("must preserve unreadable evidence") } catch {}
        var isDirectory: ObjCBool = false
        XCTAssertTrue(FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory))
        XCTAssertTrue(isDirectory.boolValue)
    }

    func testROMGrantsAndTrustAreIndependentInBothDirections() async throws {
        let dir = try directory()
        let trust = FileTrustStore(fileURL: dir.appendingPathComponent("trust.json"))
        await trust.add(peer())
        let rom = FileLibraryGrantStore(fileURL: dir.appendingPathComponent("rom.json"))
        let edits = FileLibraryEditsGrantStore(fileURL: dir.appendingPathComponent("edits.json"), trustStore: trust)
        await rom.setGrant(.everything, forPeerId: "peer")
        let absent = try await edits.grant(forPeerId: "peer")
        XCTAssertEqual(absent, .denied)
        await rom.setGrant(.denied, forPeerId: "peer")
        try await edits.setGrant(.enabled, for: peer())
        let romDenied = await rom.grant(forPeerId: "peer")
        XCTAssertEqual(romDenied, .denied)
        await rom.removeAll()
        let stillEnabled = try await edits.grant(forPeerId: "peer")
        XCTAssertEqual(stillEnabled, .enabled)
        await rom.setGrant(.everything, forPeerId: "peer")
        try await edits.removeAll()
        let romUnchanged = await rom.grant(forPeerId: "peer")
        let trusted = await trust.peer(withId: "peer")
        XCTAssertEqual(romUnchanged, .everything)
        XCTAssertEqual(trusted, peer())
    }

    func testPendingOptInCannotOverwriteLaterDenial() async throws {
        try await assertPendingOptInCannotOverwriteRevocation("deny")
    }

    func testPendingOptInCannotOverwriteLaterRemoval() async throws {
        try await assertPendingOptInCannotOverwriteRevocation("remove")
    }

    func testPendingOptInCannotOverwriteLaterRemoveAll() async throws {
        try await assertPendingOptInCannotOverwriteRevocation("removeAll")
    }

    private func assertPendingOptInCannotOverwriteRevocation(_ action: String) async throws {
        let dir = try directory()
        let selected = peer()
        let trust = BarrierEditsTrustStore(peers: [selected])
        let url = dir.appendingPathComponent("edits.json")
        let store = FileLibraryEditsGrantStore(fileURL: url, trustStore: trust)
        await trust.pauseNextLookup()
        let pending = Task { try await store.setGrant(.enabled, for: selected) }
        await trust.waitUntilLookupPaused()
        switch action {
        case "deny": try await store.setGrant(.denied, for: selected)
        case "remove": try await store.removeGrant(forPeerId: selected.id)
        default: try await store.removeAll()
        }
        let committed = try Data(contentsOf: url)
        await trust.resumeLookup()
        do { try await pending.value; XCTFail("superseded opt-in must not succeed") }
        catch { XCTAssertEqual(error as? ContinuityLibraryEditsGrantError, .operationSuperseded) }
        let grant = try await store.grant(forPeerId: selected.id)
        let restarted = try await FileLibraryEditsGrantStore(fileURL: url, trustStore: trust).grant(forPeerId: selected.id)
        XCTAssertEqual(grant, .denied)
        XCTAssertEqual(restarted, .denied)
        XCTAssertEqual(try Data(contentsOf: url), committed)
    }

    func testDifferentPeerDecisionDoesNotSupersedePendingOptIn() async throws {
        let dir = try directory()
        let selected = peer()
        let other = peer("other")
        let trust = BarrierEditsTrustStore(peers: [selected, other])
        let store = FileLibraryEditsGrantStore(fileURL: dir.appendingPathComponent("edits.json"), trustStore: trust)
        await trust.pauseNextLookup()
        let pending = Task { try await store.setGrant(.enabled, for: selected) }
        await trust.waitUntilLookupPaused()
        try await store.setGrant(.denied, for: other)
        await trust.resumeLookup()
        try await pending.value
        let grants = try await store.allGrants()
        XCTAssertEqual(grants, [selected.id: .enabled, other.id: .denied])
    }

    func testUnreadableLoadInvalidatesReadAlreadyAwaitingTrust() async throws {
        let dir = try directory()
        let selected = peer()
        let trust = BarrierEditsTrustStore(peers: [selected])
        let url = dir.appendingPathComponent("edits.json")
        let store = FileLibraryEditsGrantStore(fileURL: url, trustStore: trust)
        try await store.setGrant(.enabled, for: selected)
        await trust.pauseNextLookup()
        let pending = Task { try await store.grant(forPeerId: selected.id) }
        await trust.waitUntilLookupPaused()
        try FileManager.default.removeItem(at: url)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
        do { _ = try await store.allGrants(); XCTFail("unreadable state must be reported") } catch {}
        await trust.resumeLookup()
        let grant = try await pending.value
        XCTAssertEqual(grant, .denied)
        var isDirectory: ObjCBool = false
        XCTAssertTrue(FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory))
        XCTAssertTrue(isDirectory.boolValue)
    }

    func testReadRevalidatesDiskAfterTrustAwaitWithoutAnotherOperation() async throws {
        let dir = try directory()
        let selected = peer()
        let trust = BarrierEditsTrustStore(peers: [selected])
        let url = dir.appendingPathComponent("edits.json")
        let store = FileLibraryEditsGrantStore(fileURL: url, trustStore: trust)
        try await store.setGrant(.enabled, for: selected)
        await trust.pauseNextLookup()
        let pending = Task { try await store.grant(forPeerId: selected.id) }
        await trust.waitUntilLookupPaused()
        let corrupt = Data("corrupt evidence".utf8)
        try corrupt.write(to: url)
        await trust.resumeLookup()
        do {
            let grant = try await pending.value
            XCTAssertEqual(grant, .denied)
        } catch {} // A visible storage error also fails closed.
        XCTAssertEqual(try Data(contentsOf: url), corrupt)
    }

    func testFailedLoadInvalidatesEntireListingAlreadyAwaitingTrust() async throws {
        let dir = try directory()
        let first = peer()
        let second = peer("other")
        let trust = BarrierEditsTrustStore(peers: [first, second])
        let url = dir.appendingPathComponent("edits.json")
        let store = FileLibraryEditsGrantStore(fileURL: url, trustStore: trust)
        try await store.setGrant(.enabled, for: first)
        try await store.setGrant(.enabled, for: second)
        await trust.pauseLookup(after: 1) // One enabled result has already been collected.
        let pending = Task { try await store.allGrants() }
        await trust.waitUntilLookupPaused()
        let corrupt = Data("corrupt evidence".utf8)
        try corrupt.write(to: url)
        do { _ = try await store.allGrants(); XCTFail("invalid data must be reported") } catch {}
        await trust.resumeLookup()
        do {
            let grants = try await pending.value
            XCTAssertEqual(grants, [first.id: .denied, second.id: .denied])
        } catch {} // Discarding the whole result with a visible error also fails closed.
        XCTAssertEqual(try Data(contentsOf: url), corrupt)
    }

    func testFailedLoadInvalidatesReadAlreadyAwaitingTrust() async throws {
        let dir = try directory()
        let selected = peer()
        let trust = BarrierEditsTrustStore(peers: [selected])
        let url = dir.appendingPathComponent("edits.json")
        let store = FileLibraryEditsGrantStore(fileURL: url, trustStore: trust)
        try await store.setGrant(.enabled, for: selected)
        await trust.pauseNextLookup()
        let pending = Task { try await store.grant(forPeerId: selected.id) }
        await trust.waitUntilLookupPaused()
        let corrupt = Data("corrupt evidence".utf8)
        try corrupt.write(to: url)
        do { _ = try await store.allGrants(); XCTFail("invalid data must be reported") } catch {}
        await trust.resumeLookup()
        let grant = try await pending.value
        XCTAssertEqual(grant, .denied)
        XCTAssertEqual(try Data(contentsOf: url), corrupt)
    }

}


/// A one-shot trust lookup barrier: tests control actor reentrancy without sleeps.
private actor BarrierEditsTrustStore: ContinuityTrustStore {
    private var peers: [String: TrustedPeer]
    private var pauseNext = false
    private var lookupsBeforePause = 0
    private var paused: CheckedContinuation<Void, Never>?
    private var observer: CheckedContinuation<Void, Never>?

    init(peers: [TrustedPeer]) {
        self.peers = Dictionary(uniqueKeysWithValues: peers.map { ($0.id, $0) })
    }

    func pauseNextLookup() { pauseLookup(after: 0) }
    func pauseLookup(after count: Int) {
        pauseNext = true
        lookupsBeforePause = count
    }

    func waitUntilLookupPaused() async {
        if paused != nil { return }
        await withCheckedContinuation { observer = $0 }
    }

    func resumeLookup() {
        let continuation = paused
        paused = nil
        continuation?.resume()
    }

    func peer(withId id: String) async -> TrustedPeer? {
        let peer = peers[id]
        if pauseNext && lookupsBeforePause > 0 {
            lookupsBeforePause -= 1
        } else if pauseNext {
            pauseNext = false
            await withCheckedContinuation { continuation in
                paused = continuation
                observer?.resume()
                observer = nil
            }
        }
        return peer
    }

    func allPeers() -> [TrustedPeer] { Array(peers.values) }
    func add(_ peer: TrustedPeer) { peers[peer.id] = peer }
    func removePeer(withId id: String) { peers[id] = nil }
    func removeAll() { peers.removeAll() }
}
