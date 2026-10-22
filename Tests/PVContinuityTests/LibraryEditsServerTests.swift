import CryptoKit
import Foundation
import XCTest
import PVLibraryMetadata
@testable import PVContinuity

final class LibraryEditsServerTests: XCTestCase {
    func testExchangeAdmissionAndReplay() async throws {
        let fixture = try await Fixture()
        let token = try await fixture.token()
        let nonce = Data(repeating: 7, count: 32)
        let proof = try fixture.proof(token: token, nonce: nonce)
        let admission = try await fixture.server.admit(token: token, nonce: nonce, signature: proof,
                                                      method: "GET", path: "/test", query: [:], body: Data())
        XCTAssertEqual(admission.context.peer.id, fixture.peer.id)
        XCTAssertTrue(try admission.context.withPermit { true })
        do {
            _ = try await fixture.server.admit(token: token, nonce: nonce, signature: proof,
                                              method: "GET", path: "/test", query: [:], body: Data())
            XCTFail("replayed nonce")
        } catch { XCTAssertEqual(error as? ContinuityLibraryEditsServer.Failure, .unauthorized) }
        await fixture.server.forgetPeer(fixture.peer.id)
        XCTAssertThrowsError(try admission.context.withPermit { XCTFail("stale write") })
        do { try await fixture.server.revalidate(admission); XCTFail("stale success") } catch {}
    }

    func testProofBindsEveryRequestFieldAndWrongToken() async throws {
        let f = try await Fixture()
        let token = try await f.token()
        let nonce = Data(repeating: 8, count: 32)
        let proof = try f.proof(token: token, nonce: nonce)
        for (raw, method, path, query, body) in [
            ("ROM-token", "GET", "/test", [:], Data()),
            (token, "POST", "/test", [:], Data()),
            (token, "GET", "/else", [:], Data()),
            (token, "GET", "/test", ["limit": "1"], Data()),
            (token, "GET", "/test", [:], Data([1]))
        ] {
            do {
                _ = try await f.server.admit(token: raw, nonce: nonce, signature: proof,
                    method: method, path: path, query: query, body: body)
                XCTFail("altered proof accepted")
            } catch { XCTAssertEqual(error as? ContinuityLibraryEditsServer.Failure, .unauthorized) }
        }
        // Invalid signatures do not consume the legitimate nonce.
        _ = try await f.server.admit(token: token, nonce: nonce, signature: proof,
                                    method: "GET", path: "/test", query: [:], body: Data())
    }

    func testLiveKeyReplacementAndRevocationRejectCredentials() async throws {
        let f = try await Fixture()
        let token = try await f.token()
        let nonce = Data(repeating: 2, count: 32)
        let proof = try f.proof(token: token, nonce: nonce)
        await f.trust.add(ContinuityPeerIdentity(id: f.peer.id, name: "Replacement").asTrustedPeer())
        do {
            _ = try await f.server.admit(token: token, nonce: nonce, signature: proof,
                                        method: "GET", path: "/test", query: [:], body: Data())
            XCTFail("key replacement")
        } catch {}
        await f.trust.add(f.peer.asTrustedPeer())
        try await f.grants.setGrant(.denied, for: f.peer.asTrustedPeer())
        do { _ = try await f.token(); XCTFail("revoked") } catch {}
    }

    func testAbsoluteExpiryAndCapacity() async throws {
        let clock = TestClock()
        let f = try await Fixture(now: { clock.date })
        for _ in 0..<16 { _ = try await f.token() }
        do { _ = try await f.token(); XCTFail("token capacity") }
        catch { XCTAssertEqual(error as? ContinuityLibraryEditsServer.Failure, .capacity) }
        clock.advance(3600)
        _ = try await f.token()
        await f.server.forgetAllPeers()
        for _ in 0..<64 {
            _ = try await f.server.authStart(body: JSONEncoder().encode(ContinuityPairingMessages.AuthStartRequest(peerId: f.peer.id)))
        }
        do { _ = try await f.token(); XCTFail("challenge capacity") }
        catch { XCTAssertEqual(error as? ContinuityLibraryEditsServer.Failure, .capacity) }
        clock.advance(30)
        _ = try await f.token()
    }

    func testNonceCapacityRequiresNewAuthenticationWithoutEviction() async throws {
        let f = try await Fixture()
        let token = try await f.token()
        for value in 0...1024 {
            var nonce = Data(repeating: 0, count: 32)
            nonce[0] = UInt8(value & 255); nonce[1] = UInt8(value >> 8)
            let signature = try f.proof(token: token, nonce: nonce)
            do {
                _ = try await f.server.admit(token: token, nonce: nonce, signature: signature,
                                            method: "GET", path: "/test", query: [:], body: Data())
                XCTAssertLessThan(value, 1024)
            } catch { XCTAssertEqual(value, 1024) }
        }
        let nonce = Data(repeating: 0, count: 32)
        do {
            _ = try await f.server.admit(token: token, nonce: nonce, signature: f.proof(token: token, nonce: nonce),
                                        method: "GET", path: "/test", query: [:], body: Data())
            XCTFail("invalidated token")
        } catch {}
    }

    func testStrictBodiesAndTokenDTOIsolation() async throws {
        let f = try await Fixture()
        for body in [Data(), Data(repeating: 32, count: 4097), Data("{}".utf8)] {
            do { _ = try await f.server.authStart(body: body); XCTFail("invalid body") }
            catch { XCTAssertEqual(error as? ContinuityLibraryEditsServer.Failure, .invalidRequest) }
        }
        XCTAssertNotNil(ContinuityLibraryEditsServer.canonicalBase64(Data(repeating: 1, count: 64).base64EncodedString(), count: 64))
        for text in ["", Data(repeating: 1, count: 63).base64EncodedString(), String(repeating: "A", count: 86) + "B="] {
            XCTAssertNil(ContinuityLibraryEditsServer.canonicalBase64(text, count: 64))
        }
        let data = try JSONEncoder().encode(ContinuityLibraryEditsMessages.TokenResponse(editsToken: "synthetic"))
        XCTAssertThrowsError(try JSONDecoder().decode(ContinuityPairingMessages.SessionTokenResponse.self, from: data))
        XCTAssertThrowsError(try JSONDecoder().decode(ContinuityLibraryMessages.LibraryTokenResponse.self, from: data))
    }

    func testStopResumeRejectsSuspendedStoreCommit() async throws {
        let f = try await Fixture()
        let raw = try await f.token()
        let nonce = Data(repeating: 3, count: 32)
        let admission = try await f.server.admit(token: raw, nonce: nonce, signature: f.proof(token: raw, nonce: nonce),
                                                method: "GET", path: "/test", query: [:], body: Data())
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        var writes = 0
        let store = try LibraryMetadataStore(directoryURL: dir, write: { data, url in
            writes += 1
            try data.write(to: url, options: .atomic)
        })
        let identity = LibraryMetadataStore.Identity.game(gameID: "GALE01", discNumber: 0, revision: 0)!
        let document = try JSONSerialization.data(withJSONObject: [identity.rawValue + ":title": ["updatedAt": 123, "value": "Title"]])
        await f.server.stop()
        await f.server.resume()
        XCTAssertThrowsError(try admission.context.withPermit { try store.mergeDocument(document, for: identity) })
        XCTAssertEqual(writes, 0)
        do { try await f.server.revalidate(admission); XCTFail("stale publication") } catch {}
        _ = try await f.token()
    }

    func testDelayedTrustCannotResurrectForgottenAuthStartOrCompletion() async throws {
        for completing in [false, true] {
            let f = try await Fixture()
            let trust = SuspendedTrust(base: f.trust)
            let server = ContinuityLibraryEditsServer(identity: f.host, trustStore: trust, grantStore: f.grants)
            let start = try JSONEncoder().encode(ContinuityPairingMessages.AuthStartRequest(peerId: f.peer.id))
            let body: Data
            if completing {
                let challenge = try await server.authStart(body: start)
                body = try JSONEncoder().encode(ContinuityPairingMessages.AuthCompleteRequest(authId: challenge.authId,
                    peerId: f.peer.id, signature: ContinuityLibraryEditsAuthMath.signAuth(authId: challenge.authId,
                    nonce: challenge.nonce, peerId: f.peer.id, serverId: f.host.id, signingKey: f.peer.signingKey)))
            } else { body = start }
            await trust.suspendNext()
            let operation = Task {
                if completing { _ = try await server.authComplete(body: body) }
                else { _ = try await server.authStart(body: body) }
            }
            await trust.waitForSuspension()
            await server.forgetPeer(f.peer.id)
            await trust.release()
            do { try await operation.value; XCTFail("forgotten lookup resurrected") }
            catch { XCTAssertEqual(error as? ContinuityLibraryEditsServer.Failure, .unauthorized) }
        }
    }

    func testChallengeIsConsumedBeforeSuspendedVerificationAndStop() async throws {
        let f = try await Fixture()
        let trust = SuspendedTrust(base: f.trust)
        let server = ContinuityLibraryEditsServer(identity: f.host, trustStore: trust, grantStore: f.grants)
        let challenge = try await server.authStart(body: JSONEncoder().encode(ContinuityPairingMessages.AuthStartRequest(peerId: f.peer.id)))
        let body = try JSONEncoder().encode(ContinuityPairingMessages.AuthCompleteRequest(authId: challenge.authId,
            peerId: f.peer.id, signature: ContinuityLibraryEditsAuthMath.signAuth(authId: challenge.authId,
            nonce: challenge.nonce, peerId: f.peer.id, serverId: f.host.id, signingKey: f.peer.signingKey)))
        await trust.suspendNext()
        let operation = Task { try await server.authComplete(body: body) }
        await trust.waitForSuspension()
        do { _ = try await server.authComplete(body: body); XCTFail("challenge replay") } catch {}
        await server.stop()
        await server.resume()
        await trust.release()
        do { _ = try await operation.value; XCTFail("old completion survived resume") } catch {}
    }

    func testDelayedGrantCannotAdmitAfterForgetOrPublishAfterStop() async throws {
        for publication in [false, true] {
            let f = try await Fixture()
            let grants = SuspendedGrants(base: f.grants)
            let server = ContinuityLibraryEditsServer(identity: f.host, trustStore: f.trust, grantStore: grants)
            let raw = try await f.token(server)
            let nonce = Data(repeating: 5, count: 32)
            let proof = try f.proof(token: raw, nonce: nonce)
            let existing = try await server.admit(token: raw, nonce: nonce, signature: proof,
                                                  method: "GET", path: "/test", query: [:], body: Data())
            await grants.suspendNext()
            let operation = Task {
                if publication { try await server.revalidate(existing) }
                else {
                    let nextNonce = Data(repeating: 6, count: 32)
                    _ = try await server.admit(token: raw, nonce: nextNonce, signature: f.proof(token: raw, nonce: nextNonce),
                                              method: "GET", path: "/test", query: [:], body: Data())
                }
            }
            await grants.waitForSuspension()
            if publication { await server.stop() } else { await server.forgetAllPeers() }
            await grants.release()
            do { try await operation.value; XCTFail("stale grant bypass") } catch {}
            XCTAssertThrowsError(try existing.context.withPermit { XCTFail("revoked write") })
        }
    }

    func testChallengeExpiryAndLegacySignatureConsumeChallenge() async throws {
        let clock = TestClock()
        let f = try await Fixture(now: { clock.date })
        for expired in [true, false] {
            let challenge = try await f.server.authStart(body: JSONEncoder().encode(ContinuityPairingMessages.AuthStartRequest(peerId: f.peer.id)))
            let signature = try ContinuityPairingMath.signAuth(nonce: challenge.nonce, peerId: f.peer.id,
                serverId: f.host.id, signingKey: f.peer.signingKey)
            if expired { clock.advance(30) }
            let body = try JSONEncoder().encode(ContinuityPairingMessages.AuthCompleteRequest(authId: challenge.authId,
                peerId: f.peer.id, signature: signature))
            do { _ = try await f.server.authComplete(body: body); XCTFail("expired/legacy auth") } catch {}
            let valid = try ContinuityLibraryEditsAuthMath.signAuth(authId: challenge.authId, nonce: challenge.nonce,
                peerId: f.peer.id, serverId: f.host.id, signingKey: f.peer.signingKey)
            do {
                _ = try await f.server.authComplete(body: JSONEncoder().encode(ContinuityPairingMessages.AuthCompleteRequest(
                    authId: challenge.authId, peerId: f.peer.id, signature: valid)))
                XCTFail("consumed challenge")
            } catch {}
        }
        let raw = try await f.token()
        clock.advance(3600)
        let nonce = Data(repeating: 4, count: 32)
        do {
            _ = try await f.server.admit(token: raw, nonce: nonce, signature: f.proof(token: raw, nonce: nonce),
                                        method: "GET", path: "/test", query: [:], body: Data())
            XCTFail("expired token")
        } catch {}
    }

    private struct Fixture {
        let peer = ContinuityPeerIdentity(id: "peer", name: "Peer")
        let host = ContinuityPeerIdentity(id: "host", name: "Host")
        let server: ContinuityLibraryEditsServer
        let trust: FileTrustStore
        let grants: FileLibraryEditsGrantStore
        init(now: @escaping @Sendable () -> Date = { Date() }) async throws {
            let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
            trust = FileTrustStore(fileURL: directory.appendingPathComponent("trust"))
            await trust.add(peer.asTrustedPeer())
            grants = FileLibraryEditsGrantStore(fileURL: directory.appendingPathComponent("grants"), trustStore: trust)
            try await grants.setGrant(.enabled, for: peer.asTrustedPeer())
            server = ContinuityLibraryEditsServer(identity: host, trustStore: trust, grantStore: grants, now: now)
        }
        func token(_ selectedServer: ContinuityLibraryEditsServer? = nil) async throws -> String {
            let server = selectedServer ?? self.server
            let challenge = try await server.authStart(body: JSONEncoder().encode(ContinuityPairingMessages.AuthStartRequest(peerId: peer.id)))
            let signature = try ContinuityLibraryEditsAuthMath.signAuth(authId: challenge.authId, nonce: challenge.nonce,
                peerId: peer.id, serverId: host.id, signingKey: peer.signingKey)
            return try await server.authComplete(body: JSONEncoder().encode(ContinuityPairingMessages.AuthCompleteRequest(
                authId: challenge.authId, peerId: peer.id, signature: signature))).editsToken
        }
        func proof(token: String, nonce: Data) throws -> Data {
            try ContinuityLibraryEditsAuthMath.signRequest(token: token, nonce: nonce, peerId: peer.id,
                serverId: host.id, method: "GET", path: "/test", query: [:], body: Data(), signingKey: peer.signingKey)
        }
    }
}

private final class TestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var value = Date(timeIntervalSince1970: 1000)
    var date: Date { lock.lock(); defer { lock.unlock() }; return value }
    func advance(_ seconds: TimeInterval) { lock.lock(); defer { lock.unlock() }; value.addTimeInterval(seconds) }
}

private actor SuspendedTrust: ContinuityTrustStore {
    let base: FileTrustStore
    var shouldSuspend = false
    var suspended: CheckedContinuation<Void, Never>?
    var observer: CheckedContinuation<Void, Never>?
    init(base: FileTrustStore) { self.base = base }
    func suspendNext() { shouldSuspend = true }
    func waitForSuspension() async {
        if suspended != nil { return }
        await withCheckedContinuation { observer = $0 }
    }
    func release() { suspended?.resume(); suspended = nil }
    func peer(withId id: String) async -> TrustedPeer? {
        let value = await base.peer(withId: id)
        if shouldSuspend {
            shouldSuspend = false
            await withCheckedContinuation {
                suspended = $0
                observer?.resume(); observer = nil
            }
        }
        return value
    }
    func allPeers() async -> [TrustedPeer] { await base.allPeers() }
    func add(_ peer: TrustedPeer) async { await base.add(peer) }
    func removePeer(withId id: String) async { await base.removePeer(withId: id) }
    func removeAll() async { await base.removeAll() }
}

private actor SuspendedGrants: ContinuityLibraryEditsGrantStore {
    let base: FileLibraryEditsGrantStore
    var shouldSuspend = false
    var suspended: CheckedContinuation<Void, Never>?
    var observer: CheckedContinuation<Void, Never>?
    init(base: FileLibraryEditsGrantStore) { self.base = base }
    func suspendNext() { shouldSuspend = true }
    func waitForSuspension() async {
        if suspended != nil { return }
        await withCheckedContinuation { observer = $0 }
    }
    func release() { suspended?.resume(); suspended = nil }
    func grant(forPeerId id: String) async throws -> ContinuityLibraryEditsGrant {
        let value = try await base.grant(forPeerId: id)
        if shouldSuspend {
            shouldSuspend = false
            await withCheckedContinuation {
                suspended = $0
                observer?.resume(); observer = nil
            }
        }
        return value
    }
    func setGrant(_ grant: ContinuityLibraryEditsGrant, for peer: TrustedPeer) async throws { try await base.setGrant(grant, for: peer) }
    func removeGrant(forPeerId id: String) async throws { try await base.removeGrant(forPeerId: id) }
    func removeAll() async throws { try await base.removeAll() }
    func allGrants() async throws -> [String: ContinuityLibraryEditsGrant] { try await base.allGrants() }
}
