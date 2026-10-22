// Copyright 2026 iCube Project
// SPDX-License-Identifier: GPL-2.0-or-later

import CryptoKit
import Foundation
import PVLibraryMetadata

public enum ContinuityLibraryEditsMessages {
    /// Deliberately incompatible with ROM library/session token payloads.
    public struct TokenResponse: Codable, Sendable {
        public let editsToken: String
        public init(editsToken: String) { self.editsToken = editsToken }
    }
}

/// Metadata authentication registry. This slice registers NO HTTP routes.
/// Starts active; `stop()` invalidates every issued commit context before clearing
/// credentials. `resume()` explicitly starts a fresh epoch (also when active).
///
/// The application owner MUST await forgetPeer/forgetAllPeers/stop BEFORE grant
/// revocation, key replacement, background/emulation entry or their async work.
/// Direct external store changes cannot atomically revoke an admitted synchronous
/// write. Never hold a context permit across async/network work. Route owners must
/// validate inputs before provider work and call revalidate after every provider
/// await and before publishing success. Admissions are not reusable credentials.
public actor ContinuityLibraryEditsServer {
    public enum Failure: Error, Equatable, Sendable {
        case invalidRequest, unauthorized, denied, unavailable, capacity
    }

    public struct Admission: Sendable {
        public let context: ContinuityLibraryEditsCommitContext
        public let epoch: UUID
        fileprivate let tokenDigest: Data
        fileprivate let gate: LibraryMetadataCommitGate
    }

    private struct Challenge {
        let peer: TrustedPeer
        let nonce: Data
        let expires: Date
        let epoch: UUID
        let gate: LibraryMetadataCommitGate
    }
    private struct Token {
        let peer: TrustedPeer
        let expires: Date
        let epoch: UUID
        let gate: LibraryMetadataCommitGate
        var nonces: Set<Data> = []
    }
    private let identity: ContinuityPeerIdentity
    private let trustStore: any ContinuityTrustStore
    private let grantStore: any ContinuityLibraryEditsGrantStore
    private let now: @Sendable () -> Date
    private var active = true
    private var epoch = UUID()
    // Changes on every invalidation, including forget of a not-yet-known peer.
    // Thus a suspended first trust lookup cannot resurrect that peer's auth.
    private var revision = UUID()
    private var gates: [String: LibraryMetadataCommitGate] = [:]
    private var challenges: [String: Challenge] = [:]
    private var completing: [String: Challenge] = [:]
    private var tokens: [Data: Token] = [:]

    public init(identity: ContinuityPeerIdentity, trustStore: any ContinuityTrustStore,
                grantStore: any ContinuityLibraryEditsGrantStore,
                now: @escaping @Sendable () -> Date = { Date() }) {
        self.identity = identity
        self.trustStore = trustStore
        self.grantStore = grantStore
        self.now = now
    }

    public func stop() {
        // Invalidate the exact context gates BEFORE clearing state.
        for gate in gates.values { gate.invalidate() }
        active = false
        epoch = UUID()
        revision = UUID()
        gates.removeAll()
        challenges.removeAll()
        completing.removeAll()
        tokens.removeAll()
    }

    public func resume() { stop(); active = true }

    public func forgetPeer(_ peerId: String) {
        gates[peerId]?.invalidate()
        revision = UUID()
        gates[peerId] = nil
        challenges = challenges.filter { $0.value.peer.id != peerId }
        completing = completing.filter { $0.value.peer.id != peerId }
        tokens = tokens.filter { $0.value.peer.id != peerId }
    }

    public func forgetAllPeers() {
        let wasActive = active
        stop()
        active = wasActive
    }

    /// Body-only seam for later bounded HTTP adapters; no route is registered.
    public func authStart(body: Data) async throws -> ContinuityPairingMessages.AuthStartResponse {
        let request = try decode(ContinuityPairingMessages.AuthStartRequest.self, body: body)
        guard !request.peerId.isEmpty else { throw Failure.invalidRequest }
        let captured = revision
        let peer = try await livePeer(request.peerId, expectedKey: nil, revision: captured)
        try check(captured)
        prune()
        guard challenges.count + completing.count < 64 else { throw Failure.capacity }
        let gate = gateForPeer(peer.id)
        let id = UUID().uuidString.lowercased()
        let nonce = ContinuityPairingMath.makeNonce()
        challenges[id] = Challenge(peer: peer, nonce: nonce, expires: now().addingTimeInterval(30), epoch: epoch, gate: gate)
        return .init(authId: id, serverId: identity.id, nonce: nonce)
    }

    public func authComplete(body: Data) async throws -> ContinuityLibraryEditsMessages.TokenResponse {
        // Decode signature as text first: Codable Data decoding does not enforce
        // canonical base64 padding/pad bits.
        struct Request: Decodable { let authId: String; let peerId: String; let signature: String }
        let request = try decode(Request.self, body: body)
        guard let signature = Self.canonicalBase64(request.signature, count: 64) else { throw Failure.invalidRequest }
        try check(revision)
        // Consume before ANY await, including invalid proof attempts.
        guard let challenge = challenges.removeValue(forKey: request.authId),
              challenge.peer.id == request.peerId, challenge.expires > now(), challenge.epoch == epoch,
              gates[request.peerId] === challenge.gate else { throw Failure.unauthorized }
        completing[request.authId] = challenge
        defer { completing[request.authId] = nil }
        let captured = revision
        let peer = try await livePeer(request.peerId, expectedKey: challenge.peer.publicKey, revision: captured)
        try check(captured)
        guard challenge.expires > now(),
              ContinuityLibraryEditsAuthMath.verifyAuth(signature: signature, authId: request.authId,
                nonce: challenge.nonce, peerId: peer.id, serverId: identity.id, publicKey: peer.publicKey) else {
            throw Failure.unauthorized
        }
        prune(retainingPeer: peer.id)
        guard tokens.count < 16 else { throw Failure.capacity }
        // prune can retire a challenge-only gate after consumption; retain the
        // same instance for this token rather than creating a second permit gate.
        gates[peer.id] = challenge.gate
        let raw = ContinuityPairingMath.makeNonce().base64EncodedString()
        tokens[Self.digest(raw)] = Token(peer: peer, expires: now().addingTimeInterval(3600), epoch: epoch, gate: challenge.gate)
        return .init(editsToken: raw)
    }

    /// Adapters must reject duplicate/ambiguous headers/query keys before this
    /// semantic proof API. Nonces are client-generated 32-byte unique values;
    /// they are consumed before returning an admission or invoking any provider.
    public func admit(token raw: String, nonce: Data, signature: Data, method: String, path: String,
               query: [String: String], body: Data) async throws -> Admission {
        try check(revision)
        guard raw.utf8.count <= 256, nonce.count == 32, signature.count == 64 else { throw Failure.unauthorized }
        let digest = Self.digest(raw)
        guard let issued = tokens[digest], issued.expires > now(), issued.epoch == epoch,
              gates[issued.peer.id] === issued.gate else { throw Failure.unauthorized }
        let captured = revision
        let peer = try await livePeer(issued.peer.id, expectedKey: issued.peer.publicKey, revision: captured)
        try check(captured)
        guard var current = tokens[digest], current.expires > now(), current.epoch == epoch,
              current.gate === issued.gate else { throw Failure.unauthorized }
        guard ContinuityLibraryEditsAuthMath.verifyRequest(signature: signature, token: raw, nonce: nonce,
            peerId: peer.id, serverId: identity.id, method: method, path: path, query: query, body: body,
            publicKey: peer.publicKey), !current.nonces.contains(nonce) else { throw Failure.unauthorized }
        guard current.nonces.count < 1024 else {
            // Retire the peer gate too: outstanding admissions from the
            // exhausted registry must not commit after forced reauthentication.
            forgetPeer(current.peer.id) // Never evict individual used nonces.
            throw Failure.unauthorized
        }
        current.nonces.insert(nonce)
        tokens[digest] = current
        return Admission(context: .init(peer: peer, gate: issued.gate), epoch: epoch, tokenDigest: digest, gate: issued.gate)
    }

    public func revalidate(_ admission: Admission) async throws {
        try check(revision)
        guard admission.epoch == epoch, let token = tokens[admission.tokenDigest], token.expires > now(),
              token.gate === admission.gate, gates[token.peer.id] === admission.gate else { throw Failure.unauthorized }
        let captured = revision
        _ = try await livePeer(token.peer.id, expectedKey: token.peer.publicKey, revision: captured)
        try check(captured)
        guard admission.epoch == epoch, let current = tokens[admission.tokenDigest], current.expires > now(),
              current.gate === admission.gate else { throw Failure.unauthorized }
    }

    private func livePeer(_ id: String, expectedKey: Data?, revision captured: UUID) async throws -> TrustedPeer {
        try check(captured)
        let peer = await trustStore.peer(withId: id)
        try check(captured)
        guard let peer, peer.id == id, peer.publicKey.count == 32,
              expectedKey == nil || peer.publicKey == expectedKey else { throw Failure.unauthorized }
        let grant: ContinuityLibraryEditsGrant
        do { grant = try await grantStore.grant(forPeerId: id) }
        catch { try check(captured); throw Failure.denied }
        try check(captured)
        guard grant == .enabled else { throw Failure.denied }
        // Re-read trust after the grant await to reject a replaced key even if
        // the grant implementation performed no trust validation of its own.
        let finalPeer = await trustStore.peer(withId: id)
        try check(captured)
        guard let finalPeer, finalPeer.id == id, finalPeer.publicKey == peer.publicKey else { throw Failure.unauthorized }
        return finalPeer
    }

    private func check(_ captured: UUID) throws {
        guard active else { throw Failure.unavailable }
        guard captured == revision else { throw Failure.unauthorized }
    }
    private func gateForPeer(_ id: String) -> LibraryMetadataCommitGate {
        if let gate = gates[id] { return gate }
        let gate = LibraryMetadataCommitGate()
        gates[id] = gate
        return gate
    }
    private func prune(retainingPeer: String? = nil) {
        let date = now()
        challenges = challenges.filter { $0.value.expires > date }
        tokens = tokens.filter { $0.value.expires > date }
        // Bound gate state as well as challenge/token dictionaries. Invalidate
        // retired contexts even when their credentials expired naturally.
        let retained = Set(challenges.values.map { $0.peer.id } + completing.values.map { $0.peer.id } + tokens.values.map { $0.peer.id })
        for id in Array(gates.keys) where !retained.contains(id) && id != retainingPeer {
            gates.removeValue(forKey: id)?.invalidate()
        }
    }
    private func decode<T: Decodable>(_ type: T.Type, body: Data) throws -> T {
        guard body.count <= 4096 else { throw Failure.invalidRequest }
        do { return try JSONDecoder().decode(type, from: body) }
        catch { throw Failure.invalidRequest }
    }
    static func canonicalBase64(_ text: String, count: Int) -> Data? {
        guard text.utf8.count == ((count + 2) / 3) * 4,
              let data = Data(base64Encoded: text), data.count == count,
              data.base64EncodedString() == text else { return nil }
        return data
    }
    private static func digest(_ token: String) -> Data { Data(SHA256.hash(data: Data(token.utf8))) }
}
