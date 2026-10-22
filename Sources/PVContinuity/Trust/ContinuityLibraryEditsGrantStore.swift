// Copyright 2026 iCube Project
// SPDX-License-Identifier: GPL-2.0-or-later

import Foundation

/// Remembered metadata decisions, separate from ROM grants and pairing.
/// Enabled decisions are bound to the opted-in key and checked against live trust.
/// Callers must still authenticate requests and handle lifecycle revocation.
/// All storage errors propagate; callers must treat failed reads as disabled.
public protocol ContinuityLibraryEditsGrantStore: Sendable {
    func grant(forPeerId id: String) async throws -> ContinuityLibraryEditsGrant
    /// Enabling validates the selected peer against the injected live trust store.
    /// Denying never adds trust and is allowed for an unpaired peer.
    func setGrant(_ grant: ContinuityLibraryEditsGrant, for peer: TrustedPeer) async throws
    func removeGrant(forPeerId id: String) async throws
    func removeAll() async throws
    /// Explicit peers only, with stale or unpaired enabled decisions reported denied.
    func allGrants() async throws -> [String: ContinuityLibraryEditsGrant]
}

/// Separate JSON file with atomic, throwing mutations. The in-memory decision
/// changes only after persistence succeeds. Unreadable or unsupported existing
/// data is never replaced by a mutation, including removeAll(). Every operation
/// validates disk again so an old cached decision cannot hide storage corruption.
public actor FileLibraryEditsGrantStore: ContinuityLibraryEditsGrantStore {
    private let fileURL: URL
    private let trustStore: any ContinuityTrustStore
    private var cached: [String: Entry]?

    public init(fileURL: URL, trustStore: any ContinuityTrustStore) {
        self.fileURL = fileURL
        self.trustStore = trustStore
    }

    public func grant(forPeerId id: String) async throws -> ContinuityLibraryEditsGrant {
        guard let entry = try load()[id] else { return .denied }
        return await effectiveGrant(entry, forPeerId: id)
    }

    public func allGrants() async throws -> [String: ContinuityLibraryEditsGrant] {
        let entries = try load()
        var grants: [String: ContinuityLibraryEditsGrant] = [:]
        for (id, entry) in entries {
            grants[id] = await effectiveGrant(entry, forPeerId: id)
        }
        return grants
    }

    private func effectiveGrant(_ entry: Entry, forPeerId id: String) async -> ContinuityLibraryEditsGrant {
        guard entry.grant == .enabled,
              let current = await trustStore.peer(withId: id),
              current.id == id, current.publicKey == entry.publicKey else { return .denied }
        // A mutation may have run while live trust was awaited. Do not return
        // an older enabled snapshot after a completed local revoke or removal.
        guard cached?[id] == entry else { return .denied }
        return .enabled
    }

    public func setGrant(_ grant: ContinuityLibraryEditsGrant, for peer: TrustedPeer) async throws {
        if grant == .enabled {
            guard let current = await trustStore.peer(withId: peer.id),
                  current.id == peer.id, current.publicKey == peer.publicKey else {
                throw ContinuityLibraryEditsGrantError.peerNotTrusted
            }
        }
        // Load after the trust await so actor reentrancy cannot lose another edit.
        var grants = try load()
        grants[peer.id] = Entry(grant: grant, publicKey: peer.publicKey)
        try save(grants)
    }

    public func removeGrant(forPeerId id: String) throws {
        var grants = try load()
        grants[id] = nil
        try save(grants)
    }

    public func removeAll() throws {
        _ = try load() // Preserve evidence of an unreadable existing file.
        try save([:])
    }

    private func load() throws -> [String: Entry] {
        let data: Data
        do {
            data = try Data(contentsOf: fileURL)
        } catch let error as NSError where error.domain == NSCocoaErrorDomain && error.code == NSFileReadNoSuchFileError {
            cached = [:]
            return [:]
        }
        let document = try JSONDecoder().decode(Document.self, from: data)
        cached = document.grants
        return document.grants
    }

    private func save(_ grants: [String: Entry]) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        let data = try encoder.encode(Document(grants: grants))
        try FileManager.default.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try data.write(to: fileURL, options: .atomic)
        cached = grants
    }

    private struct Document: Codable {
        let version: Int
        let grants: [String: Entry]

        init(grants: [String: Entry]) {
            self.version = 1
            self.grants = grants
        }

        private enum CodingKeys: String, CodingKey { case version, grants }
        init(from decoder: Decoder) throws {
            try requireKeys(["version", "grants"], in: decoder)
            let container = try decoder.container(keyedBy: CodingKeys.self)
            version = try container.decode(Int.self, forKey: .version)
            guard version == 1 else { throw ContinuityLibraryEditsGrantError.invalidStoredData }
            grants = try container.decode([String: Entry].self, forKey: .grants)
        }
    }

    /// Only public key material is stored, never a private identity or token.
    private struct Entry: Codable, Equatable, Sendable {
        let grant: ContinuityLibraryEditsGrant
        let publicKey: Data

        init(grant: ContinuityLibraryEditsGrant, publicKey: Data) {
            self.grant = grant
            self.publicKey = publicKey
        }

        private enum CodingKeys: String, CodingKey { case grant, publicKey }

        init(from decoder: Decoder) throws {
            try requireKeys(["grant", "publicKey"], in: decoder)
            let container = try decoder.container(keyedBy: CodingKeys.self)
            grant = try container.decode(ContinuityLibraryEditsGrant.self, forKey: .grant)
            publicKey = try container.decode(Data.self, forKey: .publicKey)
        }
    }

    private struct AnyKey: CodingKey {
        var stringValue: String
        var intValue: Int? { nil }
        init?(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { return nil }
    }

    private static func requireKeys(_ expected: Set<String>, in decoder: Decoder) throws {
        let keys = try decoder.container(keyedBy: AnyKey.self).allKeys.map(\.stringValue)
        guard Set(keys) == expected else { throw ContinuityLibraryEditsGrantError.invalidStoredData }
    }
}
