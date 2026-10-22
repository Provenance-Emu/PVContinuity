// Copyright 2026 iCube Project
// SPDX-License-Identifier: GPL-2.0-or-later

import Foundation
import PVLibraryMetadata

/// Metadata exchange using the published shared wire values. Providers must bind
/// remote identities to independently verified local content before reading or
/// merging. Remote evidence alone is not a binding.
public protocol ContinuityLibraryEditsProviding: Sendable {
    /// The provider owns a snapshot UUID and changes it when the eligible
    /// identity/document set changes. A cursor from an expired snapshot must
    /// throw `staleCursor`, allowing the client to restart without skipping games.
    func manifest(after: String?, limit: Int) async throws -> LibraryEditsManifestPage
    func read(identity: String) async throws -> Data
    /// Perform async binding/preparation first, then wrap the final synchronous
    /// `store.mergeDocument` in `context.withPermit` immediately around the write.
    func merge(identity: String, document: Data, context: ContinuityLibraryEditsCommitContext) async throws -> Data
}

/// Stable provider failures for later HTTP status mapping. Filesystem error text
/// must never be exposed on the wire.
public enum ContinuityLibraryEditsProviderError: Error, Equatable, Sendable {
    case unavailable
    case identityUnavailable
    case staleCursor
    case invalidProviderResult
}

/// An opaque admission context, not authentication or a grant in itself.
///
/// The server owns one gate per peer and invalidates it before stop or revoke.
/// It may construct a context only after live authenticated trust, grant and
/// epoch checks. The captured gate is the same instance used by revocation.
public struct ContinuityLibraryEditsCommitContext: Sendable {
    public let peer: TrustedPeer
    private let gate: LibraryMetadataCommitGate
    private let permit: LibraryMetadataCommitGate.Permit

    init(peer: TrustedPeer, gate: LibraryMetadataCommitGate) {
        self.peer = peer
        self.gate = gate
        self.permit = gate.issue()
    }

    /// Executes once if admission remains valid. Keep the operation short and
    /// synchronous: no async/network work or recursive entry into this gate.
    /// Lock order is grant gate, then store file gate; never acquire in reverse.
    public func withPermit<T>(_ operation: () throws -> T) throws -> T {
        try gate.withPermit(permit, operation: operation)
    }
}
