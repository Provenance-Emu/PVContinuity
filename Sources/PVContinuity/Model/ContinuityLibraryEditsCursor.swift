// Copyright 2026 iCube Project
// SPDX-License-Identifier: GPL-2.0-or-later

import Foundation

/// Continuity v1 cursor grammar. Shared metadata wire cursors remain opaque.
/// A provider owns the snapshot and rejects expired snapshots with `staleCursor`.
public struct ContinuityLibraryEditsCursor: Sendable, Equatable {
    public enum ValidationError: Error, Equatable, Sendable {
        case negativeOffset
    }

    public let snapshotID: UUID
    public let offset: Int
    public var rawValue: String { "v1:\(snapshotID.uuidString.lowercased()):\(offset)" }

    public init(snapshotID: UUID, offset: Int) throws {
        guard offset >= 0 else { throw ValidationError.negativeOffset }
        self.snapshotID = snapshotID
        self.offset = offset
    }

    public static func parse(_ raw: String) -> Self? {
        // The maximum representation is a fixed prefix, UUID and Int.max.
        guard raw.utf8.count <= 40 + String(Int.max).utf8.count else { return nil }
        let parts = raw.split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count == 3, parts[0] == "v1",
              let snapshotID = UUID(uuidString: String(parts[1])),
              let offset = Int(parts[2]),
              let cursor = try? Self(snapshotID: snapshotID, offset: offset),
              cursor.rawValue == raw else { return nil }
        return cursor
    }
}
