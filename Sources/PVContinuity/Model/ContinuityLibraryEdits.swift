// Copyright 2026 iCube Project
// SPDX-License-Identifier: GPL-2.0-or-later

/// Nearby custom title, cover and tag exchange capabilities.
/// Capability advertisement does not confer permission to exchange edits.
public enum ContinuityLibraryEdits {
    public static let currentVersion = 1
}

/// Explicit metadata consent, independent of ROM permissions and pairing.
/// An absent decision is treated as denied.
public enum ContinuityLibraryEditsGrant: String, Codable, Sendable, CaseIterable {
    case enabled
    case denied
}

public enum ContinuityLibraryEditsGrantError: Error, Equatable {
    /// Opt-in requires a matching ID and key in the current trust store.
    case peerNotTrusted
    /// Unsupported or corrupt persisted consent must be resolved by the host.
    case invalidStoredData
}
