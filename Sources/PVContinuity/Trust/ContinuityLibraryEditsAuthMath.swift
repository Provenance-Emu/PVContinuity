// Copyright 2026 iCube Project
// SPDX-License-Identifier: GPL-2.0-or-later

import CryptoKit
import Foundation

/// Metadata-only client proofs, independent of ROM authorization.
///
/// Each field is its UInt32 big-endian byte count followed by its exact bytes.
/// Text is UTF-8 without normalization. Request query keys sort lexicographically
/// by UTF-8 bytes; a UInt32 big-endian pair count precedes the key/value fields.
/// The domains and field order below form the v1 interoperability contract.
///
/// Callers must enforce one-use server-issued nonces and current authorization.
/// This helper provides neither confidentiality nor server-response authentication.
public enum ContinuityLibraryEditsAuthMath {
    public enum EncodingError: Error, Equatable {
        case invalidNonceLength
        case lengthNotRepresentable
    }

    /// Domain, auth ID, peer ID, server ID, 32-byte nonce.
    public static func authMessage(
        authId: String, nonce: Data, peerId: String, serverId: String
    ) throws -> Data {
        try validateNonce(nonce)
        var message = Data()
        for field in [Data("icube-library-edits-auth-v1".utf8), Data(authId.utf8),
                      Data(peerId.utf8), Data(serverId.utf8), nonce] {
            try appendField(field, to: &message)
        }
        return message
    }

    public static func signAuth(
        authId: String, nonce: Data, peerId: String, serverId: String,
        signingKey: Curve25519.Signing.PrivateKey
    ) throws -> Data {
        try signingKey.signature(for: authMessage(authId: authId, nonce: nonce, peerId: peerId, serverId: serverId))
    }

    public static func verifyAuth(
        signature: Data, authId: String, nonce: Data, peerId: String, serverId: String,
        publicKey: Data
    ) -> Bool {
        guard signature.count == 64,
              let key = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey),
              let message = try? authMessage(authId: authId, nonce: nonce, peerId: peerId, serverId: serverId)
        else { return false }
        return key.isValidSignature(signature, for: message)
    }

    /// Domain, SHA256(raw token UTF-8), peer ID, server ID, nonce, exact method,
    /// exact path, query pair count and sorted key/value fields, SHA256(raw body).
    /// An absent HTTP body is represented by `Data()` by the caller.
    public static func requestMessage(
        token: String, nonce: Data, peerId: String, serverId: String,
        method: String, path: String, query: [String: String], body: Data
    ) throws -> Data {
        try validateNonce(nonce)
        var message = Data()
        for field in [Data("icube-library-edits-request-v1".utf8), Data(SHA256.hash(data: Data(token.utf8))),
                      Data(peerId.utf8), Data(serverId.utf8), nonce, Data(method.utf8), Data(path.utf8)] {
            try appendField(field, to: &message)
        }
        try appendCount(query.count, to: &message)
        for key in query.keys.sorted(by: { $0.utf8.lexicographicallyPrecedes($1.utf8) }) {
            try appendField(Data(key.utf8), to: &message)
            try appendField(Data(query[key]!.utf8), to: &message)
        }
        try appendField(Data(SHA256.hash(data: body)), to: &message)
        return message
    }

    public static func signRequest(
        token: String, nonce: Data, peerId: String, serverId: String,
        method: String, path: String, query: [String: String], body: Data,
        signingKey: Curve25519.Signing.PrivateKey
    ) throws -> Data {
        try signingKey.signature(for: requestMessage(token: token, nonce: nonce, peerId: peerId, serverId: serverId,
                                                     method: method, path: path, query: query, body: body))
    }

    public static func verifyRequest(
        signature: Data, token: String, nonce: Data, peerId: String, serverId: String,
        method: String, path: String, query: [String: String], body: Data,
        publicKey: Data
    ) -> Bool {
        guard signature.count == 64,
              let key = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey),
              let message = try? requestMessage(token: token, nonce: nonce, peerId: peerId, serverId: serverId,
                                               method: method, path: path, query: query, body: body)
        else { return false }
        return key.isValidSignature(signature, for: message)
    }

    private static func validateNonce(_ nonce: Data) throws {
        guard nonce.count == 32 else { throw EncodingError.invalidNonceLength }
    }

    private static func appendField(_ field: Data, to message: inout Data) throws {
        try appendCount(field.count, to: &message)
        message.append(field)
    }

    private static func appendCount(_ count: Int, to message: inout Data) throws {
        guard let value = UInt32(exactly: count) else { throw EncodingError.lengthNotRepresentable }
        var bigEndian = value.bigEndian
        withUnsafeBytes(of: &bigEndian) { message.append(contentsOf: $0) }
    }
}
