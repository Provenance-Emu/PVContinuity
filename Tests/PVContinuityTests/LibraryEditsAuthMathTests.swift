// Copyright 2026 iCube Project
// SPDX-License-Identifier: GPL-2.0-or-later

import CryptoKit
import XCTest
@testable import PVContinuity

final class LibraryEditsAuthMathTests: XCTestCase {
    private let nonce = Data(0..<32)
    // RFC 8032 §7.1 test 1 seed; no random fixture generation.
    private var key: Curve25519.Signing.PrivateKey {
        get throws { try Curve25519.Signing.PrivateKey(rawRepresentation: hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")) }
    }
    private func hex(_ value: String) -> Data {
        Data(stride(from: 0, to: value.count, by: 2).map { offset in
            let start = value.index(value.startIndex, offsetBy: offset)
            return UInt8(value[start..<value.index(start, offsetBy: 2)], radix: 16)!
        })
    }
    private func auth(authId: String = "a", nonce: Data? = nil, peerId: String = "p|é", serverId: String = "s") throws -> Data {
        try ContinuityLibraryEditsAuthMath.authMessage(authId: authId, nonce: nonce ?? self.nonce, peerId: peerId, serverId: serverId)
    }
    private func request(token: String = "t|é", nonce: Data? = nil, peerId: String = "p|é", serverId: String = "s", method: String = "POST", path: String = "/m", query: [String: String] = ["z": "x|y", "a": ""], body: Data = Data([0, 255, 124])) throws -> Data {
        try ContinuityLibraryEditsAuthMath.requestMessage(token: token, nonce: nonce ?? self.nonce, peerId: peerId, serverId: serverId, method: method, path: path, query: query, body: body)
    }

    func testAuthFixedUTF8FramingFixture() throws {
        // Hand-counted UInt32 BE fields, independently concatenated outside Swift.
        XCTAssertEqual(try auth(), hex("0000001b69637562652d6c6962726172792d65646974732d617574682d7631000000016100000004707cc3a9000000017300000020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
    }
    func testRequestFixedDigestFixture() throws {
        // Python hashlib over hand-counted binary framing, never this helper.
        XCTAssertEqual(Data(SHA256.hash(data: try request())), hex("707b7f2db4820e7c336a233d35934376b2793c4708eb25c40f27d6bc70ba9c7f"))
    }
    func testFixedKeyVerifiesIndependentEd25519Fixtures() throws {
        // Python cryptography Ed25519 over the hand-framed transcripts recorded
        // in task-3b1-report.md; seed is RFC 8032 test 1, public key below.
        let key = try key
        XCTAssertEqual(key.publicKey.rawRepresentation, hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"))
        XCTAssertTrue(ContinuityLibraryEditsAuthMath.verifyAuth(signature: hex("b75d05068c089ef98d616736acf2aa6c8e624732f7fea56f435e20af3b28a785e885d46bcf03c120aa81065b6248a45527f4161c1bd4a602031f80fc89c1fa02"), authId: "a", nonce: nonce, peerId: "p|é", serverId: "s", publicKey: key.publicKey.rawRepresentation))
        XCTAssertTrue(ContinuityLibraryEditsAuthMath.verifyRequest(signature: hex("bdee693804b1e9cdf6746cf39490ed3047114b223b6c4de174a3561be1b08971baf852cd6fcf808f514b181cc8e824e819e8d2002ae6a3e2876b0509ab5b1809"), token: "t|é", nonce: nonce, peerId: "p|é", serverId: "s", method: "POST", path: "/m", query: ["a": "", "z": "x|y"], body: Data([0, 255, 124]), publicKey: key.publicKey.rawRepresentation))
    }

    func testAuthSignVerifyAndEveryFieldBinding() throws {
        let key = try key
        let signature = try ContinuityLibraryEditsAuthMath.signAuth(authId: "a", nonce: nonce, peerId: "p|é", serverId: "s", signingKey: key)
        XCTAssertTrue(ContinuityLibraryEditsAuthMath.verifyAuth(signature: signature, authId: "a", nonce: nonce, peerId: "p|é", serverId: "s", publicKey: key.publicKey.rawRepresentation))
        for changed in [try auth(authId: "b"), try auth(nonce: Data(repeating: 1, count: 32)), try auth(peerId: "p"), try auth(serverId: "t")] {
            XCTAssertFalse(key.publicKey.isValidSignature(signature, for: changed))
        }
        XCTAssertFalse(ContinuityLibraryEditsAuthMath.verifyAuth(signature: signature, authId: "a", nonce: nonce, peerId: "p|é", serverId: "s", publicKey: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation))
    }
    func testRequestSignVerifyAndEveryFieldBinding() throws {
        let key = try key
        let signature = try ContinuityLibraryEditsAuthMath.signRequest(token: "t|é", nonce: nonce, peerId: "p|é", serverId: "s", method: "POST", path: "/m", query: ["z": "x|y", "a": ""], body: Data([0, 255, 124]), signingKey: key)
        XCTAssertTrue(ContinuityLibraryEditsAuthMath.verifyRequest(signature: signature, token: "t|é", nonce: nonce, peerId: "p|é", serverId: "s", method: "POST", path: "/m", query: ["a": "", "z": "x|y"], body: Data([0, 255, 124]), publicKey: key.publicKey.rawRepresentation))
        let changes = [try request(token: "t"), try request(nonce: Data(repeating: 2, count: 32)), try request(peerId: "p"), try request(serverId: "t"), try request(method: "post"), try request(path: "/M"), try request(query: ["z": "x|y"]), try request(query: ["a": "", "z": "x|z"]), try request(query: ["a": "", "Z": "x|y"]), try request(body: Data([0, 255, 125]))]
        for changed in changes { XCTAssertFalse(key.publicKey.isValidSignature(signature, for: changed)) }
        XCTAssertFalse(ContinuityLibraryEditsAuthMath.verifyRequest(signature: signature, token: "t|é", nonce: nonce, peerId: "p|é", serverId: "s", method: "POST", path: "/m", query: ["a": "", "z": "x|y"], body: Data([0, 255, 124]), publicKey: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation))
    }
    func testVerifyWrappersRejectEverySubstitutedField() throws {
        let key = try key
        let authSignature = try key.signature(for: auth())
        func checkAuth(authId: String = "a", nonce: Data? = nil, peerId: String = "p|é", serverId: String = "s") -> Bool {
            ContinuityLibraryEditsAuthMath.verifyAuth(signature: authSignature, authId: authId, nonce: nonce ?? self.nonce, peerId: peerId, serverId: serverId, publicKey: key.publicKey.rawRepresentation)
        }
        XCTAssertFalse(checkAuth(authId: "b"))
        XCTAssertFalse(checkAuth(nonce: Data(repeating: 1, count: 32)))
        XCTAssertFalse(checkAuth(peerId: "p"))
        XCTAssertFalse(checkAuth(serverId: "t"))
        let requestSignature = try key.signature(for: request())
        func checkRequest(token: String = "t|é", nonce: Data? = nil, peerId: String = "p|é", serverId: String = "s", method: String = "POST", path: String = "/m", query: [String: String] = ["a": "", "z": "x|y"], body: Data = Data([0, 255, 124])) -> Bool {
            ContinuityLibraryEditsAuthMath.verifyRequest(signature: requestSignature, token: token, nonce: nonce ?? self.nonce, peerId: peerId, serverId: serverId, method: method, path: path, query: query, body: body, publicKey: key.publicKey.rawRepresentation)
        }
        XCTAssertFalse(checkRequest(token: "t"))
        XCTAssertFalse(checkRequest(nonce: Data(repeating: 1, count: 32)))
        XCTAssertFalse(checkRequest(peerId: "p"))
        XCTAssertFalse(checkRequest(serverId: "t"))
        XCTAssertFalse(checkRequest(method: "post"))
        XCTAssertFalse(checkRequest(path: "/M"))
        XCTAssertFalse(checkRequest(query: ["a": "", "z": "x|z"]))
        XCTAssertFalse(checkRequest(body: Data()))
    }

    func testAuthRequestAndLegacyROMDomainsCannotCross() throws {
        let key = try key
        let authSignature = try ContinuityLibraryEditsAuthMath.signAuth(authId: "a", nonce: nonce, peerId: "p|é", serverId: "s", signingKey: key)
        let legacySignature = try ContinuityPairingMath.signAuth(nonce: nonce, peerId: "p|é", serverId: "s", signingKey: key)
        XCTAssertFalse(ContinuityPairingMath.verifyAuth(signature: authSignature, nonce: nonce, peerId: "p|é", serverId: "s", publicKey: key.publicKey.rawRepresentation))
        XCTAssertFalse(ContinuityLibraryEditsAuthMath.verifyAuth(signature: legacySignature, authId: "a", nonce: nonce, peerId: "p|é", serverId: "s", publicKey: key.publicKey.rawRepresentation))
        XCTAssertFalse(key.publicKey.isValidSignature(authSignature, for: try request()))
        XCTAssertFalse(key.publicKey.isValidSignature(try key.signature(for: request()), for: try auth()))
    }
    func testQueryOrderIsStableButEmptyAndAdditionalValuesAreBound() throws {
        var forward: [String: String] = [:]
        var reverse: [String: String] = [:]
        for pair in [("a", ""), ("z", "x|y"), ("é", "值")] { forward[pair.0] = pair.1 }
        for pair in [("é", "值"), ("z", "x|y"), ("a", "")] { reverse[pair.0] = pair.1 }
        XCTAssertEqual(try request(query: forward), try request(query: reverse))
        XCTAssertNotEqual(try request(query: [:]), try request(query: ["": ""]))
        XCTAssertNotEqual(try request(body: Data()), try request(body: Data([0])))
    }
    func testLengthFramingPreventsSeparatorAndFieldBoundaryCollisions() throws {
        XCTAssertNotEqual(try auth(peerId: "é"), try auth(peerId: "e\u{301}"))
        XCTAssertNotEqual(try auth(authId: "a|b", peerId: "c"), try auth(authId: "a", peerId: "b|c"))
        XCTAssertNotEqual(try request(method: "A|B", path: "C"), try request(method: "A", path: "B|C"))
        XCTAssertNotEqual(try request(query: ["a|b": "c"]), try request(query: ["a": "b|c"]))
        XCTAssertNotEqual(try request(query: ["a": "b", "c": "d"]), try request(query: ["a": "b|c|d"]))
    }
    func testMalformedNoncesRejectedByEncodingSigningAndVerification() throws {
        let key = try key
        for count in [0, 1, 31, 33, 64] {
            let badNonce = Data(repeating: 0, count: count)
            XCTAssertThrowsError(try auth(nonce: badNonce))
            XCTAssertThrowsError(try request(nonce: badNonce))
            XCTAssertThrowsError(try ContinuityLibraryEditsAuthMath.signAuth(authId: "a", nonce: badNonce, peerId: "p", serverId: "s", signingKey: key))
            XCTAssertThrowsError(try ContinuityLibraryEditsAuthMath.signRequest(token: "t", nonce: badNonce, peerId: "p", serverId: "s", method: "GET", path: "/", query: [:], body: Data(), signingKey: key))
            XCTAssertFalse(ContinuityLibraryEditsAuthMath.verifyAuth(signature: Data(repeating: 0, count: 64), authId: "a", nonce: badNonce, peerId: "p", serverId: "s", publicKey: key.publicKey.rawRepresentation))
            XCTAssertFalse(ContinuityLibraryEditsAuthMath.verifyRequest(signature: Data(repeating: 0, count: 64), token: "t", nonce: badNonce, peerId: "p", serverId: "s", method: "GET", path: "/", query: [:], body: Data(), publicKey: key.publicKey.rawRepresentation))
        }
    }
    func testMalformedKeysAndSignaturesFailClosed() throws {
        let key = try key
        let valid = try key.signature(for: auth())
        for pair in [(valid, Data()), (valid, Data(repeating: 0, count: 31)), (Data(), key.publicKey.rawRepresentation), (Data(repeating: 0, count: 63), key.publicKey.rawRepresentation), (Data(repeating: 0, count: 65), key.publicKey.rawRepresentation), (Data(repeating: 0, count: 64), key.publicKey.rawRepresentation)] {
            XCTAssertFalse(ContinuityLibraryEditsAuthMath.verifyAuth(signature: pair.0, authId: "a", nonce: nonce, peerId: "p|é", serverId: "s", publicKey: pair.1))
            XCTAssertFalse(ContinuityLibraryEditsAuthMath.verifyRequest(signature: pair.0, token: "t|é", nonce: nonce, peerId: "p|é", serverId: "s", method: "POST", path: "/m", query: ["a": "", "z": "x|y"], body: Data([0, 255, 124]), publicKey: pair.1))
        }
    }
}
