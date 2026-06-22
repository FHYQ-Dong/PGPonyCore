// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse
//
// Regression + reference for the "offline primary, subkeys on card" layout.
//
// Bug (confirmed by NorseHorse): the closed app's "Link to hardware key" step
// compares the card's SIGNING-slot fingerprint against the PRIMARY key
// fingerprint. With an offline primary whose signing/encryption/auth keys are
// all on-card SUBKEYS, that comparison can never pass, so link fails and
// decryption falls back to "no usable key".
//
// What lives in THIS open-source core (and is exercised here):
//   * OpenPGPPacketParser.parseAllPublicKeys  → primary + every subkey, each with
//     its own fingerprint.
//   * the encryption builder (OpenPGPPacketBuilder) → a card-decryptable message
//     to the [E] subkey.
// The buggy match logic itself is NOT in this repo — it's in the closed app
// (see README "What's deliberately not here"). These tests are the reference
// implementation + regression to hand back: match each card slot against the
// WHOLE keyblock and accept a subkey; never require slot == primary.
//
// Runs headless (no card, no device): pure bytes-in/out. The on-card PSO:DECIPHER
// of the message printed by `testGenerateSampleCiphertextToEncryptionSubkey` is
// the manual, hardware-only step.

import XCTest
import Foundation
@testable import PGPonyCore

final class OfflinePrimaryCardTests: XCTestCase {

    // MARK: - Sample key (FHYQ Dong) — public, also on keys.openpgp.org by fingerprint
    // Primary 3DE57DE3D9ABB1C930405A28CFE702FB746017E1 — ed25519 [SC], OFFLINE.
    // Subkeys, all on the card:
    //   [S] 0B171C84D21621F3  ed25519
    //   [E] 7A019AB78C093065  cv25519
    //   [A] 2D352C93EA85DF7D  ed25519
    private static let samplePubKeyArmored = """
    -----BEGIN PGP PUBLIC KEY BLOCK-----
    Comment: 3DE5 7DE3 D9AB B1C9 3040  5A28 CFE7 02FB 7460 17E1
    Comment: FHYQ Dong <FHYQ-Dong-Work@outlook.com>
    Comment: FHYQ Dong <FHYQ-Dong@outlook.com>
    Comment: Haoyu Dong <donghy23@mails.tsinghua.edu.cn>

    xjMEaESFkhYJKwYBBAHaRw8BAQdAmQNNStAj505r02VstAra1DM/xudxTpm9J1Ab
    MON4myLNJkZIWVEgRG9uZyA8RkhZUS1Eb25nLVdvcmtAb3V0bG9vay5jb20+wq8E
    ExYKAFcWIQQ95X3j2auxyTBAWijP5wL7dGAX4QUCajKyNBsUgAAAAAAEAA5tYW51
    MiwyLjUrMS4xMSwyLDECGwMFCwkIBwICIgIGFQoJCAsCBBYCAwECHgcCF4AACgkQ
    z+cC+3RgF+FPHQD/ecMv/P9JMbRilZ+J4kUakGiPrZeJ1KraKK+5IUGsICABAOgP
    UipeQjQ30CfoMkh5VGfJQq/LOSHCKmBVpyj0dNwKzSFGSFlRIERvbmcgPEZIWVEt
    RG9uZ0BvdXRsb29rLmNvbT7CiQQTFggAMRYhBD3lfePZq7HJMEBaKM/nAvt0YBfh
    BQJoRIWSAhsDBAsJCAcFFQgJCgsFFgIDAQAACgkQz+cC+3RgF+GeNgD7BTCzrWww
    /pLvM6V7zE6XZogjwp7McRzcsWp9+9jf4bYBAJpERWXMBkYjff9GCBF5/omB53Nd
    sg4jLsOnG76QfkcMzStIYW95dSBEb25nIDxkb25naHkyM0BtYWlscy50c2luZ2h1
    YS5lZHUuY24+wq8EExYKAFcWIQQ95X3j2auxyTBAWijP5wL7dGAX4QUCajKyXhsU
    gAAAAAAEAA5tYW51MiwyLjUrMS4xMSwyLDECGwMFCwkIBwICIgIGFQoJCAsCBBYC
    AwECHgcCF4AACgkQz+cC+3RgF+H60gEAjoR30oUmVS0HQuY4FBn9EJPVXxlhENzF
    a5vUIWkaCNkBAOFGYFdfNe3YpHtkgD3KeH6ELnsAymXX+1vq7VI3fXIIzjMEajKz
    bBYJKwYBBAHaRw8BAQdAZLr4NEiWVkDMe7Igfm/zvHmMLAbtFebdNRd8eBaG2O3C
    lAQYFgoAPBYhBD3lfePZq7HJMEBaKM/nAvt0YBfhBQJqMrNsGxSAAAAAAAQADm1h
    bnUyLDIuNSsxLjExLDIsMQIbIAAKCRDP5wL7dGAX4WNeAPsH5a/NJVL72XhfzNiT
    xmI6rrNmGQo9k6Z81Wh34T1idwD8CbLNJyMPAZlkGZHG4HN71oQMoz8OsHuNksUY
    HjvD5gzOMwRqMrKdFgkrBgEEAdpHDwEBB0DCaKbVr/O79N5yZSBBAn3ylRYH6Mos
    EIWnprx/0jJeuMLASwQYFgoAPBYhBD3lfePZq7HJMEBaKM/nAvt0YBfhBQJqMrKd
    GxSAAAAAAAQADm1hbnUyLDIuNSsxLjExLDIsMQIbAgCBCRDP5wL7dGAX4XYgBBkW
    CgAdFiEEs7aGfvTnsGnIbPwoCxcchNIWIfMFAmoysp0ACgkQCxcchNIWIfM4+wEA
    5TuzMi6abkKclDKuQabqs4pxTeWeKkHDIVOHoiBKyDAA/AoCZLIcZmea43BxLoHl
    7g6p48jdrsLe7fPmZq2r+u0KbrcBAPDIcAhjc+Om2UFn5v3q+FWYLNLv3ilrbA4a
    2fFW17L2AP0XtbstuwyS0FwvVpyBAqvO2C7pIrFdL9e80iuipWwxC844BGhEhZIS
    CisGAQQBl1UBBQEBB0DsZy2bUcEpJ0wTwOO02JIDaLFFllZlpSsXnATZVviBTQMB
    CAfCeAQYFggAIBYhBD3lfePZq7HJMEBaKM/nAvt0YBfhBQJoRIWSAhsMAAoJEM/n
    Avt0YBfhoAUBAKxeRO8b7UlKsXOROhR/GI9uDxU1nEuxed7e8ws9xjSpAQCwKAAD
    5shzMZKnEkyzDIwFQfO+Zj1NnuDqTH1YWcNrAw==
    =C2Xz
    -----END PGP PUBLIC KEY BLOCK-----
    """

    // Expected key IDs (lowercase, last 8 bytes of each fingerprint).
    private static let primaryKeyID = "cfe702fb746017e1"
    private static let signKeyID    = "0b171c84d21621f3"
    private static let encKeyID     = "7a019ab78c093065"
    private static let authKeyID    = "2d352c93ea85df7d"

    // OpenPGP public-key algorithm IDs (RFC 4880).
    private static let algoEdDSA: UInt8 = 22
    private static let algoECDH:  UInt8 = 18

    // MARK: - Helpers

    /// Parse the sample key into [primary, subkeys...] (primary is always first).
    private func parseSampleKeyblock(file: StaticString = #file, line: UInt = #line) throws -> [ParsedPublicKeyInfo] {
        let raw = Self.dearmor(Self.samplePubKeyArmored)
        XCTAssertFalse(raw.isEmpty, "sample key failed to de-armor", file: file, line: line)
        let keys = try OpenPGPPacketParser.parseAllPublicKeys(from: raw)
        XCTAssertEqual(keys.count, 4, "expected 1 primary + 3 subkeys", file: file, line: line)
        return keys
    }

    private func subkey(_ keyID: String, in keyblock: [ParsedPublicKeyInfo],
                        file: StaticString = #file, line: UInt = #line) throws -> ParsedPublicKeyInfo {
        let match = keyblock.dropFirst().first { $0.keyIDHex == keyID }
        return try XCTUnwrap(match, "subkey \(keyID) not found", file: file, line: line)
    }

    // MARK: - 1. Layout: offline primary, three subkeys on the card

    func testSampleKeyIsOfflinePrimaryWithSubkeysOnCard() throws {
        let keys = try parseSampleKeyblock()

        let primary = keys[0]
        XCTAssertEqual(primary.keyIDHex, Self.primaryKeyID)
        XCTAssertEqual(primary.algorithm, Self.algoEdDSA, "primary is ed25519 [SC]")
        XCTAssertEqual(primary.version, 4)

        let sign = try subkey(Self.signKeyID, in: keys)
        let enc  = try subkey(Self.encKeyID,  in: keys)
        let auth = try subkey(Self.authKeyID, in: keys)

        XCTAssertEqual(sign.algorithm, Self.algoEdDSA, "[S] subkey is ed25519")
        XCTAssertEqual(enc.algorithm,  Self.algoECDH,  "[E] subkey is cv25519 (ECDH)")
        XCTAssertEqual(auth.algorithm, Self.algoEdDSA, "[A] subkey is ed25519")
    }

    // MARK: - 2. Regression: card slots map to SUBKEYS, not the primary

    /// The reference matcher the closed app needs: find the keyblock entry whose
    /// fingerprint equals the card slot's fingerprint, searching the WHOLE keyblock
    /// (primary + subkeys), and accept a subkey. The old logic only compared
    /// against the primary, which is exactly why link failed for this layout.
    func testCardSlotsMapToSubkeysNotPrimary() throws {
        let keys = try parseSampleKeyblock()
        let primary = keys[0]

        // The card's 0x00C5 DO holds the three SUBKEY fingerprints (20-byte v4),
        // never the primary. Simulate each slot from the parsed subkey fingerprints.
        for id in [Self.signKeyID, Self.encKeyID, Self.authKeyID] {
            let onCard = try subkey(id, in: keys)
            let cardSlotFingerprint = onCard.fingerprint   // what GET DATA(0x6E)->0xC5 returns

            let match = Self.matchCardSlot(fingerprint: cardSlotFingerprint, in: keys)
            let m = try XCTUnwrap(match, "slot \(id) matched nothing in the keyblock")

            XCTAssertFalse(m.isPrimary, "slot \(id) must map to a SUBKEY, not the primary")
            XCTAssertEqual(m.key.keyIDHex, id)
            // And the heart of the bug: the slot fingerprint never equals the primary's.
            XCTAssertNotEqual(cardSlotFingerprint, primary.fingerprint,
                              "comparing slot \(id) against the primary fingerprint can never match")
        }

        // Mirror the exact symptom: card signing slot D21621F3 vs primary 746017E1.
        let sign = try subkey(Self.signKeyID, in: keys)
        XCTAssertEqual(sign.keyIDHex.suffix(8), "d21621f3")
        XCTAssertEqual(primary.keyIDHex.suffix(8), "746017e1")
        XCTAssertNotEqual(sign.keyIDHex, primary.keyIDHex)
    }

    // MARK: - 3. Generate a card-decryptable ciphertext to the [E] subkey

    /// Builds, with the kernel's OpenPGPPacketBuilder, an OpenPGP message encrypted
    /// to the cv25519 [E] subkey (7A019AB78C093065) and prints the armored result.
    /// Copy it from the test log and decrypt it on the YubiKey (PSO:DECIPHER, PIN +
    /// touch) to verify the offline-primary path end to end.
    func testGenerateSampleCiphertextToEncryptionSubkey() throws {
        let keys = try parseSampleKeyblock()
        let enc = try subkey(Self.encKeyID, in: keys)

        let recipient = try XCTUnwrap(Self.cv25519Recipient(from: enc),
                                      "could not extract Cv25519 recipient from [E] subkey")

        let plaintext = Data("PGPony offline-primary decrypt works.\n".utf8)

        // Binary form first, so we can assert the message really targets the [E] subkey.
        let binary = try OpenPGPPacketBuilder.buildEncryptedMessage(
            plaintext: plaintext, recipients: [recipient], armor: false)
        let recipientIDs = OpenPGPPacketParser.messageRecipientKeyIDs(binary)
        XCTAssertTrue(recipientIDs.contains(enc.keyID),
                      "ciphertext is not addressed to the [E] subkey")

        // Armored form for the manual on-card decrypt step.
        let armored = try OpenPGPPacketBuilder.buildEncryptedMessage(
            plaintext: plaintext, recipients: [recipient], armor: true)
        let text = try XCTUnwrap(String(data: armored, encoding: .utf8))
        XCTAssertTrue(text.contains("BEGIN PGP MESSAGE"))

        print("""
        ===== SAMPLE CIPHERTEXT (encrypt to \(Self.encKeyID)) =====
        \(text)
        ===== END SAMPLE CIPHERTEXT =====
        """)
    }

    // MARK: - Reference matcher (the bit to lift into the closed app)

    struct SlotMatch {
        let key: ParsedPublicKeyInfo
        let isPrimary: Bool
        let index: Int
    }

    /// Match a card-slot fingerprint against the whole keyblock. Returns the matched
    /// (sub)key, or nil. NOTE: searches primary + all subkeys — does NOT assume primary.
    static func matchCardSlot(fingerprint cardFingerprint: [UInt8],
                              in keyblock: [ParsedPublicKeyInfo]) -> SlotMatch? {
        for (i, key) in keyblock.enumerated() where key.fingerprint == cardFingerprint {
            return SlotMatch(key: key, isPrimary: i == 0, index: i)
        }
        return nil
    }

    // MARK: - Local helpers (no card, no app code)

    /// Build a Cv25519Recipient from a parsed v4 ECDH ([E]) subkey.
    /// v4 ECDH key material = OID(len-prefixed) | point MPI | KDF params(len-prefixed);
    /// the cv25519 point is 0x40 || 32-byte X25519.
    static func cv25519Recipient(from subkey: ParsedPublicKeyInfo) -> Cv25519Recipient? {
        guard subkey.algorithm == algoECDH else { return nil }
        let m = subkey.keyMaterial
        var off = 0

        // Curve OID (1-octet length prefix)
        guard off < m.count else { return nil }
        let oidLen = Int(m[off]); off += 1
        guard oidLen != 0, oidLen != 0xFF, off + oidLen <= m.count else { return nil }
        off += oidLen

        // Point MPI (2-octet bit length, then ceil(bits/8) bytes)
        guard off + 2 <= m.count else { return nil }
        let bits = Int(m[off]) << 8 | Int(m[off + 1]); off += 2
        let pointLen = (bits + 7) / 8
        guard off + pointLen <= m.count else { return nil }
        let point = Array(m[off ..< off + pointLen]); off += pointLen
        guard point.count == 33, point[0] == 0x40 else { return nil }  // 0x40 || 32-byte X
        let rawPoint = Array(point[1...])

        // KDF params (1-octet length prefix): [reserved=0x01, hashID, cipherID]
        guard off < m.count else { return nil }
        let kdfLen = Int(m[off]); off += 1
        guard kdfLen >= 3, off + kdfLen <= m.count else { return nil }
        let kdf = Array(m[off ..< off + kdfLen])

        return Cv25519Recipient(
            subkeyPublicKey: rawPoint,
            subkeyFingerprint: subkey.fingerprint,
            subkeyID: subkey.keyID,
            kdfHashID: kdf[1],
            kdfCipherID: kdf[2]
        )
    }

    /// Minimal ASCII-armor → binary. Drops armor headers (up to the blank line) and
    /// the CRC-24 line (`=....`), then base64-decodes the body.
    static func dearmor(_ armored: String) -> [UInt8] {
        var body = ""
        var inBlock = false
        var pastHeaders = false
        for rawLine in armored.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("-----BEGIN") { inBlock = true; continue }
            if line.hasPrefix("-----END")   { break }
            guard inBlock else { continue }
            if !pastHeaders {
                if line.isEmpty { pastHeaders = true }   // blank line ends armor headers
                continue
            }
            if line.hasPrefix("=") { continue }          // CRC-24 checksum line
            body += line
        }
        return [UInt8](Data(base64Encoded: body) ?? Data())
    }
}
