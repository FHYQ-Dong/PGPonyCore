// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse
//
// Reference implementation for the "offline primary, subkeys on card" link +
// decrypt flow — the thing the closed app currently gets wrong (it compares the
// card's signing-slot fingerprint against the PRIMARY key fingerprint instead of
// treating it as a subkey).
//
// This demo, using only PGPonyCore:
//   1. parses the sample public key  → primary + subkeys
//   2. reads the card's slot fingerprints (OpenPGPCardService.readCardInfo)
//   3. matches the card's DECRYPT slot against the WHOLE keyblock and accepts a
//      SUBKEY (never requires slot == primary)  ← the fix
//   4. PSO:DECIPHERs a message encrypted to the [E] subkey, on the card
//
// NOTE: the core is still `internal`, so this consumes it via `@testable import`
// (works in Debug with ENABLE_TESTABILITY=YES). When PGPonyCore promotes its
// audit surface to `public`, switch this to a plain `import`.

import Foundation
@testable import PGPonyCore

enum DemoError: LocalizedError {
    case decryptSlotEmpty
    case noKeyblockMatch(String)
    case slotMatchedPrimary
    case notEncryptionSubkey
    case emptyCiphertext

    var errorDescription: String? {
        switch self {
        case .decryptSlotEmpty:
            return "The card's decryption slot is empty (no fingerprint)."
        case .noKeyblockMatch(let fp):
            return "Card decrypt slot \(fp) matched no key in the public keyblock."
        case .slotMatchedPrimary:
            return "Card decrypt slot matched the PRIMARY key — expected a subkey."
        case .notEncryptionSubkey:
            return "Matched key is not a cv25519 (ECDH) encryption subkey."
        case .emptyCiphertext:
            return "The ciphertext is empty or not valid ASCII-armored PGP."
        }
    }
}

enum LinkDecryptDemo {

    /// Run the full link + on-card decrypt. `log` is called with progress lines
    /// (may be invoked off the main thread). Returns the decrypted plaintext.
    static func run(ciphertextArmored: String,
                    userPIN: String,
                    log: @escaping (String) -> Void) async throws -> String {

        // 1. Parse the sample public key into [primary, subkeys...].
        let keyblock = try OpenPGPPacketParser.parseAllPublicKeys(from: dearmor(samplePubKeyArmored))
        let primary = keyblock[0]
        log("Public key: primary \(primary.keyIDHex) + \(keyblock.count - 1) subkeys (primary is OFFLINE)")

        // 2. Connect over NFC and read the card's slot fingerprints.
        let card = try await OpenPGPCardService().connect(
            alertMessage: "Hold your hardware key to the top of your iPhone.")
        do {
            let info = try await card.readCardInfo()
            guard let decryptHex = info.decryptFingerprint else { throw DemoError.decryptSlotEmpty }
            log("Card decrypt slot fingerprint: \(decryptHex)")

            // 3. Match the card's DECRYPT slot against the whole keyblock (accept a subkey).
            let cardFP = bytes(fromHex: decryptHex)
            guard let match = matchCardSlot(fingerprint: cardFP, in: keyblock) else {
                throw DemoError.noKeyblockMatch(decryptHex)
            }
            guard !match.isPrimary else { throw DemoError.slotMatchedPrimary }
            let enc = match.key
            guard enc.algorithm == 18, let kdf = cv25519KDFParams(from: enc) else {
                throw DemoError.notEncryptionSubkey
            }
            log("→ matched [E] SUBKEY \(enc.keyIDHex), NOT the primary \(primary.keyIDHex)")

            // 4. Verify PW1 (confidentiality) and decrypt on the card.
            card.updateAlert("Verifying PIN…")
            try await card.verify(pin: userPIN, mode: .confidentiality)

            card.updateAlert("Decrypting on card — touch the key if it blinks…")
            let messageData = Data(dearmor(ciphertextArmored))
            guard !messageData.isEmpty else { throw DemoError.emptyCiphertext }

            let plaintext = try await OpenPGPPacketParser.decryptMessageOnCard(
                messageData: messageData,
                recipientSubkeyID: enc.keyID,
                recipientFingerprint: enc.fingerprint,
                kdfHashID: kdf.hashID,
                kdfCipherID: kdf.cipherID,
                provideSharedSecret: { ephemeral in
                    try await card.decipher(ephemeralPoint: ephemeral)
                }
            )

            card.end(success: true, message: "Decrypted ✓")
            return String(data: plaintext, encoding: .utf8)
                ?? plaintext.map { String(format: "%02x", $0) }.joined()
        } catch {
            card.end(success: false, message: error.localizedDescription)
            throw error
        }
    }

    // MARK: - Reference matcher (search the WHOLE keyblock; accept a subkey)

    struct SlotMatch { let key: ParsedPublicKeyInfo; let isPrimary: Bool }

    static func matchCardSlot(fingerprint cardFingerprint: [UInt8],
                              in keyblock: [ParsedPublicKeyInfo]) -> SlotMatch? {
        for (i, key) in keyblock.enumerated() where key.fingerprint == cardFingerprint {
            return SlotMatch(key: key, isPrimary: i == 0)
        }
        return nil
    }

    // MARK: - Helpers

    /// Extract the ECDH KDF hash/cipher IDs from a v4 cv25519 ([E]) subkey.
    /// Key material = OID(len) | point MPI | KDF params(len = [reserved, hash, cipher]).
    static func cv25519KDFParams(from subkey: ParsedPublicKeyInfo) -> (hashID: UInt8, cipherID: UInt8)? {
        guard subkey.algorithm == 18 else { return nil }
        let m = subkey.keyMaterial
        var off = 0
        guard off < m.count else { return nil }
        let oidLen = Int(m[off]); off += 1
        guard oidLen != 0, oidLen != 0xFF, off + oidLen <= m.count else { return nil }
        off += oidLen
        guard off + 2 <= m.count else { return nil }
        let bits = Int(m[off]) << 8 | Int(m[off + 1]); off += 2
        off += (bits + 7) / 8                          // skip the point MPI
        guard off < m.count else { return nil }
        let kdfLen = Int(m[off]); off += 1
        guard kdfLen >= 3, off + kdfLen <= m.count else { return nil }
        return (m[off + 1], m[off + 2])                // [reserved, hashID, cipherID]
    }

    static func bytes(fromHex hex: String) -> [UInt8] {
        var out: [UInt8] = []
        var it = hex.unicodeScalars.makeIterator()
        func nibble(_ s: Unicode.Scalar?) -> UInt8? {
            guard let s else { return nil }
            switch s {
            case "0"..."9": return UInt8(s.value - 48)
            case "a"..."f": return UInt8(s.value - 87)
            case "A"..."F": return UInt8(s.value - 55)
            default: return nil
            }
        }
        while let hi = nibble(it.next()), let lo = nibble(it.next()) {
            out.append(hi << 4 | lo)
        }
        return out
    }

    /// Minimal ASCII-armor → binary (drops headers up to the blank line + the CRC line).
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
                if line.isEmpty { pastHeaders = true }
                continue
            }
            if line.hasPrefix("=") { continue }
            body += line
        }
        return [UInt8](Data(base64Encoded: body) ?? Data())
    }

    // MARK: - Sample data

    /// Sample public key (FHYQ Dong): primary 3DE5…746017E1 ed25519 [SC] OFFLINE;
    /// on-card subkeys [S] 0B17…D21621F3, [E] 7A01…8C093065 cv25519, [A] 2D35…EA85DF7D.
    static let samplePubKeyArmored = """
    -----BEGIN PGP PUBLIC KEY BLOCK-----

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

    /// A sample message encrypted to the [E] subkey (plaintext: "PGPony
    /// offline-primary decrypt works.\n"). Replace with a fresh one from the CI log
    /// of `testGenerateSampleCiphertextToEncryptionSubkey` if you like — any message
    /// encrypted to 7A019AB78C093065 will decrypt on this card.
    static let sampleCiphertext = """
    -----BEGIN PGP MESSAGE-----

    wU4DegGat4wJMGUSAQdAL3qnWjbrirY74oNZyhENFsAR0Nn4AURgppPhU3tnhy4gPjRBjnlzbtWT
    rXaGCOv2sDMkTMX2+EZPiXbeqTH6MzfSVwE+RX3BA+yiElo8Sm/8hEKRvupO6sAvIj+HVwHpm+CP
    2Xxw46qqVJzY+G16ubz+GAiFqG+wjbwKgkATPiLUIwe+zvUpgWcHaff/LifsDH5AKG+r9/tajQ==
    =bMv0
    -----END PGP MESSAGE-----
    """
}
