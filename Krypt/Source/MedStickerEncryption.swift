//
//  MedStickerEncryption.swift
//  Krypt
//
//  Created by marko on 29.01.19.
//

import CryptoSwift
import Foundation
import Security

/// Encryption for Medical ID sticker public data used in Vivy iOS app
public struct MedStickerEncryption {
  /// Version of `MedStickerEncryption`
  ///
  /// - adam: legacy version, only used for backwards compatibility | Scrypt r = 8; AES 256 CBC
  /// - britney: this is the default value | Scrypt.r = 10; AES 256 GCM
  public enum Version: String {
    case adam
    case britney
    case charlie
  }

  /// Holds key and IV used for AES
  public struct CipherAttr {
    /// AES key 32 bytes
    public let key: Data

    /// AES IV 16 bytes
    public let iv: Data

    /// Medical ID Sticker encryption version
    public let version: Version

    public init(key: Data, iv: Data, version: Version) {
      self.key = key
      self.iv = iv
      self.version = version
    }
  }

  /// I/O object when interacting with Medical ID Sticker encryption
  public struct EncryptedMedSticker {
    /// AES encrypted data
    public let data: Data

    // Fingerprint file only used for version charlie
    public let fingerprintFile: Data?

    /// Cipher auth for AES encrypted data
    public let attr: CipherAttr
  }

  public static func encrypt(data: Data, pin: Data, code: Data) throws -> EncryptedMedSticker {
    do {
      let version = Version.britney
      let cipherAttr = deriveKey(pin: pin, code: code, version: version)

      let (encrypted, _, _) = try AES256.encrypt(
        data: data,
        key: cipherAttr.key,
        iv: cipherAttr.iv,
        blockMode: version.aesBlockMode
      )

      let encryptedMedSticker = EncryptedMedSticker(
        data: encrypted,
        fingerprintFile: nil,
        attr: cipherAttr
      )

      return encryptedMedSticker
    } catch {
      throw PublicError.encryptionFailed
    }
  }

  public static func decrypt(data: Data, with attr: CipherAttr) throws -> Data {
    do {
      let decrypted = try AES256.decrypt(
        data: data,
        key: attr.key,
        iv: attr.iv,
        blockMode: attr.version.aesBlockMode
      )
      return decrypted
    } catch {
      throw PublicError.encryptionFailed
    }
  }

  public static func deriveKey(pin: Data, code: Data, version: Version) -> CipherAttr {
    // Derive AES key from pin and code
    let aesKeyLength = 32 // 32 bytes for AES 256
    let aesKey = deriveBytes(length: aesKeyLength, passphrase: pin, salt: code, r: version.scryptR)

    // Derive AES IV from aesKey and pin
    let aesIVLength = 16 // 16 bytes
    let aesIV = deriveBytes(length: aesIVLength, passphrase: aesKey, salt: pin, r: version.scryptR)

    return CipherAttr(key: aesKey, iv: aesIV, version: version)
  }

  /// Creates signature for access
  /// Needs to be in this format: `${version}-${hashing_function}:${hash}`
  ///
  /// - Parameters:
  ///   - attr: `CipherAttr`
  ///   - salt: `Data`
  /// - Returns: created signature as `String`
  public static func accessSignature(attr: CipherAttr, salt: Data) -> String {
    let combinedBytes = [attr.key, attr.iv, salt]
      .compactMap([UInt8].init)
      .reduce([UInt8](), +)
    let combinedData = Data(bytes: combinedBytes)
    let digest = SHA256.digest(combinedData)
    let algorithm = [attr.version.rawValue, "sha256"].joined(separator: "-")
    return [algorithm, digest.base64EncodedString()].joined(separator: ":")
  }
}

private extension MedStickerEncryption {
  /// Derives a key of privided length with Scrypt
  ///
  /// - Parameters:
  ///   - length: length of the key to be derived
  ///   - passphrase: `Data`
  ///   - salt: `Data`
  /// - Returns: `Data` of derived key
  static func deriveBytes(length: Int, passphrase: Data, salt: Data, r: Int) -> Data {
    let derivedBytes = Scrypt().scrypt(
      passphrase: [UInt8](passphrase),
      salt: [UInt8](salt),
      n: 16384,
      r: r,
      p: 1,
      dkLen: length
    )
    return Data(bytes: derivedBytes)
  }
}

private extension MedStickerEncryption.Version {
  var scryptR: Int {
    switch self {
    case .adam:
      return 8
    case .britney, .charlie:
      return 10
    }
  }

  var aesBlockMode: AES256.BlockMode {
    switch self {
    case .adam:
      return .cbc
    case .britney, .charlie:
      return .gcm
    }
  }
}

// Implements version charlie
extension MedStickerEncryption {
  /// Generates fingerprint secret
  ///
  /// - Parameter pin: Secret to be used for hashing, 24 bytes read from QR code
  /// - Returns: Hex encoded fingerprint secret with version in front
  /// - Throws: Public encryption failure error
  public static func generateFingerprintSecret(withPin pin: String) throws -> String {
    let charlieConstantSalt: String = "5f1288159017d636c13c1c1b2835b8a871780bc2"

    let fingerprintSecretData = try hash(
      secret: pin,
      salt: charlieConstantSalt
    )
    return fingerprintSecretData.toFingerprint()
  }

  /// Encrypts data for version charlie
  ///
  /// - Parameters:
  ///   - pin: Pin from QR code
  ///   - secret: Randomly generated secret from backend
  ///   - salt: Randomly generated salt from backend
  ///   - iv: Randomly generated IV
  ///   - data: Data to encrypt
  /// - Returns: Encrypted data with cipher attributes
  /// - Throws: MedStickerEncryptionError.encrypt
  public static func encrypt(
    pin: String,
    secret: String,
    salt: String,
    iv: Data,
    data: Data
  ) throws -> EncryptedMedSticker {
    do {
      let version: MedStickerEncryption.Version = .charlie
      let keyAndFingerprintFile = try generateKeyAndFingerprintFile(
        withPin: pin,
        secret: secret,
        salt: salt
      )

      let (encrypted, _, _) = try AES256.encrypt(
        data: data,
        key: keyAndFingerprintFile.key,
        iv: iv,
        blockMode: version.aesBlockMode
      )

      let cipherAttr = CipherAttr(
        key: keyAndFingerprintFile.key,
        iv: iv,
        version: .charlie
      )

      let encryptedMedSticker = EncryptedMedSticker(
        data: encrypted,
        fingerprintFile: nil,
        attr: cipherAttr
      )

      return encryptedMedSticker
    } catch {
      throw MedStickerEncryptionError.encryption
    }
  }

  /// Decrypts data for version charlie
  ///
  /// - Parameters:
  ///   - pin: Pin
  ///   - secret: Randomly generated secret from backend
  ///   - salt: Randomly generated salt from backend
  ///   - iv: IV
  ///   - data: Data to decrypt
  /// - Returns: Decrypted data
  /// - Throws: MedStickerEncryptionError.decryption
  public static func decrypt(
    pin: String,
    secret: String,
    salt: String,
    iv: Data,
    data: Data
  ) throws -> Data {
    do {
      let version: MedStickerEncryption.Version = .charlie
      let keyAndFingerprintFile = try generateKeyAndFingerprintFile(
        withPin: pin,
        secret: secret,
        salt: salt
      )

      let decrypted = try AES256.decrypt(
        data: data,
        key: keyAndFingerprintFile.key,
        iv: iv,
        blockMode: version.aesBlockMode
      )
      return decrypted
    } catch {
      throw MedStickerEncryptionError.decryption
    }
  }
}

private extension MedStickerEncryption {
  /// Hashes data for version charlie using Scrypt
  ///
  /// - Parameters:
  ///   - secret: Password to be used for Scrypt hash
  ///   - salt: Salt
  /// - Returns: Hashed data
  /// - Throws: Thrown by Scrypt
  static func hash(
    secret: String,
    salt: String
  ) throws -> Data {
    let version: MedStickerEncryption.Version = .charlie

    let secretData = Data(secret.utf8)
    let saltData = Data(salt.utf8)
    let result = try CryptoSwift.Scrypt(
      password: [UInt8](secretData),
      salt: [UInt8](saltData),
      dkLen: 64,
      N: 16384,
      r: version.scryptR,
      p: 1
    ).calculate()
    return Data(bytes: result)
  }

  /// Generates key and fingerprint file
  ///
  /// - Parameters:
  ///   - pin: Secret to be used for hasing
  ///   - secret: Randomly generated secret by backend (backend_secret)
  ///   - salt: Randomly generated salt by backend (second_salt)
  /// - Returns: Key and fingerprint file pair
  ///            Key = First half part of the hash
  ///            Fingerprint file = Second half part of the hash
  /// - Throws: Public encryption failure error
  static func generateKeyAndFingerprintFile(
    withPin pin: String,
    secret: String,
    salt: String
  ) throws -> KeyFingerprintPair {
    let combinedSecret = [pin, secret].joined()

    let keyAndFingerprintFile = try hash(
      secret: combinedSecret,
      salt: salt
    )

    let split = keyAndFingerprintFile.splitIntoTwo()

    let key = split.first
    let fingerprintFileData = split.second

    let pair = KeyFingerprintPair(
      key: key,
      fingerprintFile: fingerprintFileData.toFingerprint()
    )

    return pair
  }
}

enum MedStickerEncryptionError: Error {
  case encryption
  case decryption
}

private extension Data {
  func splitIntoTwo() -> (first: Data, second: Data) {
    let halfLength = count / 2

    let firstHalf = self[0 ..< halfLength]
    let secondHalf = self[halfLength ..< count]

    return (first: firstHalf, second: secondHalf)
  }

  func toFingerprint() -> String {
    let version: MedStickerEncryption.Version = .charlie
    let hexString = toHexString()

    return [version.rawValue, hexString].joined(separator: ":")
  }
}
