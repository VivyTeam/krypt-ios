//
//  MedStickerEncryption.swift
//  Krypt
//
//  Created by marko on 29.01.19.
//

import Foundation
import Security

/// Encryption for Medical ID sticker public data used in Vivy iOS app
public struct MedStickerEncryption {
  /// Version of `MedStickerEncryption`
  ///
  /// - adam: legacy version, only used for backwards compatibility | Scrypt r = 8; AES 256 CBC
  /// - britney: this is the default value | Scrypt.r = 10; AES 256 GCM
  public enum Version {
    case adam
    case britney
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

      let encryptedMedSticker = EncryptedMedSticker(data: encrypted, attr: cipherAttr)

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

  public static func accessSignature(attr: CipherAttr, salt: Data) -> String {
    let combinedBytes = [attr.key, attr.iv, salt]
      .compactMap([UInt8].init)
      .reduce([UInt8](), +)
    let combinedData = Data(bytes: combinedBytes)
    let digest = SHA256.digest(combinedData)
    return digest.base64EncodedString()
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
    case .britney:
      return 10
    }
  }

  var aesBlockMode: AES256.BlockMode {
    switch self {
    case .adam:
      return .cbc
    case .britney:
      return .gcm
    }
  }
}
