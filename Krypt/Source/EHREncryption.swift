//
//  EHREncryption.swift
//  Krypt
//
//  Created by marko on 25.01.19.
//

import Foundation

/// (EHR) Electronic Health Record (E2EE) End to End Encryption used in Vivy
public struct EHREncryption {
  /// All encryption versions that are currently supported in Vivy
  ///
  /// - gcmOAEP: AES 256 GCM symetric | RSA OAEP SHA256 asymetric
  /// - cbcPKCS1: AES 256 CBC symetric | RSA PKCS7 asymetric
  public enum Version {
    case gcmOAEP
    case cbcPKCS1
  }

  /// I/O object when interacting with EHR E2EE
  public struct EncryptedData {
    /// base64 encoded
    public let cipherKey: String

    /// encrypted data
    public let data: Data

    /// raw value of `EHREncryption.Version`
    public let version: Version

    public init(cipherKey: String, data: Data, version: Version) {
      self.cipherKey = cipherKey
      self.data = data
      self.version = version
    }
  }

  /// Asymetrically encrypts the provided data with AES 256 GCM and RSA OAEP SHA256
  ///
  /// - Parameters:
  ///   - data: data to encrypt
  ///   - key: RSA public key to encrypts with
  /// - Returns: `EncryptedData` object
  /// - Throws: `PublicError.encryptionFailed`
  public static func encrypt(data: Data, with key: Key) throws -> EncryptedData {
    do {
      // Encrypting only with AES 256 GCM and RSA OAEP SHA256
      let version = Version.gcmOAEP

      // 1. Encrypt content with AES
      let (encryptedData, aesKey, aesIV) = try AES256.encrypt(data: data, blockMode: version.aesBlockMode)

      // 2. Create cipher auth from the AES key and IV
      let cipherAttr = CipherAttr(key: aesKey, iv: aesIV)
      let cipherAttrJSONData = try JSONEncoder().encode(cipherAttr)

      // 3. Encrypt meta message with RSA
      let encryptedCipherAttr = try RSA.encrypt(data: cipherAttrJSONData, with: key, padding: version.rsaPadding)
      let encryptedCipherAttrBase64 = encryptedCipherAttr.base64EncodedString()

      return EncryptedData(
        cipherKey: encryptedCipherAttrBase64,
        data: encryptedData,
        version: version
      )
    } catch {
      throw PublicError.encryptionFailed
    }
  }

  /// Asymetrically decrypts the provided encrypted data depending on the version provided
  ///
  /// - Parameters:
  ///   - encryptedData: `EncryptedData` object that contains data, cipher key and version
  ///   - key: RSA private key to decrypt with
  /// - Returns: decrypted data
  /// - Throws: `PublicError.decryptionFailed`
  public static func decrypt(encryptedData: EncryptedData, with key: Key) throws -> Data {
    do {
      let version = encryptedData.version

      // 1. Decrypt cipher auth
      guard let encryptedCipherAuth = Data(base64Encoded: encryptedData.cipherKey) else {
        throw PublicError.decryptionFailed
      }
      let cipherAttrData = try RSA.decrypt(data: encryptedCipherAuth, with: key, padding: version.rsaPadding)

      // 2. Decode cipher auth with the AES key in IV
      guard let cipherAttr = try? JSONDecoder().decode(CipherAttr.self, from: cipherAttrData) else {
        throw PublicError.decryptionFailed
      }

      // 3. Decrypt content with AES
      let decryptedData = try AES256.decrypt(data: encryptedData.data, key: cipherAttr.key, iv: cipherAttr.iv, blockMode: version.aesBlockMode)

      return decryptedData
    } catch {
      throw PublicError.decryptionFailed
    }
  }
}

private extension EHREncryption.Version {
  /// returns AES block mode depending on Vivy encryption version
  var aesBlockMode: AES256.BlockMode {
    switch self {
    case .gcmOAEP:
      return .gcm
    case .cbcPKCS1:
      return .cbc
    }
  }

  /// returns RSA padding depending on Vivy encryption version
  var rsaPadding: RSA.Padding {
    switch self {
    case .gcmOAEP:
      return .oaep
    case .cbcPKCS1:
      return .pkcs1
    }
  }
}
