//
//  EHREncryption.swift
//  Krypt
//
//  Created by marko on 25.01.19.
//

import Foundation

public struct EHREncryption {
  public enum Version: String {
    case gcmOAEP = "oeapgcm"
    case cbcPKCS1
  }

  public struct EncryptedData {
    let cipherKey: String
    let data: Data
    let version: String
  }

  public static func encrypt(data: Data, with key: Key) throws -> EncryptedData {
    do {
      // Encrypting only with AES 256 GCM and RSA OAEP SHA256
      let version = Version.gcmOAEP

      // 1. Encrypt content with AES
      let (encryptedData, aesKey, aesIV) = try AES256.encrypt(data: data, blockMode: version.aesBlockMode)

      // 2. Create meta message from the AES key and IV
      let cipherAuth = CipherAuth(key: aesKey, iv: aesIV)
      let cipherAuthJSONData = try JSONEncoder().encode(cipherAuth)

      // 3. Encrypt meta message with RSA
      let encryptedCipherAuth = try RSA.encrypt(data: cipherAuthJSONData, with: key, padding: version.rsaPadding)
      let encryptedCipherAuthBase64 = encryptedCipherAuth.base64EncodedString()

      return EncryptedData(
        cipherKey: encryptedCipherAuthBase64,
        data: encryptedData,
        version: version.rawValue
      )
    } catch {
      throw PublicError.encryptionFailed
    }
  }

  public static func decrypt(encryptedData: EncryptedData, with key: Key) throws -> Data {
    do {
      // 1. Decrypt meta message
      guard let encryptedMetaMessage = Data(base64Encoded: encryptedData.cipherKey) else {
        throw PublicError.decryptionFailed
      }
      let version: Version = Version(rawValue: encryptedData.version) ?? .cbcPKCS1
      let decryptedMetaMessage = try RSA.decrypt(data: encryptedMetaMessage, with: key, padding: version.rsaPadding)

      // 2. Decode meta message with the AES key in IV
      guard let cipherAuth = try? JSONDecoder().decode(CipherAuth.self, from: decryptedMetaMessage) else {
        throw PublicError.decryptionFailed
      }

      // 3. Decrypt content with AES
      let decryptedData = try AES256.decrypt(data: encryptedData.data, key: cipherAuth.key, iv: cipherAuth.iv, blockMode: version.aesBlockMode)

      return decryptedData
    } catch {
      throw PublicError.decryptionFailed
    }
  }
}

private extension EHREncryption.Version {
  var aesBlockMode: AES256.BlockMode {
    switch self {
    case .gcmOAEP:
      return .gcm
    case .cbcPKCS1:
      return .cbc
    }
  }

  var rsaPadding: RSA.Padding {
    switch self {
    case .gcmOAEP:
      return .oaep
    case .cbcPKCS1:
      return .pkcs1
    }
  }
}
