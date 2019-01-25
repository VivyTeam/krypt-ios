//
//  E2EE.swift
//  Krypt
//
//  Created by marko on 25.01.19.
//

import Foundation

public struct E2EE {
  public enum Error: LocalizedError {
    case invalidMetaMessageBase64
    case invalidMetaMessageContents
  }

  public enum Version {
    case gcmOAEP
    case cbcPKCS1
  }

  private struct MetaMessage: Codable {
    let base64EncodedKey: Data
    let base64EncodedIV: Data
  }

  public static func encrypt(data: Data, key: Key, version: Version) throws -> (encrypted: Data, metaMessage: Data) {
    // 1. Encrypt content with AES
    let (encryptedData, aesKey, aesIV) = try AES256.encrypt(data: data, blockMode: version.aesBlockMode)

    // 2. Create meta message from the AES key and IV
    let base64AESKey = aesKey.base64EncodedData()
    let base64AESIV = aesIV.base64EncodedData()
    let metaMessage = MetaMessage(base64EncodedKey: base64AESKey, base64EncodedIV: base64AESIV)
    let metaMessageJSONData = try JSONEncoder().encode(metaMessage)

    // 3. Encrypt meta message with RSA
    let encryptedMetaMessage = try RSA.encrypt(data: metaMessageJSONData, with: key, padding: version.rsaPadding)
    let base64EncryptedMetaMessage = encryptedMetaMessage.base64EncodedData()

    return (encryptedData, base64EncryptedMetaMessage)
  }

  public static func decrypt(data: Data, metaMessage: Data, key: Key, version: Version) throws -> Data {
    // 1. Decrypt meta message
    guard let encryptedMetaMessage = Data(base64Encoded: metaMessage) else {
      throw Error.invalidMetaMessageBase64
    }
    let decryptedMetaMessage = try RSA.decrypt(data: encryptedMetaMessage, with: key, padding: version.rsaPadding)

    // 2. Decode meta message with the AES key in IV
    guard
      let metaMessage = try? JSONDecoder().decode(MetaMessage.self, from: decryptedMetaMessage),
      let aesKey = Data(base64Encoded: metaMessage.base64EncodedKey),
      let aesIV = Data(base64Encoded: metaMessage.base64EncodedIV)
    else {
      throw Error.invalidMetaMessageContents
    }

    // 3. Decrypt content with AES
    let decryptedData = try AES256.decrypt(data: data, key: aesKey, iv: aesIV, blockMode: version.aesBlockMode)

    return decryptedData
  }
}

private extension E2EE.Version {
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
