//
//  AES256.swift
//  Krypt
//
//  Created by marko on 21.01.19.
//  Copyright © 2019 Vivy GmbH. All rights reserved.
//

import CommonCrypto
import CryptoSwift
import Foundation

public final class AES256 {
  public enum Error: LocalizedError {
    case ccError(status: CCCryptorStatus)
  }

  public enum BlockMode {
    case gcm
    case cbc
  }

  public static func encrypt(data: Data, blockMode: BlockMode) throws -> (encrypted: Data, key: Data, iv: Data) {
    switch blockMode {
    case .gcm:
      return try encryptGCM(data: data)
    case .cbc:
      return try cryptCBCPKCS7(data: data, key: nil, iv: nil, operation: CCOperation(kCCEncrypt))
    }
  }

  public static func decrypt(data: Data, key: Data, iv: Data, blockMode: BlockMode) throws -> Data {
    switch blockMode {
    case .gcm:
      return try decryptGCM(data: data, key: key, iv: iv)
    case .cbc:
      let (digest, _, _) = try cryptCBCPKCS7(data: data, key: key, iv: iv, operation: CCOperation(kCCDecrypt))
      return digest
    }
  }
}

private extension AES256 {
  static func randomData(count: Int) -> Data {
    var data = Data(count: count)
    let status = data.withUnsafeMutableBytes {
      SecRandomCopyBytes(kSecRandomDefault, count, $0)
    }
    guard status == errSecSuccess else {
      fatalError(#function)
    }
    return data
  }

  static func encryptGCM(data: Data) throws -> (encrypted: Data, key: Data, iv: Data) {
    let key = AES256.randomData(count: kCCKeySizeAES256)
    let iv = AES256.randomData(count: kCCKeySizeAES128)

    let aes = try AES(key: key.bytes, blockMode: GCM(iv: iv.bytes, mode: .combined), padding: .noPadding)
    let digest = try aes.encrypt(data.bytes)
    let encrypted = Data(bytes: digest)

    return (encrypted, key, iv)
  }

  static func decryptGCM(data: Data, key: Data, iv: Data) throws -> Data {
    let aes = try AES(key: key.bytes, blockMode: GCM(iv: iv.bytes, mode: .combined), padding: .noPadding)
    let digest = try aes.decrypt(data.bytes)
    let decrypted = Data(bytes: digest)

    return decrypted
  }

  static func cryptCBCPKCS7(
    data: Data,
    key: Data?,
    iv: Data?,
    operation: CCOperation
  ) throws -> (encrypted: Data, key: Data, iv: Data) {
    let algorithm = CCAlgorithm(kCCAlgorithmAES)
    let options = CCOptions(kCCOptionPKCS7Padding)
    let key = key ?? AES256.randomData(count: kCCKeySizeAES256)
    let iv = iv ?? AES256.randomData(count: kCCKeySizeAES128)
    var dataOut = [UInt8](repeating: 0, count: data.count + kCCBlockSizeAES128)
    var dataOutMoved = 0
    var status: CCCryptorStatus!

    key.withUnsafeBytes { (keyBytes: UnsafePointer<UInt8>) in
      iv.withUnsafeBytes { (ivBytes: UnsafePointer<UInt8>) in
        data.withUnsafeBytes { (dataInBytes: UnsafePointer<UInt8>) in
          status = CCCrypt(
            operation,
            algorithm,
            options,
            keyBytes,
            key.count,
            ivBytes,
            dataInBytes,
            data.count,
            &dataOut,
            dataOut.count,
            &dataOutMoved
          )
        }
      }
    }
    guard status == kCCSuccess else {
      throw Error.ccError(status: status)
    }
    let digest = Data(bytes: dataOut, count: dataOutMoved)
    return (digest, key, iv)
  }
}
