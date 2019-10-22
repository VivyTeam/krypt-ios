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

/// Symetric encryption used in Vivy.
///
/// Only 256 bits (32 bytes) long keys are supported along with
/// GCM and CBC being the only supported block modes
public struct AES256 {
  /// Error returned when dealing with CommonCrypto or in this case with CBC block mode AES
  ///
  /// - ccError: with `CCCryptorStatus`
  public enum Error: LocalizedError {
    case ccError(status: CCCryptorStatus)
  }

  /// Supported block modes
  ///
  /// - gcm: standart block mode for e2ee in Vivy
  /// - cbc: legacy block mode only used for mainly for decreption
  public enum BlockMode {
    case gcm
    case cbc
  }

  /// - Parameters:
  ///   - data: data to encrypt
  ///   - key: authentication key
  ///   - iv: initialization vector
  ///   - blockMode: which `BlockMode` to use
  /// - Returns: tuple of encrypted data, authentication key and initialization vector used for encryption
  /// - Throws: `ccError` or some CryptoSwift errors if using GCM
  public static func encrypt(data: Data, key: Data? = nil, iv: Data? = nil, blockMode: BlockMode) throws -> (encrypted: Data, key: Data, iv: Data) {
    switch blockMode {
    case .gcm:
      return try encryptGCM(data: data, key: key, iv: iv)
    case .cbc:
      return try cryptCBCPKCS7(data: data, key: key, iv: iv, operation: CCOperation(kCCEncrypt))
    }
  }

  /// - Parameters:
  ///   - data: data to decrypt
  ///   - key: authentication key
  ///   - iv: initialization vector
  ///   - blockMode: which `BlockMode` to use
  /// - Returns: decrypted data
  /// - Throws: `ccError` or some CryptoSwift errors if using GCM
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
  /// Generates random data of provided length
  ///
  /// - Parameter count: length of data
  /// - Returns: random data
  static func randomData(count: Int) -> Data {
    var data = Data(count: count)
    let status = data.withUnsafeMutableBytes { ptr -> Int32 in
      guard let pointer = ptr.baseAddress?.assumingMemoryBound(to: UnsafeRawBufferPointer.self) else {
        return errSecConversionError
      }
      return SecRandomCopyBytes(kSecRandomDefault, count, pointer)
    }
    guard status == errSecSuccess else {
      fatalError(#function)
    }
    return data
  }

  /// Encrypts data with GCM block mode
  /// Key and IV are randomly generated inside
  ///
  /// - Parameter data: data to encrypt
  /// - Returns: tuple of encrypted data, authentication key and initialization vector
  /// - Throws: any errors throws by CryptoSwift
  static func encryptGCM(data: Data, key: Data?, iv: Data?) throws -> (encrypted: Data, key: Data, iv: Data) {
    let key = key ?? randomData(count: kCCKeySizeAES256)
    let iv = iv ?? randomData(count: kCCKeySizeAES128)

    let aes = try AES(key: key.bytes, blockMode: GCM(iv: iv.bytes, mode: .combined), padding: .noPadding)
    let digest = try aes.encrypt(data.bytes)
    let encrypted = Data(digest)

    return (encrypted, key, iv)
  }

  /// Decrypts data with GCM block mode
  ///
  /// - Parameters:
  ///   - data: data to decrypt
  ///   - key: authentication key
  ///   - iv: initialization vector
  /// - Returns: decrypted data
  /// - Throws: any errors throws by CryptoSwift
  static func decryptGCM(data: Data, key: Data, iv: Data) throws -> Data {
    let aes = try AES(key: key.bytes, blockMode: GCM(iv: iv.bytes, mode: .combined), padding: .noPadding)
    let digest = try aes.decrypt(data.bytes)
    let decrypted = Data(digest)

    return decrypted
  }

  /// Single function for encryption with CBC block mode
  /// If key and/or IV are not provided, this functions generates a secure random data of correct length
  ///
  /// - Parameters:
  ///   - data: data to encrypt/decrypt
  ///   - key: authentication key
  ///   - iv: initialization vector
  ///   - operation: kCCEncrypt/kCCDecrypt
  /// - Returns: tuple of encrypted data, authentication key and initialization vector
  /// - Throws: any errors returned by CommonCrypto
  static func cryptCBCPKCS7(
    data: Data,
    key: Data?,
    iv: Data?,
    operation: CCOperation
  ) throws -> (encrypted: Data, key: Data, iv: Data) {
    let algorithm = CCAlgorithm(kCCAlgorithmAES)
    let options = CCOptions(kCCOptionPKCS7Padding)
    let key = key ?? randomData(count: kCCKeySizeAES256)
    let iv = iv ?? randomData(count: kCCKeySizeAES128)
    var dataOut = [UInt8](repeating: 0, count: data.count + kCCBlockSizeAES128)
    var dataOutMoved = 0
    var status: CCCryptorStatus!

    key.withUnsafeBytes { ptr in
      guard let keyBytes = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return }
      iv.withUnsafeBytes { ptr in
        guard let ivBytes = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return }
        data.withUnsafeBytes { ptr in
          guard let dataInBytes = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return }
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
