//
//  MedStickerEncryption.swift
//  Krypt
//
//  Created by marko on 29.01.19.
//

import Foundation

/// Encryption for medical sticker data using scrypt
public struct MedStickerEncryption {

  /// Version to determine block size
  ///
  /// - aes: iOS version 1
  /// - pkcs1: Android version 1
  /// - aes_r10: iOS & Android version 2
  /// iOS and Android used different version names for the first version
  public enum Version: String {
    case aes = "scryptaes"
    case pkcs1 = "scryptpkcs1"
    case aes_r10 = "scryptaes_r10"
  }

  /// Encrypts provided data with scrypt key and AES IV by using AES 256 CBC
  ///
  /// - Parameters:
  ///   - data: Data to encrypt
  ///   - pin: Used as passphrase for scrypt key and as salt for AES IV
  ///   - code: Used as salt for scrypt key
  ///   - version: Version to determine block size
  /// - Returns: Encrypted data
  /// - Throws: `PublicError.encryptionFailed`
  public static func encrypt(data: Data, pin: Data, code: Data, version: Version) throws -> Data {
    do {
      let scryptKey = Scrypt().scrypt(
        passphrase: [UInt8](pin),
        salt: [UInt8](code),
        n: 16384,
        r: version.blockSize,
        p: 1,
        dkLen: 32
      )

      let aesIV = Scrypt().scrypt(
        passphrase: scryptKey,
        salt: [UInt8](pin),
        n: 16384,
        r: version.blockSize,
        p: 1,
        dkLen: 16
      )

      let (encrypted, _, _) = try AES256.encrypt(
        data: data,
        key: Data(bytes: scryptKey),
        iv: Data(bytes: aesIV),
        blockMode: .cbc
      )
      return encrypted
    } catch {
      throw PublicError.encryptionFailed
    }
  }

  /// Decrypts provided data with scrypt key and AES IV by using AES 256 CBC
  ///
  /// - Parameters:
  ///   - data: Data to encrypt
  ///   - pin: Used as passphrase for scrypt key and as salt for AES IV
  ///   - code: Used as salt for scrypt key
  ///   - version: Version to determine block size
  /// - Returns: Decrypted data
  /// - Throws: `PublicError.decryptionFailed`
  public static func decrypt(data: Data, pin: Data, code: Data, version: Version) throws -> Data {
    do {
      let scryptKey = Scrypt().scrypt(
        passphrase: [UInt8](pin),
        salt: [UInt8](code),
        n: 16384,
        r: version.blockSize,
        p: 1,
        dkLen: 32
      )

      let aesIV = Scrypt().scrypt(
        passphrase: scryptKey,
        salt: [UInt8](pin),
        n: 16384,
        r: version.blockSize,
        p: 1,
        dkLen: 16
      )

      let decrypted = try AES256.decrypt(
        data: data,
        key: Data(bytes: scryptKey),
        iv: Data(bytes: aesIV),
        blockMode: .cbc
      )
      return decrypted
    } catch {
      throw PublicError.encryptionFailed
    }
  }
}

private extension MedStickerEncryption.Version {
  /// Returns block size by version
  var blockSize: Int {
    switch self {
    case .aes, .pkcs1:
      return 8
    case .aes_r10:
      return 10
    }
  }
}
