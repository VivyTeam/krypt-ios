//
//  MedStickerEncryption.swift
//  Krypt
//
//  Created by marko on 29.01.19.
//

import Foundation

public struct MedStickerEncryption {
  public enum Version: String {
    case aes = "scryptaes"
    case pkcs1 = "scryptpkcs1"
    case aes_r10 = "scryptaes_r10"
  }

  public enum Error: LocalizedError {
    case invalidVersion
  }

  public static func encrypt(data: Data, pin: Data, code: Data, version: Version) throws -> Data {
    do {
      var blockSize: Int?
      switch version {
      case .pkcs1, .aes:
        blockSize = 8
      case .aes_r10:
        blockSize = 10
      }

      guard let r = blockSize else {
        throw Error.invalidVersion
      }
      
      let scryptKey = Scrypt().scrypt(
        passphrase: [UInt8](pin),
        salt: [UInt8](code),
        n: 16384,
        r: r,
        p: 1,
        dkLen: 32
      )

      let aesIV = Scrypt().scrypt(
        passphrase: scryptKey,
        salt: [UInt8](pin),
        n: 16384,
        r: r,
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

  public static func decrypt(data: Data, pin: Data, code: Data, version: Version) throws -> Data {
    do {
      var blockSize: Int?
      switch version {
      case .pkcs1, .aes:
        blockSize = 8
      case .aes_r10:
        blockSize = 10
      }

      guard let r = blockSize else {
        throw Error.invalidVersion
      }

      let scryptKey = Scrypt().scrypt(
        passphrase: [UInt8](pin),
        salt: [UInt8](code),
        n: 16384,
        r: r,
        p: 1,
        dkLen: 32
      )

      let aesIV = Scrypt().scrypt(
        passphrase: scryptKey,
        salt: [UInt8](pin),
        n: 16384,
        r: r,
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
