//
//  MedStickerEncryption.swift
//  Krypt
//
//  Created by marko on 29.01.19.
//

import Foundation

public struct MedStickerEncryption {
  public static func encrypt(data: Data, pin: Data, code: Data) throws -> Data {
    do {
      let scryptKey = Scrypt().scrypt(
        passphrase: [UInt8](pin),
        salt: [UInt8](code),
        n: 16384,
        r: 8,
        p: 1,
        dkLen: 32
      )

      let aesIV = Scrypt().scrypt(
        passphrase: scryptKey,
        salt: [UInt8](pin),
        n: 16384,
        r: 8,
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

  public static func decrypt(data: Data, pin: Data, code: Data) throws -> Data {
    do {
      let scryptKey = Scrypt().scrypt(
        passphrase: [UInt8](pin),
        salt: [UInt8](code),
        n: 16384,
        r: 8,
        p: 1,
        dkLen: 32
      )

      let aesIV = Scrypt().scrypt(
        passphrase: scryptKey,
        salt: [UInt8](pin),
        n: 16384,
        r: 8,
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
