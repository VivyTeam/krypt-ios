//
//  EmergencyStickerEncryption.swift
//  Krypt
//
//  Created by Sun Bin Kim on 21.06.19.
//

import CryptoSwift
import Foundation

public class EmergencyStickerEncryption {
  /// Errors
  ///
  /// - invalidSalt: Failed to process salt
  /// - failToGenerateKeyAndFingerprintFile: Failed to generate key and fingerprint file
  public enum Error: LocalizedError {
    case invalidSalt
    case failToGenerateKeyAndFingerprintFile
  }

  /// Scrypt constants
  private static let scryptR: Int = 10
  private static let scryptN: Int = 16384
  private static let scryptP: Int = 1
  private static let scryptLength: Int = 64

  /// Key and fingerprint file length for spliting hash
  private static let fingerprintSecretLength: Int = 32
  private static let keyLength: Int = 32
  private static let fingerprintFileLength: Int = 32

  /// AES block mode
  private static let aesBlockMode: AES256.BlockMode = .gcm

  /// First salt used during fingerprint secret generation
  private static let firstSalt: String = "5f1288159017d636c13c1c1b2835b8a871780bc2"

  private static let version: MedStickerEncryption.Version = .charlie

  /// Holds key and fingerprint file
  public struct KeyFingerprintFilePair {
    public let key: Data
    public let fingerprintFile: Data
  }

  /// Generates fingerprint secret
  ///
  /// - Parameter pin: Secret to be used for hashing
  /// - Returns: Fingerprint secret
  /// - Throws: Public encryption failure error
  public static func generateFingerprintSecret(pin: Data) throws -> String {
    do {
      guard let salt = firstSalt.data(using: .utf8) else { throw Error.invalidSalt }
      let result = try hash(secret: pin, salt: salt)

      let fingerprintSecretData = result[0 ..< fingerprintSecretLength]
      let fingerprintSecretHex = fingerprintSecretData.toHexString()

      return [version.rawValue, fingerprintSecretHex].joined(separator: ":")
    } catch {
      throw PublicError.encryptionFailed
    }
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
  public static func generateKeyAndFingerprintFile(
    pin: Data,
    secret: Data,
    salt: Data
  ) throws -> KeyFingerprintFilePair {
    do {
      let combinedBytes = [pin, secret]
        .compactMap([UInt8].init)
        .reduce([UInt8](), +)
      let combinedSecret = Data(bytes: combinedBytes)

      let result = try hash(secret: combinedSecret, salt: salt)

      let pair = KeyFingerprintFilePair(
        key: result[0 ..< keyLength],
        fingerprintFile: result[keyLength ..< keyLength + fingerprintFileLength]
      )

      return pair
    } catch {
      throw PublicError.encryptionFailed
    }
  }

  /// Encrypts data
  ///
  /// - Parameters:
  ///   - data: Data to encrypt
  ///   - key: Public key to be used for encryption
  ///   - iv: IV
  /// - Returns: Encrypted data
  /// - Throws: Public encryption failure error
  public static func encrypt(
    data: Data,
    key: Data,
    iv: Data
  ) throws -> Data {
    do {
      let (encrypted, _, _) = try AES256.encrypt(
        data: data,
        key: key,
        iv: iv,
        blockMode: aesBlockMode
      )
      return encrypted
    } catch {
      throw PublicError.encryptionFailed
    }
  }

  /// Decrypts data
  ///
  /// - Parameters:
  ///   - data: Data to decrypt
  ///   - key: Private key to be used for decryption
  ///   - iv: IV
  /// - Returns: Decrypted data
  /// - Throws: Public decryption failure error
  public static func decrypt(
    data: Data,
    key: Data,
    iv: Data
  ) throws -> Data {
    do {
      let decrypted = try AES256.decrypt(
        data: data,
        key: key,
        iv: iv,
        blockMode: aesBlockMode
      )
      return decrypted
    } catch {
      throw PublicError.decryptionFailed
    }
  }
}

private extension EmergencyStickerEncryption {
  /// Hashes data
  ///
  /// - Parameters:
  ///   - secret: password to be used for Scrypt hash
  ///   - salt: Salt
  /// - Returns: Hashed data
  /// - Throws: Thrown by Scrypt
  static func hash(
    secret: Data,
    salt: Data
  ) throws -> Data {
    let result = try CryptoSwift.Scrypt(
      password: [UInt8](secret),
      salt: [UInt8](salt),
      dkLen: scryptLength,
      N: scryptN,
      r: scryptR,
      p: scryptP
    ).calculate()
    return Data(bytes: result)
  }
}
