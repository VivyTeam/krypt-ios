//
//  RSA.swift
//  Krypt
//
//  Created by marko on 23.01.19.
//

import Foundation
import Security

/// High level object for RSA used in Vivy iOS app.
/// Currently supports only `rsaEncryptionPKCS1` and `rsaEncryptionOAEPSHA256`
/// depending on the version of encryption used in Vivy.
public struct RSA {
  public enum Error: LocalizedError {
    case unsupportedAlgorithmForProvidedKey

    public var errorDescription: String? {
      return String(describing: self)
    }
  }

  /// currently supported RSA paddings in Vivy iOS app
  ///
  /// - pkcs1: PKCS1
  /// - oaep: OAEP SHA256
  public enum Padding {
    case pkcs1
    case oaep
  }

  /// Encrypts data with provided public key
  ///
  /// - Parameters:
  ///   - data: `Data` to encrypt
  ///   - key: `Key` object with `public` access to encrypt with
  ///   - padding: padding to determine which algorithm to use
  /// - Returns: encrypted `Data`
  /// - Throws: errors if algorithm is not supported or any Security errors seturned from `SecKeyCreateEncryptedData`
  public static func encrypt(data: Data, with key: Key, padding: Padding) throws -> Data {
    guard SecKeyIsAlgorithmSupported(key.secRef, .encrypt, padding.algorithm) else {
      throw Error.unsupportedAlgorithmForProvidedKey
    }
    var error: Unmanaged<CFError>?
    guard let cipher = SecKeyCreateEncryptedData(key.secRef, padding.algorithm, data as CFData, &error) as Data? else {
      throw error!.takeRetainedValue() as Swift.Error
    }
    return cipher
  }

  /// Decrypts data with provided public key
  ///
  /// - Parameters:
  ///   - data: `Data` to decrypt
  ///   - key: `Key` object with `private` access to decrypt with
  ///   - padding: padding to determine which algorithm to use
  /// - Returns: decrypted `Data`
  /// - Throws: errors if algorithm is not supported or any Security errors seturned from `SecKeyCreateDecryptedData`
  public static func decrypt(data: Data, with key: Key, padding: Padding) throws -> Data {
    guard SecKeyIsAlgorithmSupported(key.secRef, .decrypt, padding.algorithm) else {
      throw Error.unsupportedAlgorithmForProvidedKey
    }
    var error: Unmanaged<CFError>?
    guard let cipher = SecKeyCreateDecryptedData(key.secRef, padding.algorithm, data as CFData, &error) as Data? else {
      throw error!.takeRetainedValue() as Swift.Error
    }
    return cipher
  }
}

private extension RSA.Padding {
  /// Returns `SecKeyAlgorithm` depending on the Vivy encryption version
  var algorithm: SecKeyAlgorithm {
    switch self {
    case .pkcs1:
      return .rsaEncryptionPKCS1
    case .oaep:
      return .rsaEncryptionOAEPSHA256
    }
  }
}
