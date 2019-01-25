//
//  RSA.swift
//  Krypt
//
//  Created by marko on 23.01.19.
//

import Foundation
import Security

public struct RSA {
  public enum Error: LocalizedError {
    case unsupportedAlgorithmForProvidedKey

    public var errorDescription: String? {
      return String(describing: self)
    }
  }

  public enum Padding {
    case pkcs1
    case oaep
  }

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
  var algorithm: SecKeyAlgorithm {
    switch self {
    case .pkcs1:
      return .rsaEncryptionPKCS1
    case .oaep:
      return .rsaEncryptionOAEPSHA256
    }
  }
}
