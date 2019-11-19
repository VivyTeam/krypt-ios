//
//  Key.swift
//  Krypt
//
//  Created by marko on 23.01.19.
//

import Foundation
import Security

/// High level object representing an RSA key to be used for asymetric encryption.
/// Currently only RSA keys 4096 and 2048 bits long are supported.
public final class Key {
  public enum `Type` {
    case rsa
    case ecSECPrimeRandom
  }

  /// Access level of the key
  ///
  /// - `public`: for public key
  /// - `private`: for private key
  public enum Access {
    case `public`
    case `private`
  }

  public enum Size: Int {
    case bit_256 = 256
    case bit_2048 = 2048
    case bit_4096 = 4096
  }

  public let secRef: SecKey
  public let access: Access
  public init(key: SecKey, access: Access) {
    secRef = key
    self.access = access
  }
}

public extension Key {
  /// Initializes `Key` from DER data
  ///
  /// - Parameters:
  ///   - der: `Data` in DER format
  ///   - type: `Type` of key to expect
  ///   - access: `Access` level of the key
  /// - Throws: any erros that are returned by `SecKeyCreateWithData`
  convenience init(der: Data, type: Type, access: Access, size: Size) throws {
    let options: [String: Any] = [
      kSecAttrKeyType as String: type.secAttr,
      kSecAttrKeyClass as String: access.secAttr,
      kSecAttrKeySizeInBits as String: size.rawValue
    ]
    guard let key = SecKeyCreateWithData(der as CFData, options as CFDictionary, nil) else {
      throw KeyError.creatingSecKey
    }
    self.init(key: key, access: access)
  }

  convenience init(der: Data, access: Access) throws {
    try self.init(der: der, type: .rsa, access: access, size: .bit_4096)
  }

  /// Initializes `Key` from PEM string
  ///
  /// - Parameters:
  ///   - pem: `String` in PKCS#1 or PKCS#8
  ///   - type: `Type` of key to expect
  ///   - access: `Access` level of the key
  /// - Throws: any errors that can occur while converting the key from PEM -> DER -> SecKey
  convenience init(pem: String, type: Type, access: Access, size: Size) throws {
    if access == .public, let secKey = pem.publicKey {
      self.init(key: secKey, access: access)
    } else {
      guard let der = PEMConverter.convertPEMToDER(pem) else {
        throw KeyError.invalidPEMData
      }
      try self.init(der: der, type: type, access: access, size: size)
    }
  }

  convenience init(pem: String, access: Access, size: Size = .bit_4096) throws {
    try self.init(pem: pem, type: .rsa, access: access, size: .bit_4096)
  }

  /// Initializes `Key` from PEM data
  ///
  /// - Parameters:
  ///   - pem: `Data` in PKCS#1 or PKCS#8
  ///   - access: `Access` level of the key
  /// - Throws: any errors that can occur while converting the key from PEM -> DER -> SecKey
  convenience init(pem: Data, access: Access, size: Size = .bit_4096) throws {
    try self.init(pem: String(decoding: pem, as: UTF8.self), type: .rsa, access: access, size: size)
  }

  /// Converts the underlying `secRef` to PKCS#1 DER format for public and private access
  ///
  /// - Returns: `Data` representation of the key in DER format
  /// - Throws: errors occuring during `SecKeyCopyExternalRepresentation`
  func convertedToDER() throws -> Data {
    var error: Unmanaged<CFError>?
    guard let der = SecKeyCopyExternalRepresentation(secRef, &error) as Data? else {
      throw error!.takeRetainedValue() as Swift.Error
    }
    return der
  }

  /// Converts the underlying `secRef` to PEM
  ///
  /// - Returns: `String` in PKCS#1 PEM
  /// - Throws: errors occuring during `SecKeyCopyExternalRepresentation`
  func convertedToPEM() throws -> String {
    let der = try convertedToDER()
    return try PEMConverter.convertDER(der, toPEMFormat: access.pemFormat)
  }

  /// Derives the public key from the private key
  ///
  /// - Returns: Public key for the private key
  /// - Throws: errors if wrong key is used or if the public key cannot be derived
  func publicKeyRepresentation() throws -> Key {
    guard access == .private else { throw KeyError.invalidAccess }

    guard let publicKey = SecKeyCopyPublicKey(secRef), let der = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
      throw KeyError.failedToDerivePublicKey
    }

    return try Key(der: der, access: .public)
  }
}

private extension Key.Access {
  /// Security attribute for the key class depending on the access
  var secAttr: CFString {
    switch self {
    case .public:
      return kSecAttrKeyClassPublic
    case .private:
      return kSecAttrKeyClassPrivate
    }
  }

  var pemFormat: PEMFormat {
    switch self {
    case .private:
      return .privatePKCS1
    case .public:
      return .publicPKCS1
    }
  }
}

private extension Key.`Type` {
  var secAttr: CFString {
    switch self {
    case .rsa:
      return kSecAttrKeyTypeRSA
    case .ecSECPrimeRandom:
      return kSecAttrKeyTypeECSECPrimeRandom
    }
  }
}

private extension String {
  var publicKey: SecKey? {
    guard let certPEM = X509.wrap(publicKeyPEM: self) else {
      return nil
    }
    guard let certDER = PEMConverter.convertPEMToDER(certPEM) else {
      return nil
    }
    guard let cert = SecCertificateCreateWithData(nil, certDER as CFData) else {
      return nil
    }
    if #available(iOS 12.0, *) {
      return SecCertificateCopyKey(cert)
    } else {
      return SecCertificateCopyPublicKey(cert)
    }
  }
}

/// Error object containing erros that might occur during converting keys to different formats
///
/// - invalidPEMData: data was not in PKCS#1 (for private) or PKCS#8 (for public) format when initializing `Key` from PEM data
/// - creatingSecKey: converting data to SecKey failed
/// - invalidAccess: wrong access for function
/// - failedToDerivePublicKey: unable to get public key from the private key
public enum KeyError: LocalizedError {
  case invalidPEMData, creatingSecKey, invalidAccess, failedToDerivePublicKey
}
