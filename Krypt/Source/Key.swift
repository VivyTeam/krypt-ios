//
//  Key.swift
//  Krypt
//
//  Created by marko on 23.01.19.
//

import Foundation
import Security

/// High level object representing an RSA key to be used for asymetric encryption.
/// Currently only RSA keys with 4096 bits length are supported.
public final class Key {
  /// Error object containing erros that might occur during converting keys to different formats
  ///
  /// - invalidPEMData: data was not in PKCS#1 (for private) or PKCS#8 (for public) format when initializing `Key` from PEM data
  public enum Error: LocalizedError {
    case invalidPEMData
  }

  /// Access level of the key
  ///
  /// - `public`: for public key
  /// - `private`: for private key
  public enum Access {
    case `public`
    case `private`
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
  ///   - access: `Access` level of the key
  /// - Throws: any erros that are returned by `SecKeyCreateWithData`
  public convenience init(der: Data, access: Access) throws {
    let options: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
      kSecAttrKeyClass as String: access.secAttr,
      kSecAttrKeySizeInBits as String: 4096
    ]
    var error: Unmanaged<CFError>?
    guard let key = SecKeyCreateWithData(der as CFData, options as CFDictionary, &error) else {
      throw error!.takeRetainedValue() as Swift.Error
    }
    self.init(key: key, access: access)
  }

  /// Initializes `Key` from PEM data
  ///
  /// - Parameters:
  ///   - pem: `Data` in PKCS#8 format for public | PKCS#1 for private access
  ///   - access: `Access` level of the key
  /// - Throws: any errors that can occur while converting the key from PEM -> DER -> SecKey
  public convenience init(pem: Data, access: Access) throws {
    guard let pemString = String(data: pem, encoding: .utf8) else {
      throw Error.invalidPEMData
    }
    guard pemString.hasPrefix(access.pemHeader), let footerRange = pemString.range(of: access.pemFooter) else {
      throw Error.invalidPEMData
    }
    let stripped = String(pemString[access.pemHeader.endIndex ..< footerRange.lowerBound]).replacingOccurrences(of: "\n", with: "")
    guard let der = Data(base64Encoded: stripped) else {
      throw Error.invalidPEMData
    }
    try self.init(der: der, access: access)
  }

  /// Converts the underlying `secRef` to PKCS#1 DER format for public and private access
  ///
  /// - Returns: `Data` representation of the key in DER format
  /// - Throws: errors occuring during `SecKeyCopyExternalRepresentation`
  public func convertedToDER() throws -> Data {
    var error: Unmanaged<CFError>?
    guard let der = SecKeyCopyExternalRepresentation(secRef, &error) as Data? else {
      throw error!.takeRetainedValue() as Swift.Error
    }
    return der
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

  /// PEM header used when importing keys.
  /// Currently supports only PKCS#8 format for public and PKCS#1 for private
  var pemHeader: String {
    switch self {
    case .public:
      return "-----BEGIN PUBLIC KEY-----\n"
    case .private:
      return "-----BEGIN RSA PRIVATE KEY-----\n"
    }
  }

  /// PEM footer used when importing keys.
  /// Currently supports only PKCS#8 format for public and PKCS#1 for private
  var pemFooter: String {
    switch self {
    case .public:
      return "\n-----END PUBLIC KEY-----"
    case .private:
      return "\n-----END RSA PRIVATE KEY-----"
    }
  }
}
