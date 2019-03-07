//
//  Key.swift
//  Krypt
//
//  Created by marko on 23.01.19.
//

import Foundation
import Security

/// High level object representing an RSA key to be used for asymetric encryption.
/// Currently only RSA keys 4096 bits long are supported.
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
  ///   - pem: `Data` in PKCS#1 or PKCS#8
  ///   - access: `Access` level of the key
  /// - Throws: any errors that can occur while converting the key from PEM -> DER -> SecKey
  public convenience init(pem: Data, access: Access) throws {
    guard let pemString = String(data: pem, encoding: .utf8) else {
      throw Error.invalidPEMData
    }
    // Check if the provided key is in PKCS#1 or PKCS#8
    let isPKCS1 = pemString.hasPrefix(access.pemHeaderPKCS1)

    let pemHeader = isPKCS1 ? access.pemHeaderPKCS1 : access.pemHeaderPKCS8
    let pemFooter = isPKCS1 ? access.pemFooterPKCS1 : access.pemFooterPKCS8

    guard pemString.hasPrefix(pemHeader), let footerRange = pemString.range(of: pemFooter) else {
      throw Error.invalidPEMData
    }
    let stripped = String(pemString[pemHeader.endIndex ..< footerRange.lowerBound]).replacingOccurrences(of: "\n", with: "")
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

  /// Converts the underlying `secRef` to PEM
  ///
  /// - Returns: `String` in PKCS#1 PEM
  /// - Throws: errors occuring during `SecKeyCopyExternalRepresentation`
  public func convertedToPEM() throws -> String {
    let der = try convertedToDER()
    let keyBase64 = der.base64EncodedString()

    // Insert newline `\n` every 64 characters
    var index = 0
    var splits = [String]()
    while index < keyBase64.count {
      let startIndex = keyBase64.index(keyBase64.startIndex, offsetBy: index)
      let endIndex = keyBase64.index(startIndex, offsetBy: 64, limitedBy: keyBase64.endIndex) ?? keyBase64.endIndex
      index = endIndex.encodedOffset

      let chunk = String(keyBase64[startIndex ..< endIndex])
      splits.append(chunk)
    }
    let keyBase64WithNewlines = splits.joined(separator: "\n")

    return [access.pemHeaderPKCS1, keyBase64WithNewlines, access.pemFooterPKCS1].joined()
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

  var pemHeaderPKCS1: String {
    switch self {
    case .public:
      return "-----BEGIN RSA PUBLIC KEY-----\n"
    case .private:
      return "-----BEGIN RSA PRIVATE KEY-----\n"
    }
  }

  var pemFooterPKCS1: String {
    switch self {
    case .public:
      return "\n-----END RSA PUBLIC KEY-----"
    case .private:
      return "\n-----END RSA PRIVATE KEY-----"
    }
  }

  var pemHeaderPKCS8: String {
    switch self {
    case .public:
      return "-----BEGIN PUBLIC KEY-----\n"
    case .private:
      return "-----BEGIN PRIVATE KEY-----\n"
    }
  }

  var pemFooterPKCS8: String {
    switch self {
    case .public:
      return "\n-----END PUBLIC KEY-----"
    case .private:
      return "\n-----END PRIVATE KEY-----"
    }
  }
}
