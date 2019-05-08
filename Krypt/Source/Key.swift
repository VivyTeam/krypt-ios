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

  /// Supported Key sizes in Vivy
  ///
  /// - bit_4096: default
  /// - bit_2048: used for integrations
  public enum Size: Int {
    case bit_4096 = 4096
    case bit_2048 = 2048
  }
}

public extension Key {
  /// Initializes `Key` from DER data
  ///
  /// - Parameters:
  ///   - der: `Data` in DER format
  ///   - access: `Access` level of the key
  /// - Throws: any erros that are returned by `SecKeyCreateWithData`
  convenience init(der: Data, access: Access, size: Size = .bit_4096) throws {
    let options: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
      kSecAttrKeyClass as String: access.secAttr,
      kSecAttrKeySizeInBits as String: size.rawValue
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
  convenience init(pem: Data, access: Access, size: Size = .bit_4096) throws {
    guard let der = PEMConverter.convertPEMToDER(String(decoding: pem, as: UTF8.self)) else {
      throw Error.invalidPEMData
    }
    try self.init(der: der, access: access, size: size)
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
    return PEMConverter.convertDER(der, toPEMFormat: access.pemFormat)
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

  var pemFormat: PEMConverterFormat {
    switch self {
    case .private:
      return .privatePKCS1
    case .public:
      return .publicPKCS1
    }
  }
}
