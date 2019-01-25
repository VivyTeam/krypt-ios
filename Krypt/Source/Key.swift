//
//  Key.swift
//  Krypt
//
//  Created by marko on 23.01.19.
//

import Foundation
import Security

public final class Key {
  public enum Error: LocalizedError {
    case invalidPEMData
  }

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

  public func convertedToDER() throws -> Data {
    var error: Unmanaged<CFError>?
    guard let der = SecKeyCopyExternalRepresentation(secRef, &error) as Data? else {
      throw error!.takeRetainedValue() as Swift.Error
    }
    return der
  }
}

private extension Key.Access {
  var secAttr: CFString {
    switch self {
    case .public:
      return kSecAttrKeyClassPublic
    case .private:
      return kSecAttrKeyClassPrivate
    }
  }

  var pemHeader: String {
    switch self {
    case .public:
      return "-----BEGIN PUBLIC KEY-----\n"
    case .private:
      return "-----BEGIN RSA PRIVATE KEY-----\n"
    }
  }

  var pemFooter: String {
    switch self {
    case .public:
      return "\n-----END PUBLIC KEY-----"
    case .private:
      return "\n-----END RSA PRIVATE KEY-----"
    }
  }
}
