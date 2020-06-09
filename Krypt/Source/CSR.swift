//
//  CSR.swift
//  Krypt
//
//  Created by marko on 27.02.19.
//

import Foundation

/// Creates Certificate Signing Request (CSR)
public struct CSR {
  /// General errors that might occur during creation
  ///
  /// - invalidKey: provided key must be the private part
  /// - failedCreatingCSR:
  public enum Error: LocalizedError {
    case invalidKey
    case failedCreatingCSR
  }

  /// Creates Certificate signing request (CSR)
  ///
  /// - Parameters:
  ///   - key: Private key to use to create CSR
  ///   - attributes: Object with attributes specified in X.509 standard
  /// - Returns: `String` representing CSR
  /// - Throws: `CSR.Error` or `Key.Error`
  public static func create(with key: Key, attributes: CSRAttributes?) throws -> String {
    guard key.access == .private else {
      throw Error.invalidKey
    }

    let keyPEM = try key.convertedToPEM()

    let result = createCSR(
      keyPEM.unsafeUtf8cString,
      (attributes?.country ?? "").unsafeUtf8cString,
      (attributes?.state ?? "").unsafeUtf8cString,
      (attributes?.location ?? "").unsafeUtf8cString,
      (attributes?.organization ?? "").unsafeUtf8cString,
      (attributes?.organizationUnit ?? "").unsafeUtf8cString,
      (attributes?.emailAddress ?? "").unsafeUtf8cString,
      (attributes?.uniqueIdentifier ?? "").unsafeUtf8cString,
      (attributes?.givenName ?? "").unsafeUtf8cString,
      (attributes?.surname ?? "").unsafeUtf8cString
    )

    guard let csr = result else {
      throw Error.failedCreatingCSR
    }

    return String(cString: csr)
  }
}
