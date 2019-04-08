//
//  CSR.swift
//  Krypt
//
//  Created by marko on 27.02.19.
//

import Foundation
import Krypt_internal

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

  /// Creates a CSR with provided subjects
  ///
  /// - Parameters:
  ///   - key: private key to use
  ///   - country: The two-letter country code where your company is legally located
  ///   - state: The state/province where your company is legally located
  ///   - location: The city where your company is legally located
  ///   - organization: Your company's legally registered name (e.g., YourCompany, Inc.)
  ///   - organizationUnit: The name of your department within the organization
  ///   - emailAddress: Email address
  /// - Returns: `Data` object representing the CSR in PEM format
  /// - Throws: `CSR.Error`
  public static func create(
    with key: Key,
    country: String,
    state: String,
    location: String,
    organization: String,
    organizationUnit: String,
    emailAddress: String,
    uid: String,
    gn: String,
    sn: String
  ) throws -> Data {
    guard key.access == .private else {
      throw Error.invalidKey
    }

    let keyPEM = try key.convertedToPEM()

    let result = createCSR(
      keyPEM.unsafeUtf8cString,
      country.unsafeUtf8cString,
      state.unsafeUtf8cString,
      location.unsafeUtf8cString,
      organization.unsafeUtf8cString,
      organizationUnit.unsafeUtf8cString,
      emailAddress.unsafeUtf8cString,
      uid,
      gn,
      sn
    )
    guard result != nil, let csrData = String(cString: result!).data(using: .utf8) else {
      throw Error.failedCreatingCSR
    }
    return csrData
  }
}

private extension String {
  var unsafeUtf8cString: [CChar] {
    return cString(using: .utf8) ?? []
  }
}
