//
//  PEMConverter.swift
//  Krypt
//
//  Created by marko on 08.05.19.
//

import Foundation

struct PEMConverter {
  static func convertPEMToDER(_ pem: String) -> Data? {
    let supportedHeadersAndFooters = PEMFormat.supportedHeadersAndFooters

    var stripped = ""
    pem.enumerateLines { line, _ in
      guard !supportedHeadersAndFooters.contains(line) else { return }
      stripped += line
    }
    return Data(base64Encoded: stripped)
  }

  /// Converts DER to `PKCS1`
  ///
  /// - Parameters:
  ///   - der: DER data
  ///   - format: PEM format to encode to
  /// - Returns: PEM representation of DER
  static func convertDER(_ der: Data, toPEMFormat format: PEMFormat) throws -> String {
    switch format.standard {
    case .pkcs1, .pkcs12:
      return try wrapDER(der, inPEMFormat: format)
    case .pkcs8:
      switch format.contentType {
      case .rsa:
        let rsaPublicKeyPKCS1Format = PEMFormat(contentType: .rsa, standard: .pkcs1, keyAccess: .public)
        let pkcs1PEM = try wrapDER(der, inPEMFormat: rsaPublicKeyPKCS1Format)
        guard let pkcs8PEM = PKCS8.convertPKCS1PEMToPKCS8PEM(pkcs1PEM) else {
          throw PEMConverterError.invalidDERData
        }
        return pkcs8PEM
      case .ec:
        return try wrapDER(der.ecPublicKeyDERWithHeaderInfo, inPEMFormat: format)
      case .x509:
        throw PEMConverterError.invalidFormat
      }
    }
  }
}

private extension PEMConverter {
  static func wrapDER(_ der: Data, inPEMFormat format: PEMFormat) throws -> String {
    guard let header = format.header, let footer = format.footer else {
      throw PEMConverterError.invalidFormat
    }
    let derBase64 = der.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
    let elements = [
      header,
      derBase64,
      footer
    ]
    return elements.joined(separator: "\n").appending("\n")
  }
}

enum PEMConverterError: Error {
  case invalidPEMData
  case invalidFormat
  case invalidDERData
}

enum PEMContentType: String {
  case rsa = "RSA"
  case ec = "EC"
  case x509 = "CERTIFICATE"
}

enum PEMStandard {
  case pkcs1
  case pkcs8
  case pkcs12
}

enum PEMKeyAccess: String {
  case `private` = "PRIVATE KEY"
  case `public` = "PUBLIC KEY"
}

struct PEMFormat {
  let contentType: PEMContentType
  let standard: PEMStandard
  let keyAccess: PEMKeyAccess?

  var header: String? {
    switch standard {
    case .pkcs1:
      switch contentType {
      case .rsa, .ec:
        let access = keyAccess ?? .private
        return "-----BEGIN \(contentType.rawValue) \(access.rawValue)-----"
      case .x509:
        return nil
      }
    case .pkcs8:
      let access = keyAccess ?? .public
      return "-----BEGIN \(access.rawValue)-----"
    case .pkcs12:
      return "-----BEGIN \(contentType.rawValue)-----"
    }
  }

  var footer: String? {
    switch standard {
    case .pkcs1:
      switch contentType {
      case .rsa, .ec:
        let access = keyAccess ?? .private
        return "-----END \(contentType.rawValue) \(access.rawValue)-----"
      case .x509:
        return nil
      }
    case .pkcs8:
      let access = keyAccess ?? .public
      return "-----END \(access.rawValue)-----"
    case .pkcs12:
      return "-----END \(contentType.rawValue)-----"
    }
  }
}

private extension PEMFormat {
  static var supportedHeadersAndFooters: [String] {
    let formats = [
      PEMFormat(contentType: .rsa, standard: .pkcs1, keyAccess: .private),
      PEMFormat(contentType: .rsa, standard: .pkcs1, keyAccess: .public),
      PEMFormat(contentType: .rsa, standard: .pkcs8, keyAccess: .public),
      PEMFormat(contentType: .ec, standard: .pkcs1, keyAccess: .private),
      PEMFormat(contentType: .ec, standard: .pkcs8, keyAccess: .public),
      PEMFormat(contentType: .x509, standard: .pkcs12, keyAccess: nil)
    ]
    let headers = formats.compactMap { $0.header }
    let footers = formats.compactMap { $0.footer }
    return headers + footers
  }
}

private extension Data {
  var ecPublicKeyDERWithHeaderInfo: Data {
    let header: [UInt8] = [0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00]
    let headerLength = 26
    let headerData = Data(bytes: header, count: headerLength)
    return headerData + self
  }
}
