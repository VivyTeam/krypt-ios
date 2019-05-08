//
//  PEMConverter.swift
//  Krypt
//
//  Created by marko on 08.05.19.
//

import Foundation

public struct PEMConverter {
  public static func convertPEMToDER(_ pem: String) -> Data? {
    let possibleHeaders = PEMConverterHeaders.allCases.map { $0.header }
    let possibleFooters = PEMConverterHeaders.allCases.map { $0.footer }
    let possibleHeadersAndFooters = possibleHeaders + possibleFooters

    var stripped = ""
    pem.enumerateLines { line, _ in
      guard !possibleHeadersAndFooters.contains(line) else { return }
      stripped += line
    }
    return Data(base64Encoded: stripped)
  }
}

public enum PEMConverterError: Error {
  case errorInvalidPEMData
}

public enum PEMConverterHeaders: CaseIterable {
  case privatePKCS1
  case publicPKCS1
  case publicPKCS8
  case certificate

  var header: String {
    switch self {
    case .privatePKCS1:
      return "-----BEGIN RSA PRIVATE KEY-----"
    case .publicPKCS1:
      return "-----BEGIN RSA PUBLIC KEY-----"
    case .publicPKCS8:
      return "-----BEGIN PUBLIC KEY-----"
    case .certificate:
      return "-----BEGIN CERTIFICATE-----"
    }
  }

  var footer: String {
    switch self {
    case .privatePKCS1:
      return "-----END RSA PRIVATE KEY-----"
    case .publicPKCS1:
      return "-----END RSA PUBLIC KEY-----"
    case .publicPKCS8:
      return "-----END PUBLIC KEY-----"
    case .certificate:
      return "-----END CERTIFICATE-----"
    }
  }
}
