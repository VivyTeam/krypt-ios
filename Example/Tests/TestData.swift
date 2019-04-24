//
//  TestData.swift
//  Krypt_Tests
//
//  Created by marko on 24.01.19.
//  Copyright © 2019 CocoaPods. All rights reserved.
//

import Foundation

private final class TestDataClass {}

enum TestData: String {
  case openSSLPrivateKeyPEM = "openssl-private-key-pkcs1-pem"
  case openSSLPrivateKey2048PEM = "openssl-private-key-pkcs1-2048-pem"
  case openSSLPublicKey2048PEM = "openssl-public-key-pkcs8-2048-pem"
  case openSSLPublicKeyPKCS1PEM = "openssl-public-key-pkcs1-pem"
  case openSSLPublicKeyPEM = "openssl-public-key-pkcs8-pem"
  case ehrContractGCMMessage = "ehr-gcm-contract-message-base64"
  case ehrContractGCMCipherKey = "ehr-gcm-contract-cipher-key-base64"
  case ehrContractCBCMessage = "ehr-cbc-contract-message-base64"
  case ehrContractCBCCipherKey = "ehr-cbc-contract-cipher-key-base64"
  case opensslCSR = "openssl-csr"
  case kvConnectEmail = "kvconnect-mail"
  case kvConnectEmailDec = "kvconnect-mail-dec"
  case kvPrivateKeyOpenPEM = "kvprivatekey-open-pem"
  case kvRootAndVivyCAPEM = "kvroot-kvvivy-ca-pem"

  var data: Data {
    guard
      let url = Bundle(for: TestDataClass.self)
      .url(forResource: self.rawValue, withExtension: nil),
      let data = try? Data(contentsOf: url)
    else {
      fatalError("No file found")
    }
    return data
  }

  var base64Decoded: Data {
    return Data(base64Encoded: stringTrimmingWhitespacesAndNewlines)!
  }
  
  var string: String {
    return String(data: data, encoding: .utf8)!
  }

  var stringTrimmingWhitespacesAndNewlines: String {
    return string.trimmingCharacters(in: .whitespacesAndNewlines)
  }
}
