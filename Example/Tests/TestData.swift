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
  case openSSLPublicKeyECPRIME256R1PKCS8PEM = "openssl-public-key-ec-prime256r1-pkcs8-pem"
  case openSSLPrivateKeyEncryptedPKCS8PEM = "openssl-private-key-encrypted-pkcs8-pem"
  case openSSLCertificateX509PEM = "openssl-certificate-x509-cer"
  case ehrContractGCMMessage = "ehr-gcm-contract-message-base64"
  case ehrContractGCMCipherKey = "ehr-gcm-contract-cipher-key-base64"
  case ehrContractCBCMessage = "ehr-cbc-contract-message-base64"
  case ehrContractCBCCipherKey = "ehr-cbc-contract-cipher-key-base64"
  case opensslCSR = "openssl-csr"
  case opensslCSRWithUmlauts = "openssl-csr-with-umlauts"
  case kvConnectEmail = "kvconnect-mail"
  case kvConnectEmailCorrupted = "kvconnect-mail-corrupted"
  case kvConnectEmailDec = "kvconnect-mail-dec"
  case kvConnectEmailDecVerified = "kvconnect-mail-dec-verified"
  case kvConnectEmailDecVerifiedBothLayers = "kvconnect-mail-dec-verified-both-layers"
  case kvPrivateKeyOpenPEM = "kvprivatekey-open-pem"
  case wrongPrivateKeyOpenPEM = "wrong-privatekey-open-pem"
  case kvRootCAPEM = "kvroot-ca-pem"
  case kvVivyCAPEM = "kvvivy-ca-pem"
  case kvRootAndVivyCAPEM = "kvroot-kvvivy-ca-pem"
  case wrongCAPEM = "wrong-ca-pem"
  case kvConnectEmailVerificationValid = "kvconnect-mail-verification-valid"
  case kvConnectEmailVerificationInvalidSignatureDigest = "kvconnect-mail-verification-invalid-signature-digest"
  case kvConnectEmailVerificationCertificateIssuerNotTrusted = "kvconnect-mail-verification-certificate-issuer-not-trusted"
  case kvConnectEmailVerificationSignatureDoesntBelongToSender = "kvconnect-mail-verification-signature-doesnt-belong-to-sender"
  case kvConnectEmailVerificationSmimeContainsUnencryptedPart = "kvconnect-mail-verification-smime-contains-unencrypted-part"
  case kvConnectRootCAPEM = "kvconnect-root-ca-pem"
  case kvConnectUserCAPEM = "kvconnect-user-ca-pem"
  case kvConnectUserCAPEMExpired = "kvconnect-user-ca-pem-expired"

  var data: Data {
    guard let data = try? Data(contentsOf: self.url)
    else {
      fatalError("No file found")
    }
    return data
  }

  var url: URL {
    guard let url = Bundle(for: TestDataClass.self)
      .url(forResource: self.rawValue, withExtension: nil) else {
      fatalError("URL not found")
    }
    return url
  }

  var base64Decoded: Data {
    return Data(base64Encoded: stringTrimmingWhitespacesAndNewlines)!
  }

  var string: String {
    return String(data: data, encoding: .utf8)!
  }

  var stringTrimmingWhitespacesAndNewlines: String {
    return data.stringTrimmingWhitespacesAndNewlines
  }
}
