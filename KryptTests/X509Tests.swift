//
//  X509Tests.swift
//  Krypt_Tests
//
//  Created by marko on 14.11.19.
//  Copyright © 2019 CocoaPods. All rights reserved.
//

import XCTest
@testable import Krypt

class X509Tests: XCTestCase {
  func testWrapPublicKeyPEM_whenKeyIsRSA2048bitPKCS8__shouldCreateExpectedCertificateWithExpectedKey() {
    // given
    let testKey = TestData.openSSLPublicKey2048PEM

    // when
    let pem = X509.wrap(publicKeyPEM: testKey.string)

    // then
    let cert = pem?.certificate
    XCTAssertNotNil(cert)
    let publicKey = cert?.secKey
    XCTAssertNotNil(publicKey)
    let attributes = publicKey?.attributes
    XCTAssertNotNil(attributes)
    XCTAssertEqual(attributes?[kSecAttrKeyClass] as! CFString, kSecAttrKeyClassPublic)
    XCTAssertEqual(attributes?[kSecAttrKeyType] as! CFString, kSecAttrKeyTypeRSA)
    XCTAssertEqual(attributes?[kSecAttrKeySizeInBits] as! Int, 2048)
  }

  func testWrapPublicKeyPEM_whenKeyIsRSA4096bitPKCS8__shouldCreateExpectedCertificateWithExpectedKey() {
    // given
    let testKey = TestData.openSSLPublicKeyPEM

    // when
    let pem = X509.wrap(publicKeyPEM: testKey.string)

    // then
    let cert = pem?.certificate
    XCTAssertNotNil(cert)
    let publicKey = cert?.secKey
    XCTAssertNotNil(publicKey)
    let attributes = publicKey?.attributes
    XCTAssertNotNil(attributes)
    XCTAssertEqual(attributes?[kSecAttrKeyClass] as! CFString, kSecAttrKeyClassPublic)
    XCTAssertEqual(attributes?[kSecAttrKeyType] as! CFString, kSecAttrKeyTypeRSA)
    XCTAssertEqual(attributes?[kSecAttrKeySizeInBits] as! Int, 4096)
  }

  func testWrapPublicKeyPEM_whenKeyIsECPRIME256R1PKCS8__shouldCreateExpectedCertificateWithExpectedKey() {
    // given
    let testKey = TestData.openSSLPublicKeyECPRIME256R1PKCS8PEM

    // when
    let pem = X509.wrap(publicKeyPEM: testKey.string)

    // then
    let cert = pem?.certificate
    XCTAssertNotNil(cert)
    let publicKey = cert?.secKey
    XCTAssertNotNil(publicKey)
    let attributes = publicKey?.attributes
    XCTAssertNotNil(attributes)
    XCTAssertEqual(attributes?[kSecAttrKeyClass] as! CFString, kSecAttrKeyClassPublic)
    XCTAssertEqual(attributes?[kSecAttrKeyType] as! CFString, kSecAttrKeyTypeECSECPrimeRandom)
    XCTAssertEqual(attributes?[kSecAttrKeySizeInBits] as! Int, 256)
  }
}

private extension String {
  var certificate: SecCertificate? {
    let stripped = self.replacingOccurrences(of: "-----BEGIN CERTIFICATE-----", with: "")
      .replacingOccurrences(of: "-----END CERTIFICATE-----", with: "")
    let data = Data(base64Encoded: stripped, options: .ignoreUnknownCharacters)
    return data.flatMap { SecCertificateCreateWithData(nil, $0 as CFData) }
  }
}

private extension SecCertificate {
  var secKey: SecKey? {
    if #available(iOS 12.0, *) {
      return SecCertificateCopyKey(self)
    } else {
      return SecCertificateCopyPublicKey(self)
    }
  }
}

private extension SecKey {
  var attributes: [CFString: Any]? {
    return SecKeyCopyAttributes(self) as? [CFString: Any]
  }
}
