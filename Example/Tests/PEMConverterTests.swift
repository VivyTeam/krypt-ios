//
//  PEMConverterTests.swift
//  Krypt_Tests
//
//  Created by marko on 08.05.19.
//  Copyright © 2019 CocoaPods. All rights reserved.
//

import Krypt
import XCTest

final class PEMConverterTests: XCTestCase {
  func testConvertToDER_pkcs1PrivateKey__shouldGiveValidDERData() {
    // given
    let testData = TestData.openSSLPrivateKeyPEM.string

    // when
    let data = PEMConverter.convertPEMToDER(testData)

    // then
    let attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
      kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
      kSecAttrKeySizeInBits as String: 4096
    ]
    XCTAssertNotNil(SecKeyCreateWithData(data! as CFData, attributes as CFDictionary, nil))
  }

  func testConvertToDER_pkcs1PublicKey__shouldGiveValidDERData() {
    // given
    let testData = TestData.openSSLPublicKeyPKCS1PEM.string

    // when
    let data = PEMConverter.convertPEMToDER(testData)

    // then
    let attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
      kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
      kSecAttrKeySizeInBits as String: 4096
    ]
    XCTAssertNotNil(SecKeyCreateWithData(data! as CFData, attributes as CFDictionary, nil))
  }

  func testConvertToDER_pkcs8PublicKey__shouldGiveValidDERData() {
    // given
    let testData = TestData.openSSLPublicKeyPEM.string

    // when
    let data = PEMConverter.convertPEMToDER(testData)

    // then
    let attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
      kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
      kSecAttrKeySizeInBits as String: 4096
    ]
    XCTAssertNotNil(SecKeyCreateWithData(data! as CFData, attributes as CFDictionary, nil))
  }

  func testConvertToDER_certificate__shouldGiveValidDERData() {
    // given
    let testData = TestData.openSSLCertificateX509PEM.string

    // when
    let data = PEMConverter.convertPEMToDER(testData)

    // then
    XCTAssertNotNil(SecCertificateCreateWithData(nil, data! as CFData))
  }
}
