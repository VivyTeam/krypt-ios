//
//  PEMConverterTests.swift
//  Krypt_Tests
//
//  Created by marko on 08.05.19.
//  Copyright © 2019 CocoaPods. All rights reserved.
//

@testable import Krypt
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

  func testConvertDERToPEM_privateKey__shouldGiveExpectedPEM() {
    // given
    let expectedPEM = TestData.openSSLPrivateKeyPEM.string
    let der = PEMConverter.convertPEMToDER(expectedPEM)!

    // when
    let pem = try! PEMConverter.convertDER(der, toPEMFormat: .privatePKCS1)

    // then
    XCTAssertEqual(pem, expectedPEM)
  }

  func testConvertDERToPEM_publicKey__shouldGiveExpectedPKCS1PEM() {
    // given
    let expectedPEM = TestData.openSSLPublicKeyPKCS1PEM.string
    let der = PEMConverter.convertPEMToDER(expectedPEM)!

    // when
    let pem = try! PEMConverter.convertDER(der, toPEMFormat: .publicPKCS1)

    // then
    XCTAssertEqual(pem, expectedPEM)
  }

  func testConvertDERToPEM_publicKey__shouldGiveExpectedPKCS8PEM() {
    // given
    let expectedPEM = TestData.openSSLPublicKeyPEM.string
    let pkcs1PEM = TestData.openSSLPublicKeyPKCS1PEM.string
    let der = PEMConverter.convertPEMToDER(pkcs1PEM)!

    // when
    let pem = try! PEMConverter.convertDER(der, toPEMFormat: .publicPKCS8)

    // then
    XCTAssertEqual(pem, expectedPEM)
  }

  func testConvertDERToPEM_certificate__shouldGiveExpectedPEM() {
    // given
    let expectedPEM = TestData.openSSLCertificateX509PEM.string
    let der = PEMConverter.convertPEMToDER(expectedPEM)!

    // when
    let pem = try! PEMConverter.convertDER(der, toPEMFormat: .certificateX509)

    // then
    XCTAssertEqual(pem, expectedPEM)
  }
}
