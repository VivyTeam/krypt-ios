//
//  PKCS8Tests.swift
//  Krypt_Tests
//
//  Created by Max on 24.06.19.
//  Copyright © 2019 CocoaPods. All rights reserved.
//

import Krypt
import XCTest
import CryptoKit

final class PKCS8Tests: XCTestCase {

  func testConvertPKCS1_toPKCS8__shouldConvertCorrectly() {
    // given
    let expectedPEM = TestData.openSSLPublicKeyPEM.string
    let pkcs1PEMData = TestData.openSSLPublicKeyPKCS1PEM.data

    // when
    let convertedPKCS8PEM = PKCS8.convertPKCS1PEMToPKCS8PEM(pkcs1PEMData)

    // then
    XCTAssertEqual(expectedPEM, convertedPKCS8PEM)
  }

  func testConvertPKCS8PEM_toPKCS8__shouldReturnNil() {
    // given
    let pkcs8PEM = TestData.openSSLPublicKeyPEM.data

    // when
    let convertedPKCS8PEM = PKCS8.convertPKCS1PEMToPKCS8PEM(pkcs8PEM)

    // then
    XCTAssertNil(convertedPKCS8PEM)
  }

  func testEncryptPKCS1_simplePassword__shouldEncrypt() {
    // given
    let pkcs1PEMData = TestData.openSSLPrivateKeyPEM.data
    let password = "password"

    // when
    let encrypted = PKCS8.encrypt(pkcs1PEMData, password: password)

    // then
    XCTAssertNotNil(encrypted)
  }

  func testEncryptPKCS1_emptyPassword__shouldReturnNil() {
    // given
    let pkcs1PEMData = TestData.openSSLPrivateKeyPEM.data
    let password = ""

    // when
    let encrypted = PKCS8.encrypt(pkcs1PEMData, password: password)

    // then
    XCTAssertNil(encrypted)
  }

  func testEncryptPKCS1_uuidPassword__shouldEncrypt() {
    // given
    let pkcs1PEMData = TestData.openSSLPrivateKeyPEM.data
    let password = UUID().uuidString

    // when
    let encrypted = PKCS8.encrypt(pkcs1PEMData, password: password)

    // then
    XCTAssertNotNil(encrypted)
  }

  func testEncryptPKCS1_sha512Password__shouldEncrypt() {
    // given
    let pkcs1PEMData = TestData.openSSLPrivateKeyPEM.data
    let password = "B109F3BBBC244EB82441917ED06D618B9008DD09B3BEFD1B5E07394C706A8BB980B1D7785E5976EC049B46DF5F1326AF5A2EA6D103FD07C95385FFAB0CACBC86"

    // when
    let encrypted = PKCS8.encrypt(pkcs1PEMData, password: password)

    // then
    XCTAssertNotNil(encrypted)
  }

  func testEncryptPKCS1_specialCharactersPassword__shouldEncrypt() {
    // given
    let pkcs1PEMData = TestData.openSSLPrivateKeyPEM.data
    let password = "äū☁️🤯"

    // when
    let encrypted = PKCS8.encrypt(pkcs1PEMData, password: password)

    // then
    XCTAssertNotNil(encrypted)
  }
}
