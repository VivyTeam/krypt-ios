//
//  PKCS8Tests.swift
//  Krypt_Tests
//
//  Created by Max on 24.06.19.
//  Copyright © 2019 CocoaPods. All rights reserved.
//

import Krypt
import XCTest

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
}
