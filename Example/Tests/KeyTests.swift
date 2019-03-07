//
//  KeyTests.swift
//  Krypt_Tests
//
//  Created by marko on 24.01.19.
//  Copyright © 2019 CocoaPods. All rights reserved.
//

import Krypt
import XCTest

final class KeyTests: XCTestCase {
  func testInit_publicPEMFromOpenSSL__shouldInitialize() throws {
    // given
    let pem = TestData.openSSLPublicKeyPEM.data

    // then
    XCTAssertNoThrow(try Key(pem: pem, access: .public))
  }

  func testInit_privatePEMFromOpenSSL__shouldInitialize() throws {
    // given
    let pem = TestData.openSSLPrivateKeyPEM.data

    // then
    XCTAssertNoThrow(try Key(pem: pem, access: .private))
  }

  func testConvertedToPEM_privatePEMFromOpenSSL__shouldMatchTestPEM() throws {
    // given
    let testPEMData = TestData.openSSLPrivateKeyPEM.data
    let testPEM = String(data: testPEMData, encoding: .utf8)

    // when
    let key = try Key(pem: testPEMData, access: .private)

    // then
    let pem = try key.convertedToPEM()
    XCTAssertEqual(pem, testPEM)
  }

  func testConvertedToPEM_publicPEMFromOpenSSL__shouldMatchTestPEM() throws {
    // given
    let testPEMData = TestData.openSSLPublicKeyPKCS1PEM.data
    let testPEM = String(data: testPEMData, encoding: .utf8)!

    // when
    let key = try Key(pem: testPEMData, access: .public)

    // then
    let pem = try key.convertedToPEM()
    XCTAssertEqual(pem, testPEM)
  }
}
