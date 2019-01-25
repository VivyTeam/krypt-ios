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
}
