//
//  SHA256Tests.swift
//  Krypt_Tests
//
//  Created by Simon Feistel on 21.01.20.
//  Copyright © 2020 CocoaPods. All rights reserved.
//

import Krypt
import XCTest

class SHA256Tests: XCTestCase {
  func testSHA256Calculation_buffered__shouldProduceSameAsUnbuffered() {
    // given
    let testData = TestData.kvConnectEmailVerificationInvalidSignatureDigest
    // when
    let unbufferedDigest = SHA256.digest(testData.data)
    let bufferedDigest = SHA256.digest(from: testData.url)
    // then
    XCTAssertEqual(unbufferedDigest, bufferedDigest)
  }
}
