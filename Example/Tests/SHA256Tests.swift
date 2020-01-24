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
  func testSAH256Calculation_nonBuffered__shouldProduceCorrectHash() {
    // given
    let testData = TestData.largeTestData
    /// Was calculated locally using openssl
    let expectedHash = "4b9ecf8a918594442fa56d14f2f8e975b258d134bf71c3a05c913b952d40af46"
    // when
    let digest = SHA256.digest(testData.data)
    // then
    XCTAssertEqual(digest, Data(hex: expectedHash))
  }

  func testSHA256Calculation_buffered__shouldProduceSameAsUnbuffered() {
    // given
    /// Test data large enough to force at least 5 buffer fills
    let testData = TestData.largeTestData
    // when
    let unbufferedDigest = SHA256.digest(testData.data)
    let bufferedDigest = try! SHA256.digest(file: testData.url)
    // then
    XCTAssertEqual(unbufferedDigest, bufferedDigest)
  }
}
