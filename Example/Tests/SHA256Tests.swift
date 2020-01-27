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
  // Computed using `openssl dgst -sha256 -hex [file path]
  private let expectedHash = "4b9ecf8a918594442fa56d14f2f8e975b258d134bf71c3a05c913b952d40af46"

  func testDigestData__shouldProduceExpectedHash() {
    // given
    let testData = TestData.largeTestData
    // when
    let digest = SHA256.digest(testData.data)
    // then
    XCTAssertEqual(digest, Data(hex: expectedHash))
  }

  func testDigestFile_whenDataLargeEnoughFor5BufferFills__shouldProduceExpectedHash() {
    // given
    /// Test data large enough to force at least 5 buffer fills
    let testData = TestData.largeTestData
    // when
    let bufferedDigest = try! SHA256.digest(file: testData.url)
    // then
    XCTAssertEqual(bufferedDigest, Data(hex: expectedHash))
  }

  func testSHA256Calculation_bufferedWithCustomBufferSize__shouldProduceCorrectHash() {
    // given
    /// Test data large enough to force at least 5 buffer fills
    let testData = TestData.largeTestData
    // when
    let bufferedDigest = try! SHA256.digest(file: testData.url, withBufferSize: 1024)
    // then
    XCTAssertEqual(bufferedDigest, Data(hex: expectedHash))
  }
}
