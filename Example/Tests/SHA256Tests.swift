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

  func testDigestFile_withCustomBufferSize__shouldProduceExpectedHash() {
    // given
    /// Test data large enough to force at least 5 buffer fills
    let testData = TestData.largeTestData
    // when
    let bufferedDigest = try! SHA256.digest(file: testData.url, withBufferSize: 1024)
    // then
    XCTAssertEqual(bufferedDigest, Data(hex: expectedHash))
  }

  @available(iOS 13, *)
  func testDigestData_usingCryptoKit__shouldProduceExpectedHash() {
    // given
    let testData = TestData.largeTestData
    // when
    let digest = SHA256.digestV2(testData.data)
    // then
    XCTAssertEqual(digest, Data(hex: expectedHash))
  }

  @available(iOS 13, *)
  func testDigestFile_usingCryptoKit_whenDataLargeEnoughFor5BufferFills__shouldProduceExpectedHash() {
    // given
    /// Test data large enough to force at least 5 buffer fills
    let testData = TestData.largeTestData
    // when
    let bufferedDigest = try! SHA256.digestV2(file: testData.url)
    // then
    XCTAssertEqual(bufferedDigest, Data(hex: expectedHash))
  }

  @available(iOS 13, *)
  func testDigestFile_iOS13_withCustomBufferSize__shouldProduceExpectedHash() {
    // given
    /// Test data large enough to force at least 5 buffer fills
    let testData = TestData.largeTestData
    // when
    let bufferedDigest = try! SHA256.digestV2(file: testData.url, withBufferSize: 1024)
    // then
    XCTAssertEqual(bufferedDigest, Data(hex: expectedHash))
  }
}
