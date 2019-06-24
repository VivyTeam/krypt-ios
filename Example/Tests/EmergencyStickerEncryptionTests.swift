//
//  EmergencyStickerEncryptionTests.swift
//  Krypt_Tests
//
//  Created by Sun Bin Kim on 21.06.19.
//  Copyright © 2019 CocoaPods. All rights reserved.
//

import Krypt
import XCTest

final class EmergencyStickerEncryptionTests: XCTestCase {
  func testGenerateFingerprintSecret__shouldGenerate72StringsAndContainVersionCharlie() {
    let expectedLength = 32 * 2 + 8 // 32 bytes * 2(as hex string) + "charlie:" (8)

    let fakePinData = "fakePin".data(using: .utf8)!
    let subject = try! EmergencyStickerEncryption.generateFingerprintSecret(pin: fakePinData)

    XCTAssertEqual(subject.count, expectedLength)
    XCTAssertTrue(subject.hasPrefix("charlie:"))
  }

  func testGenerateKeyAndFingerprintFile__shouldGenerate256BitsKeyAnd256BitsFingerprintFilePair() {
    let expectedKeyLength = 32 // 32bytes = 256bits
    let expectedFingerprintFileLength = 32 * 2 + 8 // 32 bytes * 2(as hex string) + "charlie:" (8)

    let fakePinData = "fakePin".data(using: .utf8)!
    let fakeBackendSecret = "fakeBackendSecret".data(using: .utf8)!
    let fakeSecondSalt = "fakeSecondSalt".data(using: .utf8)!

    let subject = try! EmergencyStickerEncryption.generateKeyAndFingerprintFile(pin: fakePinData, secret: fakeBackendSecret, salt: fakeSecondSalt)

    XCTAssertEqual(subject.key.count, expectedKeyLength)
    XCTAssertEqual(subject.fingerprintFile.count, expectedFingerprintFileLength)
    XCTAssertTrue(subject.fingerprintFile.hasPrefix("charlie:"))
  }
}
