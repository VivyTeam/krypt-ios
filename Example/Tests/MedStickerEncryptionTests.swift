//
//  MedStickerEncryptionTests.swift
//  Krypt_Tests
//
//  Created by marko on 04.02.19.
//  Copyright © 2019 CocoaPods. All rights reserved.
//

import Krypt
import XCTest

final class MedStickerEncryptionTests: XCTestCase {
  let slogan = "A Healthier Life is a Happier Life"

  let pin = "qmHuG263".data(using: .utf8)!
  let code = "7i6XA2zz".data(using: .utf8)!

  let salt = "98C1EB4EE93476743763878FCB96A25FBC9A175074D64004779ECB5242F645E6".data(using: .utf8)!

  func testEncryptDecrypt_shouldDoFullLoop() throws {
    // given
    let messageData = slogan.data(using: .utf8)!

    // when
    let encrypted = try MedStickerEncryption.encrypt(data: messageData, pin: pin, code: code)
    let decrypted = try MedStickerEncryption.decrypt(data: encrypted.data, with: encrypted.attr)

    // then
    XCTAssertEqual(String(data: decrypted, encoding: .utf8), slogan)
  }

  func testDecrypt_manualEncryptWithBritney_shouldDecrypt() throws {
    // given
    let messageData = slogan.data(using: .utf8)!

    // when
    let cipherAttr = MedStickerEncryption.deriveKey(pin: pin, code: code, version: .britney)
    let encrypted = try AES256.encrypt(data: messageData, key: cipherAttr.key, iv: cipherAttr.iv, blockMode: .gcm)
    let decrypted = try MedStickerEncryption.decrypt(data: encrypted.encrypted, with: cipherAttr)

    // then
    XCTAssertEqual(String(data: decrypted, encoding: .utf8), slogan)
  }

  func testDecrypt_manualEncryptWithAdam_shouldDecrypt() throws {
    // given
    let messageData = slogan.data(using: .utf8)!

    // when
    let cipherAttr = MedStickerEncryption.deriveKey(pin: pin, code: code, version: .adam)
    let encrypted = try AES256.encrypt(data: messageData, key: cipherAttr.key, iv: cipherAttr.iv, blockMode: .cbc)
    let decrypted = try MedStickerEncryption.decrypt(data: encrypted.encrypted, with: cipherAttr)

    // then
    XCTAssertEqual(String(data: decrypted, encoding: .utf8), slogan)
  }

  func testContract_decryptWithBritney__shouldEqualContractResult() throws {
    // given
    let encrypted = Data(base64Encoded: "1EkGWJAKP0BG2CAstCFcq8ysbOEvYwruJrrJUBRVGQMe8590wfdKge/jfKcLwEjFg7Q=")!
    let cipherAttr = MedStickerEncryption.CipherAttr(
      key: Data(base64Encoded: "1v6YGdN6BW2AR1uEylOmjSwKu/kUr5qNYR42X0Che3U=")!,
      iv: Data(base64Encoded: "aoiywBzTwYxzKQz45UxWaQ==")!,
      version: .britney
    )

    // when
    let decrypted = try MedStickerEncryption.decrypt(data: encrypted, with: cipherAttr)

    // then
    XCTAssertEqual(String(data: decrypted, encoding: .utf8), slogan)
  }

  func testContract_decryptWithAdam__shouldEqualContractResult() throws {
    // given
    let encrypted = Data(base64Encoded: "rIfjcSAsEh/so+5+ijho97FmIRH36LCCkD/a0V0HWsmw01SEpxoYrQjp5Il5IITw")!
    let cipherAttr = MedStickerEncryption.CipherAttr(
      key: Data(base64Encoded: "Pivil9wBlqECOP8qulkJnHFnIiIwSffQt4rXo27X4Uk=")!,
      iv: Data(base64Encoded: "gi44bZGuBBdLpMISpeppWQ==")!,
      version: .adam
    )

    // when
    let decrypted = try MedStickerEncryption.decrypt(data: encrypted, with: cipherAttr)

    // then
    XCTAssertEqual(String(data: decrypted, encoding: .utf8), slogan)
  }

  func testContract_deriveKey_britney__shouldEqualContractResult() {
    // given
    let expectedDerivedKeyBase64 = "1v6YGdN6BW2AR1uEylOmjSwKu/kUr5qNYR42X0Che3U="
    let expectedDerivedIVBase64 = "aoiywBzTwYxzKQz45UxWaQ=="

    // when
    let cipherAttr = MedStickerEncryption.deriveKey(pin: pin, code: code, version: .britney)

    // then
    XCTAssertEqual(cipherAttr.key.base64EncodedString(), expectedDerivedKeyBase64)
    XCTAssertEqual(cipherAttr.iv.base64EncodedString(), expectedDerivedIVBase64)
  }

  func testContract_deriveKey_adam__shouldEqualContractResult() {
    // given
    let expectedDerivedKeyBase64 = "Pivil9wBlqECOP8qulkJnHFnIiIwSffQt4rXo27X4Uk="
    let expectedDerivedIVBase64 = "gi44bZGuBBdLpMISpeppWQ=="

    // when
    let cipherAttr = MedStickerEncryption.deriveKey(pin: pin, code: code, version: .adam)

    // then
    XCTAssertEqual(cipherAttr.key.base64EncodedString(), expectedDerivedKeyBase64)
    XCTAssertEqual(cipherAttr.iv.base64EncodedString(), expectedDerivedIVBase64)
  }

  func testSignature_britney__shouldCreateSignature() {
    // given
    let cipherAttr = MedStickerEncryption.CipherAttr(
      key: Data(base64Encoded: "1v6YGdN6BW2AR1uEylOmjSwKu/kUr5qNYR42X0Che3U=")!,
      iv: Data(base64Encoded: "aoiywBzTwYxzKQz45UxWaQ==")!,
      version: .britney
    )
    let expectedSignature = "britney-sha256:RonmY2BVOex5wlGRrLPkXn/MZV1Rhot4wRc9+cuK0zY="

    // when
    let signature = MedStickerEncryption.accessSignature(attr: cipherAttr, salt: salt)

    // then
    XCTAssertEqual(signature, expectedSignature)
  }

  func testSignature_adam__shouldCreateSignature() {
    // given
    let cipherAttr = MedStickerEncryption.CipherAttr(
      key: Data(base64Encoded: "Pivil9wBlqECOP8qulkJnHFnIiIwSffQt4rXo27X4Uk=")!,
      iv: Data(base64Encoded: "gi44bZGuBBdLpMISpeppWQ==")!,
      version: .adam
    )
    let expectedSignature = "adam-sha256:hpK5lcLpZoZ2AHIXUi4IgyRnwGCDqApocWM0DDc++zk="

    // when
    let signature = MedStickerEncryption.accessSignature(attr: cipherAttr, salt: salt)

    // then
    XCTAssertEqual(signature, expectedSignature)
  }

  func testSignature_britney__shouldHaveRightAlgorithmPrefix() {
    // given
    let cipherAttr = MedStickerEncryption.CipherAttr(
      key: Data(base64Encoded: "1v6YGdN6BW2AR1uEylOmjSwKu/kUr5qNYR42X0Che3U=")!,
      iv: Data(base64Encoded: "aoiywBzTwYxzKQz45UxWaQ==")!,
      version: .britney
    )

    // when
    let signature = MedStickerEncryption.accessSignature(attr: cipherAttr, salt: salt)

    // then
    XCTAssertTrue(signature.hasPrefix("britney-sha256"))
  }

  func testSignature_adam__shouldHaveRightAlgorithmPrefix() {
    // given
    let cipherAttr = MedStickerEncryption.CipherAttr(
      key: Data(base64Encoded: "Pivil9wBlqECOP8qulkJnHFnIiIwSffQt4rXo27X4Uk=")!,
      iv: Data(base64Encoded: "gi44bZGuBBdLpMISpeppWQ==")!,
      version: .adam
    )

    // when
    let signature = MedStickerEncryption.accessSignature(attr: cipherAttr, salt: salt)

    // then
    XCTAssertTrue(signature.hasPrefix("adam-sha256"))
  }

  func testGenerateFingerprintSecret__shouldGenerate72StringsAndContainVersionCharlie() {
    let expectedLength = 32 * 2 + 8 // 32 bytes * 2(as hex string) + "charlie:" (8)

    let fakePinData = "fakePin".data(using: .utf8)!
    let subject = MedStickerEncryption.generateFingerprintSecret(withPin: fakePinData)

    XCTAssertEqual(subject.count, expectedLength)
    XCTAssertTrue(subject.hasPrefix("charlie:"))
  }

  func testGenerateKeyAndFingerprintFile__shouldGenerate256BitsKeyAnd256BitsFingerprintFilePair() {
    let expectedKeyLength = 32 // 32bytes = 256bits
    let expectedFingerprintFileLength = 32 * 2 + 8 // 32 bytes * 2(as hex string) + "charlie:" (8)

    let fakePinData = "fakePin".data(using: .utf8)!
    let fakeBackendSecret = "fakeBackendSecret".data(using: .utf8)!
    let fakeSecondSalt = "fakeSecondSalt".data(using: .utf8)!

    let subject = MedStickerEncryption.generateKeyAndFingerprint(withPin: fakePinData, secret: fakeBackendSecret, salt: fakeSecondSalt)

    XCTAssertEqual(subject.key.count, expectedKeyLength)
    XCTAssertEqual(subject.fingerprint.count, expectedFingerprintFileLength)
    XCTAssertTrue(subject.fingerprint.hasPrefix("charlie:"))
  }
}
