//
//  AES256Tests.swift
//  Krypt_Tests
//
//  Created by marko on 22.01.19.
//  Copyright © 2019 CocoaPods. All rights reserved.
//

import CryptoSwift
import Krypt
import XCTest

final class AES256Tests: XCTestCase {
  func testCBC_encryptDecrypt__shouldDoFullLoop() throws {
    // given
    let secret = UUID().uuidString
    let secretData = secret.data(using: .utf8)!

    // when
    let (encrypted, key, iv) = try AES256.encrypt(data: secretData, blockMode: .cbc)
    let decrypted = try AES256.decrypt(data: encrypted, key: key, iv: iv, blockMode: .cbc)
    let decryptedString = String(data: decrypted, encoding: .utf8)

    // then
    XCTAssertEqual(decryptedString, secret)
  }

  func testCBC_encryptWithCryptoSwiftDecryptWithKrypt__shouldDoFullLoop() throws {
    // given
    let secret = UUID().uuidString
    let secretData = secret.data(using: .utf8)!
    let key = Data(count: 32) // 256 bit
    let iv = Data(count: 16) // 128 bit

    // when
    let cryptoSwiftAES = try AES(key: key.bytes, blockMode: CBC(iv: iv.bytes), padding: .pkcs7)
    let encrypted = try cryptoSwiftAES.encrypt(secretData.bytes)
    let decrypted = try AES256.decrypt(data: Data(bytes: encrypted), key: key, iv: iv, blockMode: .cbc)
    let decryptedString = String(data: decrypted, encoding: .utf8)

    //then
    XCTAssertEqual(decryptedString, secret)
  }

  func testCBC_encryptWithKryptDecryptWithCryptoSwift__shouldDoFullLoop() throws {
    // given
    let secret = UUID().uuidString
    let secretData = secret.data(using: .utf8)!

    // when
    let (encrypted, key, iv) = try AES256.encrypt(data: secretData, blockMode: .cbc)
    let cryptoSwiftAES = try AES(key: key.bytes, blockMode: CBC(iv: iv.bytes), padding: .pkcs7)
    let decrypted = try cryptoSwiftAES.decrypt(encrypted.bytes)
    let decryptedString = String(data: Data(bytes: decrypted), encoding: .utf8)

    // then
    XCTAssertEqual(decryptedString, secret)
  }

  func testGCM_encryptDecrypt__shouldDoFullLoop() throws {
    // given
    let secret = UUID().uuidString
    let secretData = secret.data(using: .utf8)!

    // when
    let (encrypted, key, iv) = try AES256.encrypt(data: secretData, blockMode: .gcm)
    let decrypted = try AES256.decrypt(data: encrypted, key: key, iv: iv, blockMode: .gcm)
    let decryptedString = String(data: decrypted, encoding: .utf8)

    // then
    XCTAssertEqual(decryptedString, secret)
  }
}
