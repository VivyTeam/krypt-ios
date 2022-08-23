//
//  RSATests.swift
//  Krypt_Tests
//
//  Created by marko on 23.01.19.
//  Copyright © 2019 CocoaPods. All rights reserved.
//

import Krypt
import XCTest

final class RSATests: XCTestCase {
  let publicKey = try! Key(pem: TestData.openSSLPublicKeyPEM.data, access: .public)
  let privateKey = try! Key(pem: TestData.openSSLPrivateKeyPEM.data, access: .private)

  func testOEAP_encryptDecrypt_shouldDoWholeLoop() throws {
    // given
    let message = UUID().uuidString
    let messageData = message.data(using: .utf8)!

    // when
    let encrypted = try RSA.encrypt(data: messageData, with: publicKey, padding: .oaep)
    let decrypted = try RSA.decrypt(data: encrypted, with: privateKey, padding: .oaep)
    let decryptedMessage = String(data: decrypted, encoding: .utf8)

    // then
    XCTAssertEqual(decryptedMessage, message)
  }

  func testPKCS1_encryptDecrypt_shouldDoWholeLoop() throws {
    // given
    let message = UUID().uuidString
    let messageData = message.data(using: .utf8)!

    // when
    let encrypted = try RSA.encrypt(data: messageData, with: publicKey, padding: .pkcs1)
    let decrypted = try RSA.decrypt(data: encrypted, with: privateKey, padding: .pkcs1)
    let decryptedMessage = String(data: decrypted, encoding: .utf8)

    // then
    XCTAssertEqual(decryptedMessage, message)
  }
}
