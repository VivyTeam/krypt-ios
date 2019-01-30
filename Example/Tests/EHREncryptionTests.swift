//
//  EHREncryptionTests.swift
//  Krypt_Tests
//
//  Created by marko on 25.01.19.
//  Copyright © 2019 CocoaPods. All rights reserved.
//

@testable import Krypt
import XCTest

final class EHREncryptionTests: XCTestCase {
  let publicKey = try! Key(pem: TestData.openSSLPublicKeyPEM.data, access: .public)
  let privateKey = try! Key(pem: TestData.openSSLPrivateKeyPEM.data, access: .private)

  func testGCMOAEP_encryptDecrypt__shouldDoWholeLoop() {
    // given
    let message = UUID().uuidString
    let messageData = message.data(using: .utf8)!

    // when
    let encrypted = try! EHREncryption.encrypt(data: messageData, with: publicKey)
    let decrypted = try! EHREncryption.decrypt(encryptedData: encrypted, with: privateKey)

    // then
    XCTAssertEqual(String(data: decrypted, encoding: .utf8), message)
  }

  func testGCMOAEP_encrypt__shouldHaveProperlyBase64EncodedCipherAuth() {
    // given
    let message = UUID().uuidString
    let messageData = message.data(using: .utf8)!

    // when
    let encrypted = try! EHREncryption.encrypt(data: messageData, with: publicKey)
    let decryptedCipherKey = try! RSA.decrypt(data: Data(base64Encoded: encrypted.cipherKey)!, with: privateKey, padding: .oaep)
    let cipherAuth = try! JSONDecoder().decode(CipherAuth.self, from: decryptedCipherKey)

    // then
    XCTAssertEqual(cipherAuth.key.count, 32)
    XCTAssertEqual(cipherAuth.iv.count, 16)
  }
}
