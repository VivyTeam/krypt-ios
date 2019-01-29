//
//  EHREncryptionTests.swift
//  Krypt_Tests
//
//  Created by marko on 25.01.19.
//  Copyright © 2019 CocoaPods. All rights reserved.
//

import Krypt
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
}
