//
//  E2EETests.swift
//  Krypt_Tests
//
//  Created by marko on 25.01.19.
//  Copyright © 2019 CocoaPods. All rights reserved.
//

import Krypt
import XCTest

final class E2EETests: XCTestCase {
  let publicKey = try! Key(pem: TestData.openSSLPublicKeyPEM.data, access: .public)
  let privateKey = try! Key(pem: TestData.openSSLPrivateKeyPEM.data, access: .private)

  func testGCMOAEP_encryptDecrypt__shouldDoWholeLoop() {
    // given
    let message = UUID().uuidString
    let messageData = message.data(using: .utf8)!

    // when
    let (encrypted, metaMessage) = try! E2EE.encrypt(data: messageData, key: publicKey, version: .gcmOAEP)
    let decrypted = try! E2EE.decrypt(data: encrypted, metaMessage: metaMessage, key: privateKey, version: .gcmOAEP)

    // then
    XCTAssertEqual(String(data: decrypted, encoding: .utf8), message)
  }
}
