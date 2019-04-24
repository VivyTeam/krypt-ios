//
//  SMIMETests.swift
//  Krypt_Tests
//
//  Created by marko on 11.04.19.
//  Copyright © 2019 CocoaPods. All rights reserved.
//

import Krypt
import XCTest

final class SMIMETests: XCTestCase {
  private let email = TestData.kvConnectEmail.data
  private let key = try! Key(pem: TestData.kvPrivateKeyOpenPEM.data, access: .private, size: .bit_2048)

  // MARK: DECRYPTION
  
  func testDecrypt_whenAllDataProvided__decryptsEmail() {
    // given
    let email = TestData.kvConnectEmail.data
    let privateKeyPEM = TestData.kvPrivateKeyOpenPEM.data
    let key = try! Key(pem: privateKeyPEM, access: .private, size: .bit_2048)
    let expectedDecryptedEmail = TestData.kvConnectEmailDec.stringTrimmingWhitespacesAndNewlines
    
    // when
    let decryptedEmail = SMIME.decrypt(data: email, key: key)?.stringByTrimmingWhitespacesAndNewlines
    
    // then
    XCTAssertEqual(decryptedEmail, expectedDecryptedEmail)
  }

  func testDecrypt_whenWrongPrivateKeyProvided__failsToDecrypt() {
    // given
    let email = TestData.kvConnectEmail.data
    let privateKeyPEM = TestData.wrongPrivateKeyOpenPEM.data
    let key = try! Key(pem: privateKeyPEM, access: .private, size: .bit_2048)
    
    // then
    XCTAssertNil(SMIME.decrypt(data: email, key: key)?.stringByTrimmingWhitespacesAndNewlines)
  }

  func testDecrypt_whileEncryptedEmailCorrupted__failsToDecrypt() {
    // given
    let email = TestData.kvConnectEmailCorrupted.data
    let privateKeyPEM = TestData.kvPrivateKeyOpenPEM.data
    let key = try! Key(pem: privateKeyPEM, access: .private, size: .bit_2048)
    
    // then
    XCTAssertNil(SMIME.decrypt(data: email, key: key)?.stringByTrimmingWhitespacesAndNewlines)
  }

  // MARK: VERIFICATION
  
  func testVerify_whenCACertificateChainProvided__verifySucceeds() {
    // given
    let certificates = [TestData.kvRootCAPEM.data, TestData.kvVivyCAPEM.data]
    
    // then
    XCTAssertTrue(SMIME.verify(data: decryptedEmail, certificates: certificates))
  }

  func testVerify_whenCACertificateChainIncomplete__verifyFails() {
    // given
    let certificates = [TestData.kvRootCAPEM.data]
    
    // then
    XCTAssertFalse(SMIME.verify(data: decryptedEmail, certificates: certificates))
  }
  
  func testVerify_whenWrongCertificateChainProvided__verifyFails() {
    // given
    let certificates = [TestData.wrongCAPEM.data]
        
    // then
    XCTAssertFalse(SMIME.verify(data: decryptedEmail, certificates: certificates))
  }
}

extension SMIMETests {
  var decryptedEmail: Data {
    let decryptedString = SMIME.decrypt(data: email, key: key)!.stringByTrimmingWhitespacesAndNewlines
    return Data(decryptedString.utf8)
  }
}

private extension Data {
  var stringByTrimmingWhitespacesAndNewlines: String {
    return String(data: self, encoding: .utf8)!.trimmingCharacters(in: .whitespacesAndNewlines)
  }
}
