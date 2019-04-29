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
    let decryptedEmail = try! SMIME.decrypt(data: email, key: key).stringTrimmingWhitespacesAndNewlines
    
    // then
    XCTAssertEqual(decryptedEmail, expectedDecryptedEmail)
  }

  func testDecrypt_whenWrongPrivateKeyProvided__throwsError() {
    // given
    let email = TestData.kvConnectEmail.data
    let privateKeyPEM = TestData.wrongPrivateKeyOpenPEM.data
    let key = try! Key(pem: privateKeyPEM, access: .private, size: .bit_2048)
    
    // then
    XCTAssertThrowsError(try SMIME.decrypt(data: email, key: key))
  }

  func testDecrypt_whileEncryptedEmailCorrupted__throwsError() {
    // given
    let email = TestData.kvConnectEmailCorrupted.data
    let privateKeyPEM = TestData.kvPrivateKeyOpenPEM.data
    let key = try! Key(pem: privateKeyPEM, access: .private, size: .bit_2048)
    
    // then
    XCTAssertThrowsError(try SMIME.decrypt(data: email, key: key))
  }

  // MARK: VERIFICATION
  
  func testVerify_whenCACertificateChainProvided__returnsContentWithoutSignature() {
    // given
    let caTrustedCerts = CACertificates(certificates: [TestData.kvRootCAPEM.data, TestData.kvVivyCAPEM.data])
    let expectedContent = TestData.kvConnectEmailDecVerified.stringTrimmingWhitespacesAndNewlines
    
    //when
    let content = try! SMIME.verify(data: decryptedEmail, caCertificates: caTrustedCerts).stringTrimmingWhitespacesAndNewlines

    // then
    XCTAssertEqual(content, expectedContent)
  }

  func testVerify_whenCACertificateChainIncomplete__verifyFails() {
    // given
    let certificates = CACertificates(certificates: [TestData.kvRootCAPEM.data])

    // then
    XCTAssertThrowsError(try SMIME.verify(data: decryptedEmail, caCertificates: certificates))
  }
  
  func testVerify_whenWrongCertificateChainProvided__verifyFails() {
    // given
    let certificates = CACertificates(certificates: [TestData.wrongCAPEM.data])

    // then
    XCTAssertThrowsError(try SMIME.verify(data: decryptedEmail, caCertificates: certificates))
  }  
}

extension SMIMETests {
  var decryptedEmail: Data {
    let decryptedString = try! SMIME.decrypt(data: email, key: key).stringTrimmingWhitespacesAndNewlines
    return Data(decryptedString.utf8)
  }
}
