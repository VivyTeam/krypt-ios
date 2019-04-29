//
//  KVConnectSMIMETests.swift
//  Krypt_Example
//
//  Created by Miso Lubarda on 29.04.19.
//  Copyright © 2019 CocoaPods. All rights reserved.
//

import Foundation

import Krypt
import XCTest

final class KVConnectSMIMETests: XCTestCase {
  private let email = TestData.kvConnectEmail.data
  private let key = try! Key(pem: TestData.kvPrivateKeyOpenPEM.data, access: .private, size: .bit_2048)
  
  // MARK: DOCUMENTS
  
  func testGetMime_whenAllDataProvided_returnsMIMEMessage() {
    // given
    let email = TestData.kvConnectEmail.data
    let privateKeyPEM = TestData.kvPrivateKeyOpenPEM.data
    let key = try! Key(pem: privateKeyPEM, access: .private, size: .bit_2048)
    let caTrustedCerts = CACertificates(certificates: [TestData.kvRootCAPEM.data, TestData.kvVivyCAPEM.data])
    let expectedMimeMessage = TestData.kvConnectEmailDecVerifiedBothLayers.stringTrimmingWhitespacesAndNewlines
    let kvConnectSMIME = KVConnectSMIME(smime: email)
    
    // when
    let mimeMessage = try! kvConnectSMIME.getMime(identifyingWith: key, trustedCACertificates: caTrustedCerts).stringTrimmingWhitespacesAndNewlines
    
    // then
    XCTAssertEqual(mimeMessage, expectedMimeMessage)
  }

  func testGetMime_whenWrongPrivateKeyProvided__throwsError() {
    // given
    let email = TestData.kvConnectEmail.data
    let privateKeyPEM = TestData.wrongPrivateKeyOpenPEM.data
    let key = try! Key(pem: privateKeyPEM, access: .private, size: .bit_2048)
    let caTrustedCerts = CACertificates(certificates: [TestData.kvRootCAPEM.data, TestData.kvVivyCAPEM.data])
    let kvConnectSMIME = KVConnectSMIME(smime: email)

    // then
    XCTAssertThrowsError(try kvConnectSMIME.getMime(identifyingWith: key, trustedCACertificates: caTrustedCerts))
  }
  
  func testGetMime_whileEncryptedEmailCorrupted__throwsError() {
    // given
    let email = TestData.kvConnectEmailCorrupted.data
    let privateKeyPEM = TestData.kvPrivateKeyOpenPEM.data
    let key = try! Key(pem: privateKeyPEM, access: .private, size: .bit_2048)
    let caTrustedCerts = CACertificates(certificates: [TestData.kvRootCAPEM.data, TestData.kvVivyCAPEM.data])
    let kvConnectSMIME = KVConnectSMIME(smime: email)

    // then
    XCTAssertThrowsError(try kvConnectSMIME.getMime(identifyingWith: key, trustedCACertificates: caTrustedCerts))
  }

  func testGetMime_whenCACertificateChainIncomplete__throwsError() {
    // given
    let email = TestData.kvConnectEmail.data
    let privateKeyPEM = TestData.kvPrivateKeyOpenPEM.data
    let key = try! Key(pem: privateKeyPEM, access: .private, size: .bit_2048)
    let caTrustedCerts = CACertificates(certificates: [TestData.kvVivyCAPEM.data])
    let kvConnectSMIME = KVConnectSMIME(smime: email)

    // then
    XCTAssertThrowsError(try kvConnectSMIME.getMime(identifyingWith: key, trustedCACertificates: caTrustedCerts))
  }
  
  func testGetMime_whenWrongCertificateChainProvided__throwsError() {
    // given
    let email = TestData.kvConnectEmail.data
    let privateKeyPEM = TestData.kvPrivateKeyOpenPEM.data
    let key = try! Key(pem: privateKeyPEM, access: .private, size: .bit_2048)
    let caTrustedCerts = CACertificates(certificates: [TestData.wrongCAPEM.data])
    let kvConnectSMIME = KVConnectSMIME(smime: email)

    // then
    XCTAssertThrowsError(try kvConnectSMIME.getMime(identifyingWith: key, trustedCACertificates: caTrustedCerts))
  }
}
