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

final class KVConnectDecryptionTests: XCTestCase {
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
    let kvConnectSMIME = KVConnectDecryption(smime: email)
    
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
    let kvConnectSMIME = KVConnectDecryption(smime: email)

    // then
    XCTAssertThrowsError(try kvConnectSMIME.getMime(identifyingWith: key, trustedCACertificates: caTrustedCerts))
  }
  
  func testGetMime_whileEncryptedEmailCorrupted__throwsError() {
    // given
    let email = TestData.kvConnectEmailCorrupted.data
    let privateKeyPEM = TestData.kvPrivateKeyOpenPEM.data
    let key = try! Key(pem: privateKeyPEM, access: .private, size: .bit_2048)
    let caTrustedCerts = CACertificates(certificates: [TestData.kvRootCAPEM.data, TestData.kvVivyCAPEM.data])
    let kvConnectSMIME = KVConnectDecryption(smime: email)

    // then
    XCTAssertThrowsError(try kvConnectSMIME.getMime(identifyingWith: key, trustedCACertificates: caTrustedCerts))
  }

  func testGetMime_whenCACertificateChainIncomplete__throwsError() {
    // given
    let email = TestData.kvConnectEmail.data
    let privateKeyPEM = TestData.kvPrivateKeyOpenPEM.data
    let key = try! Key(pem: privateKeyPEM, access: .private, size: .bit_2048)
    let caTrustedCerts = CACertificates(certificates: [TestData.kvVivyCAPEM.data])
    let kvConnectSMIME = KVConnectDecryption(smime: email)

    // then
    XCTAssertThrowsError(try kvConnectSMIME.getMime(identifyingWith: key, trustedCACertificates: caTrustedCerts))
  }
  
  func testGetMime_whenWrongCertificateChainProvided__throwsError() {
    // given
    let email = TestData.kvConnectEmail.data
    let privateKeyPEM = TestData.kvPrivateKeyOpenPEM.data
    let key = try! Key(pem: privateKeyPEM, access: .private, size: .bit_2048)
    let caTrustedCerts = CACertificates(certificates: [TestData.wrongCAPEM.data])
    let kvConnectSMIME = KVConnectDecryption(smime: email)

    // then
    XCTAssertThrowsError(try kvConnectSMIME.getMime(identifyingWith: key, trustedCACertificates: caTrustedCerts))
  }

  // MARK: Special verification checks

  func testGetMime_whileEncryptedEmailVerificationNotHacked__doesntThrowError() {
    // given
    let email = TestData.kvConnectEmailVerificationNotHacked.data
    let privateKeyPEM = TestData.openSSLPrivateKeyPEM.data
    let key = try! Key(pem: privateKeyPEM, access: .private)
    let caTrustedCerts = CACertificates(certificates: [TestData.kvConnectRootCAPEM.data, TestData.kvConnectUserCAPEM.data])
    let kvConnectSMIME = KVConnectDecryption(smime: email)

    // then
    XCTAssertNoThrow(try kvConnectSMIME.getMime(identifyingWith: key, trustedCACertificates: caTrustedCerts))
  }

  func testGetMime_whileEncryptedEmailVerificationCorrupted1__throwsError() {
    // given
    let email = TestData.kvConnectEmailVerificationHacked1.data
    let privateKeyPEM = TestData.openSSLPrivateKeyPEM.data
    let key = try! Key(pem: privateKeyPEM, access: .private)
    let caTrustedCerts = CACertificates(certificates: [TestData.kvConnectRootCAPEM.data, TestData.kvConnectUserCAPEM.data])
    let kvConnectSMIME = KVConnectDecryption(smime: email)

    // then
    XCTAssertThrowsError(try kvConnectSMIME.getMime(identifyingWith: key, trustedCACertificates: caTrustedCerts))
  }

  func testGetMime_whileEncryptedEmailVerificationCorrupted2__throwsError() {
    // given
    let email = TestData.kvConnectEmailVerificationHacked2.data
    let privateKeyPEM = TestData.openSSLPrivateKeyPEM.data
    let key = try! Key(pem: privateKeyPEM, access: .private)
    let caTrustedCerts = CACertificates(certificates: [TestData.kvConnectRootCAPEM.data, TestData.kvConnectUserCAPEM.data])
    let kvConnectSMIME = KVConnectDecryption(smime: email)


    // then
    XCTAssertThrowsError(try kvConnectSMIME.getMime(identifyingWith: key, trustedCACertificates: caTrustedCerts))
  }

  func testGetMime_whileEncryptedEmailVerificationCorrupted3__throwsError() {
    // given
    let email = TestData.kvConnectEmailVerificationHacked3.data
    let privateKeyPEM = TestData.openSSLPrivateKeyPEM.data
    let key = try! Key(pem: privateKeyPEM, access: .private)
    let caTrustedCerts = CACertificates(certificates: [TestData.kvConnectRootCAPEM.data, TestData.kvConnectUserCAPEM.data])
    let kvConnectSMIME = KVConnectDecryption(smime: email)

    // then
    XCTAssertThrowsError(try kvConnectSMIME.getMime(identifyingWith: key, trustedCACertificates: caTrustedCerts))
  }

  func testGetMime_whileEncryptedEmailVerificationCorrupted4__throwsError() {
    // given
    let email = TestData.kvConnectEmailVerificationHacked4.data
    let privateKeyPEM = TestData.openSSLPrivateKeyPEM.data
    let key = try! Key(pem: privateKeyPEM, access: .private)
    let caTrustedCerts = CACertificates(certificates: [TestData.kvConnectRootCAPEM.data, TestData.kvConnectUserCAPEM.data])
    let kvConnectSMIME = KVConnectDecryption(smime: email)

    // then
    XCTAssertThrowsError(try kvConnectSMIME.getMime(identifyingWith: key, trustedCACertificates: caTrustedCerts))
  }
}
