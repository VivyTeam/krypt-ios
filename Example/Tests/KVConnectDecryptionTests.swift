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

  func testGetMime_whenPublicInsteadOfPrivateKeyProvided__throwsError() {
    // given
    let email = TestData.kvConnectEmail.data
    let publicKeyPEM = TestData.openSSLPublicKeyPEM.data
    let key = try! Key(pem: publicKeyPEM, access: .public, size: .bit_2048)
    let caTrustedCerts = CACertificates(certificates: [TestData.kvRootCAPEM.data, TestData.kvVivyCAPEM.data])
    let kvConnectSMIME = KVConnectDecryption(smime: email)

    // then
    XCTAssertThrowsError(try kvConnectSMIME.getMime(identifyingWith: key, trustedCACertificates: caTrustedCerts), "should throw SMIMEError.privateKeyRequired") { error in
      XCTAssertEqual(error as? SMIMEError, SMIMEError.privateKeyRequired)
    }
  }

  func testGetMime_whenWrongPrivateKeyProvided__throwsError() {
    // given
    let email = TestData.kvConnectEmail.data
    let privateKeyPEM = TestData.wrongPrivateKeyOpenPEM.data
    let key = try! Key(pem: privateKeyPEM, access: .private, size: .bit_2048)
    let caTrustedCerts = CACertificates(certificates: [TestData.kvRootCAPEM.data, TestData.kvVivyCAPEM.data])
    let kvConnectSMIME = KVConnectDecryption(smime: email)

    // then
    XCTAssertThrowsError(try kvConnectSMIME.getMime(identifyingWith: key, trustedCACertificates: caTrustedCerts), "should throw SMIMEError.decryptionFailed") { error in
      XCTAssertEqual(error as? SMIMEError, SMIMEError.decryptionFailed)
    }
  }

  func testGetMime_whileEncryptedEmailCorrupted__throwsError() {
    // given
    let email = TestData.kvConnectEmailCorrupted.data
    let privateKeyPEM = TestData.kvPrivateKeyOpenPEM.data
    let key = try! Key(pem: privateKeyPEM, access: .private, size: .bit_2048)
    let caTrustedCerts = CACertificates(certificates: [TestData.kvRootCAPEM.data, TestData.kvVivyCAPEM.data])
    let kvConnectSMIME = KVConnectDecryption(smime: email)

    // then
    XCTAssertThrowsError(try kvConnectSMIME.getMime(identifyingWith: key, trustedCACertificates: caTrustedCerts), "should throw SMIMEError.decryptionFailed") { error in
      XCTAssertEqual(error as? SMIMEError, SMIMEError.decryptionFailed)
    }
  }

  func testGetMime_whenCACertificateChainIncomplete__throwsError() {
    // given
    let email = TestData.kvConnectEmail.data
    let privateKeyPEM = TestData.kvPrivateKeyOpenPEM.data
    let key = try! Key(pem: privateKeyPEM, access: .private, size: .bit_2048)
    let caTrustedCerts = CACertificates(certificates: [TestData.kvVivyCAPEM.data])
    let kvConnectSMIME = KVConnectDecryption(smime: email)

    // then
    XCTAssertThrowsError(try kvConnectSMIME.getMime(identifyingWith: key, trustedCACertificates: caTrustedCerts), "should throw SMIMEError.certificateVerificationFailed") { error in
      XCTAssertEqual(error as? SMIMEError, SMIMEError.certificateVerificationFailed)
    }
  }

  func testGetMime_whenWrongCertificateChainProvided__throwsError() {
    // given
    let email = TestData.kvConnectEmail.data
    let privateKeyPEM = TestData.kvPrivateKeyOpenPEM.data
    let key = try! Key(pem: privateKeyPEM, access: .private, size: .bit_2048)
    let caTrustedCerts = CACertificates(certificates: [TestData.wrongCAPEM.data])
    let kvConnectSMIME = KVConnectDecryption(smime: email)

    // then
    XCTAssertThrowsError(try kvConnectSMIME.getMime(identifyingWith: key, trustedCACertificates: caTrustedCerts), "should throw SMIMEError.certificateVerificationFailed") { error in
      XCTAssertEqual(error as? SMIMEError, SMIMEError.certificateVerificationFailed)
    }
  }

  // MARK: Special verification cases

  /// Testing the positive smime verification case.
  func testGetMime_whileEncryptionAndVerificationValid__doesntThrowError() {
    // given
    let email = TestData.kvConnectEmailVerificationValid.data
    let privateKeyPEM = TestData.openSSLPrivateKeyPEM.data
    let key = try! Key(pem: privateKeyPEM, access: .private)
    let caTrustedCerts = CACertificates(certificates: [TestData.kvConnectRootCAPEM.data, TestData.kvConnectUserCAPEM.data])
    let kvConnectSMIME = KVConnectDecryption(smime: email)

    // then
    XCTAssertNoThrow(try kvConnectSMIME.getMime(identifyingWith: key, trustedCACertificates: caTrustedCerts))
  }

  /// Testing the case where the digest of the message doesn't match the calculated digest.
  func testGetMime_whileInvalidSignatureDigest__throwsDigestVerificationError() {
    // given
    let email = TestData.kvConnectEmailVerificationInvalidSignatureDigest.data
    let privateKeyPEM = TestData.openSSLPrivateKeyPEM.data
    let key = try! Key(pem: privateKeyPEM, access: .private)
    let caTrustedCerts = CACertificates(certificates: [TestData.kvConnectRootCAPEM.data, TestData.kvConnectUserCAPEM.data])
    let kvConnectSMIME = KVConnectDecryption(smime: email)

    // then
    XCTAssertThrowsError(try kvConnectSMIME.getMime(identifyingWith: key, trustedCACertificates: caTrustedCerts), "should throw SMIMEError.digestVerificationFailed") { error in
      XCTAssertEqual(error as? SMIMEError, SMIMEError.digestVerificationFailed)
    }
  }

  /// Testing the case where the signature certificate was issued by untrusted CA.
  func testGetMime_whileCertificateIssuerNotTrusted__throwsCertificateVerificationError() {
    // given
    let email = TestData.kvConnectEmailVerificationCertificateIssuerNotTrusted.data
    let privateKeyPEM = TestData.openSSLPrivateKeyPEM.data
    let key = try! Key(pem: privateKeyPEM, access: .private)
    let caTrustedCerts = CACertificates(certificates: [TestData.kvConnectRootCAPEM.data, TestData.kvConnectUserCAPEM.data])
    let kvConnectSMIME = KVConnectDecryption(smime: email)

    // then
    XCTAssertThrowsError(try kvConnectSMIME.getMime(identifyingWith: key, trustedCACertificates: caTrustedCerts), "should throw SMIMEError.certificateVerificationFailed") { error in
      XCTAssertEqual(error as? SMIMEError, SMIMEError.certificateVerificationFailed)
    }
  }

  /// Testing the case where the signature doesn't belong to the sender of the message.
  func testGetMime_whileSignatureDoesntBelongToSender__throwsSignatureDoesNotBelongToSenderError() {
    // given
    let email = TestData.kvConnectEmailVerificationSignatureDoesntBelongToSender.data
    let privateKeyPEM = TestData.openSSLPrivateKeyPEM.data
    let key = try! Key(pem: privateKeyPEM, access: .private)
    let caTrustedCerts = CACertificates(certificates: [TestData.kvConnectRootCAPEM.data, TestData.kvConnectUserCAPEM.data])
    let kvConnectSMIME = KVConnectDecryption(smime: email)

    // then
    XCTAssertThrowsError(try kvConnectSMIME.getMime(identifyingWith: key, trustedCACertificates: caTrustedCerts), "should throw SMIMEError.signatureDoesNotBelongToSender") { error in
      XCTAssertEqual(error as? SMIMEError, SMIMEError.signatureDoesNotBelongToSender)
    }
  }

  /// Testing the case where the message contains unencrypted part.
  func testGetMime_whileSmimeContainsUnencryptedPart__throwsInvalidMimeTypeError() {
    // given
    let email = TestData.kvConnectEmailVerificationSmimeContainsUnencryptedPart.data
    let privateKeyPEM = TestData.openSSLPrivateKeyPEM.data
    let key = try! Key(pem: privateKeyPEM, access: .private)
    let caTrustedCerts = CACertificates(certificates: [TestData.kvConnectRootCAPEM.data, TestData.kvConnectUserCAPEM.data])
    let kvConnectSMIME = KVConnectDecryption(smime: email)

    // then
    XCTAssertThrowsError(try kvConnectSMIME.getMime(identifyingWith: key, trustedCACertificates: caTrustedCerts), "should throw SMIMEError.invalidMimeType") { error in
      XCTAssertEqual(error as? SMIMEError, SMIMEError.invalidMimeType)
    }
  }
}
