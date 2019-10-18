//
//  KeyTests.swift
//  Krypt_Tests
//
//  Created by marko on 24.01.19.
//  Copyright © 2019 CocoaPods. All rights reserved.
//

import Krypt
import XCTest

final class KeyTests: XCTestCase {
  func testInit_pemData_publicPEMFromOpenSSL__shouldInitialize() throws {
    // given
    let pem = TestData.openSSLPublicKeyPEM.data

    // then
    XCTAssertNoThrow(try Key(pem: pem, access: .public))
  }

  func testInit_pemString_publicPEMFromOpenSSL__shouldInitialize() throws {
    // given
    let pem = TestData.openSSLPublicKeyPEM.stringTrimmingWhitespacesAndNewlines

    // then
    XCTAssertNoThrow(try Key(pem: pem, access: .public))
  }

  func testInit_pemData_privatePEMFromOpenSSL__shouldInitialize() throws {
    // given
    let pem = TestData.openSSLPrivateKeyPEM.data

    // then
    XCTAssertNoThrow(try Key(pem: pem, access: .private))
  }

  func testInit_pemString_privatePEMFromOpenSSL__shouldInitialize() throws {
    // given
    let pem = TestData.openSSLPrivateKeyPEM.stringTrimmingWhitespacesAndNewlines

    // then
    XCTAssertNoThrow(try Key(pem: pem, access: .private))
  }

  func testConvertedToPEM_privatePEMFromOpenSSL__shouldMatchTestPEM() throws {
    // given
    let testPEMData = TestData.openSSLPrivateKeyPEM.data
    let testPEM = String(data: testPEMData, encoding: .utf8)

    // when
    let key = try Key(pem: testPEMData, access: .private)

    // then
    let pem = try key.convertedToPEM()
    XCTAssertEqual(pem, testPEM)
  }

  func testConvertedToPEM_publicPEMFromOpenSSL__shouldMatchTestPEM() throws {
    // given
    let testPEMData = TestData.openSSLPublicKeyPKCS1PEM.data
    let testPEM = String(data: testPEMData, encoding: .utf8)!

    // when
    let key = try Key(pem: testPEMData, access: .public)

    // then
    let pem = try key.convertedToPEM()
    XCTAssertEqual(pem, testPEM)
  }

  func testInit_pemData_privateKey2048__shouldInitialize() throws {
    // given
    let pem = TestData.openSSLPrivateKey2048PEM.data

    // then
    XCTAssertNoThrow(try Key(pem: pem, access: .private, size: .bit_2048))
  }

  func testInit_pemString_privateKey2048__shouldInitialize() throws {
    // given
    let pem = TestData.openSSLPrivateKey2048PEM.stringTrimmingWhitespacesAndNewlines

    // then
    XCTAssertNoThrow(try Key(pem: pem, access: .private, size: .bit_2048))
  }

  func testInit_pemData_publicKey2048__shouldInitialize() throws {
    // given
    let pem = TestData.openSSLPublicKey2048PEM.data

    // then
    XCTAssertNoThrow(try Key(pem: pem, access: .public, size: .bit_2048))
  }

  func testInit_pemString_publicKey2048__shouldInitialize() throws {
    // given
    let pem = TestData.openSSLPublicKey2048PEM.stringTrimmingWhitespacesAndNewlines

    // then
    XCTAssertNoThrow(try Key(pem: pem, access: .public, size: .bit_2048))
  }

  func testDerivePublicKeyFromPrivateKey_usingPrivateKey_shouldReturnCorrectPublicKey() {
    // given
    let pem = TestData.openSSLPrivateKeyPEM.data
    let privateKey = try! Key(pem: pem, access: .private)

    // when
    let publicKey = try? privateKey.publicKeyRepresentation()
    let publicKeyPEM = ((try? publicKey?.convertedToPEM()) as String??)

    // then
    XCTAssertEqual(publicKeyPEM, TestData.openSSLPublicKeyPKCS1PEM.string)
  }

  func testDerivePublicKeyFromPrivateKey_usingPublicKey_shouldReturnErrorInvalidAccess() {
    // given
    let pem = TestData.openSSLPublicKeyPEM.data
    let publicKey = try! Key(pem: pem, access: .public)

    // then
    XCTAssertThrowsError(try publicKey.publicKeyRepresentation(), "Should throw KeyError.invalidAccess error") { error in
      XCTAssertEqual(error as? KeyError, KeyError.invalidAccess)
    }
  }
}
