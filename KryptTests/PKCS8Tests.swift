//
//  PKCS8Tests.swift
//  Krypt_Tests
//
//  Created by Max on 24.06.19.
//  Copyright © 2019 CocoaPods. All rights reserved.
//

import XCTest
@testable import Krypt

final class PKCS8Tests: XCTestCase {

  func testConvertPKCS1_toPKCS8__shouldConvertCorrectly() {
    // given
    let expectedPEM = TestData.openSSLPublicKeyPEM.string
    let pkcs1PEMData = TestData.openSSLPublicKeyPKCS1PEM.data

    // when
    let convertedPKCS8PEM = PKCS8.convertPKCS1PEMToPKCS8PEM(pkcs1PEMData)

    // then
    XCTAssertEqual(expectedPEM, convertedPKCS8PEM)
  }

  func testConvertPKCS8PEM_toPKCS8__shouldReturnNil() {
    // given
    let pkcs8PEM = TestData.openSSLPublicKeyPEM.data

    // when
    let convertedPKCS8PEM = PKCS8.convertPKCS1PEMToPKCS8PEM(pkcs8PEM)

    // then
    XCTAssertNil(convertedPKCS8PEM)
  }

  func testEncryptPKCS1_simplePassword__shouldEncrypt() {
    // given
    let pkcs1PEMData = TestData.openSSLPrivateKeyPEM.data
    let password = "password"

    // when
    let encrypted = PKCS8.encrypt(pkcs1PEMData, password: password)

    // then
    XCTAssertNotNil(encrypted)
  }

  func testEncryptPKCS1_emptyPassword__shouldReturnNil() {
    // given
    let pkcs1PEMData = TestData.openSSLPrivateKeyPEM.data
    let password = ""

    // when
    let encrypted = PKCS8.encrypt(pkcs1PEMData, password: password)

    // then
    XCTAssertNil(encrypted)
  }

  func testEncryptPKCS1_uuidPassword__shouldEncrypt() {
    // given
    let pkcs1PEMData = TestData.openSSLPrivateKeyPEM.data
    let password = UUID().uuidString

    // when
    let encrypted = PKCS8.encrypt(pkcs1PEMData, password: password)

    // then
    XCTAssertNotNil(encrypted)
  }

  func testEncryptPKCS1_sha512Password__shouldEncrypt() {
    // given
    let pkcs1PEMData = TestData.openSSLPrivateKeyPEM.data
    let password = "B109F3BBBC244EB82441917ED06D618B9008DD09B3BEFD1B5E07394C706A8BB980B1D7785E5976EC049B46DF5F1326AF5A2EA6D103FD07C95385FFAB0CACBC86"

    // when
    let encrypted = PKCS8.encrypt(pkcs1PEMData, password: password)

    // then
    XCTAssertNotNil(encrypted)
  }

  func testEncryptPKCS1_specialCharactersPassword__shouldEncrypt() {
    // given
    let pkcs1PEMData = TestData.openSSLPrivateKeyPEM.data
    let password = "äū☁️🤯"

    // when
    let encrypted = PKCS8.encrypt(pkcs1PEMData, password: password)

    // then
    XCTAssertNotNil(encrypted)
  }

  func testEncryptPKCS1_stringTerminatorPassword__shouldEncrypt() {
    // given
    let pkcs1PEMData = TestData.openSSLPrivateKeyPEM.data
    let password = "pass\0word"

    // when
    let encrypted = PKCS8.encrypt(pkcs1PEMData, password: password)

    // then
    XCTAssertNotNil(encrypted)
  }

  /// parameters were extracted using this online tool: https://lapo.it/asn1js/
  func testEncryptPKCS1_simplePassword__shouldContainRightEncryptionParameters() {
    // given
    let pkcs1PEMData = TestData.openSSLPrivateKeyPEM.data
    let password = "password"

    let expectedPBEAlgorithmBytes: [UInt8] = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D] // 1.2.840.113549.1.5.13 pkcs5PBES2 (PKCS #5 v2.0)
    let expectedKDFBytes: [UInt8] = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C] // 1.2.840.113549.1.5.12 pkcs5PBKDF2 (PKCS #5 v2.0)
    let expectedKDFIterationCountBytes: [UInt8] = [0x02, 0x03, 0x01, 0x86, 0xA0] // 100_000 iterations for PBKDF2
    let expectedHashingAlgorithmBytes: [UInt8] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x09] // 1.2.840.113549.2.9 hmacWithSHA256 (RSADSI digestAlgorithm)
    let expectedSymmetricEncryptionAlgorithmBytes: [UInt8] = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A] // 2.16.840.1.101.3.4.1.42 aes256-CBC (NIST Algorithm)

    // when
    let encrypted = PKCS8.encrypt(pkcs1PEMData, password: password)

    // then
    XCTAssertNotNil(encrypted)

    let der = encrypted!.der
    XCTAssertEqual(der.passwordBasedEncryptionAlgorithmBytes, expectedPBEAlgorithmBytes)
    XCTAssertEqual(der.keyDerivationFunctionBytes, expectedKDFBytes)
    XCTAssertEqual(der.kdfIterationCountBytes, expectedKDFIterationCountBytes)
    XCTAssertEqual(der.hashingAlgorithmBytes, expectedHashingAlgorithmBytes)
    XCTAssertEqual(der.symmetricEncryptionAlgorithmBytes, expectedSymmetricEncryptionAlgorithmBytes)
  }

  func testDecrypt_encryptedExample_whenPasswordIsCorrect__shouldDecryptExpectedPKCS8Key() {
    // given
    let encryptedPEMData = TestData.openSSLPrivateKeyEncryptedPKCS8PEM.data
    let password = "password"
    let expectedDecryptedPEM = TestData.openSSLPrivateKeyPEM.string

    // when
    let decryptedPEM = PKCS8.decrypt(encryptedPEMData, password: password)

    // then
    XCTAssertEqual(decryptedPEM, expectedDecryptedPEM)
  }

  func testDecrypt_encryptedExample_whenPasswordIsEmpty__shouldNotDecrypt() {
    // given
    let encryptedPEMData = TestData.openSSLPrivateKeyEncryptedPKCS8PEM.data
    let password = ""

    // when
    let decryptedPEM = PKCS8.decrypt(encryptedPEMData, password: password)

    // then
    XCTAssertNil(decryptedPEM)
  }

  func testDecrypt_encryptedExample_whenPasswordIsRandom__shouldNotDecrypt() {
    // given
    let encryptedPEMData = TestData.openSSLPrivateKeyEncryptedPKCS8PEM.data
    let password = UUID().uuidString

    // when
    let decryptedPEM = PKCS8.decrypt(encryptedPEMData, password: password)

    // then
    XCTAssertNil(decryptedPEM)
  }

  func testDecrypt_encryptedExample_whenPasswordIsCorrect__shouldDecryptValidSecKey() {
    // given
    let encryptedPEMData = TestData.openSSLPrivateKeyEncryptedPKCS8PEM.data
    let password = "password"

    // when
    let decryptedPEM = PKCS8.decrypt(encryptedPEMData, password: password)

    // then
    XCTAssertNotNil(decryptedPEM?.secKey)
  }

  func testEncryptDecryptE2E_simplePassword__shouldEncryptAndDecryptExpectedPKCS8Key() {
    // given
    let pkcs1PEMData = TestData.openSSLPrivateKeyPEM.data
    let password = "password"
    let expectedDecryptedPEM = TestData.openSSLPrivateKeyPEM.string

    // when
    let encrypted = PKCS8.encrypt(pkcs1PEMData, password: password)
    let decrypted = PKCS8.decrypt(Data(encrypted!.utf8), password: password)

    // then
    XCTAssertEqual(decrypted, expectedDecryptedPEM)
  }
}

private extension String {
  var der: Data {
    let stripped = self.replacingOccurrences(of: "-----BEGIN ENCRYPTED PRIVATE KEY-----", with: "")
      .replacingOccurrences(of: "-----BEGIN RSA PRIVATE KEY-----", with: "")
      .replacingOccurrences(of: "-----END ENCRYPTED PRIVATE KEY-----", with: "")
      .replacingOccurrences(of: "-----END RSA PRIVATE KEY-----", with: "")
      .replacingOccurrences(of: "\n", with: "")
    return Data(base64Encoded: stripped)!
  }
}

private extension Data {
  var passwordBasedEncryptionAlgorithmBytes: [UInt8] {
    return [UInt8](self[6...16])
  }

  var keyDerivationFunctionBytes: [UInt8] {
    return [UInt8](self[21...31])
  }

  var kdfIterationCountBytes: [UInt8] {
    return [UInt8](self[44...48])
  }

  var hashingAlgorithmBytes: [UInt8] {
    return [UInt8](self[51...60])
  }

  var symmetricEncryptionAlgorithmBytes: [UInt8] {
    return [UInt8](self[65...75])
  }
}

private extension String {
  var secKey: SecKey? {
    let attr = [
      kSecAttrKeyType: kSecAttrKeyTypeRSA,
      kSecAttrKeyClass: kSecAttrKeyClassPrivate,
      kSecAttrKeySizeInBits: 4096
    ] as CFDictionary
    let data = der as CFData
    return SecKeyCreateWithData(data, attr, nil)
  }
}
