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
  let slogan = "A Healthier Life is a Happier Life"

  let publicKey = try! Key(pem: TestData.openSSLPublicKeyPEM.data, access: .public)
  let privateKey = try! Key(pem: TestData.openSSLPrivateKeyPEM.data, access: .private)

  func testEncryptDecrypt__shouldDoWholeLoop() throws {
    // given
    let message = UUID().uuidString
    let messageData = message.data(using: .utf8)!

    // when
    let encrypted = try EHREncryption.encrypt(data: messageData, with: publicKey)
    let decrypted = try EHREncryption.decrypt(encryptedData: encrypted, with: privateKey)

    // then
    XCTAssertEqual(String(data: decrypted, encoding: .utf8), message)
  }

  func testEncrypt__shouldHaveProperlyBase64EncodedCipherAuth() throws {
    // given
    let message = UUID().uuidString
    let messageData = message.data(using: .utf8)!

    // when
    let encrypted = try EHREncryption.encrypt(data: messageData, with: publicKey)
    let decryptedCipherKey = try RSA.decrypt(data: Data(base64Encoded: encrypted.cipherKey)!, with: privateKey, padding: .oaep)
    let cipherAttr = try JSONDecoder().decode(CipherAttr.self, from: decryptedCipherKey)

    // then
    XCTAssertEqual(cipherAttr.key.count, 32)
    XCTAssertEqual(cipherAttr.iv.count, 16)
  }

  func testEncrypt__shouldEncryptWithGCMOAEP() throws {
    // given
    let message = UUID().uuidString
    let messageData = message.data(using: .utf8)!

    // when
    let encrypted = try EHREncryption.encrypt(data: messageData, with: publicKey)

    // then
    XCTAssertEqual(encrypted.version, EHREncryption.Version.gcmOAEP)
  }

  func testEncrypt_gcmOAEP_encryptWithPrivate__shouldThrowPublicError() throws {
    // given
    let message = UUID().uuidString
    let messageData = message.data(using: .utf8)!

    // when
    XCTAssertThrowsError(try EHREncryption.encrypt(data: messageData, with: privateKey)) {
      // then
      XCTAssertEqual($0 as? PublicError, PublicError.encryptionFailed)
    }
  }

  func testDecrypt_gcmOAEP__shouldDecrypt() throws {
    // given
    let message = UUID().uuidString
    let messageData = message.data(using: .utf8)!
    let (encrypted, key, iv) = try AES256.encrypt(data: messageData, blockMode: .gcm)
    let cipherKeyData = try JSONEncoder().encode(CipherAttr(key: key, iv: iv))
    let cipherKeyEncryptedBase64 = try RSA.encrypt(data: cipherKeyData, with: publicKey, padding: .oaep).base64EncodedString()
    let encryptedData = EHREncryption.EncryptedData(cipherKey: cipherKeyEncryptedBase64, data: encrypted, version: .gcmOAEP)

    // when
    let decrypted = try EHREncryption.decrypt(encryptedData: encryptedData, with: privateKey)

    // then
    XCTAssertEqual(String(data: decrypted, encoding: .utf8)!, message)
  }

  func testDecrypt_cbcPKCS1__shouldDecrypt() throws {
    // given
    let message = UUID().uuidString
    let messageData = message.data(using: .utf8)!
    let (encrypted, key, iv) = try AES256.encrypt(data: messageData, blockMode: .cbc)
    let cipherKeyData = try JSONEncoder().encode(CipherAttr(key: key, iv: iv))
    let cipherKeyEncryptedBase64 = try RSA.encrypt(data: cipherKeyData, with: publicKey, padding: .pkcs1).base64EncodedString()
    let encryptedData = EHREncryption.EncryptedData(cipherKey: cipherKeyEncryptedBase64, data: encrypted, version: .cbcPKCS1)

    // when
    let decrypted = try EHREncryption.decrypt(encryptedData: encryptedData, with: privateKey)

    // then
    XCTAssertEqual(String(data: decrypted, encoding: .utf8)!, message)
  }

  func testDecrypt_gcmOAEP_cbc__shouldThrowPublicError() throws {
    // given
    let message = UUID().uuidString
    let messageData = message.data(using: .utf8)!
    let (encrypted, key, iv) = try AES256.encrypt(data: messageData, blockMode: .cbc)
    let cipherKeyData = try JSONEncoder().encode(CipherAttr(key: key, iv: iv))
    let cipherKeyEncryptedBase64 = try RSA.encrypt(data: cipherKeyData, with: publicKey, padding: .oaep).base64EncodedString()
    let encryptedData = EHREncryption.EncryptedData(cipherKey: cipherKeyEncryptedBase64, data: encrypted, version: .cbcPKCS1)

    // when
    XCTAssertThrowsError(try EHREncryption.decrypt(encryptedData: encryptedData, with: privateKey)) {
      // then
      XCTAssertEqual($0 as? PublicError, PublicError.decryptionFailed)
    }
  }

  func testDecrypt_gcmOAEP_pkcs1RSAPadding__shouldThrowPublicError() throws {
    // given
    let message = UUID().uuidString
    let messageData = message.data(using: .utf8)!
    let (encrypted, key, iv) = try AES256.encrypt(data: messageData, blockMode: .gcm)
    let cipherKeyData = try JSONEncoder().encode(CipherAttr(key: key, iv: iv))
    let cipherKeyEncryptedBase64 = try RSA.encrypt(data: cipherKeyData, with: publicKey, padding: .pkcs1).base64EncodedString()
    let encryptedData = EHREncryption.EncryptedData(cipherKey: cipherKeyEncryptedBase64, data: encrypted, version: .gcmOAEP)

    // when
    XCTAssertThrowsError(try EHREncryption.decrypt(encryptedData: encryptedData, with: privateKey)) {
      // then
      XCTAssertEqual($0 as? PublicError, PublicError.decryptionFailed)
    }
  }

  func testDecrypt_gcmOAEP_cbcPKCS1Version__shouldThrowPublicError() throws {
    // given
    let message = UUID().uuidString
    let messageData = message.data(using: .utf8)!
    let (encrypted, key, iv) = try AES256.encrypt(data: messageData, blockMode: .gcm)
    let cipherKeyData = try JSONEncoder().encode(CipherAttr(key: key, iv: iv))
    let cipherKeyEncryptedBase64 = try RSA.encrypt(data: cipherKeyData, with: publicKey, padding: .oaep).base64EncodedString()
    let encryptedData = EHREncryption.EncryptedData(cipherKey: cipherKeyEncryptedBase64, data: encrypted, version: .cbcPKCS1)

    // when
    XCTAssertThrowsError(try EHREncryption.decrypt(encryptedData: encryptedData, with: privateKey)) {
      // then
      XCTAssertEqual($0 as? PublicError, PublicError.decryptionFailed)
    }
  }

  func testDecrypt_gcmOAEP_decryptWithPublicKey__shouldThrowPublicError() throws {
    // given
    let message = UUID().uuidString
    let messageData = message.data(using: .utf8)!
    let (encrypted, key, iv) = try AES256.encrypt(data: messageData, blockMode: .gcm)
    let cipherKeyData = try JSONEncoder().encode(CipherAttr(key: key, iv: iv))
    let cipherKeyEncryptedBase64 = try RSA.encrypt(data: cipherKeyData, with: publicKey, padding: .oaep).base64EncodedString()
    let encryptedData = EHREncryption.EncryptedData(cipherKey: cipherKeyEncryptedBase64, data: encrypted, version: .gcmOAEP)

    // when
    XCTAssertThrowsError(try EHREncryption.decrypt(encryptedData: encryptedData, with: publicKey)) {
      // then
      XCTAssertEqual($0 as? PublicError, PublicError.decryptionFailed)
    }
  }

  func testContract_decrypt_gcmOAEP__decryptedMessageShouldMatchSlogan() throws {
    // given
    let encryptedContractData = TestData.ehrContractGCMMessage.base64Decoded
    let contractCipherKey = String(data: TestData.ehrContractGCMCipherKey.data, encoding: .utf8)!.trimmingCharacters(in: .whitespacesAndNewlines)
    let encryptedData = EHREncryption.EncryptedData(cipherKey: contractCipherKey, data: encryptedContractData, version: .gcmOAEP)

    // when
    let decrypted = try EHREncryption.decrypt(encryptedData: encryptedData, with: privateKey)

    // then
    XCTAssertEqual(String(data: decrypted, encoding: .utf8)!, slogan)
  }

  func testContract_decrypt_cbcPKCS1__decryptedMessageShouldMatchSlogan() throws {
    // given
    let encryptedContractData = TestData.ehrContractCBCMessage.base64Decoded
    let contractCipherKey = String(data: TestData.ehrContractCBCCipherKey.data, encoding: .utf8)!.trimmingCharacters(in: .whitespacesAndNewlines)
    let encryptedData = EHREncryption.EncryptedData(cipherKey: contractCipherKey, data: encryptedContractData, version: .cbcPKCS1)

    // when
    let decrypted = try EHREncryption.decrypt(encryptedData: encryptedData, with: privateKey)

    // then
    XCTAssertEqual(String(data: decrypted, encoding: .utf8)!, slogan)
  }
}
