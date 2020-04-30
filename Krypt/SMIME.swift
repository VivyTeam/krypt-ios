//
//  SMIME.swift
//  Krypt
//
//  Created by marko on 11.04.19.
//

import Foundation
import Krypt_internal

public struct SMIME {
  /// Decrypts encrypted SMIME content using private key
  ///
  /// - Parameters:
  ///   - data: encrypted SMIME content
  ///   - key: private key
  /// - Returns: Decrypted SMIME content
  /// - Throws: SMIMEError
  public static func decrypt(data: Data, key: Key) throws -> Data {
    guard key.access == .private else {
      throw SMIMEError.privateKeyRequired
    }

    guard let dataString = data.unsafeUtf8cString else {
      throw SMIMEError.dataCorrupted
    }

    let keyPEM = try key.convertedToPEM().unsafeUtf8cString

    guard let decryptedString = smime_decrypt(dataString, keyPEM),
      let decryptedData = decryptedString.data else {
      throw SMIMEError.decryptionFailed
    }

    return decryptedData
  }

  /// Verifies the decrypted SMIME content signature against trusted CA certificates. The certificate chain needs to be complete for verification to succeed.
  ///
  /// - Parameters:
  ///   - data: SMIME content
  ///   - certificates: collection of CA certificates to trust
  /// - Returns: Decrypted SMIME content without signature
  /// - Throws: SMIMEError.
  public static func verify(data: Data, senderEmail: String, caCertificates: CACertificates) throws -> Data {
    guard let dataString = data.unsafeUtf8cString else {
      throw SMIMEError.dataCorrupted
    }

    guard let senderEmailCString = senderEmail.cString(using: .utf8) else {
      throw SMIMEError.senderEmailCorrupted
    }

    var certificateCStrings = caCertificates.certificateCStrings

    var contentWithoutSignature: UnsafeMutablePointer<Int8>?
    var error = Smime_error(0)

    let result = smime_verify(dataString, senderEmailCString, &certificateCStrings, Int32(certificateCStrings.count), &contentWithoutSignature, &error)
    guard result == 1 else {
      switch error {
      case Smime_error_certificate_verify_error:
        throw SMIMEError.certificateVerificationFailed
      case Smime_error_digest_fail:
        throw SMIMEError.digestVerificationFailed
      case Smime_error_signature_doesnt_belong_to_sender:
        throw SMIMEError.signatureDoesNotBelongToSender
      case Smime_error_invalid_mime_type:
        throw SMIMEError.invalidMimeType
      default:
        throw SMIMEError.verificationFailed
      }
    }

    guard let content = contentWithoutSignature?.data else {
      throw SMIMEError.postVerificationContentCorrupted
    }

    certificateCStrings.freePointers()
    contentWithoutSignature?.deallocate()

    return content
  }
}

private extension UnsafeMutablePointer where Pointee == Int8 {
  var data: Data? {
    return String(cString: self).data(using: .utf8)
  }
}

private extension Collection where Element == UnsafePointer<Int8>? {
  func freePointers() {
    forEach { free(UnsafeMutablePointer(mutating: $0)) }
  }
}

public enum SMIMEError: Error {
  case
    privateKeyRequired,
    dataCorrupted,
    decryptionFailed,
    senderEmailCorrupted,
    signatureDoesNotBelongToSender,
    postVerificationContentCorrupted,
    certificateVerificationFailed,
    digestVerificationFailed,
    verificationFailed,
    invalidMimeType
}
