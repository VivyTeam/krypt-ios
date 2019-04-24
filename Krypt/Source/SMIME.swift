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
  /// - Returns: Decrypted SMIME content in case of successful decryption or nil in case of failure.
  public static func decrypt(data: Data, key: Key) -> Data? {
    guard key.access == .private else {
      return nil
    }
    guard let dataString = data.unsafeUtf8cString else {
      return nil
    }
    
    guard let keyPEM = try? key.convertedToPEM().unsafeUtf8cString else {
      return nil
    }

    return smime_decrypt(dataString, keyPEM)?.data
  }
  
  /// Verifies the decrypted SMIME content signature against trusted CA certificates. The certificate chain needs to be complete for verification to succeed.
  ///
  /// - Parameters:
  ///   - data: SMIME content
  ///   - certificates: collection of CA certificates to trust
  /// - Returns: True in case verification succeeded
  public static func verify(data: Data, certificates: [Data]) -> Bool {
    guard let dataString = data.unsafeUtf8cString else {
      return false
    }
    
    let certificateStrings = certificates.map { String(decoding: $0, as: UTF8.self) }
    var certificateCStrings = certificateStrings.cStringsByCoping
    
    let success = smime_verify(dataString, &certificateCStrings, Int32(certificateCStrings.count)) == 1
    certificateCStrings.freePointers()

    return success
  }
}

private extension Data {
  var unsafeUtf8cString: [CChar]? {
    return String(data: self, encoding: .utf8)?.unsafeUtf8cString
  }
}

private extension UnsafeMutablePointer where Pointee == Int8 {
  var data: Data? {
    return String(cString: self).data(using: .utf8)
  }
}

private extension Collection where Element == String {
  var cStringsByCoping: [UnsafePointer<Int8>?] {
    return map { UnsafePointer<Int8>(strdup($0)) }
  }
}

private extension Collection where Element == UnsafePointer<Int8>? {
  func freePointers() {
    forEach { free(UnsafeMutablePointer(mutating: $0)) }
  }
}
