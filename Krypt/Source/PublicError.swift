//
//  PublicError.swift
//  Krypt
//
//  Created by marko on 29.01.19.
//

import Foundation

/// High level error used in E2EE
///
/// - encryptionFailed: encapsulates any error that could occur during encryption
/// - decryptionFailed: encapsulates any error that could occur during decryption
public enum PublicError: LocalizedError {
  case encryptionFailed
  case decryptionFailed
}
