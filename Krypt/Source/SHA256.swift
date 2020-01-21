//
//  SHA256.swift
//  Krypt
//
//  Created by marko on 01.02.19.
//

import CommonCrypto
import Foundation

public struct SHA256 {
  public static func digest(_ data: Data) -> Data? {
    var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
    let status = data.withUnsafeBytes { ptr -> OSStatus in
      guard let pointer = ptr.baseAddress?.assumingMemoryBound(to: UnsafeRawBufferPointer.self) else {
        return errSecConversionError
      }
      _ = CC_SHA256(pointer, CC_LONG(data.count), &hash)
      return errSecSuccess
    }
    return status == errSecSuccess ? Data(hash) : nil
  }

  // MARK: - Buffered SHA-256 Calculation

  public static func digest(from file: URL, with bufferSize: Int = 1024 * 1024) -> Data? {
    guard let handle = try? FileHandle(forReadingFrom: file) else { return nil }
    /// Close file handle on scope exit
    defer {
      handle.closeFile()
    }
    /// Common Crypto SHA256 Setup
    var context = CC_SHA256_CTX()
    CC_SHA256_Init(&context)

    /// Fill buffer in an autoreleasepool so we dont run out of memory for large files
    while autoreleasepool(invoking: {
      /// Fill buffer
      let data = handle.readData(ofLength: bufferSize)
      /// Update SHA256
      if data.count > 0 {
        data.withUnsafeBytes {
          _ = CC_SHA256_Update(&context, $0.baseAddress, numericCast(data.count))
        }
        return true
      } else {
        /// EOF
        return false
      }
    }) {}

    /// SHA256 Digest & Finalize
    var digest = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
    digest.withUnsafeMutableBytes {
      _ = CC_SHA256_Final($0.bindMemory(to: UInt8.self).baseAddress, &context)
    }

    return digest
  }
}
