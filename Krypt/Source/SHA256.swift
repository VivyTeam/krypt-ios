//
//  SHA256.swift
//  Krypt
//
//  Created by marko on 01.02.19.
//

import CommonCrypto
import CryptoKit
import Foundation

public struct SHA256 {
  public static func digest(_ data: Data) -> Data? {
    if #available(iOS 13, *) {
      return Data(CryptoKit.SHA256.hash(data: data))
    }
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

  /// Calculates SHA256 hash of a given file using a buffer to avoid running out of memory for potentially large files
  /// - Parameters:
  ///   - url: The url to the file to calculate the SHA256 hash for
  ///   - withBufferSize: The size of the buffer to use in bytes, defaults to 1024 * 1024 bytes =  1MB
  public static func digest(file url: URL, withBufferSize bufferSize: Int = 1024 * 1024) throws -> Data {
    if #available(iOS 13, *) {
      guard let stream = InputStream(fileAtPath: url.path) else {
        throw SHA256Error.fileOperationError
      }
      stream.open()
      let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
      defer {
        buffer.deallocate()
      }
      var hasher = CryptoKit.SHA256()
      while stream.hasBytesAvailable {
        let read = stream.read(buffer, maxLength: bufferSize)
        let bufferPointer = UnsafeRawBufferPointer(start: buffer, count: read)
        hasher.update(bufferPointer: bufferPointer)
      }
      let digest = hasher.finalize()
      return Data(digest)
    }

    let handle = try FileHandle(forReadingFrom: url)
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

/// Errors that can occur during the SHA256 hash calculation
public enum SHA256Error: Error {
  /// An error occured during an operation on the file to calculate the hash for
  case fileOperationError
}
