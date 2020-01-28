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

  /// Calculates SHA256 hash of given data using CryptoKit
  /// - Parameter data: The data to calculate the hash for
  @available(iOS 13, *)
  public static func digestV2(_ data: Data) -> Data? {
    return Data(CryptoKit.SHA256.hash(data: data))
  }

  // MARK: - Buffered SHA-256 Calculation

  /// Calculates SHA256 hash of a given file using a buffer to avoid running out of memory for potentially large files
  /// - Parameters:
  ///   - url: The url to the file to calculate the SHA256 hash for
  ///   - withBufferSize: The size of the buffer to use in bytes, defaults to 1024 * 1024 bytes =  1MB
  public static func digest(file url: URL, withBufferSize: Int = 1024 * 1024) throws -> Data {
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
      let data = handle.readData(ofLength: withBufferSize)
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

  /// iOS 13 Variant of SHA256 hash calculation for large files using a buffer and CryptoKit
  /// - Parameters:
  ///   - url: The url to the file to calculate the SHA256 hash for
  ///   - withBufferSize: The size of the buffer to use in bytes, defaults to 1024*1024 bytes = 1 MB
  @available(iOS 13, *)
  public static func digestV2(file url: URL, withBufferSize: Int = 1024 * 1024) throws -> Data {
    guard let stream = InputStream(fileAtPath: url.path) else {
      throw SHA256Error.fileOperationError
    }
    stream.open()
    let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: withBufferSize)
    defer {
      buffer.deallocate()
    }
    var hasher = CryptoKit.SHA256()
    while stream.hasBytesAvailable {
      let read = stream.read(buffer, maxLength: withBufferSize)
      let bufferPointer = UnsafeRawBufferPointer(start: buffer, count: read)
      hasher.update(bufferPointer: bufferPointer)
    }
    let digest = hasher.finalize()
    return Data(digest)
  }
}

/// Errors that can occur during the SHA256 hash calculation
public enum SHA256Error: Error {
  /// An error occured during an operation on the file to calculate the hash for
  case fileOperationError
}
