//
//  SHA256.swift
//  Krypt
//
//  Created by marko on 01.02.19.
//

import CommonCrypto
import Foundation

public struct SHA256 {
  public static func digest(_ data: Data) -> Data {
    var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
    data.withUnsafeBytes {
      _ = CC_SHA256($0, CC_LONG(data.count), &hash)
    }
    return Data(hash)
  }
}
