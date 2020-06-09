//
//  CipherAttr.swift
//  Krypt
//
//  Created by marko on 29.01.19.
//

import Foundation

/// DTO for AES256 authentication
struct CipherAttr: Codable {
  let key: Data
  let iv: Data

  enum CodingKeys: String, CodingKey {
    case key = "base64EncodedKey"
    case iv = "base64EncodedIV"
  }
}
