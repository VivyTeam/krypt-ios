//
//  CipherAuth.swift
//  Krypt
//
//  Created by marko on 29.01.19.
//

import Foundation

struct CipherAuth: Codable {
  let key: Data
  let iv: Data

  enum CodingKeys: String, CodingKey {
    case key = "base64EncodedKey"
    case iv = "base64EncodedIV"
  }
}
