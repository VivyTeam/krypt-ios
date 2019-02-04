//
//  LocalEncryption.swift
//  Krypt
//
//  Created by marko on 01.02.19.
//

import Foundation

public struct LocalEncryption {
  public static func encrypt(data: Data, with key: Key) throws -> EHREncryption.EncryptedData {
    return try EHREncryption.encrypt(data: data, with: key)
  }

  public static func decrypt(encryptedData: EHREncryption.EncryptedData, with key: Key) throws -> Data {
    return try EHREncryption.decrypt(encryptedData: encryptedData, with: key)
  }
}
