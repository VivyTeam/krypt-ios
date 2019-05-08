//
//  KVConnectDecryption.swift
//  Krypt
//
//  Created by Miso Lubarda on 29.04.19.
//

import Foundation

public struct KVConnectDecryption {
  private let smime: Data
  
  public init(smime: Data) {
    self.smime = smime
  }
  
  public func getMime(identifyingWith privateKey: Key, trustedCACertificates: CACertificates) throws -> Data {
    let decryptedFirstLayer = try SMIME.decrypt(data: smime, key: privateKey)
    let decryptedFirstLayerNoSignature = try SMIME.verify(data: decryptedFirstLayer, caCertificates: trustedCACertificates)
    let decryptedFirstLayerNoSignatureTrimmed = try trimRedundantHeader(from: decryptedFirstLayerNoSignature)
    let decryptedSecondLayer = try SMIME.decrypt(data: decryptedFirstLayerNoSignatureTrimmed, key: privateKey)
    let decryptedSecondLayerNoSignature = try SMIME.verify(data: decryptedSecondLayer, caCertificates: trustedCACertificates)
    
    return decryptedSecondLayerNoSignature
  }
  
  private func trimRedundantHeader(from smime: Data) throws -> Data {
    guard let smimeString = String(data: smime, encoding: .utf8) else {
      throw KVConnectError.error
    }

    var smimeArray = smimeString.split(separator: "\r\n", omittingEmptySubsequences: false)
    smimeArray.removeFirst(3)
    let strippedSmime = smimeArray.joined(separator: "\r\n")
    return Data(strippedSmime.utf8)
  }
}

enum KVConnectError: Error {
  case error
}
