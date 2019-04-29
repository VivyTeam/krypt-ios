//
//  CACertificates.swift
//  CryptoSwift
//
//  Created by Miso Lubarda on 28.04.19.
//

import Foundation

public struct CACertificates {
  let certificates: [Data]
  
  public init(certificates: [Data]) {
    self.certificates = certificates
  }
  
  var certificateCStrings: [UnsafePointer<Int8>?] {
    let certificateStrings = certificates.map { String(decoding: $0, as: UTF8.self) }
    return certificateStrings.cStringsByCoping
  }
}

private extension Collection where Element == String {
  var cStringsByCoping: [UnsafePointer<Int8>?] {
    return map { UnsafePointer<Int8>(strdup($0)) }
  }
}
