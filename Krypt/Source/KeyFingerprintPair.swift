//
//  KeyFingerprintPair.swift
//  Krypt
//
//  Created by Sun Bin Kim on 24.06.19.
//

import Foundation

/// Holds key and fingerprint
//  fingerprint is hex encoded and contains version in front
public struct KeyFingerprintPair {
  public let key: Data
  public let fingerprint: String
}
