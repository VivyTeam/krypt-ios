//
//  MedStickerKeyFingerprintPair.swift
//  Krypt
//
//  Created by Sun Bin Kim on 24.06.19.
//

import Foundation

/// Holds key and fingerprint
//  fingerprintFile is hex encoded and contains version in front
public struct MedStickerKeyFingerprintPair {
  public let key: Data
  public let fingerprintFile: String
}
