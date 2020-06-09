//
//  Data+String.swift
//  Krypt_Tests
//
//  Created by Miso Lubarda on 29.04.19.
//  Copyright © 2019 CocoaPods. All rights reserved.
//

import Foundation

extension Data {
  var stringTrimmingWhitespacesAndNewlines: String {
    return String(data: self, encoding: .utf8)!.trimmingCharacters(in: .whitespacesAndNewlines)
  }
}
