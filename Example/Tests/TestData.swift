//
//  TestData.swift
//  Krypt_Tests
//
//  Created by marko on 24.01.19.
//  Copyright © 2019 CocoaPods. All rights reserved.
//

import Foundation

private final class TestDataClass {}

enum TestData: String {
  case openSSLPrivateKeyPEM = "openssl-private-key-pkcs1-pem"
  case openSSLPublicKeyPEM = "openssl-public-key-pkcs8-pem"

  var data: Data {
    guard
      let url = Bundle(for: TestDataClass.self)
      .url(forResource: self.rawValue, withExtension: nil),
      let data = try? Data(contentsOf: url)
    else {
      fatalError("No file found")
    }
    return data
  }
}
