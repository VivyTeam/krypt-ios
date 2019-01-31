//
//  ViewController.swift
//  Krypt_Example
//
//  Created by marko on 30.01.19.
//  Copyright © 2019 CocoaPods. All rights reserved.
//

import Krypt
import Security
import UIKit

class ViewController: UIViewController {
  lazy var privateKey: SecKey? = {
    let attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
      kSecAttrKeySizeInBits as String: 4096
    ]
    return SecKeyCreateRandomKey(attributes as CFDictionary, nil)
  }()

  lazy var publicKey: SecKey? = {
    guard let privateKey = privateKey else {
      return nil
    }
    return SecKeyCopyPublicKey(privateKey)
  }()

  override func viewDidLoad() {
    super.viewDidLoad()
  }
}
