//
//  ViewController.swift
//  Krypt
//
//  Created by markobyte on 01/21/2019.
//  Copyright (c) 2019 markobyte. All rights reserved.
//

import Krypt
import UIKit

class ViewController: UIViewController {
  override func viewDidLoad() {
    super.viewDidLoad()

    let text = "Encrypt everything"
    let textData = text.data(using: .utf8)!

    let cbcEncrypted = try! AES256.encrypt(data: textData, blockMode: .cbc)
    print(cbcEncrypted)
    let cbcDecrypted = try! AES256.decrypt(data: cbcEncrypted.encrypted, key: cbcEncrypted.key, iv: cbcEncrypted.iv, blockMode: .cbc)
    print(String(data: cbcDecrypted, encoding: .utf8)!)

    let gcmEncrypted = try! AES256.encrypt(data: textData, blockMode: .gcm)
    print(gcmEncrypted)
    let gcmDecrypted = try! AES256.decrypt(data: gcmEncrypted.encrypted, key: gcmEncrypted.key, iv: gcmEncrypted.iv, blockMode: .gcm)
    print(String(data: gcmDecrypted, encoding: .utf8)!)
  }

  override func didReceiveMemoryWarning() {
    super.didReceiveMemoryWarning()
    // Dispose of any resources that can be recreated.
  }
}
