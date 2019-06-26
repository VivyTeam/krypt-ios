//
//  PKCS8.swift
//  Krypt
//
//  Created by Max on 24.06.19.
//

import Foundation
import Krypt_internal

public final class PKCS8 {
  public static func convertPKCS1PEMToPKCS8PEM(_ pem: Data) -> String? {
    guard
      let dataString = pem.unsafeUtf8cString,
      let pemCString = convert_pkcs1_to_pkcs8(dataString)
    else {
      return nil
    }

    return String(cString: pemCString)
  }
}
