//
//  PKCS8.swift
//  Krypt
//
//  Created by Max on 24.06.19.
//

import Foundation

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

  public static func encrypt(_ pem: Data, password: String) -> String? {
    guard !password.isEmpty else { return nil }
    guard
      let pemCString = pem.unsafeUtf8cString,
      let passwordCString = Data(password.utf8).unsafeUtf8cString,
      let encryptedPEMCString = pkcs8_encrypt(pemCString, passwordCString)
      else {
        return nil
    }

    return String(cString: encryptedPEMCString)
  }

  public static func decrypt(_ pem: Data, password: String) -> String? {
    guard
      let pemCString = pem.unsafeUtf8cString,
      let passwordCString = Data(password.utf8).unsafeUtf8cString,
      let decryptedPEMCString = pkcs8_decrypt(pemCString, passwordCString)
      else {
        return nil
    }

    return String(cString: decryptedPEMCString)
  }
}
