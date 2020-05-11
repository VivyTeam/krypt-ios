//
//  X509.swift
//  Krypt
//
//  Created by marko on 14.11.19.
//

import Foundation
import Krypt_internal

public struct X509 {

  public static func wrap(publicKeyPEM pem: String) -> String? {
    // Providing a random private key to sign the certificate
    let dummyPrivateKeyPEM = """
      -----BEGIN EC PRIVATE KEY-----
      MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCCeakECXap+wYDKMyhU
      yRsljYiBZih/66cV8EFIJ5kdPA==
      -----END EC PRIVATE KEY-----
      """
    let pkeyCString = dummyPrivateKeyPEM.unsafeUtf8cString
    let keyCString = pem.unsafeUtf8cString

    return x509_wrap_pubkey(pkeyCString, keyCString).flatMap { String(cString: $0) }
  }

}
