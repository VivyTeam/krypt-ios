//
//  PKCS8.swift
//  Krypt
//
//  Created by Max on 24.06.19.
//

import Foundation
import Krypt_internal

public final class PKCS8 {
    public static func convertPKCS1DERToPKCS8PEM(_ der: Data) -> String? {
        guard let dataString = der.unsafeUtf8cString else { return nil }
        let pemCString = pkcs8_get_public_key_pem(dataString)!
        let returnVal = String(cString: pemCString)
        print(returnVal)
        return returnVal
    }
}
