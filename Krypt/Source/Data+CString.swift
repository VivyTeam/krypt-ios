//
//  Data+CString.swift
//  Krypt
//
//  Created by Max on 24.06.19.
//

import Foundation

extension Data {
    var unsafeUtf8cString: [CChar]? {
        return String(data: self, encoding: .utf8)?.unsafeUtf8cString
    }
}
