//
//  String+CString.swift
//  Krypt
//
//  Created by marko on 11.04.19.
//

import Foundation

extension String {
  var unsafeUtf8cString: [CChar] {
    return cString(using: .utf8) ?? []
  }
}
