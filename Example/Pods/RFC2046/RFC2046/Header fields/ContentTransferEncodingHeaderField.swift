//
//  ContentTransferEncodingHeaderField.swift
//  RFC2046
//
//  Created by Miso Lubarda on 06.05.19.
//

import Foundation

struct ContentTransferEncodingHeaderField: HeaderField {
  enum Value: String {
    case base64
  }
  
  static let fieldName = "content-transfer-encoding"
  let value: Value
  
  init(value: String, attributes: [String : String]?) throws {
    guard let value = Value(rawValue: value) else { throw HeaderFieldError.parsingValueFailed }
    
    self.value = value
  }
}
