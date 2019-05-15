//
//  HeaderField.swift
//  RFC2046
//
//  Created by Miso Lubarda on 06.05.19.
//

import Foundation

protocol HeaderField {
  associatedtype Value
  
  static var fieldName: String { get }
  var value: Value { get }
  
  init(value: String, attributes: [String: String]?) throws
}

enum HeaderFieldError: Error {
  case parsingValueFailed, requiredAttributeMissing
}
