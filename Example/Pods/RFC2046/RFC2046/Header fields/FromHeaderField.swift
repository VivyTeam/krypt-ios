//
//  FromHeaderField.swift
//  RFC2046
//
//  Created by Miso Lubarda on 14.05.19.
//

import Foundation

struct FromHeaderField: HeaderField {
  static let fieldName = "from"
  let value: String
  let emailAddress: String

  init(value: String, attributes _: [String: String]?) throws {
    let trimmedValue = value.trimmingCharacters(in: .whitespacesAndNewlines)

    let bracketsSplit = trimmedValue.split { $0 == "<" || $0 == ">" }
    guard let email = bracketsSplit.first(where: { String($0).isValidEmailAddress }) else { throw HeaderFieldError.parsingValueFailed }

    self.value = trimmedValue
    emailAddress = String(email)
  }
}

private extension String {
  var isValidEmailAddress: Bool {
    let regexp = "[A-Z0-9a-z._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}"
    let predicate = NSPredicate(format: "SELF MATCHES %@", regexp)
    return predicate.evaluate(with: self)
  }
}
