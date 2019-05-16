//
//  RFC2046Decoder.swift
//  RFC2046
//
//  Created by Miso Lubarda on 07.05.19.
//

import Foundation

final class RFC2046Decoder {

  /// Searches for requested header field in header and decodes it in HeaderField object.
  ///
  /// - Parameters:
  ///   - headerField: Type of HeaderField to decode to
  ///   - from: Header text from which to decode header field
  /// - Returns: Decoded header field of type conforming to HeaderField protocol
  /// - Throws: Throws an error if header lines are malformed or the requested header doesn't exist.
  func decode<T>(_ headerField: T.Type, from header: String) throws -> T where T: HeaderField {
    let lines = header.splitToRFC2046HeaderLines
    guard verifyHeaderLinesFormat(lines) else { throw RFC2046ParserError.headerMalformed }
    guard let line = getLine(fromLines: lines, containingFieldName: headerField.fieldName) else { throw RFC2046ParserError.noSuchField }

    return try parse(line: line, to: headerField)
  }

  /// Verify if header lines start with combination of letters and/or dashes (-) followed by colon (:)
  ///
  /// - Parameter lines: header lines
  /// - Returns: True if header lines conform to rules (check the description)
  /// - Example:
  ///
  /// Successful case:
  /// ````
  /// "Content-Type: multipart/mixed;charset=utf-8; boundary="------------020509070606080100000104""
  /// ````
  ///
  /// Unsuccessful case:
  /// ````
  /// ":multipart/mixed;charset=utf-8; boundary="------------020509070606080100000104""
  /// ````
  private func verifyHeaderLinesFormat(_ lines: [String]) -> Bool {
    let allowedCharacterSet = CharacterSet.letters.union(CharacterSet(charactersIn: "-"))
    for line in lines {
      guard let fieldName = line.split(separator: ":").first else { return false }
      let containsForbiddenCharacters = fieldName.unicodeScalars.contains { (unicodeScalar) -> Bool in
        return !allowedCharacterSet.contains(unicodeScalar)
      }
      if containsForbiddenCharacters == true {
        return false
      }
    }
    return true
  }

  /// Get line from header lines which contains field name at the beginning of the line
  ///
  /// - Parameters:
  ///   - lines: Header lines
  ///   - fieldname: Header field name
  /// - Returns: Line containing filedname at the beginning
  private func getLine(fromLines lines: [String], containingFieldName fieldname: String) -> String? {
    return lines.first { $0.lowercased().starts(with: fieldname.lowercased()) }
  }


  /// Parse header field line into HeaderField object
  ///
  /// - Parameters:
  ///   - line: Header line to parse
  ///   - headerField:
  /// - Returns: Header line converted in object
  /// - Throws: Throws wether the field name or value is missing
  private func parse<T>(line: String, to headerField: T.Type) throws -> T where T: HeaderField {
    // Detach header attributes
    let fieldWithAttributes = line.split(separator: ";")
    // First part of line should be header field. Header field and attributes are separated by semicolon.
    guard let field = fieldWithAttributes.first else { throw RFC2046ParserError.noSuchField }

    // Field name and value are separated by colon
    let fieldNameAndValue = field.split(separator: ":").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
    guard fieldNameAndValue.count == 2, fieldNameAndValue.first!.lowercased() == headerField.fieldName.lowercased(),
      let fieldValue = fieldNameAndValue.last else { throw RFC2046ParserError.noFieldValue }


    var attributesNameAndValues = [String: String]()

    let attributes = fieldWithAttributes.dropFirst()
    attributes.forEach { attribute in
      // Attribute name and value are separated by "="
      let nameAndValues = attribute.split(separator: "=")
      if nameAndValues.count == 2 {
        let name = nameAndValues.first!.trimmingCharacters(in: .whitespacesAndNewlines)
        let value = nameAndValues.last!.trimmingCharacters(in: .whitespacesAndNewlines)
        attributesNameAndValues[name] = value
      }
    }

    return try headerField.init(value: fieldValue, attributes: attributesNameAndValues.isEmpty ? nil : attributesNameAndValues)
  }
}

private extension String {
  /// Split header to array of lines since the delimited is CRLF as per RFC822
  var splitToRFC2046HeaderLines: [String] {
    var lines = [String]()
    enumerateLines { (line, stop) in
      lines.append(line)
    }
    return lines.reduce([]) { partialResult, line -> [String] in
      guard let lastLine = partialResult.last else { return [line] }
      if lastLine.trimmingCharacters(in: .whitespacesAndNewlines).last == ";" {
        return partialResult.dropLast() + [lastLine + line]
      } else {
        return partialResult + [line]
      }
    }
  }
}
