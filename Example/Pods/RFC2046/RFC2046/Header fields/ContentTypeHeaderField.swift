//
//  ContentTypeHeaderField.swift
//  RFC2046
//
//  Created by Miso Lubarda on 06.05.19.
//

import Foundation

struct ContentTypeHeaderField: HeaderField {
  enum Value {
    // Descrete types as per RFC822
    case applicationXML
    case textPlain
    case applicationPDF
    case imageJPEG
    case imageBMP
    case textHTML
    case imagePNG
    case videoMP4

    // Structured types as per RFC822
    case multipartMixed(boundary: String)
    case multipartAlternative(boundary: String)

    init(rawValue: String, attributes: [String: String]?) throws {
      switch rawValue {
      case "multipart/mixed":
        guard let boundary = attributes?["boundary"]?.trimmingCharacters(in: CharacterSet(charactersIn: "\"'")) else { throw HeaderFieldError.requiredAttributeMissing }
        self = .multipartMixed(boundary: boundary)
      case "multipart/alternative":
        guard let boundary = attributes?["boundary"]?.trimmingCharacters(in: CharacterSet(charactersIn: "\"'")) else { throw HeaderFieldError.requiredAttributeMissing }
        self = .multipartAlternative(boundary: boundary)
      case "application/xml":
        self = .applicationXML
      case "text/plain":
        self = .textPlain
      case "application/pdf":
        self = .applicationPDF
      case "image/jpeg":
        self = .imageJPEG
      case "image/bmp":
        self = .imageBMP
      case "text/html":
        self = .textHTML
      case "image/png":
        self = .imagePNG
      case "video/mp4":
        self = .videoMP4
      default:
        throw HeaderFieldError.parsingValueFailed
      }
    }
  }

  static let fieldName = "content-type"
  let value: Value
  let contentName: String?

  init(value: String, attributes: [String: String]?) throws {
    self.value = try Value(rawValue: value, attributes: attributes)
    contentName = attributes?["name"]?.trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
  }
}
