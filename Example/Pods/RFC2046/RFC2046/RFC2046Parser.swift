//
//  RFC2046Parser.swift
//  RFC2046
//
//  Created by Miso Lubarda on 06.05.19.
//

import Foundation

public class RFC2046Parser {
  private let text: String
  
  public init (text: String) {
    self.text = text
  }
  
  public func getMessages() throws -> [RFC2046Message] {
    return try parse(fromText: text)
  }

  public func getSenderEmailAddress() throws -> String {
    let headerAndBody = try getHeaderAndBody(text: text)

    let header = headerAndBody.header.trimmingCharacters(in: .whitespacesAndNewlines)
    let from = try RFC2046Decoder().decode(FromHeaderField.self, from: header)

    return from.emailAddress
  }

  /// Parse RFC2046 formatted text to Message objects
  ///
  /// - Parameter text: RFC2046 compliant text
  /// - Returns: Message objects representing the content of RFC2046 formatted text
  /// - Throws: Throws if header or body is missing, the Content-Type header field cannot be decoded, parsing root multipart fails. If child mutlipart is part of parent multipart, parsing the child won't throw an error.
  /// - Note: Backward compatible with RFC822
  private func parse(fromText text: String) throws -> [RFC2046Message] {
    let headerAndBody = try getHeaderAndBody(text: text)
    
    let header = headerAndBody.header.trimmingCharacters(in: .whitespacesAndNewlines)
    let body = headerAndBody.body.trimmingCharacters(in: .whitespacesAndNewlines)

    let contentType = try RFC2046Decoder().decode(ContentTypeHeaderField.self, from: header)
    switch contentType.value {
    case let .multipartMixed(boundary):
      let mutlipartParts = try getPartsFromMultipart(withBoundary: boundary, inBody: body)
      return mutlipartParts.flatMap { (try? parse(fromText: $0)) ?? [] }
    case let .multipartAlternative(boundary):
      let mutlipartParts = try getPartsFromMultipart(withBoundary: boundary, inBody: body)
      return mutlipartParts.flatMap { (try? parse(fromText: $0)) ?? [] }
    case .applicationXML, .textPlain, .applicationPDF, .imageJPEG, .imageBMP, .textHTML, .imagePNG, .videoMP4:
      var data: Data
      if let encoding = try? RFC2046Decoder().decode(ContentTransferEncodingHeaderField.self, from: header), encoding.value == .base64 {
        guard let encodedData = Data(base64Encoded: body.replacingOccurrences(of: "\r\n", with: "")) else { return [] }
        data = Data(String(decoding: encodedData, as: UTF8.self).utf8)
      } else {
        data = Data(body.utf8)
      }

      return [RFC2046Message(contentType: contentType.messageContentType, content: data, name: contentType.contentName)]
    }
  }


  /// Get header and body from text
  ///
  /// - Parameter text: Text to split to header and body
  /// - Returns: Header and body
  private func getHeaderAndBody(text: String) throws -> (header: String, body: String) {
    let trimmedText = text.trimmingCharacters(in: .whitespacesAndNewlines)
    var header = ""
    var body = trimmedText
    var failed = false

    trimmedText.enumerateLines { (line, stop) in
      if line.isEmpty {
        // As per RFC2046 the separation between header and body is an empty line.
        stop = true
      } else {
        guard let headerLineRange = body.range(of: line) else {
          stop = true
          failed = true
          return
        }
        body.removeSubrange(headerLineRange)
        header += (header.isEmpty ? "" : "\r\n") + line
      }
    }

    if failed {
      throw RFC2046ParserError.cannotDevideBodyAndHeader
    }

    body = body.trimmingCharacters(in: .whitespacesAndNewlines)

    return (header: header, body: body)
  }


  /// Splits multipart body into parts using boundary attribute
  ///
  /// - Parameters:
  ///   - boundary: Multipart boundary as per RFC822
  ///   - body: Body containing multipart text
  /// - Returns: Multipart parts
  /// - Throws: Throws an error if there is not even one part of the body
  private func getPartsFromMultipart(withBoundary boundary: String, inBody body: String) throws -> [String] {
    var mutlipartParts = body.components(separatedBy: "--\(boundary)")
    // There should be at least two boundaries which results into three components (before boundary, between boundaries, after boundary)
    guard mutlipartParts.count > 3 else { throw RFC2046ParserError.noPartsInMultipartBody }
    mutlipartParts.removeFirst()
    mutlipartParts.removeLast()

    return mutlipartParts
  }
}

private extension ContentTypeHeaderField {
  var messageContentType: RFC2046Message.ContentType {
    switch value {
    case .textPlain:
      return .textPlain
    case .applicationXML:
      return .applicationXML
    case .applicationPDF:
      return .applicationPDF
    case .imageJPEG:
      return .imageJPEG
    case .imageBMP:
      return .imageBMP
    case .textHTML :
      return .textHTML
    case .imagePNG:
      return .imagePNG
    case .videoMP4:
      return .videoMP4
    case .multipartMixed, .multipartAlternative:
      return .unknown
    }
  }
}

enum RFC2046ParserError: Error {
  case noSuchField, noFieldValue, headerMalformed, noPartsInMultipartBody, cannotDevideBodyAndHeader
}
