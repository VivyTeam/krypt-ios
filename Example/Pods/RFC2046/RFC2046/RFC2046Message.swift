//
//  Message.swift
//  RFC2046
//
//  Created by Miso Lubarda on 06.05.19.
//

import Foundation

public struct RFC2046Message {
  public enum ContentType {
    case applicationPDF, imageJPEG, imageBMP, imagePNG, videoMP4, textHTML, unknown
  }
  
  public let contentType: ContentType
  public let content: Data
  public let name: String?
  
  public init(contentType: ContentType, content: Data, name: String? = nil) {
    self.contentType = contentType
    self.content = content
    self.name = name
  }
}
