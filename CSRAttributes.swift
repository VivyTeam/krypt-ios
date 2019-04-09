//
//  CSRAttributes.swift
//  CryptoSwift
//
//  Created by Miso Lubarda on 08.04.19.
//

import Foundation

/// Object with attributes specified in X.509 standard
public struct CSRAttributes {
  public let country: String?
  public let state: String?
  public let location: String?
  public let organization: String?
  public let organizationUnit: String?
  public let emailAddress: String?
  public let uniqueIdentifier: String?
  public let givenName: String?
  public let surname: String?
    
  public init(
    country: String?,
    state: String?,
    location: String?,
    organization: String?,
    organizationUnit: String?,
    emailAddress: String?,
    uniqueIdentifier: String?,
    givenName: String?,
    surname: String?)
  {
    self.country = country
    self.state = state
    self.location = location
    self.organization = organization
    self.organizationUnit = organizationUnit
    self.emailAddress = emailAddress
    self.uniqueIdentifier = uniqueIdentifier
    self.givenName = givenName
    self.surname = surname
  }
}
