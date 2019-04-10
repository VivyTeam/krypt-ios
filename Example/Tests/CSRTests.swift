//
//  CSRTests.swift
//  Krypt_Tests
//
//  Created by marko on 07.03.19.
//  Copyright © 2019 CocoaPods. All rights reserved.
//

import Krypt
import XCTest

final class CSRTests: XCTestCase {
  func testCreateCSR_withCorrectAttributes__shouldMatchExpectedCSR() {
    let attributes = CSRAttributes.withCorrectAttributes
    
    let result = try! CSR.create(with: privateKey, attributes: attributes)

    XCTAssertEqual(result, expectedCSR)
  } 
  
  func testCreateCSR_withWrongLocation__shouldNotMatchExpectedCSR() {
    let attributes = CSRAttributes.withWrongLocation

    let result = try! CSR.create(with: privateKey, attributes: attributes)

    XCTAssertNotEqual(result, expectedCSR)
  }

  func testCreateCSR_whenLocationAttributeEmpty__shouldNotMatchExpectedCSR() {
    let attributes = CSRAttributes.withEmptyLocation

    let result = try! CSR.create(with: privateKey, attributes: attributes)

    XCTAssertNotEqual(result, expectedCSR)
  }

  func testCreateCSR_whenAllAttributesEmpty__shouldNotMatchExpectedCSR() {
    let attributes = CSRAttributes.withEmptyAttributes
    
    let result = try! CSR.create(with: privateKey, attributes: attributes)
    
    XCTAssertNotEqual(result, expectedCSR)
  }

  func testCreateCSR_whenAllAttributesNil__shouldNotMatchExpectedCSR() {
    let attributes = CSRAttributes.withNilAttributes
    
    let result = try! CSR.create(with: privateKey, attributes: attributes)
    
    XCTAssertNotEqual(result, expectedCSR)
  }

  private var privateKey: Key {
    return try! Key(pem: TestData.openSSLPrivateKeyPEM.data, access: .private)
  }

  private var expectedCSR: String {
    return TestData.opensslCSR.string
  }
}

private extension CSRAttributes {
  static var withCorrectAttributes: CSRAttributes {
    return CSRAttributes(
      country: "DE",
      state: "Berlin",
      location: "Berlin",
      organization: "Vivy GmbH",
      organizationUnit: "IT",
      emailAddress: "tech@vivy.com",
      uniqueIdentifier: "someUID",
      givenName: "someGN",
      surname: "someSN")
  }
  
  static var withWrongLocation: CSRAttributes {
    return CSRAttributes(
      country: "DE",
      state: "Berlin",
      location: "Hamburg",
      organization: "Vivy GmbH",
      organizationUnit: "IT",
      emailAddress: "tech@vivy.com",
      uniqueIdentifier: "someUID",
      givenName: "someGN",
      surname: "someSN")
  }
  
  static var withEmptyLocation: CSRAttributes {
    return CSRAttributes(
      country: "DE",
      state: "Berlin",
      location: "",
      organization: "Vivy GmbH",
      organizationUnit: "IT",
      emailAddress: "tech@vivy.com",
      uniqueIdentifier: "someUID",
      givenName: "someGN",
      surname: "someSN")
  }
  
  static var withEmptyAttributes: CSRAttributes {
    return CSRAttributes(
      country: "",
      state: "",
      location: "",
      organization: "",
      organizationUnit: "",
      emailAddress: "",
      uniqueIdentifier: "",
      givenName: "",
      surname: "")
  }

  static var withNilAttributes: CSRAttributes {
    return CSRAttributes(
      country: nil,
      state: nil,
      location: nil,
      organization: nil,
      organizationUnit: nil,
      emailAddress: nil,
      uniqueIdentifier: nil,
      givenName: nil,
      surname: nil)
  }
}
