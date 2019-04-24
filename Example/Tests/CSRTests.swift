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
    
    let result = createCSR(from: attributes)

    XCTAssertEqual(result, expectedCSR)
  } 
  
  func testCreateCSR_withWrongLocation__shouldNotMatchExpectedCSR() {
    let attributes = CSRAttributes.withWrongLocation

    let result = createCSR(from: attributes)

    XCTAssertNotEqual(result, expectedCSR)
  }

  func testCreateCSR_whenLocationAttributeEmpty__shouldNotMatchExpectedCSR() {
    let attributes = CSRAttributes.withEmptyLocation

    let result = createCSR(from: attributes)

    XCTAssertNotEqual(result, expectedCSR)
  }

  func testCreateCSR_whenAllAttributesEmpty__shouldNotMatchExpectedCSR() {
    let attributes = CSRAttributes.withEmptyAttributes
    
    let result = createCSR(from: attributes)

    XCTAssertNotEqual(result, expectedCSR)
  }

  func testCreateCSR_whenAllAttributesNil__shouldNotMatchExpectedCSR() {
    let attributes = CSRAttributes.withNilAttributes
    
    let result = createCSR(from: attributes)

    XCTAssertNotEqual(result, expectedCSR)
  }
  
  private func createCSR(from attributes: CSRAttributes) -> String {
    let privateKey = try! Key(pem: TestData.openSSLPrivateKeyPEM.data, access: .private)
    let result = try! CSR.create(with: privateKey, attributes: attributes)
    return result.trimmingCharacters(in: .whitespacesAndNewlines)
  }

  private var expectedCSR: String {
    return TestData.opensslCSR.stringTrimmingWhitespacesAndNewlines
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
