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
    // given
    let attributes = CSRAttributes.withCorrectAttributes

    // when
    let result = createCSR(from: attributes)

    // then
    XCTAssertEqual(result, expectedCSR)
  }

  func testCreateCSR_withUmlauts__shouldMatchExpectedCSR() {
    // given
    let attributes = CSRAttributes.withCorrectAttributesAndUmlauts

    // when
    let result = createCSR(from: attributes)

    // then
    XCTAssertEqual(result, expectedCSRWithUmlauts)
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

  /// Generated with
  /// `openssl req -new -utf8 -key ./Example/Tests/Files/OpenSSL/openssl-private-key-pkcs1-pem -out ./Example/Tests/Files/CSR/openssl-csr-with-umlauts -subj "/C=DE/ST=Baden-Württemberg/L=Nürnberg/O=Vüvy/OU=ÄIT/emailAddress=test@vivy.com/UID=someÜID/GN=Gǖvenname/SN=Söörnamê"`
  private var expectedCSRWithUmlauts: String {
    return TestData.opensslCSRWithUmlauts.stringTrimmingWhitespacesAndNewlines
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
      surname: "someSN"
    )
  }

  static var withCorrectAttributesAndUmlauts: CSRAttributes {
    return CSRAttributes(
      country: "DE",
      state: "Baden-Württemberg",
      location: "Nürnberg",
      organization: "Vüvy",
      organizationUnit: "ÄIT",
      emailAddress: "test@vivy.com",
      uniqueIdentifier: "someÜID",
      givenName: "Gǖvenname",
      surname: "Söörnamê"
    )
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
      surname: "someSN"
    )
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
      surname: "someSN"
    )
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
      surname: ""
    )
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
      surname: nil
    )
  }
}
