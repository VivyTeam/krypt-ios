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
  func testCreateCSR_testSubjectFields__shouldMatchOpenSSLRequest() throws {
    // given
    let testPEM = TestData.opensslCSR.string
    let privateKey = try Key(pem: TestData.openSSLPrivateKeyPEM.data, access: .private)
    let country = "DE"
    let state = "Berlin"
    let location = "Berlin"
    let organization = "Vivy GmbH"
    let organizationUnit = "IT"
    let email = "tech@vivy.com"
    let uid = "someUID"
    let gn = "someGN"
    let sn = "someSN"
    
    // when
    let result = try CSR.create(
      with: privateKey,
      country: country,
      state: state,
      location: location,
      organization: organization,
      organizationUnit: organizationUnit,
      emailAddress: email,
      uid: uid,
      gn: gn,
      sn: sn
    )
    let resultString = String(data: result, encoding: .utf8)!

    // then
    XCTAssertEqual(resultString, testPEM)
  }
}
