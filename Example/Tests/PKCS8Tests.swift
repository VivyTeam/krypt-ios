//
//  PKCS8Tests.swift
//  Krypt_Tests
//
//  Created by Max on 24.06.19.
//  Copyright © 2019 CocoaPods. All rights reserved.
//

import Krypt
import XCTest

final class PKCS8Tests: XCTestCase {
   
    func testConvertPKCS1DER_toPKCS8__shouldConvertCorrectly() {
        // given
        let expectedPEM = TestData.openSSLPublicKeyPEM.string
        let pkcs1DER = TestData.openSSLPublicKeyPKCS1DER.data
        
        // when
        let convertedPKCS8PEM = PKCS8.convertPKCS1DERToPKCS8PEM(pkcs1DER)
        
        // then
        XCTAssertEqual(expectedPEM, convertedPKCS8PEM)
    }
}
