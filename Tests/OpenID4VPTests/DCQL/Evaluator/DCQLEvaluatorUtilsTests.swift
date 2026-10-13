import XCTest
@testable import OpenID4VP

fileprivate func mockJsonLdExpander(data: [String : Any]) async throws -> [String : Any] {
    return [
        "@type": data["type"] ?? []
    ]
}

final class DCQLUtilsTests: XCTestCase {

    private let mockExpander = mockJsonLdExpander
    
    private let claims: [String: Any] = [
        "name": "Arthur Dent",
        "address": [
            "street_address": "42 Market Street",
            "locality": "Milliways",
            "postal_code": "12345"
        ] as [String: Any],
        "degrees": [
            ["type": "Bachelor of Science", "university": "University of Betelgeuse"],
            ["type": "Master of Science",   "university": "University of Betelgeuse"]
        ] as [[String: Any]],
        "nationalities": ["British", "Betelgeusian"]
    ]

    private func path(_ elements: Any?...) -> [AnyCodable] {
        elements.map { AnyCodable($0) }
    }

    // MARK: - expandCredentialTag: ldp_vc

    func testExpandCredentialTag_LdpVc_WithHolderBinding() async throws {
        var credential = ldpVC()
        if var subject = credential["credentialSubject"] as? [String: Any] {
            subject["id"] = "did:example:holder"
            credential["credentialSubject"] = subject
        }
        let input = Credential(format: .ldp_vc, data: AnyCodable(credential), credentialId: "c1")

        let result = try await expandCredentialTag(input, jsonLdExpander: mockExpander)

        let w3c = try XCTUnwrap(result as? W3cTaggedCredential)
        XCTAssertEqual(w3c.credentialFormat, .ldp_vc)
        XCTAssertTrue(w3c.hasCryptographicHolderBinding)
        XCTAssertTrue(w3c.types.contains("IDCardCredential"))
    }

    func testExpandCredentialTag_LdpVc_WithoutHolderBinding() async throws {
        let credential = ldpVC(addHolderBinding: false)
        let input = Credential(format: .ldp_vc, data: AnyCodable(credential), credentialId: "c1")

        let result = try await expandCredentialTag(input, jsonLdExpander: mockExpander)

        let w3c = try XCTUnwrap(result as? W3cTaggedCredential)
        XCTAssertFalse(w3c.hasCryptographicHolderBinding)
    }

    func testExpandCredentialTag_LdpVc_ThrowsWhenDataIsNotDictionary() async throws {
        let input = Credential(format: .ldp_vc, data: AnyCodable("invalid"), credentialId: "c1")

        await XCTAssertAsyncThrowsError(try await expandCredentialTag(input, jsonLdExpander: mockExpander)) { error in
            assertOpenID4VPException(error, expectedMessage: "Credential data is not in the expected format", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    // MARK: - expandCredentialTag: mso_mdoc

    func testExpandCredentialTag_MsoMdoc_ReturnsDoctype() async throws {
        let input = Credential(format: .mso_mdoc, data: AnyCodable(sampleMdoc), credentialId: "c1")

        let result = try await expandCredentialTag(input, jsonLdExpander: mockExpander)

        let mdoc = try XCTUnwrap(result as? MdocTaggedCredential)
        XCTAssertEqual(mdoc.doctype, "org.iso.18013.5.1.mDL")
        XCTAssertTrue(mdoc.hasCryptographicHolderBinding)
    }

    func testExpandCredentialTag_MsoMdoc_ThrowsWhenDataIsNotString() async throws {
        let input = Credential(format: .mso_mdoc, data: AnyCodable(["invalid": "data"]), credentialId: "c1")

        await XCTAssertAsyncThrowsError(try await expandCredentialTag(input, jsonLdExpander: mockExpander)) { error in
            assertOpenID4VPException(error, expectedMessage: "MDOC credential is not a String", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testExpandCredentialTag_MsoMdoc_ThrowsWhenBase64IsInvalid() async throws {
        let input = Credential(format: .mso_mdoc, data: AnyCodable("not-valid-cbor!!!"), credentialId: "c1")

        await XCTAssertAsyncThrowsError(try await expandCredentialTag(input, jsonLdExpander: mockExpander)) { error in
            assertOpenID4VPException(error, expectedMessage: "Invalid Verifiable Credential: Error while decoding credential", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    // MARK: - expandCredentialTag: dc_sd_jwt / vc_sd_jwt

    func testExpandCredentialTag_DcSdJwt_WithHolderBinding() async throws {
        let input = Credential(format: .dc_sd_jwt, data: AnyCodable(sampeVcSdJwtWithHolderBinding), credentialId: "c1")

        let result = try await expandCredentialTag(input, jsonLdExpander: mockExpander)

        let sdJwt = try XCTUnwrap(result as? SdJwtTaggedCredential)
        XCTAssertEqual(sdJwt.credentialFormat, .dc_sd_jwt)
        XCTAssertEqual(sdJwt.vct, "https://example.eudi.ec.europa.eu/cor/1")
        XCTAssertTrue(sdJwt.hasCryptographicHolderBinding)
    }

    func testExpandCredentialTag_VcSdJwt_WithNoHolderBinding() async throws {
        let input = Credential(format: .vc_sd_jwt, data: AnyCodable(sampleVcSdJwtWithNoHolderBinding), credentialId: "c1")

        let result = try await expandCredentialTag(input, jsonLdExpander: mockExpander)

        let sdJwt = try XCTUnwrap(result as? SdJwtTaggedCredential)
        XCTAssertEqual(sdJwt.credentialFormat, .vc_sd_jwt)
        XCTAssertFalse(sdJwt.hasCryptographicHolderBinding)
    }

    func testExpandCredentialTag_SdJwt_ThrowsWhenDataIsNotString() async throws {
        let input = Credential(format: .dc_sd_jwt, data: AnyCodable(42), credentialId: "c1")

        await XCTAssertAsyncThrowsError(try await expandCredentialTag(input, jsonLdExpander: mockExpander)) { error in
            assertOpenID4VPException(error, expectedMessage: "SD-JWT credential is not a String", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testExpandCredentialTag_SdJwt_ThrowsWhenStringIsEmpty() async throws {
        let input = Credential(format: .dc_sd_jwt, data: AnyCodable(""), credentialId: "c1")

        await XCTAssertAsyncThrowsError(try await expandCredentialTag(input, jsonLdExpander: mockExpander)) { error in
            assertOpenID4VPException(error, expectedMessage: "SD-JWT credential is malformed or empty", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    // MARK: - convertToProcessedCredentials: ldp_vc

    func testConvertToProcessedCredentials_LdpVc_ReturnsW3cProcessedCredential() throws {
        let credential = ldpVC()
        let input = Credential(format: .ldp_vc, data: AnyCodable(credential), credentialId: "c1")
        let credentialIdToCredential = ["c1": input]

        let result = try convertToProcessedCredentials(["c1"], credentialIdToCredential)

        let w3c = try XCTUnwrap(result["c1"] as? W3cProcessedCredential)
        XCTAssertEqual(w3c.credentialId, "c1")
        XCTAssertEqual(w3c.credentialFormat, .ldp_vc)
        XCTAssertNotNil(w3c.claims["credentialSubject"])
    }

    func testConvertToProcessedCredentials_LdpVc_ThrowsWhenDataIsNotDictionary() throws {
        let input = Credential(format: .ldp_vc, data: AnyCodable("invalid"), credentialId: "c1")
        let credentialIdToCredential = ["c1": input]

        XCTAssertThrowsError(try convertToProcessedCredentials(["c1"], credentialIdToCredential)) { error in
            assertOpenID4VPException(error, expectedMessage: "Credential data is not in the expected format", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    // MARK: - convertToProcessedCredentials: mso_mdoc

    func testConvertToProcessedCredentials_MsoMdoc_ReturnsMdocProcessedCredential() throws {
        let input = Credential(format: .mso_mdoc, data: AnyCodable(sampleMdoc), credentialId: "c1")
        let credentialIdToCredential = ["c1": input]

        let result = try convertToProcessedCredentials(["c1"], credentialIdToCredential)

        let mdoc = try XCTUnwrap(result["c1"] as? MdocProcessedCredential)
        XCTAssertEqual(mdoc.credentialId, "c1")
        XCTAssertNotNil(mdoc.namespaces["org.iso.18013.5.1"])
        let ns = try XCTUnwrap(mdoc.namespaces["org.iso.18013.5.1"])
        XCTAssertNotNil(ns["given_name"])
        XCTAssertNotNil(ns["family_name"])
    }

    func testConvertToProcessedCredentials_MsoMdoc_ThrowsWhenDataIsNotString() throws {
        let input = Credential(format: .mso_mdoc, data: AnyCodable(["invalid": "data"]), credentialId: "c1")
        let credentialIdToCredential = ["c1": input]

        XCTAssertThrowsError(try convertToProcessedCredentials(["c1"], credentialIdToCredential)) { error in
            assertOpenID4VPException(error, expectedMessage: "MDOC credential is not a String", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testConvertToProcessedCredentials_MsoMdoc_ThrowsWhenBase64IsInvalid() throws {
        let input = Credential(format: .mso_mdoc, data: AnyCodable("not-valid-cbor!!!"), credentialId: "c1")
        let credentialIdToCredential = ["c1": input]

        XCTAssertThrowsError(try convertToProcessedCredentials(["c1"], credentialIdToCredential)) { error in
            assertOpenID4VPException(error, expectedMessage: "Invalid Verifiable Credential: Error while decoding credential", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    // MARK: - convertToProcessedCredentials: dc_sd_jwt / vc_sd_jwt

    func testConvertToProcessedCredentials_DcSdJwt_ReturnsSdJwtProcessedCredential() throws {
        let input = Credential(format: .dc_sd_jwt, data: AnyCodable(sampeVcSdJwtWithHolderBinding), credentialId: "c1")
        let credentialIdToCredential = ["c1": input]

        let result = try convertToProcessedCredentials(["c1"], credentialIdToCredential)

        let sdJwt = try XCTUnwrap(result["c1"] as? SdJwtProcessedCredential)
        XCTAssertEqual(sdJwt.credentialId, "c1")
        XCTAssertEqual(sdJwt.credentialFormat, .dc_sd_jwt)
        XCTAssertNotNil(sdJwt.claims["vct"])
    }

    func testConvertToProcessedCredentials_VcSdJwt_ReturnsSdJwtProcessedCredential() throws {
        let input = Credential(format: .vc_sd_jwt, data: AnyCodable(sampleVcSdJwtWithNoHolderBinding), credentialId: "c1")
        let credentialIdToCredential = ["c1": input]

        let result = try convertToProcessedCredentials(["c1"], credentialIdToCredential)

        let sdJwt = try XCTUnwrap(result["c1"] as? SdJwtProcessedCredential)
        XCTAssertEqual(sdJwt.credentialFormat, .vc_sd_jwt)
    }

    func testConvertToProcessedCredentials_SdJwt_ThrowsWhenDataIsNotString() throws {
        let input = Credential(format: .dc_sd_jwt, data: AnyCodable(42), credentialId: "c1")
        let credentialIdToCredential = ["c1": input]

        XCTAssertThrowsError(try convertToProcessedCredentials(["c1"], credentialIdToCredential)) { error in
            assertOpenID4VPException(error, expectedMessage: "SD-JWT credential is not a String", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testConvertToProcessedCredentials_SdJwt_ThrowsWhenStringIsEmpty() throws {
        let input = Credential(format: .dc_sd_jwt, data: AnyCodable(""), credentialId: "c1")
        let credentialIdToCredential = ["c1": input]

        XCTAssertThrowsError(try convertToProcessedCredentials(["c1"], credentialIdToCredential)) { error in
            assertOpenID4VPException(error, expectedMessage: "SD-JWT credential is malformed or empty", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    // MARK: - convertToProcessedCredentials: unknown credentialId

    func testConvertToProcessedCredentials_SkipsUnknownCredentialId() throws {
        let result = try convertToProcessedCredentials(["unknown-id"], [:])
        XCTAssertTrue(result.isEmpty)
    }

    // MARK: - convertToProcessedCredentials: multiple credentials

    func testConvertToProcessedCredentials_MultipleCredentials() throws {
        let ldpInput = Credential(format: .ldp_vc, data: AnyCodable(ldpVC()), credentialId: "ldp1")
        let mdocInput = Credential(format: .mso_mdoc, data: AnyCodable(sampleMdoc), credentialId: "md1")
        let sdJwtInput = Credential(format: .dc_sd_jwt, data: AnyCodable(sampeVcSdJwtWithHolderBinding), credentialId: "sd1")
        let credentialIdToCredential = ["ldp1": ldpInput, "md1": mdocInput, "sd1": sdJwtInput]

        let result = try convertToProcessedCredentials(["ldp1", "md1", "sd1"], credentialIdToCredential)

        XCTAssertEqual(result.count, 3)
        XCTAssertTrue(result["ldp1"] is W3cProcessedCredential)
        XCTAssertTrue(result["md1"] is MdocProcessedCredential)
        XCTAssertTrue(result["sd1"] is SdJwtProcessedCredential)
    }
    
    // MARK: - Resolve claims path pointer Tests

    // String navigation

    func testResolvesTopLevelStringKey() throws {
        let result = try resolveClaimsPathPointer(path("name"), in: claims)
        XCTAssertEqual(result as? String, "Arthur Dent")
    }

    func testResolvesNestedStringKey() throws {
        let result = try resolveClaimsPathPointer(path("address", "street_address"), in: claims)
        XCTAssertEqual(result as? String, "42 Market Street")
    }

    func testResolvesObjectValueWithSubClaims() throws {
        let result = try resolveClaimsPathPointer(path("address"), in: claims)
        
        assertDictionariesEqual(expected: [
            "street_address": "42 Market Street",
            "locality": "Milliways",
            "postal_code": "12345"
        ], actual: result as? [String: Any])
    }

    func testReturnsEmptyForMissingKey() throws {
        let result = try resolveClaimsPathPointer(path("nonexistent"), in: claims)
        
        XCTAssertNil(result)
    }
    
    func testReturnsEmptyWhenStringNavigationHitsNonObject() {
        // "name" is a String, not an object — navigating further into it must return []
        
        XCTAssertThrowsError(try resolveClaimsPathPointer(path("name", "first"), in: claims)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "currently selected element(s) is not an object",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    //  Integer index navigation

    func testResolvesArrayElementByIndex() throws {
        // ["nationalities", 1] → "Betelgeusian"
        let result = try resolveClaimsPathPointer(path("nationalities", 1), in: claims)
        
        XCTAssertEqual(result as? String, "Betelgeusian")
    }

    func testResolvesFirstArrayElementByIndex() throws {
        // ["nationalities", 0] → "British"
        let result = try resolveClaimsPathPointer(path("nationalities", 0), in: claims)
        
        XCTAssertEqual(result as? String, "British")
    }

    func testReturnsEmptyForOutOfBoundsIndex() throws {
        let result = try resolveClaimsPathPointer(path("nationalities", 99), in: claims)
        
        XCTAssertNil(result)
    }

    func testResolvesNestedFieldInsideIndexedArrayElement() throws {
        // ["degrees", 0, "type"] → "Bachelor of Science"
        let result = try resolveClaimsPathPointer(path("degrees", 0, "type"), in: claims)
        
        XCTAssertEqual(result as? String, "Bachelor of Science")
    }

    // Null wildcard navigation

    func testNullWildcardSelectsAllArrayElements() throws {
        // ["nationalities", null] → ["British", "Betelgeusian"]
        let result = try resolveClaimsPathPointer(path("nationalities", Optional<Any>.none), in: claims)
        
        XCTAssertEqual(result as? [String], ["British", "Betelgeusian"])
    }

    func testNullWildcardThenStringSelectsFieldFromAllElements() throws {
        // ["degrees", null, "type"] → ["Bachelor of Science", "Master of Science"]
        let result = try resolveClaimsPathPointer(path("degrees", Optional<Any>.none, "type"), in: claims)
        
        XCTAssertEqual(result as? [String], ["Bachelor of Science", "Master of Science"])
    }

    func testNullWildcardThenStringSelectsNestedFieldFromAllElements() throws {
        // ["degrees", null, "university"]
        let result = try resolveClaimsPathPointer(path("degrees", Optional<Any>.none, "university"), in: claims)
        
        XCTAssertEqual(result as? [String], ["University of Betelgeuse", "University of Betelgeuse"])
    }

    // Error paths

    func testReturnsEmptyForEmptyPath() throws {
        let result = try resolveClaimsPathPointer([], in: claims)
        
        assertDictionariesEqual(expected: claims, actual: result as? [String: Any])
    }

    func testReturnsEmptyWhenIntegerIndexHitsNonArray() {
        // "name" is a String, not an array — integer indexing must return []
        XCTAssertThrowsError(try resolveClaimsPathPointer(path("name", 0), in: claims)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "currently selected element(s) is not an array",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testReturnsEmptyWhenNullWildcardHitsNonArray() {
        XCTAssertThrowsError(try resolveClaimsPathPointer(path("address", Optional<Any>.none), in: claims)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "currently selected element(s) is not an array",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    // If the component is anything else, abort processing and return an error.
    func testThrowsErrorWhenPathElementIsNotExpectedType() {
        XCTAssertThrowsError(try resolveClaimsPathPointer(path(1.7), in: claims)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Unexpected path pointer component",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    func testNestedWildcardsFanOutAcrossArrays() throws {
        let nested: [String: Any] = ["degrees": [
            ["subjects": [["name": "Math"], ["name": "Physics"]]],
            ["subjects": [["name": "Chemistry"]]]
        ]]
        let result = try resolveClaimsPathPointer(path("degrees", nil, "subjects", nil, "name"), in: nested)
        XCTAssertEqual(result as? [String], ["Math", "Physics", "Chemistry"])
    }

    func testIndexAfterWildcardSelectsFromEachArray() throws {
        let nested: [String: Any] = ["groups": [["Math", "Physics"], [], ["Chemistry"]]]
        let result = try resolveClaimsPathPointer(path("groups", NSNull(), 0), in: nested)
        XCTAssertEqual(result as? [String], ["Math", "Chemistry"])
    }

    func testMissingWildcardFieldsReturnNil() throws {
        let result = try resolveClaimsPathPointer(path("degrees", nil, "missing", "name"), in: claims)
        XCTAssertNil(result)
    }

    func testEmptyWildcardSelectionReturnsNil() throws {
        let result = try resolveClaimsPathPointer(path("items", nil), in: ["items": [] as [Any]])
        XCTAssertNil(result)
    }

}
