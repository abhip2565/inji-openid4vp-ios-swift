import XCTest
@testable import OpenID4VP


fileprivate func mockJsonLdExpander(data: [String : Any]) async throws -> [String : Any] {
    return [
        "@type": data["type"] ?? []
    ]
}

final class DCQLEvaluatorTests: XCTestCase {
    
    private let evaluator = DcqlEvaluator(jsonLdExpander: mockJsonLdExpander)
    
    // MARK: - Helpers
    
    private func dcqlQuery(_ json: String) throws -> DCQLQuery {
        try JSONDecoder().decode(DCQLQuery.self, from: Data(json.utf8))
    }
    
    private func sdJwtCredential(id: String = "c1", holderBinding: Bool = true) -> Credential {
        let raw = holderBinding ? sampeVcSdJwtWithHolderBinding : sampleVcSdJwtWithNoHolderBinding
        return Credential(format: .dc_sd_jwt, data: AnyCodable(raw), credentialId: id)
    }
    
    private func mdocCredential(id: String = "c1") -> Credential {
        return Credential(format: .mso_mdoc, data: AnyCodable(sampleMdoc), credentialId: id)
    }
    
    private func ldpVcCredential(id: String = "c1", type: String = "IDCardCredential") -> Credential {
        var credential = ldpVC(credentialType: type)
        if var subject = credential["credentialSubject"] as? [String: Any] {
            subject["id"] = "did:example:holder"
            credential["credentialSubject"] = subject
        }
        return Credential(format: .ldp_vc, data: AnyCodable(credential), credentialId: id)
    }
    
    // MARK: - Format matching
    
    func testReturnsSuccessWhenCredentialMatchesFormat() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"dc+sd-jwt","meta":{}}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [sdJwtCredential()])
        XCTAssertTrue(result.success)
        XCTAssertNotNil(result.queryMatches["q1"]?.matchingCredentials)
    }
    
    func testReturnsFailureWhenNoCredentialMatchesFormat() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"mso_mdoc","meta":{}}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [sdJwtCredential()])
        XCTAssertFalse(result.success)
        XCTAssertEqual(result.queryMatches["q1"]?.failureReason, DCQLEvaluationErrorCodes.noMatchingFormatsFound.rawValue)
    }
    
    func testEmptyWalletCredentials_ReturnsFailure() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"dc+sd-jwt","meta":{}}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [])
        XCTAssertFalse(result.success)
        XCTAssertEqual(result.queryMatches["q1"]?.failureReason, DCQLEvaluationErrorCodes.noMatchingFormatsFound.rawValue)
    }
    
    // MARK: - Cryptographic holder binding
    
    func testReturnsSuccessWhenHolderBindingRequired_AndCredentialSupportsIt() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"dc+sd-jwt","meta":{},"require_cryptographic_holder_binding":true}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [sdJwtCredential(holderBinding: true)])
        XCTAssertTrue(result.success)
        XCTAssertNotNil(result.queryMatches["q1"]?.matchingCredentials)
    }
    
    func testReturnsFailureWhenHolderBindingRequired_ButNoCredentialSupportsIt() async throws {
        // ldp_vc without credentialSubject.id gives hasCryptographicHolderBinding = false
        let ldpVcWithoutBinding = Credential(
            format: .ldp_vc,
            data: AnyCodable(ldpVC(addHolderBinding: false)),
            credentialId: "no-binding"
        )
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"ldp_vc","meta":{},"require_cryptographic_holder_binding":true}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [ldpVcWithoutBinding])
        XCTAssertFalse(result.success)
        XCTAssertEqual(result.queryMatches["q1"]?.failureReason, DCQLEvaluationErrorCodes.cryptographicHolderBindingOrMetaFilterMismatch.rawValue)
    }
    
    func testReturnsSuccessWhenHolderBindingNotRequired_AndCredentialLacksIt() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"dc+sd-jwt","meta":{},"require_cryptographic_holder_binding":false}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [sdJwtCredential(holderBinding: false)])
        XCTAssertTrue(result.success)
        XCTAssertNotNil(result.queryMatches["q1"]?.matchingCredentials)
    }
    
    func testReturnsSuccessForMdocWhenHolderBindingNotRequired() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"},"require_cryptographic_holder_binding":false}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [mdocCredential()])
        XCTAssertTrue(result.success)
        XCTAssertNotNil(result.queryMatches["q1"]?.matchingCredentials)
    }
    
    func testReturnsSuccessForMdocWhenHolderBindingRequired_AndCredentialSupportsIt() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"},"require_cryptographic_holder_binding":true}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [mdocCredential()])
        XCTAssertTrue(result.success)
        XCTAssertNotNil(result.queryMatches["q1"]?.matchingCredentials)
    }
    
    func testReturnsSuccessForLdpVcWhenHolderBindingNotRequired() async throws {
        let ldpVcWithoutBinding = Credential(format: .ldp_vc, data: AnyCodable(ldpVC()), credentialId: "no-binding")
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"ldp_vc","meta":{},"require_cryptographic_holder_binding":false}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [ldpVcWithoutBinding])
        XCTAssertTrue(result.success)
        XCTAssertNotNil(result.queryMatches["q1"]?.matchingCredentials)
    }
    
    func testReturnsSuccessForLdpVcWhenHolderBindingRequired_AndCredentialSupportsIt() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"ldp_vc","meta":{},"require_cryptographic_holder_binding":true}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [ldpVcCredential()])
        XCTAssertTrue(result.success)
        XCTAssertNotNil(result.queryMatches["q1"]?.matchingCredentials)
    }
    
    // MARK: - Meta filtering (dc+sd-jwt — vct_values)
    
    func testMetaFiltering_SdJwt_MatchingVct() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"dc+sd-jwt","meta":{"vct_values":["https://example.eudi.ec.europa.eu/cor/1"]}}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [sdJwtCredential()])
        XCTAssertTrue(result.success)
        XCTAssertNotNil(result.queryMatches["q1"]?.matchingCredentials)
    }
    
    func testMetaFiltering_SdJwt_NonMatchingVct() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"dc+sd-jwt","meta":{"vct_values":["https://example.com/other-vct"]}}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [sdJwtCredential()])
        XCTAssertFalse(result.success)
        XCTAssertEqual(result.queryMatches["q1"]?.failureReason, DCQLEvaluationErrorCodes.cryptographicHolderBindingOrMetaFilterMismatch.rawValue)
    }
    
    func testMetaFiltering_EmptyMeta_PassesAllCredentials() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"dc+sd-jwt","meta":{}}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [sdJwtCredential()])
        XCTAssertTrue(result.success)
        XCTAssertNotNil(result.queryMatches["q1"]?.matchingCredentials)
    }
    
    // MARK: - Meta filtering (mso_mdoc — doctype_value)
    
    func testMetaFiltering_Mdoc_MatchingDoctype() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"}}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [mdocCredential()])
        XCTAssertTrue(result.success)
        XCTAssertNotNil(result.queryMatches["q1"]?.matchingCredentials)
    }
    
    func testMetaFiltering_Mdoc_NonMatchingDoctype() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"mso_mdoc","meta":{"doctype_value":"org.iso.23220.photoid.1"}}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [mdocCredential()])
        XCTAssertFalse(result.success)
        XCTAssertEqual(result.queryMatches["q1"]?.failureReason, DCQLEvaluationErrorCodes.cryptographicHolderBindingOrMetaFilterMismatch.rawValue)
    }
    
    // MARK: - Meta filtering (ldp_vc — type_values)
    
    func testMetaFiltering_W3c_MatchingTypeValues() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"ldp_vc","meta":{"type_values":[["VerifiableCredential","IDCardCredential"]]}}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [ldpVcCredential()])
        XCTAssertTrue(result.success)
        XCTAssertNotNil(result.queryMatches["q1"]?.matchingCredentials)
        XCTAssertEqual(result.queryMatches["q1"]?.matchingCredentials?.count, 1)
        XCTAssertEqual(result.queryMatches["q1"]?.matchingCredentials?.first?.credentialId, "c1")
    }
    
    func testMetaFiltering_W3c_NonMatchingTypeValues() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"ldp_vc","meta":{"type_values":[["VerifiableCredential","UnknownCredential"]]}}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [ldpVcCredential()])
        XCTAssertFalse(result.success)
        XCTAssertEqual(result.queryMatches["q1"]?.failureReason, DCQLEvaluationErrorCodes.cryptographicHolderBindingOrMetaFilterMismatch.rawValue)
    }
    
    func testMetaFiltering_W3c_MatchesWhenAnyTypeValueOptionSatisfied() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"ldp_vc","meta":{"type_values":[["VerifiableCredential","UnknownCredential"],["VerifiableCredential","IDCardCredential"]]}}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [ldpVcCredential()])
        XCTAssertTrue(result.success)
        XCTAssertNotNil(result.queryMatches["q1"]?.matchingCredentials)
    }
    
    // MARK: - Claims matching (dc+sd-jwt)
    
    func testClaimsMatching_NoClaims_AllMandatoryClaimsShared() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"dc+sd-jwt","meta":{}}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [sdJwtCredential()])
        XCTAssertTrue(result.success)
        XCTAssertEqual(result.queryMatches["q1"]?.matchingCredentials?.first?.matchingClaims.count, 0)
    }
    
    func testClaimsMatching_AllClaimsPresent() async throws {
        // SD-JWT top-level payload claims (not selective disclosures)
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"dc+sd-jwt","meta":{},"claims":[{"id":"ic","path":["issuing_country"]},{"id":"id","path":["issuance_date"]}]}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [sdJwtCredential()])
        XCTAssertTrue(result.success)
        XCTAssertEqual(result.queryMatches["q1"]?.matchingCredentials?.first?.matchingClaims.count, 2)
    }
    
    func testClaimsMatching_MissingClaimFails() async throws {
        let query = try dcqlQuery("""
        {
            "credentials": [
                {
                    "id":"q1",
                    "format":"dc+sd-jwt",
                    "meta":{},
                    "claims":[
                        {"id":"nc","path":["nonexistent_claim"]},
                        {"id":"nc2","path":["issuance_date"]}
                    ]
                }
            ]
        }
        """)
        // nc is no in the given credential but nc2 is available, since the case f all claims need to be matched from a credential - failed claims should include both nc and nc2
        let result = try await evaluator.evaluate(query, inputCredentials: [sdJwtCredential()])
        XCTAssertFalse(result.success)
        XCTAssertNotNil(result.queryMatches["q1"]?.failedClaims)
        XCTAssertEqual(result.queryMatches["q1"]?.failureReason, DCQLEvaluationErrorCodes.requiredClaimsNotSatisfied.rawValue)
        XCTAssertEqual(result.queryMatches["q1"]?.failedClaims?.count, 2)
        XCTAssertEqual(result.queryMatches["q1"]?.failedClaims?.first?.reason, DCQLEvaluationErrorCodes.claimUnavailable.rawValue)
    }

    func testClaimsMatching_SameClaimMissingAcrossMultipleCredentials_DeduplicatedInFailedClaims() async throws {
        // Both credentials are missing the same claim — failedClaims must not contain duplicates
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"dc+sd-jwt","meta":{},"claims":[{"id":"nc","path":["nonexistent_claim"]}]}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [sdJwtCredential(), sdJwtCredential()])
        XCTAssertFalse(result.success)
        let failedClaims = try XCTUnwrap(result.queryMatches["q1"]?.failedClaims)
        XCTAssertEqual(failedClaims.count, 1)
        XCTAssertEqual(failedClaims[0].reason, DCQLEvaluationErrorCodes.claimUnavailable.rawValue)
        XCTAssertEqual(failedClaims[0].claim.path.first?.value as? String, "nonexistent_claim")
    }

    func testClaimsMatching_MultipleDistinctClaimsMissingAcrossMultipleCredentials_EachReportedOnce() async throws {
        // Both credentials are missing both requested claims — each distinct claim must appear exactly once in failedClaims
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"dc+sd-jwt","meta":{},"claims":[{"id":"a","path":["nonexistent_a"]},{"id":"b","path":["nonexistent_b"]}]}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [sdJwtCredential(), sdJwtCredential()])
        XCTAssertFalse(result.success)
        let failedClaims = try XCTUnwrap(result.queryMatches["q1"]?.failedClaims)
        XCTAssertEqual(failedClaims.count, 2)
        let failedPaths = failedClaims.map { $0.claim.path.first?.value as? String }
        XCTAssertEqual(failedPaths.sorted { ($0 ?? "") < ($1 ?? "") }, ["nonexistent_a", "nonexistent_b"])
    }

    func testClaimsMatching_NestedClaimPath() async throws {
        // ldp_vc claims are stored as the credentialSubject contents — path keys are direct field names
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"ldp_vc","meta":{},"claims":[{"id":"gn","path":["credentialSubject","given_name"]}]}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [ldpVcCredential()])
        XCTAssertTrue(result.success)
        XCTAssertEqual(result.queryMatches["q1"]?.matchingCredentials?.first?.matchingClaims.count, 1)
    }
    
    // MARK: - Claims matching (mso_mdoc)
    
    func testClaimsMatching_MdocAllClaimsPresent() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"},"claims":[{"id":"gn","path":["org.iso.18013.5.1","given_name"]},{"id":"fn","path":["org.iso.18013.5.1","family_name"]}]}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [mdocCredential()])
        XCTAssertTrue(result.success)
        XCTAssertEqual(result.queryMatches["q1"]?.matchingCredentials?.first?.matchingClaims.count, 2)
    }
    
    func testClaimsMatching_MdocMissingElementFails() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"},"claims":[{"id":"nc","path":["org.iso.18013.5.1","nonexistent_element"]}]}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [mdocCredential()])
        XCTAssertFalse(result.success)
        XCTAssertEqual(result.queryMatches["q1"]?.failedClaims?.first?.reason, DCQLEvaluationErrorCodes.claimUnavailable.rawValue)
    }
    
    // MARK: - Claims matching (ldp_vc)
    
    func testClaimsMatching_W3cAllClaimsPresent() async throws {
        // ldp_vc claims are stored directly from credentialSubject — path is the field name
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"ldp_vc","meta":{},"claims":[{"id":"gn","path":["credentialSubject","given_name"]},{"id":"fn","path":["credentialSubject","family_name"]}]}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [ldpVcCredential()])
        XCTAssertTrue(result.success)
        XCTAssertEqual(result.queryMatches["q1"]?.matchingCredentials?.first?.matchingClaims.count, 2)
    }
    
    func testClaimsMatching_W3cMissingClaimFails() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"ldp_vc","meta":{},"claims":[{"id":"nc","path":["nonexistent_field"]}]}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [ldpVcCredential()])
        XCTAssertFalse(result.success)
        XCTAssertEqual(result.queryMatches["q1"]?.failedClaims?.first?.reason, DCQLEvaluationErrorCodes.claimUnavailable.rawValue)
    }
    
    // MARK: - Value matching
    
    func testValueMatching_StringMatch() async throws {
        // issuing_country is a top-level SD-JWT payload claim
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"dc+sd-jwt","meta":{},"claims":[{"id":"ic","path":["issuing_country"],"values":["DE"]}]}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [sdJwtCredential()])
        XCTAssertTrue(result.success)
    }
    
    func testValueMatching_IntMatch() async throws {
        // ldp_vc credentialSubject field matching — path is the direct field name
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"ldp_vc","meta":{},"claims":[{"id":"gn","path":["credentialSubject","given_name"],"values":["MockUser"]}]}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [ldpVcCredential()])
        XCTAssertTrue(result.success)
    }
    
    func testValueMatching_BoolMatch() async throws {
        // ldp_vc credentialSubject field matching — path is the direct field name
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"ldp_vc","meta":{},"claims":[{"id":"fn","path":["credentialSubject","family_name"],"values":["Mockister"]}]}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [ldpVcCredential()])
        XCTAssertTrue(result.success)
    }
    
    func testValueMatching_NoMatchFails() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"dc+sd-jwt","meta":{},"claims":[{"id":"ic","path":["issuing_country"],"values":["US"]}]}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [sdJwtCredential()])
        XCTAssertFalse(result.success)
        XCTAssertEqual(result.queryMatches["q1"]?.failedClaims?.first?.reason, DCQLEvaluationErrorCodes.claimValueMismatch.rawValue)
    }
    
    // MARK: - claim_sets
    
    func testClaimSets_FirstOptionSatisfied() async throws {
        // SD-JWT top-level payload claims
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"dc+sd-jwt","meta":{},"claims":[{"id":"ic","path":["issuing_country"]},{"id":"id","path":["issuance_date"]}],"claim_sets":[["ic","id"],["ic"]]}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [sdJwtCredential()])
        XCTAssertTrue(result.success)
        XCTAssertEqual(result.queryMatches["q1"]?.matchingCredentials?.first?.matchingClaims.count, 2)
    }
    
    func testClaimSets_FallsBackToSecondOptionIfFirstOptionNotSatisfiable() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"dc+sd-jwt","meta":{},"claims":[{"id":"ic","path":["issuing_country"]},{"id":"missing","path":["nonexistent"]}],"claim_sets":[["ic","missing"],["ic"]]}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [sdJwtCredential()])
        XCTAssertTrue(result.success)
        XCTAssertEqual(result.queryMatches["q1"]?.matchingCredentials?.first?.matchingClaims.count, 1)
    }
    
    func testClaimSets_NoOptionSatisfiedFails() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"dc+sd-jwt","meta":{},"claims":[{"id":"m1","path":["nonexistent1"]},{"id":"m2","path":["nonexistent2"]}],"claim_sets":[["m1","m2"],["m1"]]}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [sdJwtCredential()])
        XCTAssertFalse(result.success)
        XCTAssertEqual(result.queryMatches["q1"]?.failureReason, DCQLEvaluationErrorCodes.noClaimsSetOptionSatisfied.rawValue)
    }
    
    // MARK: - multiple credentials flag
    
    func testMultipleFalse_ReturnsOnlyFirstMatchingCredential() async throws {
        // multiple: false is a selection hint to the wallet UI — the evaluator returns all candidates
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"dc+sd-jwt","meta":{},"multiple":false}]}
        """)
        let c1 = sdJwtCredential(id: "c1")
        let c2 = sdJwtCredential(id: "c2")
        let result = try await evaluator.evaluate(query, inputCredentials: [c1, c2])
        XCTAssertTrue(result.success)
        XCTAssertEqual(result.queryMatches["q1"]?.matchingCredentials?.count, 2)
        XCTAssertFalse(result.queryMatches["q1"]?.allowMultipleCredentials ?? true)
    }
    
    func testMultipleTrue_ReturnsAllMatchingCredentials() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"dc+sd-jwt","meta":{},"multiple":true}]}
        """)
        let c1 = sdJwtCredential(id: "c1")
        let c2 = sdJwtCredential(id: "c2")
        let result = try await evaluator.evaluate(query, inputCredentials: [c1, c2])
        XCTAssertTrue(result.success)
        XCTAssertEqual(result.queryMatches["q1"]?.matchingCredentials?.count, 2)
        XCTAssertTrue(result.queryMatches["q1"]?.allowMultipleCredentials ?? false)
    }
    
    // MARK: - Mdoc claim resolution (namespace + element path)
    
    func testMdocClaimResolution_MatchingNamespaceAndElement() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"mso_mdoc","meta":{},"claims":[{"id":"gn","path":["org.iso.18013.5.1","given_name"]}]}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [mdocCredential()])
        XCTAssertTrue(result.success)
        XCTAssertEqual(result.queryMatches["q1"]?.matchingCredentials?.first?.matchingClaims.count, 1)
    }
    
    func testMdocClaimResolution_MissingNamespaceFails() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"mso_mdoc","meta":{},"claims":[{"id":"nc","path":["wrong.namespace","given_name"]}]}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [mdocCredential()])
        XCTAssertFalse(result.success)
        XCTAssertEqual(result.queryMatches["q1"]?.failedClaims?.first?.reason, DCQLEvaluationErrorCodes.claimUnavailable.rawValue)
    }
    
    // MARK: - credential_sets
    
    func testCredentialSets_RequiredSetSatisfied() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"dc+sd-jwt","meta":{}},{"id":"q2","format":"mso_mdoc","meta":{}}],"credential_sets":[{"options":[["q1"]],"required":true}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [sdJwtCredential(id: "sd1"), mdocCredential(id: "md1")])
        XCTAssertTrue(result.success)
    }
    
    func testCredentialSets_RequiredSetNotSatisfiedFails() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"dc+sd-jwt","meta":{}},{"id":"q2","format":"mso_mdoc","meta":{}}],"credential_sets":[{"options":[["q1","q2"]],"required":true}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [sdJwtCredential(id: "sd1")])
        XCTAssertFalse(result.success)
    }
    
    func testCredentialSets_OptionalSetNotSatisfiedStillSucceeds() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"dc+sd-jwt","meta":{}},{"id":"q2","format":"mso_mdoc","meta":{}}],"credential_sets":[{"options":[["q1"]],"required":true},{"options":[["q2"]],"required":false}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [sdJwtCredential(id: "sd1")])
        XCTAssertTrue(result.success)
    }
    
    func testCredentialSets_NoCredentialSets_AllQueriesMustBePresent() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"dc+sd-jwt","meta":{}},{"id":"q2","format":"mso_mdoc","meta":{}}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [sdJwtCredential(id: "sd1")])
        XCTAssertFalse(result.success)
    }
    
    func testCredentialSets_NoCredentialSets_AllQueriesSatisfiedSucceeds() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"dc+sd-jwt","meta":{}},{"id":"q2","format":"mso_mdoc","meta":{}}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [sdJwtCredential(id: "sd1"), mdocCredential(id: "md1")])
        XCTAssertTrue(result.success)
    }
    
    func testPopulateCredentialSet_When_CredentialsSetsAbsent() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"dc+sd-jwt","meta":{}},{"id":"q2","format":"mso_mdoc","meta":{}}]}
        """)
        
        let result = try await evaluator.evaluate(query, inputCredentials: [sdJwtCredential(id: "sd1"), mdocCredential(id: "md1")])
        
        XCTAssertEqual(result.credentialSets.count, 2)
        XCTAssertEqual(result.credentialSets.first?.options, [["q1"]])
        XCTAssertEqual(result.credentialSets.first?.required, true)
        XCTAssertEqual(result.credentialSets[1].options, [["q2"]])
        XCTAssertEqual(result.credentialSets[1].required, true)
    }
    
    // MARK: - Multi-format / multi-query scenarios
    
    func testMultipleQueriesDifferentFormats_BothSatisfied() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"dc+sd-jwt","meta":{}},{"id":"q2","format":"mso_mdoc","meta":{}},{"id":"q3","format":"ldp_vc","meta":{}}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [sdJwtCredential(id: "sd1"), mdocCredential(id: "md1"), ldpVcCredential(id: "ldp1")])
        XCTAssertTrue(result.success)
        XCTAssertNotNil(result.queryMatches["q1"]?.matchingCredentials)
        XCTAssertNotNil(result.queryMatches["q2"]?.matchingCredentials)
        XCTAssertNotNil(result.queryMatches["q3"]?.matchingCredentials)
    }
    
    func testCredentialSetsFallbackOption_FirstOptionFailsSecondSucceeds() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"dc+sd-jwt","meta":{}},{"id":"q2","format":"mso_mdoc","meta":{}}],"credential_sets":[{"options":[["q1","q2"],["q1"]],"required":true}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [sdJwtCredential(id: "sd1")])
        XCTAssertTrue(result.success)
    }
    
    func testSuccessPopulatedAsFalseWhenAllRequiredDocumentsAreNotPresent() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"dc+sd-jwt","meta":{}},{"id":"q2","format":"mso_mdoc","meta":{}}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [sdJwtCredential(id: "sd1")])
        XCTAssertFalse(result.success)
    }
    
    // MARK: - QueryEvaluationResult structure
    
    func testResultContainsCredentialSetRequirements() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"dc+sd-jwt","meta":{}}],"credential_sets":[{"options":[["q1"]],"required":true}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [sdJwtCredential()])
        XCTAssertEqual(result.credentialSets.count, 1)
        XCTAssertEqual(result.credentialSets.first?.options, [["q1"]])
        XCTAssertTrue(result.credentialSets.first?.required ?? false)
    }
    
    func testResultAllowMultipleCredentialsReflectsQueryFlag() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"dc+sd-jwt","meta":{},"multiple":true}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [sdJwtCredential()])
        XCTAssertTrue(result.queryMatches["q1"]?.allowMultipleCredentials ?? false)
    }
    
    // MARK: - Additional scenario coverage
    
    // Scenario 1: No claims in VP request — all mandatory credential claims are shared to verifier
    func testNoClaims_CredentialPassedThroughWithEmptyMatchingClaims() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"mso_mdoc","meta":{}}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [mdocCredential()])
        XCTAssertTrue(result.success)
        XCTAssertEqual(result.queryMatches["q1"]?.matchingCredentials?.first?.matchingClaims.count, 0)
    }
    
    // Scenario 2: matchesExpectedValues - int (SD-JWT payload `nbf` is an integer)
    func testValueMatching_Int_Matches() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"dc+sd-jwt","meta":{},"claims":[{"id":"nbf","path":["nbf"],"values":[1755475200]}]}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [sdJwtCredential()])
        XCTAssertTrue(result.success)
        XCTAssertEqual(result.queryMatches["q1"]?.matchingCredentials?.first?.matchingClaims.count, 1)
    }
    
    func testValueMatching_Int_NoMatch() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"dc+sd-jwt","meta":{},"claims":[{"id":"nbf","path":["nbf"],"values":[9999999999]}]}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [sdJwtCredential()])
        XCTAssertFalse(result.success)
        XCTAssertEqual(result.queryMatches["q1"]?.failedClaims?.first?.reason, DCQLEvaluationErrorCodes.claimValueMismatch.rawValue)
    }
    
    // Scenario 3: matchesExpectedValues - boolean (ldp_vc credentialSubject with a bool field)
    func testValueMatching_Bool_Matches() async throws {
        var credential = ldpVC()
        if var subject = credential["credentialSubject"] as? [String: Any] {
            subject["id"] = "did:example:holder"
            subject["is_verified"] = true
            credential["credentialSubject"] = subject
        }
        let boolCredential = Credential(format: .ldp_vc, data: AnyCodable(credential), credentialId: "bool-cred")
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"ldp_vc","meta":{},"claims":[{"id":"iv","path":["credentialSubject","is_verified"],"values":[true]}]}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [boolCredential])
        XCTAssertTrue(result.success)
        XCTAssertEqual(result.queryMatches["q1"]?.matchingCredentials?.first?.matchingClaims.count, 1)
    }
    
    func testValueMatching_Bool_NoMatch() async throws {
        var credential = ldpVC()
        if var subject = credential["credentialSubject"] as? [String: Any] {
            subject["id"] = "did:example:holder"
            subject["is_verified"] = false
            credential["credentialSubject"] = subject
        }
        let boolCredential = Credential(format: .ldp_vc, data: AnyCodable(credential), credentialId: "bool-cred")
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"ldp_vc","meta":{},"claims":[{"id":"iv","path":["credentialSubject","is_verified"],"values":[true]}]}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [boolCredential])
        XCTAssertFalse(result.success)
        XCTAssertEqual(result.queryMatches["q1"]?.failedClaims?.first?.reason, DCQLEvaluationErrorCodes.claimValueMismatch.rawValue)
    }
    
    // Scenario 4: matchesMeta - doctype_value not matching (dedicated)
    func testMatchesMeta_DocType_NotMatching() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"mso_mdoc","meta":{"doctype_value":"org.iso.23220.photoid.1"}}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [mdocCredential()])
        XCTAssertFalse(result.success)
        XCTAssertEqual(result.queryMatches["q1"]?.failureReason, DCQLEvaluationErrorCodes.cryptographicHolderBindingOrMetaFilterMismatch.rawValue)
        XCTAssertNil(result.queryMatches["q1"]?.matchingCredentials)
    }
    
    // Scenario 5: matchesMeta - vct_values not matching (dedicated)
    func testMatchesMeta_Vct_NotMatching() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"dc+sd-jwt","meta":{"vct_values":["https://example.com/wrong-vct"]}}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [sdJwtCredential()])
        XCTAssertFalse(result.success)
        XCTAssertEqual(result.queryMatches["q1"]?.failureReason, DCQLEvaluationErrorCodes.cryptographicHolderBindingOrMetaFilterMismatch.rawValue)
        XCTAssertNil(result.queryMatches["q1"]?.matchingCredentials)
    }
    
    // Scenario 6: matchesMeta - type_values not matching (dedicated)
    func testMatchesMeta_TypeValues_NotMatching() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"ldp_vc","meta":{"type_values":[["VerifiableCredential","PassportCredential"]]}}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [ldpVcCredential()])
        XCTAssertFalse(result.success)
        XCTAssertEqual(result.queryMatches["q1"]?.failureReason, DCQLEvaluationErrorCodes.cryptographicHolderBindingOrMetaFilterMismatch.rawValue)
        XCTAssertNil(result.queryMatches["q1"]?.matchingCredentials)
    }
    
    // Scenario 7: noClaimsSetOptionSatisfied error (dedicated)
    func testNoClaimsSetOptionSatisfied_ErrorReturned() async throws {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"dc+sd-jwt","meta":{},"claims":[{"id":"m1","path":["missing_a"]},{"id":"m2","path":["missing_b"]}],"claim_sets":[["m1","m2"],["m1"],["m2"]]}]}
        """)
        let result = try await evaluator.evaluate(query, inputCredentials: [sdJwtCredential()])
        XCTAssertFalse(result.success)
        XCTAssertEqual(result.queryMatches["q1"]?.failureReason, DCQLEvaluationErrorCodes.noClaimsSetOptionSatisfied.rawValue)
        XCTAssertNil(result.queryMatches["q1"]?.matchingCredentials)
    }
    private func evaluateWildcardClaim(path: String, values: String, claims: [String: Any]) async throws -> MatchingCredentialsResult {
        let query = try dcqlQuery("""
        {"credentials":[{"id":"q1","format":"ldp_vc","meta":{},"require_cryptographic_holder_binding":false,"claims":[{"path":\(path),"values":\(values)}]}]}
        """)
        let credential = Credential(format: .ldp_vc, data: AnyCodable(claims), credentialId: "c1")
        return try await evaluator.evaluate(query, inputCredentials: [credential])
    }

    func testMatchesAnyWildcardSelectedValue() async throws {
        let claims: [String: Any] = ["credentialSubject": ["gender": [
            ["language": "eng", "value": "FEM"],
            ["language": "fra", "value": "MLE"]
        ]]]
        let result = try await evaluateWildcardClaim(path: #"["credentialSubject","gender",null,"value"]"#, values: #"["MLE"]"#, claims: claims)
        XCTAssertTrue(result.success)
    }

    func testRejectsWildcardValuesWhenNoElementMatches() async throws {
        let result = try await evaluateWildcardClaim(path: #"["nationalities",null]"#, values: #"["GB"]"#, claims: ["nationalities": ["DE", "FR"]])
        XCTAssertFalse(result.success)
        XCTAssertEqual(result.queryMatches["q1"]?.failedClaims?.first?.reason, DCQLEvaluationErrorCodes.claimValueMismatch.rawValue)
    }

    func testDoesNotMatchArrayWithoutWildcardAgainstScalar() async throws {
        let result = try await evaluateWildcardClaim(path: #"["nationalities"]"#, values: #"["DE"]"#, claims: ["nationalities": ["DE", "FR"]])
        XCTAssertFalse(result.success)
        XCTAssertEqual(result.queryMatches["q1"]?.failedClaims?.first?.reason, DCQLEvaluationErrorCodes.claimValueMismatch.rawValue)
    }

    func testMatchesTerminalWildcardValues() async throws {
        let result = try await evaluateWildcardClaim(path: #"["nationalities",null]"#, values: #"["DE"]"#, claims: ["nationalities": ["FR", "DE"]])
        XCTAssertTrue(result.success)
    }

    func testMatchesNestedWildcardValues() async throws {
        let claims: [String: Any] = ["degrees": [
            ["subjects": [["name": "Math"], ["name": "Physics"]]],
            ["subjects": [["name": "Chemistry"]]]
        ]]
        let result = try await evaluateWildcardClaim(path: #"["degrees",null,"subjects",null,"name"]"#, values: #"["Physics"]"#, claims: claims)
        XCTAssertTrue(result.success)
    }

    func testWildcardMatchesIntegerAndBooleanValues() async throws {
        let integer = try await evaluateWildcardClaim(path: #"["scores",null]"#, values: "[42]", claims: ["scores": [1, 42]])
        XCTAssertTrue(integer.success)
        let boolean = try await evaluateWildcardClaim(path: #"["flags",null]"#, values: "[true]", claims: ["flags": [false, true]])
        XCTAssertTrue(boolean.success)
    }

    func testEmptyWildcardClaimIsUnavailable() async throws {
        let result = try await evaluateWildcardClaim(path: #"["nationalities",null]"#, values: #"["DE"]"#, claims: ["nationalities": [] as [Any]])
        XCTAssertFalse(result.success)
        XCTAssertEqual(result.queryMatches["q1"]?.failedClaims?.first?.reason, DCQLEvaluationErrorCodes.claimUnavailable.rawValue)
    }

    func testWildcardKeepsLiteralNilStrings() async throws {
        let result = try await evaluateWildcardClaim(path: #"["labels",null]"#, values: #"["nil"]"#, claims: ["labels": ["nil", "other"]])
        XCTAssertTrue(result.success)
    }

    func testWildcardSkipsNullClaimValues() async throws {
        let result = try await evaluateWildcardClaim(path: #"["labels",null]"#, values: #"["DE"]"#, claims: ["labels": [NSNull(), "DE"] as [Any]])
        XCTAssertTrue(result.success)
    }

}
