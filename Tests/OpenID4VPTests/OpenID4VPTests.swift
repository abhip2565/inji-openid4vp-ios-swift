 @testable import OpenID4VP
import XCTest

class OpenID4VPTests: XCTestCase {
    var openID4VP: OpenID4VP!
    var mockNetworkManager: MockNetworkManager!
    var mockNonceProvider: NonceProvider!
    var authorizationRequest: AuthorizationRequest!

    let jws = "wemcn3234ns"
    let signatureAlgoType = "JsonWebSignature2020"
    let publicKey = "-----BEGIN PUBLIC KEY-----\\nMIIBIjANBggvSPv73S\\nG5ToTt07NZPdKDrg9lSjetZup39oj12u0YoyRMlMhY0xYL6c8X1BexM7Wlp+c13o\\n1QIDAQAB\\n-----END PUBLIC KEY-----\\n"
    let domain = "https://example"
    let descriptorMap: [DescriptorMap] = [
        DescriptorMap(id: "bank_input", format: .ldp_vp, path: "$", pathNested: PathNested(id: "input_1", format: .ldp_vc, path: "$.verifiableCredential[0]")),
        DescriptorMap(id: "bank_input", format: .ldp_vp, path: "$", pathNested: PathNested(id: "input_1", format: .ldp_vc, path: "$.verifiableCredential[0]")),
    ]

    let decodedPresentationDefinition = "{\"id\":\"#2345333\",\"input_descriptors\":[{\"id\":\"banking_input_1\",\"name\":\"Bank Account Information\",\"purpose\":\"We can\",\"constraints\":{\"fields\":[{\"path\":[\"$.crede\"],\"purpose\":\"We can use for  # verification purpose # for anything\",\"filter\":{\"type\":\"string\",\"pattern\":\"^$\"}},{\"path\":[\"$.vc.credential\",\"$.vc.credentialSubject.account[*].route\",\"$.account[*].route\"],\"purpose\":\"We can use for verification purpose\",\"filter\":{\"type\":\"string\",\"pattern\":\"^\"}}]}}]}"

    let decodedClientMetadata =
        "{\"name\":\"dummyClient\"}"
    let processedSuccessfullyMessage = "{\"message\":\"Some additional info\"}"
    let responseUri = "https://mock-verifier.com"
    let responseDispatchInfo = ResponseDispatchInfo(responseMode: "direct_post", nonce: "vakue", walletNonce: "wallet-nonce", state: "state", clientId: "clientId", responseUrl: "https://mock-verifier.com")
    var walletConfig : WalletConfig!

    override func setUp() {
        super.setUp()
        mockNetworkManager = MockNetworkManager()
        mockNonceProvider = MockNonceProvider()

        openID4VP = OpenID4VP(
            traceabilityId: "AXESWSAW123",
            networkManager: mockNetworkManager,
            walletConfig: WalletConfig(trustedVerifiers: preRegisteredVerifiers),
            nonceProvider: MockNonceProvider(),
            jsonLdCanonicalizer: { _ in "Y2Fub25pY2FsaXplZA" }
        )
        openID4VP.setResponseDispatchInfo(ResponseDispatchInfo(responseMode: "direct_post", nonce: nil, walletNonce: nil, state: nil, clientId: "", responseUrl: "https://mock-verifier.com", responseEncryptionSpecification: nil))
        openID4VP.authorizationRequest = authorizationRequest
        
        JsonLd.setCanonicalizer { _ in "Y2Fub25pY2FsaXplZA" }
        walletConfig = createWalletConfig()
    }

    override func tearDown() {
        openID4VP = nil
        mockNetworkManager = nil
        mockNonceProvider = nil
        super.tearDown()
    }

    func testWalletNonceIsDifferentForEveryAuthenticateVerifierCall() async {
        let openID4VP = OpenID4VP(traceabilityId: "trace-id")
        _ = try! await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: testValidUrlEncodedVPRequestWithRedirectUri)
        let firstMirror = Mirror(reflecting: openID4VP as Any)
        let firstNonce = firstMirror.children.first(where: { $0.label == "walletNonce" })?.value as? String

        _ = try! await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: testValidUrlEncodedVPRequestWithRedirectUri)
        let secondMirror = Mirror(reflecting: openID4VP as Any)
        let secondNonce = secondMirror.children.first(where: { $0.label == "walletNonce" })?.value as? String

        XCTAssertNotEqual(firstNonce, secondNonce, "Wallet nonce should be different for every authenticateVerifier call")
    }

    // client_id_prefix = redirect_uri
    func testAuthorizationRequestJsonStringConversion() async {
        do {
            let decoded = try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: testValidUrlEncodedVPRequestWithRedirectUri)
            let jsonData = try JSONEncoder().encode(decoded)
            let authorizationRequestJsonString = String(decoding: jsonData, as: UTF8.self)

            assertJsonString(expected: "{\"nonce\":\"VbRRB\\/LTxLiXmVNZuyMO8A==\",\"state\":\"+mRQe1d6pBoJqF6Ab28klg==\",\"response_uri\":\"https:\\/\\/mock-verifier.com\",\"response_mode\":\"direct_post\",\"dcql_query\":{\"credentials\":[{\"format\":\"dc+sd-jwt\",\"multiple\":false,\"id\":\"cred1\",\"meta\":{},\"require_cryptographic_holder_binding\":true},{\"format\":\"mso_mdoc\",\"multiple\":false,\"id\":\"cred2\",\"meta\":{},\"require_cryptographic_holder_binding\":true},{\"require_cryptographic_holder_binding\":true,\"id\":\"cred3\",\"meta\":{},\"format\":\"ldp_vc\",\"multiple\":false}]},\"client_id\":\"redirect_uri:https:\\/\\/mock-verifier.com\",\"response_type\":\"vp_token\",\"client_metadata\":{\"jwks\":{\"keys\":[{\"use\":\"enc\",\"kty\":\"OKP\",\"alg\":\"ECDH-ES\",\"kid\":\"ed-key1\",\"crv\":\"X25519\",\"x\":\"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4\"},{\"use\":\"sig\",\"kty\":\"OKP\",\"alg\":\"EdDSA\",\"kid\":\"ed-key2\",\"crv\":\"Ed25519\",\"x\":\"5tvU4k_TGAfDAru3LfS53qbfHzghjc0kvPGAb2VUwWc\"}]},\"logo_uri\":\"https:\\/\\/mock-verifier.com\\/logo\",\"client_name\":\"Requester name\",\"vp_formats_supported\":{\"ldp_vp\":{\"proof_type_values\":[\"Ed25519Signature2020\"]}}}}", actual: authorizationRequestJsonString)
        } catch {
            XCTFail("Should not get error but got error - \(error)")
        }
    }
    
    // client_id_prefix = redirect_uri, test with deprecated authenticateVerifier including trustedVerifierJSON parameter
    func testAuthorizationRequestJsonStringConversionDeprecatedMethod() async {
        do {
            let decoded = try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: testValidUrlEncodedVPRequestWithRedirectUri)
            let jsonData = try JSONEncoder().encode(decoded)
            let authorizationRequestJsonString = String(decoding: jsonData, as: UTF8.self)

            assertJsonString(expected: "{\"response_uri\":\"https:\\/\\/mock-verifier.com\",\"state\":\"+mRQe1d6pBoJqF6Ab28klg==\",\"response_mode\":\"direct_post\",\"client_id\":\"redirect_uri:https:\\/\\/mock-verifier.com\",\"dcql_query\":{\"credentials\":[{\"require_cryptographic_holder_binding\":true,\"id\":\"cred1\",\"meta\":{},\"format\":\"dc+sd-jwt\",\"multiple\":false},{\"require_cryptographic_holder_binding\":true,\"id\":\"cred2\",\"meta\":{},\"format\":\"mso_mdoc\",\"multiple\":false},{\"require_cryptographic_holder_binding\":true,\"id\":\"cred3\",\"meta\":{},\"format\":\"ldp_vc\",\"multiple\":false}]},\"response_type\":\"vp_token\",\"nonce\":\"VbRRB\\/LTxLiXmVNZuyMO8A==\",\"client_metadata\":{\"jwks\":{\"keys\":[{\"use\":\"enc\",\"crv\":\"X25519\",\"kty\":\"OKP\",\"alg\":\"ECDH-ES\",\"kid\":\"ed-key1\",\"x\":\"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4\"},{\"use\":\"sig\",\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"alg\":\"EdDSA\",\"kid\":\"ed-key2\",\"x\":\"5tvU4k_TGAfDAru3LfS53qbfHzghjc0kvPGAb2VUwWc\"}]},\"client_name\":\"Requester name\",\"vp_formats_supported\":{\"ldp_vp\":{\"proof_type_values\":[\"Ed25519Signature2020\"]}},\"logo_uri\":\"https:\\/\\/mock-verifier.com\\/logo\"}}", actual: authorizationRequestJsonString)
        } catch {
            XCTFail("Should not get error but got error - \(error)")
        }
    }

    // client_id_prefix = redirect_uri, response_mode = fragment
    func testInvalidResponseModeWithRedirectUriScheme() async {
        let result = await Task {
            try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: testVPRequestWithRedirectUriAndClientIdNotEqual)
        }.result

        switch result {
        case let .failure(error):
            assertOpenID4VPException(
                error,
                expectedMessage: "Given response_mode - fragment is not supported",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        case .success:
            XCTFail("Expected error for unsupported response_mode but got success")
        }
    }

    // Missing nonce must NOT trigger a verifier notification
    func testAuthenticateVerifierDoesNotNotifyVerifierWhenNonceIsMissing() async {
        let requestWithoutNonce = createUrlEncodedAuthorizationRequest(
            requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdParameter),
            clientIdPrefix: .redirectUri,
            applicableFields: authRequestWithRedirectUriByValue.filter { $0 != "nonce" },
            addEncryptionClientMetadataParams: false
        )

        let result = await Task {
            try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: requestWithoutNonce)
        }.result

        switch result {
        case let .failure(error):
            assertOpenID4VPException(
                error,
                expectedMessage: "Missing Input: nonce param is required",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        case .success:
            XCTFail("Expected error for missing nonce but got success")
        }

        // No error POST should have been dispatched to the verifier's response_uri
        XCTAssertTrue(
            mockNetworkManager.recordedRequests.isEmpty,
            "Verifier should not be notified when nonce is missing"
        )
    }

    // client_id_prefix = pre-registered
    func testReturnDataForValidRequestWithResponseUri() async {
        let requestUriResponse = createAuthorizationRequestObject(clientIdPrefix: .preRegistered, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdParameters), applicableFields: authRequestWithPreRegisteredByValue)
        mockNetworkManager.setMockResponse(for: requestUri.absoluteString, response: (requestUriResponse, httpUrlResponseForJWS))

        await XCTAssertNoThrowAndVerifyAsync(
            try await openID4VP.authenticateVerifier(
                urlEncodedAuthorizationRequest: testValidUrlEncodedVPRequestWithResponseUri
            )
        ) { authorizationRequest in
            XCTAssertEqual(authorizationRequest.clientId, "mock-client")
        }
    }

    // client_id_prefix = pre-registered, validation of client via validatePreregisteredVerifier

    func testAuthenticateVerifierWithValidatePreregisteredVerifierFalse() async throws {
        openID4VP = OpenID4VP(
            traceabilityId: "AXESWSAW123",
            networkManager: mockNetworkManager,
            walletConfig: WalletConfig(trustedVerifiers: preRegisteredVerifiers, validateTrustedVerifier: false),
            nonceProvider: MockNonceProvider(),
            jsonLdCanonicalizer: { _ in "Y2Fub25pY2FsaXplZA" }
        )
        
        await XCTAssertAsyncNoThrowsError(try await openID4VP.authenticateVerifier(
            urlEncodedAuthorizationRequest: testUrlEncodedAuthRequestOfUntrustedVerifier
        ), "should not throw even though the client ID isn't in the trusted list because validatePreregisteredVerifier is false")
    }

    func testAuthenticateVerifierWithValidatePreregisteredVerifierTrue() async throws {
        await XCTAssertAsyncThrowsError(try await openID4VP.authenticateVerifier(
            urlEncodedAuthorizationRequest: testUrlEncodedAuthRequestOfUntrustedVerifier
        )) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Verifier is not trusted by the wallet",
                expectedCode: OpenID4VPErrorCodes.invalidClient
            )
        }
    }

    func testAuthenticateVerifierWithoutValidatePreregisteredVerifierParam() async throws {
        await XCTAssertAsyncThrowsError(try await openID4VP.authenticateVerifier(
            urlEncodedAuthorizationRequest: testUrlEncodedAuthRequestOfUntrustedVerifier
        )) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Verifier is not trusted by the wallet",
                expectedCode: OpenID4VPErrorCodes.invalidClient
            )
        }
    }

    // client_id_prefix = pre_registered, ClientMetadata mandatory values are not present
    func testMissingClientMetadataRequiredFieldsInRequest() async {
        openID4VP = OpenID4VP(
            traceabilityId: "AXESWSAW123",
            networkManager: mockNetworkManager,
            walletConfig: WalletConfig(trustedVerifiers: [Verifier(clientId: "mock-client-2", responseUris: ["https://mock-verifier.com"], jwksUri: "https://mock-client.com/jwks", allowUnsignedRequest: true)]),
            nonceProvider: MockNonceProvider(),
            jsonLdCanonicalizer: { _ in "Y2Fub25pY2FsaXplZA" }
        )
        
        let result = await Task {
            try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: urlEncodedAuthorizationRequestWithInvalidClientMetadata)
        }.result

        switch result {
        case let .failure(error):
            assertOpenID4VPException(
                error,
                expectedMessage: "Error during client metadata decoding - The data couldn’t be read because it is missing.",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        case .success:
            XCTFail("Expected failure but got success")
        }
    }

    func testShouldConstructAuthorizationRequestSuccessfullyWhenPresentationDefinitionIsSentByReference() async {
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/presentation-definition", responseBody: convertToJsonString(presentationDefinition))
        do {
            let authorizationRequest = try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: urlEncodedAuthRequestWithPresentationDefinitionUri)
            XCTAssertNotNil(authorizationRequest)
            XCTAssertEqual("mock-client", authorizationRequest.clientId)
        } catch {
            XCTFail("should not get error but got error \(error)")
        }
    }

    // client_id_prefix = did
    func testReturnDataForValidRequestWithDid() async {
        mockNetworkManager.setMockResponse(for: requestUri.absoluteString, response: (validJwtResponse, httpUrlResponseForJWS))
        mockNetworkManager.setMockResponse(for: didDocumentUrl, responseBody: didResponse)

        let decodedAuthorizationRequest: Any?
        do {
            decodedAuthorizationRequest = try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: testValidSignedVPRequestWithDid)
        } catch {
            decodedAuthorizationRequest = nil
            XCTFail("Should not get error but got error - \(error)")
        }

        XCTAssertTrue(decodedAuthorizationRequest is AuthorizationRequest, "decodedResponse should be an instance of AuthorizationRequest")
        XCTAssertTrue(decodedAuthorizationRequest != nil, "decodedResponse should not be null")
    }

    // jwt -> client_id_prefix = did, Invalid did
    func testThrowErrorForInValidSignatureInRequest() async {
        mockNetworkManager.setMockResponse(
            for: "https://mock-verifier.com/verifier/get-auth-request-obj",
            response: (invalidJwtResponse, httpUrlResponseForJWS)
        )
        mockNetworkManager.setMockResponse(
            for: didDocumentUrl,
            responseBody: didResponse
        )

        await XCTAssertAsyncThrowsError(try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: testValidSignedVPRequestWithDid)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Request URI response validation failed - JWS proof verification failed",
                expectedCode: OpenID4VPErrorCodes.invalidRequestObject
            )
        }
    }

    // jwt -> client_id_prefix = did, Mismatching clientId's in QR data and Request Uri response
    func testThrowErrorIfClientIdIsMismatchingWithQrDataAndRequest() async {
        mockNetworkManager.setMockResponse(
            for: requestUri.absoluteString,
            response: (validJwtResponse, httpUrlResponseForJWS)
        )
        mockNetworkManager.setMockResponse(for: didDocumentUrl, responseBody: didResponse)

        await XCTAssertAsyncThrowsError(try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: testInValidSignedVPRequestWithDidAndClientIdDifferent)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Client Id mismatch in Authorization Request parameter and the Request Object",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // jwt -> client_id_prefix = did, Kid is empty in the JWT header
    func testThrowErrorIfKidExtractionFailedFromJws() async {
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/verifier/get-auth-request-obj", response: (invalidJwtResponseWithoutKid, httpUrlResponseForJWS))
        mockNetworkManager.setMockResponse(for: didDocumentUrl, responseBody: didResponse)

        await XCTAssertAsyncThrowsError(try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: testValidSignedVPRequestWithDid)) {
            error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Request URI response validation failed - keyId is required to extract public key in decentralized_identifier client_id_prefix",
                expectedCode: OpenID4VPErrorCodes.invalidRequestObject
            )
        }
    }

    // client_id_prefix = redirect_uri, Client id validation is false
    func testReturnDataForValidRequestWhenClientValidationIsFalse() async {
        let decoded: Any?
        openID4VP = OpenID4VP(
            traceabilityId: "AXESWSAW123",
            networkManager: mockNetworkManager,
            walletConfig: WalletConfig(trustedVerifiers: preRegisteredVerifiers, validateTrustedVerifier: false),
            nonceProvider: MockNonceProvider(),
            jsonLdCanonicalizer: { _ in "Y2Fub25pY2FsaXplZA" }
        )

        do {
            decoded = try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: testValidUrlEncodedVPRequestWithRedirectUri)
        } catch {
            decoded = nil
            XCTFail("should not get error but got error \(error)")
        }
        XCTAssertTrue(decoded is AuthorizationRequest, "decodedResponse should be an instance of AuthenticationResponse")
        XCTAssertTrue(decoded != nil, "decodedResponse should not be null")
    }

    func testMissingPresentationDefinitionFields() async {
        let result = await Task {
            try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: testInvalidPresentationDefinitionVPRequest)
        }.result

        switch result {
        case let .failure(error):
            assertOpenID4VPException(
                error,
                expectedMessage: "Missing Input: presentation_definition->id param is required",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        case .success:
            XCTFail("Expected OpenID4VPException but got success response")
        }
    }

    // Construct and return VP token for signing
    func testShareVerifiablePresentation() async {
        var received: [UnsignedVPToken]?
        JsonLd.setCanonicalizer { _ in "Y2Fub25pY2FsaXplZA" }

        do {
            _ = try await openID4VP.authenticateVerifier(
                urlEncodedAuthorizationRequest: mockUrlEncodedVPRequestWithDirectPostJwt
            )

            let mockCredentials: [String: [Credential]] = [
                "cred3": [Credential(format: .ldp_vc, data: AnyCodable(ldpVC()), credentialId: "cred3")],
            ]

            received = try await openID4VP.constructUnsignedVPToken(
                selectedCredentials: mockCredentials
            )
        } catch {
            XCTFail("Unexpected error: \(error)")
        }

        XCTAssertNotNil(received, "The response should not be nil for valid credentials map")
    }

    func testResetOfOpenID4VPFields() async throws {
        let openID4VP = OpenID4VP(traceabilityId: "trace-id", networkManager: mockNetworkManager)
        mockNetworkManager.setMockResponse(for: requestUri.absoluteString, response: (validJwtResponse, httpUrlResponseForJWS))
        mockNetworkManager.setMockResponse(for: didDocumentUrl, responseBody: didResponse)

        // first call
        _ = try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: testValidSignedVPRequestWithDid)
        let firstMirror = Mirror(reflecting: openID4VP as Any)
        let firstResponseDispatchInfo = firstMirror.children.first(where: { $0.label == "responseDispatchInfo" })?.value
        let firstAuthorizationRequest = firstMirror.children.first(where: { $0.label == "authorizationRequest" })?.value as? AuthorizationRequest
        XCTAssertNotNil(firstResponseDispatchInfo, "responseDispatchInfo should not be nil after first authenticateVerifier call")
        XCTAssertNotNil(firstAuthorizationRequest, "authorizedRequest should not be nil after first authenticateVerifier call")

        // second call
        // clear all mock responses and set only those required for the second call
        mockNetworkManager.clearResponses()
        mockNetworkManager.setMockResponse(
            for: "https://mock-verifier.com/verifier/get-auth-request-obj",
            response: (invalidJwtResponse, httpUrlResponseForJWS)
        )
        mockNetworkManager.setMockResponse(
            for: didDocumentUrl,
            responseBody: didResponse
        )

        await XCTAssertAsyncThrowsError(try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: testValidSignedVPRequestWithDid)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Request URI response validation failed - JWS proof verification failed",
                expectedCode: OpenID4VPErrorCodes.invalidRequestObject
            )
        }
        let secondMirror = Mirror(reflecting: openID4VP as Any)
        let secondResponseDispatchInfo = secondMirror.children.first(where: { $0.label == "responseDispatchInfo" })?.value
        let secondAuthorizationRequest = secondMirror.children.first(where: { $0.label == "authorizationRequest" })?.value as? AuthorizationRequest
        XCTAssertNil(secondResponseDispatchInfo as? ResponseDispatchInfo, "responseDispatchInfo should be nil after second authenticateVerifier call which throws error")
        XCTAssertNil(secondAuthorizationRequest, "authorizedRequest should be nil after second authenticateVerifier call which throws error")
        // No error to verifier to be sent as no response dispatch info is available
        XCTAssertTrue(mockNetworkManager.recordedRequests.count == 2, "No requests should be recorded as responseDispatchInfo is nil")
    }

    func testThrowErrorWhenResponseUriNotAvailableDuringsendErrorInfoToVerifier
    () async throws {
        let error = AccessDenied(message: "Some error", className: "test")
        let openID4VP = OpenID4VP(traceabilityId: "trace-id", networkManager: mockNetworkManager)

        // directly call sendErrorInfoToVerifier
        await XCTAssertAsyncThrowsError(try await openID4VP.sendErrorInfoToVerifier(error: error)) { error in
            XCTAssertEqual(error.localizedDescription, "Failed to send error to verifier: Response dispatch details are not set. Cannot send error to verifier.")
        }
    }

    func testSuccessWhensendErrorInfoToVerifierCalled
    () async throws {
        let error = AccessDenied(message: "Some error", className: "test")
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: processedSuccessfullyMessage)

        let openID4VP = OpenID4VP(traceabilityId: "trace-id", networkManager: mockNetworkManager)
        openID4VP.setResponseDispatchInfo(ResponseDispatchInfo(responseMode: "direct_post", nonce: nil, walletNonce: nil, state: nil, clientId: "", responseUrl: responseUri, responseEncryptionSpecification: nil))

        await XCTAssertNoThrowAndVerifyAsync(try await openID4VP.sendErrorInfoToVerifier(error: error)) { result in
            XCTAssertEqual(result.body(), "{\"message\":\"Some additional info\"}")
            XCTAssertEqual(result.statusCode, 200)
            XCTAssertEqual(result.headers, ["Content-Type": "application/json"])
        }
    }

    func testThrownExceptionHavingVerifierResponse() async {
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "{\"message\":\"Some additional info\",\"redirect_uri\":\"https://mock-verifier.com/redirect#response_code=200\"}")

        await XCTAssertAsyncThrowsError(try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: testInvalidPresentationDefinitionVPRequest)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Missing Input: presentation_definition->id param is required",
                expectedCode: OpenID4VPErrorCodes.invalidRequest,
                expectedVerifierResponse: VerifierResponse(
                    statusCode: 200,
                    responseBody: "{\"message\":\"Some additional info\",\"redirect_uri\":\"https://mock-verifier.com/redirect#response_code=200\"}",
                    redirectUri: "https://mock-verifier.com/redirect#response_code=200",
                    additionalParams: "{\"message\":\"Some additional info\"}",
                    headers: ["Content-Type": "application/json"]
                )
            )
        }
    }

    func testAuthenticateVerifierDirectPostJwtSendsEncryptedErrorWhenValidationFailsAfterDispatchInfoPopulation() async {
        let draft23JwtClientMetadata = clientMetadataSpecVersionDraft23.merging([
            "authorization_encrypted_response_alg": "ECDH-ES",
            "authorization_encrypted_response_enc": "A256GCM"
        ]) { _, new in new }
        let invalidPresentationDefinitionRequest = createUrlEncodedAuthorizationRequest(
            requestParams: mergeMaps(
                authorizationRequestParamsWithValue,
                preRegisteredSchemeClientIdParameters,
                [
                    AuthorizationRequestFieldConstants.responseMode: ResponseMode.directPostJwt.rawValue,
                    AuthorizationRequestFieldConstants.presentationDefinition: convertToJsonString(["input_descriptor": []]),
                    AuthorizationRequestFieldConstants.clientMetadata: draft23JwtClientMetadata
                ]
            ),
            clientIdPrefix: .preRegistered,
            specVersion: .draft23
        )
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "{\"message\":\"Some additional info\"}")

        await XCTAssertAsyncThrowsError(
            try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: invalidPresentationDefinitionRequest)
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Missing Input: presentation_definition->id param is required",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }

        let recordedRequest = mockNetworkManager.recordedRequests[responseUri]
        XCTAssertNotNil(recordedRequest)
        XCTAssertNotNil(recordedRequest?.requestBody?["response"])
        XCTAssertNil(recordedRequest?.requestBody?["error"])
        XCTAssertNil(recordedRequest?.requestBody?["error_description"])
    }

    func testAuthenticateVerifierDirectPostJwtSendsEncryptedErrorWhenValidationFailsAfterDispatchInfoPopulationSpecV1() async {
        let invalidDcqlQueryRequest = createUrlEncodedAuthorizationRequest(
            requestParams: mergeMaps(
                authorizationRequestParamsWithValue,
                preRegisteredSchemeClientIdParameters,
                [
                    AuthorizationRequestFieldConstants.responseMode: ResponseMode.directPostJwt.rawValue,
                    AuthorizationRequestFieldConstants.dcqlQuery: convertToJsonString(["credentials": []]),
                    AuthorizationRequestFieldConstants.clientMetadata: clientMetadataSpecVersion1
                ]
            ),
            clientIdPrefix: .preRegistered,
            specVersion: .v1
        )
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "{\"message\":\"Some additional info\"}")

        await XCTAssertAsyncThrowsError(
            try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: invalidDcqlQueryRequest)
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Invalid Input: dcql_query->credentials value cannot be empty or null",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }

        let recordedRequest = mockNetworkManager.recordedRequests[responseUri]
        XCTAssertNotNil(recordedRequest)
        XCTAssertNotNil(recordedRequest?.requestBody?["response"])
        XCTAssertNil(recordedRequest?.requestBody?["error"])
        XCTAssertNil(recordedRequest?.requestBody?["error_description"])
    }

    func testAuthenticateVerifierSuccess_WithRedirectUriClientIdPrefix() async {
        let authorizationRequest = baseAuthRequest(
            clientId: "redirect_uri:https://example.com/iar/callback",
            responseUri: "https://example.com/iar/callback"
        )

        let trustedVerifiers = [
            Verifier(clientId: "redirect-uri:https://example.com/callback", responseUris: ["https://example.com/callback"]),
        ]
        openID4VP = OpenID4VP(
            traceabilityId: "AXESWSAW123",
            networkManager: mockNetworkManager,
            walletConfig: WalletConfig(trustedVerifiers: trustedVerifiers),
            nonceProvider: MockNonceProvider(),
            jsonLdCanonicalizer: { _ in "Y2Fub25pY2FsaXplZA" }
        )

        do {
            _ = try await openID4VP.authenticateVerifier(
                authorizationRequest: authorizationRequest
            )
        } catch let error {
            print(error)
            XCTFail("Should not throw error")
        }
    }

    func testConstructVPResponse_Success() {
        let handler = MockAuthorizationResponseHandler(networkManager: MockNetworkManager(), walletConfig: walletConfig)
        handler.expectedVPResponse = ["vp_token": "jwt-token"]

        let openIdVP = OpenID4VP(traceabilityId: "AXESWSAW123", networkManager: mockNetworkManager, nonceProvider: MockNonceProvider(), authorizationResponseHandler: handler)
        openIdVP.authorizationRequest = mockAuthorizationRequestObjectWithDirectPostResponseMode
        let result = openIdVP.constructVPResponse(vpTokenSigningResults: [VPTokenSigningResult(id: "uuid1", signedData: Data("signed-data".utf8))])

        XCTAssertEqual(result["vp_token"] as! String, "jwt-token")
    }

    

    func testConstructVPResponseSuccess() {
        let handler = MockAuthorizationResponseHandler(networkManager: mockNetworkManager, walletConfig: walletConfig)
        handler.expectedVPResponse = ["vp_token": "signed-token", "presentation_submission": "submission"]

        let openIdVP = OpenID4VP(traceabilityId: "AXESWSAW123", networkManager: mockNetworkManager, nonceProvider: MockNonceProvider(), authorizationResponseHandler: handler)
        openIdVP.authorizationRequest = mockAuthorizationRequestObjectWithDirectPostResponseMode

        let signingResults = [VPTokenSigningResult(id: "uuid1", signedData: Data("signed-token".utf8))]
        let result = openIdVP.constructVPResponse(vpTokenSigningResults: signingResults)

        XCTAssertEqual(result["vp_token"] as? String, "signed-token")
        XCTAssertEqual(result["presentation_submission"] as? String, "submission")
    }

    func testConstructVPResponseReturnsErrorInfoWhenHandlerThrows() {
        let handler = MockAuthorizationResponseHandler(networkManager: mockNetworkManager, walletConfig: walletConfig)
        handler.expectedErrorResponse = ["error": "invalid_request", "error_description": "signing failed"]

        let openIdVP = OpenID4VP(traceabilityId: "AXESWSAW123", networkManager: mockNetworkManager, nonceProvider: MockNonceProvider(), authorizationResponseHandler: handler)
        openIdVP.authorizationRequest = mockAuthorizationRequestObjectWithDirectPostResponseMode

        let result = openIdVP.constructVPResponse(vpTokenSigningResults: [])

        XCTAssertEqual(result["error"] as? String, "invalid_request")
    }

    func testConstructUnsignedVPTokenReturnsTokenList() async {
        let expectedTokens = [
            UnsignedVPToken(id: "uuid1", format: .ldp_vc, holderKeyReference: "did:example:123", signatureAlgorithm: "JsonWebSignature2020", dataToSign: Data("data1".utf8)),
            UnsignedVPToken(id: "uuid2", format: .mso_mdoc, holderKeyReference: "key-ref", signatureAlgorithm: "ES256", dataToSign: Data("data2".utf8))
        ]
        let handler = MockAuthorizationResponseHandler(networkManager: mockNetworkManager, walletConfig: walletConfig)
        handler.expectedUnsignedVPTokens = expectedTokens

        let openIdVP = OpenID4VP(traceabilityId: "AXESWSAW123", networkManager: mockNetworkManager, nonceProvider: MockNonceProvider(), authorizationResponseHandler: handler)
        openIdVP.authorizationRequest = mockAuthorizationRequestObjectWithDirectPostJwtResponseMode
        openIdVP.setResponseDispatchInfo(responseDispatchInfo)

        do {
            let result = try await openIdVP.constructUnsignedVPToken(
                selectedCredentials: ["input_1": [Credential(format: .ldp_vc, data: AnyCodable(ldpVC()), credentialId: "input_1")]]
            )
            XCTAssertEqual(result.count, 2)
            XCTAssertEqual(result[0].format, .ldp_vc)
            XCTAssertEqual(result[0].holderKeyReference, "did:example:123")
            XCTAssertEqual(result[0].signatureAlgorithm, "JsonWebSignature2020")
            XCTAssertEqual(result[1].format, .mso_mdoc)
        } catch {
            XCTFail("Should not throw but got: \(error)")
        }
    }

    func testConstructUnsignedVPTokenPropagatesAndSendsError() async {
        let openIdVP = OpenID4VP(traceabilityId: "AXESWSAW123", networkManager: mockNetworkManager, nonceProvider: MockNonceProvider())
        // Use a PE request so the PE flow is exercised and holderId is extracted from the credential
        openIdVP.authorizationRequest = getMockAuthorizationRequest(responseMode: .directPostJwt, specVersion: .draft23)

        mockNetworkManager.setMockResponse(for: responseUri, responseBody: processedSuccessfullyMessage)
        openIdVP.setResponseDispatchInfo(responseDispatchInfo)

        // Credential with no credentialSubject — extraction of holderId will fail
        let credentialWithNoSubject: [String: Any] = ["type": ["VerifiableCredential"]]

        await XCTAssertAsyncThrowsError(
            try await openIdVP.constructUnsignedVPToken(
                selectedCredentials: ["input_1": [Credential(format: .ldp_vc, data: AnyCodable(credentialWithNoSubject), credentialId: "input_1")]]
            )
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "The wallet encountered an internal error while preparing the presentation.",
                expectedCode: OpenID4VPErrorCodes.serverError,
                expectedUnderlyingErrorMessage: "Holder ID not available in the credential"
            )
        }
    }
    
    func testSendVPResponseToVerifierThrowsInsteadOfCrashingWhenVerifierIsNotAuthenticated() async {
        let openIdVP = OpenID4VP(traceabilityId: "AXESWSAW123", networkManager: mockNetworkManager, nonceProvider: MockNonceProvider())

        await XCTAssertAsyncThrowsError(try await openIdVP.sendVPResponseToVerifier(vpTokenSigningResults: [VPTokenSigningResult(id: "uuid1", signedData: "signed".data(using: .utf8) ?? Data())])) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Authorization request is not available. Call authenticateVerifier before constructing or sending the VP response.",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testConstructUnsignedVPTokenThrowsInsteadOfCrashingWhenVerifierIsNotAuthenticated() async {
        let openIdVP = OpenID4VP(traceabilityId: "AXESWSAW123", networkManager: mockNetworkManager, nonceProvider: MockNonceProvider())

        await XCTAssertAsyncThrowsError(
            try await openIdVP.constructUnsignedVPToken(
                selectedCredentials: ["input_1": [Credential(format: .ldp_vc, data: AnyCodable(ldpVC()), credentialId: "input_1")]]
            )
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Authorization request is not available. Call authenticateVerifier before constructing or sending the VP response.",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testConstructVPResponseReturnsErrorInfoInsteadOfCrashingWhenVerifierIsNotAuthenticated() {
        let openIdVP = OpenID4VP(traceabilityId: "AXESWSAW123", networkManager: mockNetworkManager, nonceProvider: MockNonceProvider())

        let result = openIdVP.constructVPResponse(
            vpTokenSigningResults: [VPTokenSigningResult(id: "uuid1", signedData: "signed".data(using: .utf8) ?? Data())]
        )

        XCTAssertEqual(result["error"] as? String, "invalid_request")
    }
}

