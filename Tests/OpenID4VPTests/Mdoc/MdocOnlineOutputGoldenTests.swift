import SwiftCBOR
import XCTest
@testable import OpenID4VP

/// Locks today's online mdoc output, built from the sample credential, so that sharing the
/// DeviceAuthentication and document code with in-person presentation cannot change what online
/// verifiers receive. The DeviceResponse is compared decoded: SwiftCBOR writes map keys in
/// dictionary order, which changes from run to run.
final class MdocOnlineOutputGoldenTests: XCTestCase {

    private func dataToSign(_ specVersion: SpecVersion) async throws -> String {
        let builder = try UnsignedMdocVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: specVersion),
            specVersion: specVersion,
            mdocGeneratedNonce: "mock-nonce"
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), inputDescriptorId: "id-1")
        ]
        let (_, tokens) = try await builder.build(credentialInputDescriptorMappings: &mappings)
        return try XCTUnwrap(tokens.first).dataToSign.map { String(format: "%02x", $0) }.joined()
    }

    func testDraft23DataToSignIsUnchanged() async throws {
        let expected =
            "846a5369676e61747572653143a10126405893d818588f847444657669636541757468656e7469636174696f6e83f6f6" +
            "8358209638306b73250a57c42baf6b7095d70fce74ec88b18f4ef6ddf9a3d0c431d5ca5820db0609f1b65f9e8d1c4f70" +
            "5c51de343fece577957a64968c3282266eebdffea77674487761687749364d355f43645f536a356b325f4177756f7267" +
            "2e69736f2e31383031332e352e312e6d444cd81841a0"

        let actual = try await dataToSign(.draft23)

        XCTAssertEqual(actual, expected)
    }

    func testSpecV1DataToSignIsUnchanged() async throws {
        let expected =
            "846a5369676e61747572653143a1012640586cd8185868847444657669636541757468656e7469636174696f6e83f6f6" +
            "82714f70656e494434565048616e646f7665725820a3b94655c7cfd230039f7e76ca3c469bb16b53574aa55e1605e351" +
            "4bae0b9594756f72672e69736f2e31383031332e352e312e6d444cd81841a0"

        let actual = try await dataToSign(.v1)

        XCTAssertEqual(actual, expected)
    }

    func testDeviceResponseForAFixedSignatureIsUnchanged() throws {
        let mapping = CredentialToCredentialQueryIdMapping(
            format: .mso_mdoc, credential: AnyCodable(sampleMdoc), identifier: "id-1", credentialQueryId: "mobile-id"
        )
        // any 64 bytes stand in for an ES256 signature; only the wrapping is locked here
        let signature = Data((0..<64).map { UInt8($0) })

        let result = try MdocVPTokenBuilder(authorizationRequest: getMockAuthorizationRequest(specVersion: .v1)).build(
            credentialToCredentialQueryIdMappings: [mapping],
            unsignedVPTokenResult: (vpTokenSigningPayload: ["id-1": "payload"], unsignedVPTokens: []),
            vpTokenSigningResults: [VPTokenSigningResult(id: "id-1", signedData: signature)]
        )

        let token = try XCTUnwrap(result["mobile-id"]?.first as? MdocVPToken)
        let actual = try decodeBase64UrlCbor(token.base64EncodedDeviceResponse)
        let expected =
            "o2lkb2N1bWVudHOBo2xkZXZpY2VTaWduZWSiamRldmljZUF1dGihb2RldmljZVNpZ25hdHVyZYRDoQEmoPZYQAABAgMEBQYH" +
            "CAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj9qbmFtZVNwYWNlc9gYQaBn" +
            "ZG9jVHlwZXVvcmcuaXNvLjE4MDEzLjUuMS5tRExsaXNzdWVyU2lnbmVkompuYW1lU3BhY2VzoXFvcmcuaXNvLjE4MDEzLjUu" +
            "MYjYGFhYpGhkaWdlc3RJRAJmcmFuZG9tUG2FLLW-amGqmgxhF71nQ-dxZWxlbWVudElkZW50aWZpZXJqaXNzdWVfZGF0ZWxl" +
            "bGVtZW50VmFsdWVqMjAyNS0wNC0xNNgYWFmkaGRpZ2VzdElEBmZyYW5kb21Q3JeFc5mOaF6IXLNh-GyXRnFlbGVtZW50SWRl" +
            "bnRpZmllcmtleHBpcnlfZGF0ZWxlbGVtZW50VmFsdWVqMjAzMC0wNC0xNNgYWJ-kaGRpZ2VzdElEA2ZyYW5kb21QIL6_sBEA" +
            "snZUVxjDD0BsyHFlbGVtZW50SWRlbnRpZmllcnJkcml2aW5nX3ByaXZpbGVnZXNsZWxlbWVudFZhbHVleEh7aXNzdWVfZGF0" +
            "ZT0yMDI1LTA0LTE0LCB2ZWhpY2xlX2NhdGVnb3J5X2NvZGU9QSwgZXhwaXJ5X2RhdGU9MjAzMC0wNC0xNH3YGFhdpGhkaWdl" +
            "c3RJRAFmcmFuZG9tUOOhiP_xEFnrb7zmJlXfvW9xZWxlbWVudElkZW50aWZpZXJvZG9jdW1lbnRfbnVtYmVybGVsZW1lbnRW" +
            "YWx1ZWo5MjYxNDgxMDI02BhYVaRoZGlnZXN0SUQEZnJhbmRvbVCDuJZw1tn5v1LYPe7cC_ZicWVsZW1lbnRJZGVudGlmaWVy" +
            "b2lzc3VpbmdfY291bnRyeWxlbGVtZW50VmFsdWViSU7YGFhYpGhkaWdlc3RJRABmcmFuZG9tUAWDXMwWrWgtjEeKJvRQJ5hx" +
            "ZWxlbWVudElkZW50aWZpZXJqYmlydGhfZGF0ZWxlbGVtZW50VmFsdWVqMTk5NC0xMS0wNtgYWFSkaGRpZ2VzdElEB2ZyYW5k" +
            "b21QSVmbVt1TszUaVytA8n9y03FlbGVtZW50SWRlbnRpZmllcmpnaXZlbl9uYW1lbGVsZW1lbnRWYWx1ZWZKb3NlcGjYGFhV" +
            "pGhkaWdlc3RJRAVmcmFuZG9tUH80e12ZeRYs-pWdKDKkYZZxZWxlbWVudElkZW50aWZpZXJrZmFtaWx5X25hbWVsZWxlbWVu" +
            "dFZhbHVlZkFnYXRoYWppc3N1ZXJBdXRohEOhASahGCFZAgAwggH8MIIBowIUBds23oHVqtVxy5na1WWSDkUv3nwwCgYIKoZI" +
            "zj0EAwIwgYAxCzAJBgNVBAYTAklOMQswCQYDVQQIDAJLQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQKDAVJSUlUQjEM" +
            "MAoGA1UECwwDRENTMRAwDgYDVQQDDAdDRVJUSUZZMSAwHgYJKoZIhvcNAQkBFhFtb3NpcHFhQGdtYWlsLmNvbTAeFw0yNTAy" +
            "MTIxMjMxNTdaFw0yNjAyMTIxMjMxNTdaMIGAMQswCQYDVQQGEwJJTjELMAkGA1UECAwCS0ExEjAQBgNVBAcMCUJBTkdBTE9S" +
            "RTEOMAwGA1UECgwFSUlJVEIxDDAKBgNVBAsMA0RDUzEQMA4GA1UEAwwHQ0VSVElGWTEgMB4GCSqGSIb3DQEJARYRbW9zaXBx" +
            "YUBnbWFpbC5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQHGV67IDUgAc4PaP3TSruktqV7id4YGJV9ethMeeiFBgyW" +
            "T_yJUQqxEDx2Ukpedw8JaS-Ih4rAEqhWkUIlwLapMAoGCCqGSM49BAMCA0cAMEQCIBiOget0HHCUOAfOIUY0RpUVESeUkjU7" +
            "n--MPpxPM6kQAiAN3Yog91QgORuo6Bnk0l_l8e_bIYQ6wplB7o9y5Obi9VkCUdgYWQJMpmd2ZXJzaW9uYzEuMG9kaWdlc3RB" +
            "bGdvcml0aG1nU0hBLTI1Nmdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGx2YWx1ZURpZ2VzdHOhcW9yZy5pc28uMTgw" +
            "MTMuNS4xqAJYIKGFubG-hEhaLOuSXXKxpaVuA828sntNhs8WKXW9eJU-BlggTipm8pr2cfZpV_s6u3yj8zNwTwaeXvCiw_xu" +
            "JNRrDEsDWCBZSlQV7axD8gx6QqfhPzE9kUwnbmemL6POJIwI_fhe_QFYIHmAxk38fMO0s9oSEL5GdUIba17JIQ42ZEv3IDeh" +
            "z9fKBFggXmZZFtvYqlAS8QBZTnx68-al4qFyimqMhBGCPemMir8AWCCJQxeLk9Q9zCxj7Cy_pFQT9Eh8sQGHAFX_Ui2C1CVF" +
            "IAdYIBbiNHJldVsEiRr-VcSOWuw7JunyKq9jHiAwZmIyJWdKBVggPPJDqPCjRrQqZdlx-QlzHIKBOg_32oPcY5j6C1HKYKRt" +
            "ZGV2aWNlS2V5SW5mb6FpZGV2aWNlS2V5pAECIAEhWCAk9csuc8FEz1hEkvCkYBS65DBZ1jGzpDT_b2Z0ZRqabyJYIAZe6qDS" +
            "347X_6-jOeN52pUVBgLfjzYvLuUL4Tn9zECsbHZhbGlkaXR5SW5mb6Nmc2lnbmVkwHQyMDI1LTA0LTE0VDA3OjIxOjI3Wml2" +
            "YWxpZEZyb23AdDIwMjUtMDQtMTRUMDc6MjE6MjdaanZhbGlkVW50aWzAdDIwMjctMDQtMTRUMDc6MjE6MjdaWEDKtrGEuoDs" +
            "qKIeMHy5UjemgDME8-Yo_oJd8ITML1tvOVHmrHNajZrBVJxOfsgKYTNcRfBdnDDD1iNApG4kSBhQZnN0YXR1cwBndmVyc2lv" +
            "bmMxLjA"
        XCTAssertEqual(actual, try decodeBase64UrlCbor(expected))
    }

    private func decodeBase64UrlCbor(_ text: String) throws -> CBOR? {
        try CBOR.decode([UInt8](try Base64Decoder.decodeBase64ToData(text)))
    }
}
