import SwiftCBOR
import XCTest
@testable import OpenID4VP

/// The DeviceResponse for in-person presentation: ISO/IEC 18013-5 clauses 8.3.2.1.2.2 and 9.1.3.
final class MdocProximityTests: XCTestCase {
    private let mdl = "org.iso.18013.5.1.mDL"
    private let mdlNameSpace = "org.iso.18013.5.1"
    private lazy var familyName = TestElement(nameSpace: mdlNameSpace, identifier: "family_name", value: "Doe")
    private lazy var ageOver18 = TestElement(nameSpace: mdlNameSpace, identifier: "age_over_18", value: "true")
    private let signature = Data(repeating: 7, count: 64)

    /// The encoded SessionTranscript inside SessionTranscriptBytes (tag 24 removed).
    private var sessionTranscript: [UInt8] {
        guard case let .tagged(_, .byteString(transcript))? = try? CBOR.decode([UInt8](ProximityVectors.sessionTranscriptBytes)) else {
            fatalError("Session transcript vector is not tag 24")
        }
        return transcript
    }

    private func build(
        _ credentials: [Data],
        sessionTranscriptBytes: Data = ProximityVectors.sessionTranscriptBytes,
        sign: ((MdocSigningInput) async throws -> Data)? = nil
    ) async throws -> CBOR {
        let fixed = signature
        let response = try await MdocProximity.buildDeviceResponse(
            sessionTranscriptBytes: sessionTranscriptBytes, credentials: credentials, sign: sign ?? { _ in fixed }
        )
        return try XCTUnwrap(CBOR.decode([UInt8](response)))
    }

    private func error(of action: () async throws -> Void) async -> Error? {
        do {
            try await action()
            return nil
        } catch {
            return error
        }
    }

    func testBuildsADeviceResponseWithVersion1_0TheDocumentAndStatus0() async throws {
        let response = try await build([TestMdocs.credential(docType: mdl, familyName)])

        XCTAssertEqual(response[text: "version"], "1.0")
        XCTAssertEqual(response[text: "status"], 0)
        XCTAssertEqual(response[text: "documents"].items.count, 1)
    }

    func testTheDocumentCarriesTheDocTypeOfTheMso() async throws {
        let response = try await build([TestMdocs.credential(docType: mdl, familyName)])

        XCTAssertEqual(response[text: "documents"].items.first?[text: "docType"], .utf8String(mdl))
    }

    func testIssuerSignedItemsAreSentByteForByteAsTheyAreInTheCredential() async throws {
        let credential = TestMdocs.credential(docType: mdl, familyName, ageOver18)
        let stored = try XCTUnwrap(CBOR.decode([UInt8](credential)))[text: "nameSpaces"][text: mdlNameSpace].items

        let response = try await build([credential])

        let sent = response[text: "documents"].items.first?[text: "issuerSigned"][text: "nameSpaces"][text: mdlNameSpace].items
        XCTAssertEqual(sent?.map(encodeCanonicalCbor), stored.map(encodeCanonicalCbor))
    }

    func testIssuerAuthIsSentUnchanged() async throws {
        let credential = TestMdocs.credential(docType: mdl, familyName)
        let stored = try XCTUnwrap(CBOR.decode([UInt8](credential)))[text: "issuerAuth"]

        let response = try await build([credential])

        let sent = try XCTUnwrap(response[text: "documents"].items.first)[text: "issuerSigned"][text: "issuerAuth"]
        XCTAssertEqual(encodeCanonicalCbor(sent), encodeCanonicalCbor(stored))
    }

    func testDeviceSignedHoldsEmptyDeviceNameSpacesBytesAndADetachedCoseSign1WithTheWalletsSignature() async throws {
        let response = try await build([TestMdocs.credential(docType: mdl, familyName)])

        let deviceSigned = try XCTUnwrap(response[text: "documents"].items.first)[text: "deviceSigned"]
        XCTAssertEqual(Data(encodeCanonicalCbor(deviceSigned[text: "nameSpaces"])).hex, "d81841a0")
        let sign1 = deviceSigned[text: "deviceAuth"][text: "deviceSignature"].items
        // protected header {1: -7} (ES256), empty unprotected header, null payload
        XCTAssertEqual(sign1, [.byteString([0xa1, 0x01, 0x26]), .map([:]), .null, .byteString([UInt8](signature))])
    }

    func testAResponseForTwoDocumentsHoldsBothInTheGivenOrder() async throws {
        let pidElement = TestElement(nameSpace: "eu.europa.ec.eudi.pid.1", identifier: "given_name", value: "Jane")
        let pid = TestMdocs.credential(docType: "eu.europa.ec.eudi.pid.1", pidElement)

        let response = try await build([TestMdocs.credential(docType: mdl, familyName), pid])

        let docTypes = response[text: "documents"].items.map { $0[text: "docType"] }
        XCTAssertEqual(docTypes, [.utf8String(mdl), .utf8String("eu.europa.ec.eudi.pid.1")])
    }

    func testWithNoCredentialsTheResponseLeavesDocumentsOut() async throws {
        // clause 8.3.2.1.2.2: documents is optional and, when present, holds at least one document
        let response = try await build([])

        XCTAssertEqual(response[text: "documents"], .undefined)
        XCTAssertEqual(response[text: "status"], 0)
    }

    func testTheBase64UrlOverloadGivesTheSameResponseAsTheByteVersion() async throws {
        let credential = TestMdocs.credential(docType: mdl, familyName)
        let fixed = signature

        let fromString = try await MdocProximity.buildDeviceResponse(
            sessionTranscriptBytes: ProximityVectors.sessionTranscriptBytes,
            credentials: [credential.toBase64UrlEncoded()]
        ) { _ in fixed }

        let fromBytes = try await build([credential])
        XCTAssertEqual(try CBOR.decode([UInt8](fromString)), fromBytes)
    }

    func testAcceptsACredentialStoredAsADocumentHoldingIssuerSigned() async throws {
        let issuerSigned = TestMdocs.issuerSigned(docType: mdl, [familyName])
        let wrapped = Data(encodeCanonicalCbor(.map(["docType": .utf8String(mdl), "issuerSigned": issuerSigned])))

        let response = try await build([wrapped])

        XCTAssertEqual(response[text: "documents"].items.first?[text: "issuerSigned"], issuerSigned)
    }

    func testTheResponseIsTheSameBytesEveryTime() async throws {
        // SwiftCBOR writes maps in dictionary order; the response must not depend on it
        let credentials = [TestMdocs.credential(docType: mdl, familyName, ageOver18)]
        let fixed = signature
        var responses: Set<Data> = []

        for _ in 0..<5 {
            responses.insert(try await MdocProximity.buildDeviceResponse(
                sessionTranscriptBytes: ProximityVectors.sessionTranscriptBytes, credentials: credentials
            ) { _ in fixed })
        }

        XCTAssertEqual(responses.count, 1)
    }

    func testSignIsAskedOncePerDocumentWithTheMsoDeviceKeyItsAlgorithmAndTheDeviceAuthenticationData() async throws {
        var asked: [MdocSigningInput] = []
        let fixed = signature

        _ = try await build([TestMdocs.credential(docType: mdl, familyName)]) { input in
            asked.append(input)
            return fixed
        }

        let input = try XCTUnwrap(asked.first)
        XCTAssertEqual(asked.count, 1)
        XCTAssertEqual(input.signatureAlgorithm, "ES256")
        XCTAssertFalse(input.holderKeyReference.isEmpty)
        let expected = try MdocDeviceResponseUtils.deviceAuthenticationDataToSign(sessionTranscript: sessionTranscript, docType: mdl, alg: "ES256")
        XCTAssertEqual(input.dataToSign, Data(expected))
    }

    func testAnErrorFromSignFailsTheCallWithThatSameError() async {
        struct BiometricPromptCancelled: Error {}

        let failure = await error { _ = try await self.build([TestMdocs.credential(docType: self.mdl, self.familyName)]) { _ in
            throw BiometricPromptCancelled()
        } }

        XCTAssertTrue(failure is BiometricPromptCancelled, "\(String(describing: failure))")
    }

    func testAnES256SignatureThatIsNot64RawBytesIsRejectedWithTheExpectedLength() async {
        // a DER-encoded ECDSA signature is 70 to 72 bytes; COSE needs raw r and s
        let failure = await error { _ = try await self.build([TestMdocs.credential(docType: self.mdl, self.familyName)]) { _ in
            Data(repeating: 0, count: 71)
        } }

        let invalidData = failure as? InvalidData
        XCTAssertNotNil(invalidData, "\(String(describing: failure))")
        XCTAssertTrue(invalidData?.message.contains("ES256 signature must be 64 raw bytes (not DER), got 71") == true)
    }

    func testAnEd448DeviceKeyIsSignedWithItsKeyReferenceAndTheResponseHoldsThe114ByteSignature() async throws {
        // EdDSA (alg -8) on Ed448 (crv 7), whose signatures are 114 bytes
        let deviceKey = TestMdocs.edDsaDeviceKey(curve: 7, keyBytes: 57)
        let credential = TestMdocs.credential(docType: mdl, deviceKey: deviceKey, familyName)
        let ed448Signature = Data((0..<114).map { UInt8($0) })
        var keyReference: String?

        let response = try await build([credential]) { input in
            keyReference = input.holderKeyReference
            return ed448Signature
        }

        let referencedKey = try XCTUnwrap(Data(base64UrlEncoded: try XCTUnwrap(keyReference)))
        XCTAssertEqual(try CBOR.decode([UInt8](referencedKey)), deviceKey)
        let sign1 = try XCTUnwrap(response[text: "documents"].items.first)[text: "deviceSigned"][text: "deviceAuth"][text: "deviceSignature"].items
        XCTAssertEqual(sign1.last, .byteString([UInt8](ed448Signature)))
    }

    func testAnEd448DeviceKeyRejectsA64ByteSignatureWithTheExpectedLength() async {
        let credential = TestMdocs.credential(docType: mdl, deviceKey: TestMdocs.edDsaDeviceKey(curve: 7, keyBytes: 57), familyName)

        let failure = await error { _ = try await self.build([credential]) { _ in Data(repeating: 0, count: 64) } }

        let invalidData = failure as? InvalidData
        XCTAssertNotNil(invalidData, "\(String(describing: failure))")
        XCTAssertTrue(invalidData?.message.contains("EdDSA signature must be 114 raw bytes (not DER), got 64") == true)
    }

    func testADeviceKeyAlgorithmTooLargeForIntIsRejectedInsteadOfCrashing() async {
        // alg UInt64.max does not fit in Int
        let deviceKey: CBOR = .map([1: 2, 3: .unsignedInt(UInt64.max), -1: 1])
        let credential = TestMdocs.credential(docType: mdl, deviceKey: deviceKey, familyName)

        let failure = await error { _ = try await self.build([credential]) }

        XCTAssertTrue(failure is InvalidData, "\(String(describing: failure))")
    }

    func testAnEdDsaDeviceKeyCurveTooLargeForIntIsRejectedBeforeAnythingIsSigned() async {
        // crv UInt64.max does not fit in Int
        let credential = TestMdocs.credential(docType: mdl, deviceKey: TestMdocs.edDsaDeviceKey(curve: UInt64.max, keyBytes: 32), familyName)
        var signed = false
        let fixed = signature

        let failure = await error { _ = try await self.build([credential]) { _ in
            signed = true
            return fixed
        } }

        XCTAssertTrue(failure is InvalidData, "\(String(describing: failure))")
        XCTAssertFalse(signed)
    }

    func testAnEdDsaDeviceKeyOnAnUnknownCurveIsRejectedBeforeAnythingIsSigned() async {
        // crv 99 is not an EdDSA curve
        let credential = TestMdocs.credential(docType: mdl, deviceKey: TestMdocs.edDsaDeviceKey(curve: 99, keyBytes: 32), familyName)
        var signed = false
        let fixed = signature

        let failure = await error { _ = try await self.build([credential]) { _ in
            signed = true
            return fixed
        } }

        XCTAssertTrue(failure is InvalidData, "\(String(describing: failure))")
        XCTAssertFalse(signed)
    }

    func testAnItemWhoseDigestDoesNotMatchTheMsoIsRejectedBeforeAnythingIsSigned() async {
        // the wallet re-encoded or changed an item while removing the fields not to share
        let changed = TestElement(nameSpace: mdlNameSpace, identifier: "family_name", value: "Roe")
        let tampered = TestMdocs.issuerSigned(docType: mdl, [familyName]) { items in
            items.mapValues { nameSpaceItems in
                nameSpaceItems.map { TestMdocs.issuerSignedItem(digestId: TestMdocs.digestId(of: $0), changed) }
            }
        }
        var signed = false
        let fixed = signature

        let failure = await error { _ = try await self.build([Data(encodeCanonicalCbor(tampered))]) { _ in
            signed = true
            return fixed
        } }

        XCTAssertTrue(failure is InvalidData, "\(String(describing: failure))")
        XCTAssertFalse(signed)
    }

    func testANamespaceWithNoItemsIsRejected() async {
        // clause 8.3.2.1.2.2: each namespace holds at least one IssuerSignedItemBytes
        let emptied = TestMdocs.issuerSigned(docType: mdl, [familyName]) { items in items.mapValues { _ in [] } }

        let failure = await error { _ = try await self.build([Data(encodeCanonicalCbor(emptied))]) }

        XCTAssertTrue(failure is InvalidData, "\(String(describing: failure))")
    }

    func testTheSameElementTwiceInOneNamespaceIsRejected() async {
        let repeated = TestMdocs.issuerSigned(docType: mdl, [familyName]) { items in items.mapValues { $0 + $0 } }

        let failure = await error { _ = try await self.build([Data(encodeCanonicalCbor(repeated))]) }

        XCTAssertTrue(failure is InvalidData, "\(String(describing: failure))")
    }

    func testTwoCredentialsOfTheSameDocTypeAreRejected() async {
        let failure = await error {
            _ = try await self.build([
                TestMdocs.credential(docType: self.mdl, self.familyName),
                TestMdocs.credential(docType: self.mdl, self.ageOver18),
            ])
        }

        XCTAssertTrue(failure is InvalidData, "\(String(describing: failure))")
    }

    func testAnMsoWithAnUnknownDigestAlgorithmIsRejected() async {
        let md5 = TestMdocs.issuerSigned(docType: mdl, [familyName], digestAlgorithm: "MD5")

        let failure = await error { _ = try await self.build([Data(encodeCanonicalCbor(md5))]) }

        XCTAssertTrue(failure is InvalidData, "\(String(describing: failure))")
    }

    func testACredentialThatIsNotCborIsRejected() async {
        let failure = await error { _ = try await self.build([Data([0x01, 0x02])]) }

        XCTAssertTrue(failure is InvalidData, "\(String(describing: failure))")
    }

    func testACredentialFollowedByMoreBytesIsRejected() async {
        let withTrailingByte = TestMdocs.credential(docType: mdl, familyName) + Data([0x00])

        let failure = await error { _ = try await self.build([withTrailingByte]) }

        XCTAssertTrue(failure is InvalidData, "\(String(describing: failure))")
    }

    func testABareSessionTranscriptWithoutItsTag24ByteStringIsRejected() async {
        let bare = Data(sessionTranscript)

        let failure = await error {
            _ = try await self.build([TestMdocs.credential(docType: self.mdl, self.familyName)], sessionTranscriptBytes: bare)
        }

        XCTAssertTrue(failure is InvalidData, "\(String(describing: failure))")
    }

    func testSessionTranscriptBytesInAByteStringWithoutTag24AreRejected() async {
        let untaggedByteString = Data(CBOR.byteString(sessionTranscript).encode())

        let failure = await error {
            _ = try await self.build([TestMdocs.credential(docType: self.mdl, self.familyName)], sessionTranscriptBytes: untaggedByteString)
        }

        XCTAssertTrue(failure is InvalidData, "\(String(describing: failure))")
    }

    func testAnEmptySessionTranscriptInsideTag24IsRejectedBeforeAnythingIsSigned() async {
        let empty = Data(CBOR.tagged(CBOR.Tag(rawValue: 24), .byteString([])).encode())
        var signed = false
        let fixed = signature

        let failure = await error {
            _ = try await self.build([TestMdocs.credential(docType: self.mdl, self.familyName)], sessionTranscriptBytes: empty) { _ in
                signed = true
                return fixed
            }
        }

        XCTAssertTrue(failure is InvalidData, "\(String(describing: failure))")
        XCTAssertFalse(signed)
    }

    func testASessionTranscriptOfTwoCborItemsIsRejectedBeforeAnythingIsSigned() async {
        // 01 02: the integers 1 and 2 instead of the 3-item SessionTranscript array
        let twoItems = Data(CBOR.tagged(CBOR.Tag(rawValue: 24), .byteString([0x01, 0x02])).encode())
        var signed = false
        let fixed = signature

        let failure = await error {
            _ = try await self.build([TestMdocs.credential(docType: self.mdl, self.familyName)], sessionTranscriptBytes: twoItems) { _ in
                signed = true
                return fixed
            }
        }

        XCTAssertTrue(failure is InvalidData, "\(String(describing: failure))")
        XCTAssertFalse(signed)
    }

    func testSessionTranscriptBytesUnderAnotherTagThan24AreRejected() async {
        // tag 25 instead of 24 around the same transcript bytes
        let otherTag = Data(CBOR.tagged(CBOR.Tag(rawValue: 25), .byteString(sessionTranscript)).encode())

        let failure = await error {
            _ = try await self.build([TestMdocs.credential(docType: self.mdl, self.familyName)], sessionTranscriptBytes: otherTag)
        }

        XCTAssertTrue(failure is InvalidData, "\(String(describing: failure))")
    }

    func testSessionTranscriptBytesFollowedByAnythingElseAreRejected() async {
        let withTrailingByte = ProximityVectors.sessionTranscriptBytes + Data([0x00])

        let failure = await error {
            _ = try await self.build([TestMdocs.credential(docType: self.mdl, self.familyName)], sessionTranscriptBytes: withTrailingByte)
        }

        XCTAssertTrue(failure is InvalidData, "\(String(describing: failure))")
    }
}
