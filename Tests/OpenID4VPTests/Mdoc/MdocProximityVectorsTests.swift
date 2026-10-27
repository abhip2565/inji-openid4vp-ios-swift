import CryptoKit
import SwiftCBOR
import XCTest
@testable import OpenID4VP

/// The DeviceResponse built from credentials signed by an independent test issuer (tuvali-iso-tools
/// generate_mdoc_response.py, cbor2 + cryptography), with the device key signing for real. The same
/// vectors are checked by the Kotlin library.
final class MdocProximityVectorsTests: XCTestCase {
    private var deviceKey: P256.Signing.PrivateKey!

    override func setUpWithError() throws {
        deviceKey = try P256.Signing.PrivateKey(rawRepresentation: ProximityVectors.bytes("deviceKey.privateScalar"))
    }

    private func credential(_ document: String) -> Data { ProximityVectors.bytes("\(document).sharedCredential") }

    private func build(_ documents: [String], asked: ((MdocSigningInput) -> Void)? = nil) async throws -> Data {
        let key = deviceKey!
        return try await MdocProximity.buildDeviceResponse(
            sessionTranscriptBytes: ProximityVectors.sessionTranscriptBytes,
            credentials: documents.map(credential)
        ) { input in
            asked?(input)
            // signs like a wallet: ECDSA P-256 with SHA-256, raw r ‖ s
            return try key.signature(for: input.dataToSign).rawRepresentation
        }
    }

    func testTheDeviceIsAskedToSignExactlyTheDataComputedIndependentlyForTheMdl() async throws {
        var asked: [MdocSigningInput] = []

        _ = try await build(["mdl"]) { asked.append($0) }

        XCTAssertEqual(asked.map(\.dataToSign.hex), [ProximityVectors.string("mdl.dataToSign")])
    }

    func testEachOfTwoDocumentsGetsItsOwnDataToSign() async throws {
        var asked: [MdocSigningInput] = []

        _ = try await build(["mdl", "pid"]) { asked.append($0) }

        XCTAssertEqual(asked.map(\.dataToSign.hex), ["mdl", "pid"].map { ProximityVectors.string("\($0).dataToSign") })
    }

    func testTheHolderKeyReferenceIsTheDeviceKeyFromTheMso() async throws {
        var asked: [MdocSigningInput] = []

        _ = try await build(["mdl"]) { asked.append($0) }

        let reference = try XCTUnwrap(Data(base64UrlEncoded: try XCTUnwrap(asked.first).holderKeyReference))
        let expected = try CBOR.decode([UInt8](ProximityVectors.bytes("deviceKey.coseKey")))
        XCTAssertEqual(try CBOR.decode([UInt8](reference)), expected)
    }

    func testIssuerSignedInTheResponseIsTheSharedCredentialAsPassedIn() async throws {
        let built = try await build(["mdl"])
        let response = try XCTUnwrap(CBOR.decode([UInt8](built)))

        let issuerSigned = try XCTUnwrap(response[text: "documents"].items.first)[text: "issuerSigned"]
        XCTAssertEqual(Data(encodeCanonicalCbor(issuerSigned)).hex, ProximityVectors.string("mdl.sharedCredential"))
    }

    func testWithAFixedSignatureTheResponseIsByteForByteTheOneBuiltIndependently() async throws {
        // the same expected bytes are checked by the Kotlin library, so both platforms send the same response
        let signature = ProximityVectors.bytes("withFixedSignature.signature")

        let response = try await MdocProximity.buildDeviceResponse(
            sessionTranscriptBytes: ProximityVectors.sessionTranscriptBytes,
            credentials: ["mdl", "pid"].map(credential)
        ) { _ in signature }

        XCTAssertEqual(response.hex, ProximityVectors.string("withFixedSignature.mdlAndPidDeviceResponse"))
    }

    func testPrintsTheResponseForTheTwoDocumentsForVerifyDeviceResponsePy() async throws {
        let response = try await build(["mdl", "pid"])

        // copy the line from the test log into a file for tuvali-iso-tools/verify_device_response.py
        print("DEVICE-RESPONSE-HEX \(response.hex)")
        XCTAssertEqual(try XCTUnwrap(CBOR.decode([UInt8](response)))[text: "documents"].items.count, 2)
    }
}
