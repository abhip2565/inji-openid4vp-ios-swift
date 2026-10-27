import Foundation
import SwiftCBOR

private let arrayOfFour: UInt8 = 0x84
private let tagEncodedCbor: UInt64 = 24

/// Building blocks of an mdoc DeviceResponse, shared by online (OpenID4VP) and in-person presentation.
internal enum MdocDeviceResponseUtils {

    /// What the mdoc signs for mdoc authentication (ISO/IEC 18013-5 clause 9.1.3.4): the COSE
    /// Sig_structure over DeviceAuthenticationBytes = #6.24(bstr .cbor ["DeviceAuthentication",
    /// SessionTranscript, DocType, DeviceNameSpacesBytes]).
    ///
    /// [sessionTranscript] is the encoded SessionTranscript and is spliced in exactly as given: the
    /// reader rebuilds these bytes from its own copy of the transcript, so they must not be decoded and
    /// re-encoded. DeviceNameSpaces is always empty, as Inji returns no device-signed data elements.
    static func deviceAuthenticationDataToSign(sessionTranscript: [UInt8], docType: String, alg: String) throws -> [UInt8] {
        let deviceAuthentication = [arrayOfFour]
            + CBOR.utf8String("DeviceAuthentication").encode()
            + sessionTranscript
            + CBOR.utf8String(docType).encode()
            + emptyDeviceNameSpacesBytes().encode()
        let deviceAuthenticationBytes = CBOR.tagged(CBOR.Tag(rawValue: tagEncodedCbor), .byteString(deviceAuthentication)).encode()
        return try CoseSignature1Utils.createSignature1Structure(payload: deviceAuthenticationBytes, alg: alg)
    }

    /// One returned document of a DeviceResponse (clause 8.3.2.1.2.2): {docType, issuerSigned,
    /// deviceSigned}. [issuerSigned] is used as given. deviceSigned holds no device-signed data
    /// elements and the wallet's [signature] as a detached COSE_Sign1 (clause 9.1.3.6).
    static func document(docType: String, issuerSigned: CBOR, alg: String, signature: [UInt8]) throws -> CBOR {
        let deviceSignature = try CoseSignature1Utils.createCoseSign1(signingAlgorithm: alg, signature: signature)
        let deviceSigned = CBOR.map([
            .utf8String("deviceAuth"): .map([.utf8String("deviceSignature"): deviceSignature]),
            .utf8String("nameSpaces"): emptyDeviceNameSpacesBytes(),
        ])
        return CBOR.map([
            .utf8String("issuerSigned"): issuerSigned,
            .utf8String("docType"): .utf8String(docType),
            .utf8String("deviceSigned"): deviceSigned,
        ])
    }

    /// The encoded SessionTranscript inside SessionTranscriptBytes (#6.24(bstr .cbor SessionTranscript),
    /// clause 9.1.5.1), to be passed to [deviceAuthenticationDataToSign] as it is. Anything other than
    /// exactly one tag 24 byte string is rejected.
    static func sessionTranscriptFrom(_ sessionTranscriptBytes: [UInt8], className: String) throws -> [UInt8] {
        let item: CBOR
        do {
            item = try decodeSingleCborItem(sessionTranscriptBytes, className: className)
        } catch {
            throw InvalidData(message: "Session transcript bytes are not one CBOR item", className: className)
        }
        guard case let .tagged(tag, .byteString(transcript)) = item, tag.rawValue == tagEncodedCbor else {
            throw InvalidData(message: "Session transcript bytes must be one tag 24 byte string", className: className)
        }
        return transcript
    }

    /// DeviceNameSpacesBytes = #6.24(bstr .cbor {}): no device-signed data elements.
    private static func emptyDeviceNameSpacesBytes() -> CBOR {
        .tagged(CBOR.Tag(rawValue: tagEncodedCbor), .byteString(CBOR.map([:]).encode()))
    }
}
