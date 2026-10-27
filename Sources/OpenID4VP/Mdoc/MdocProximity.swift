import Foundation
import SwiftCBOR

private let className = "MdocProximity"
private let deviceResponseVersion = "1.0"
private let statusOk: UInt64 = 0

// ES256 (r ‖ s on P-256) and EdDSA (Ed25519) signatures are both 64 bytes
private let signatureBytes = 64

/// Builds the answer to an in-person (ISO/IEC 18013-5 proximity) mdoc request: the DeviceResponse
/// (clause 8.3.2.1.2.2), which the wallet hands to the transport (Tuvali) as it is.
///
/// The wallet passes each credential with only the data elements to share already in it; nothing
/// is filtered here. Each element must still be exactly as issued, so a credential's items are
/// checked against their digests in the MSO before that credential is signed. For each document the wallet is asked, through
/// the sign callback, to sign the mdoc authentication data (clause 9.1.3) with the credential's
/// device key.
public enum MdocProximity {

    /// [sessionTranscriptBytes] are the SessionTranscriptBytes of the session (#6.24 around the
    /// SessionTranscript), exactly as the transport provides them. [credentials] are mdoc
    /// credentials as CBOR, one per docType. An error thrown by [sign] fails the call unchanged.
    public static func buildDeviceResponse(
        sessionTranscriptBytes: Data,
        credentials: [Data],
        sign: (MdocSigningInput) async throws -> Data
    ) async throws -> Data {
        let sessionTranscript = try MdocDeviceResponseUtils.sessionTranscriptFrom([UInt8](sessionTranscriptBytes), className: className)
        var documents: [CBOR] = []
        var docTypes: Set<String> = []
        for credential in credentials {
            let decoded = try decodeSingleCborItem([UInt8](credential), className: className)
            guard case .map = decoded else { throw InvalidData(message: "mdoc credential is not a CBOR map", className: className) }
            let issuerSigned = try getIssuerSigned(from: decoded, className: className)
            guard case let .map(issuerSignedMap) = issuerSigned else {
                throw InvalidData(message: "issuerSigned is not a CBOR map", className: className)
            }
            let mso = try MdocCredentialUtils.getMso(issuerSignedMap, className: className)
            try MdocCredentialUtils.validateMdocDigests(issuerSigned: issuerSignedMap, mso: mso, className: className)
            guard case let .utf8String(docType)? = mso[.utf8String("docType")] else {
                throw InvalidData(message: "docType missing or invalid in the MSO", className: className)
            }
            guard docTypes.insert(docType).inserted else {
                throw InvalidData(message: "Duplicate Mdoc Credentials with same doctype found", className: className)
            }
            let (holderKeyReference, algorithm) = try extractKeyReferenceAndAlg(fromMso: mso)

            let dataToSign = try MdocDeviceResponseUtils.deviceAuthenticationDataToSign(
                sessionTranscript: sessionTranscript, docType: docType, alg: algorithm
            )
            let signature = try await sign(MdocSigningInput(
                holderKeyReference: holderKeyReference, signatureAlgorithm: algorithm, dataToSign: Data(dataToSign)
            ))
            guard signature.count == signatureBytes else {
                throw InvalidData(
                    message: "\(algorithm) signature must be \(signatureBytes) raw bytes, got \(signature.count)",
                    className: className
                )
            }
            documents.append(try MdocDeviceResponseUtils.document(
                docType: docType, issuerSigned: issuerSigned, alg: algorithm, signature: [UInt8](signature)
            ))
        }

        var response: [CBOR: CBOR] = [
            .utf8String("version"): .utf8String(deviceResponseVersion),
            .utf8String("status"): .unsignedInt(statusOk),
        ]
        // documents, when present, holds at least one document
        if !documents.isEmpty { response[.utf8String("documents")] = .array(documents) }
        return Data(encodeCanonicalCbor(.map(response)))
    }

    /// As [buildDeviceResponse], with each credential given as base64url-encoded CBOR.
    public static func buildDeviceResponse(
        sessionTranscriptBytes: Data,
        credentials: [String],
        sign: (MdocSigningInput) async throws -> Data
    ) async throws -> Data {
        let decoded = try credentials.map { credential -> Data in
            guard let bytes = Data(base64UrlEncoded: credential) else {
                throw InvalidData(message: "mdoc credential is not base64url", className: className)
            }
            return bytes
        }
        return try await buildDeviceResponse(sessionTranscriptBytes: sessionTranscriptBytes, credentials: decoded, sign: sign)
    }
}
