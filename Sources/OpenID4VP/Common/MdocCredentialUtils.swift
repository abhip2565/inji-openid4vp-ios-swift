import CryptoKit
import SwiftCBOR

/// Normalizes both mDoc formats to return just the issuerSigned CBOR map.
/// - Format 1 `{nameSpaces, issuerAuth}`: the whole map IS the issuerSigned.
/// - Format 2 `{docType, issuerSigned: {nameSpaces, issuerAuth}}`: extracts the nested issuerSigned.
func getIssuerSigned(from decodedMdoc: CBOR, className: String) throws -> CBOR {
    if getValueFromCBORMap(cborMap: decodedMdoc, key: "issuerAuth") != nil {
        return decodedMdoc
    } else if let issuerSigned = getValueFromCBORMap(cborMap: decodedMdoc, key: "issuerSigned") {
        return issuerSigned
    } else {
        throw InvalidData(message: "Invalid mDoc structure: neither issuerAuth nor issuerSigned found", className: className)
    }
}

func decodeMdoc(_ credential: AnyCodable, className: String) throws -> (mdocCredential: String, decodedMdoc: CBOR) {
    let mdocCredential = try extractMdocString(from: credential, className: className)
    
    guard let decodedMdoc = try? decodeCBOR(base64EncodedInput: mdocCredential) else {
        throw InvalidData(
            message: "Invalid Verifiable Credential: Error while decoding credential",
            className: className
        )
    }
    
    return (mdocCredential, decodedMdoc)
}

func extractMdocString(from credential: AnyCodable, className: String) throws -> String {
    guard let mdocCredential = credential.value as? String else {
        throw InvalidData(
            message: "MDOC credential is not a String",
            className: AuthorizationResponseHandler.className
        )
    }
    
    return mdocCredential
}

func extractMdocDocType(from decodedCredential: CBOR, className: String) throws -> (docType: CBOR, docTypeString: String) {
    if let issuerAuth = getValueFromCBORMap(cborMap: decodedCredential, key: "issuerAuth"){
        switch issuerAuth {
        case .array(let issuerAuthArray):
            guard issuerAuthArray.count > 2,
                  case let .byteString(msoBytes) = issuerAuthArray[2] else {
                throw InvalidData(
                    message: "issuerAuth payload missing or invalid",
                    className: className
                )
            }
            var decodedMso = try CBORDecoder(input: msoBytes).decodeItem()
            if case let CBOR.tagged(tag, inner)? = decodedMso, tag.rawValue == 24 {
                guard case let CBOR.byteString(innerBytes) = inner else {
                    throw InvalidData(
                        message: "cbor tag 24 inner not bstr",
                        className: className
                    )
                }
                decodedMso = try CBORDecoder(input: innerBytes).decodeItem()
            }
            guard let decodedMso = decodedMso else {
                throw InvalidData(
                    message: "Failed to decode MSO",
                    className: className
                )
            }
            if let docType = getValueFromCBORMap(cborMap: decodedMso, key: "docType"),
               let docTypeString = extractStringFromCBOR(docType) {
                return (docType, docTypeString)
            } else {
                throw InvalidData(
                    message: "docType missing or invalid in issuerAuth",
                    className: className
                )
            }
        default:
            throw InvalidData(
                message: "issuerAuth is not an array",
                className: className
            )
        }
    } else  if let docType = getValueFromCBORMap(cborMap: decodedCredential, key: "docType"),
               let docTypeString = extractStringFromCBOR(docType) {
        return (docType, docTypeString)
    } else {
        throw InvalidData(
            message: "docType missing or invalid in credential",
            className: className
        )
    }
}

func getMdocDocTypeAndIssuerSigned(from credential: AnyCodable, className: String) throws -> (docType: CBOR, issuerSigned: CBOR) {
    let (_, decodedCredential) = try decodeMdoc(credential, className: className)
    let issuerSigned = try getIssuerSigned(from: decodedCredential, className: className)
    let (docType, _) = try extractMdocDocType(from: issuerSigned, className: className)
    return (docType, issuerSigned)
}

// MARK: - Reading and checking a credential for in-person presentation

private let tagEncodedCbor: UInt64 = 24

enum MdocCredentialUtils {

    /// Throws InvalidData unless every IssuerSignedItemBytes of [issuerSigned] matches its digest in
    /// the [mso] (ISO/IEC 18013-5 clause 9.1.2.5, over the item as it will be sent), and each
    /// namespace holds at least one item and no element twice (clause 8.3.2.1.2.2).
    static func validateMdocDigests(issuerSigned: [CBOR: CBOR], mso: [CBOR: CBOR], className: String) throws {
        guard let nameSpaces = issuerSigned[.utf8String("nameSpaces")] else { return }
        guard case let .map(nameSpaceMap) = nameSpaces else {
            throw InvalidData(message: "nameSpaces is not a map", className: className)
        }
        guard case let .utf8String(digestAlgorithm)? = mso[.utf8String("digestAlgorithm")],
              let digest = digestFunction(digestAlgorithm) else {
            throw InvalidData(message: "MSO digestAlgorithm is missing or not SHA-256, SHA-384 or SHA-512", className: className)
        }
        guard case let .map(valueDigests)? = mso[.utf8String("valueDigests")] else {
            throw InvalidData(message: "MSO valueDigests is missing", className: className)
        }

        for (nameSpaceKey, nameSpaceItems) in nameSpaceMap {
            guard case let .utf8String(nameSpace) = nameSpaceKey else {
                throw InvalidData(message: "A namespace is not a text string", className: className)
            }
            guard case let .array(items) = nameSpaceItems else {
                throw InvalidData(message: "Namespace \(nameSpace) does not hold an array", className: className)
            }
            guard !items.isEmpty else {
                throw InvalidData(message: "Namespace \(nameSpace) holds no data elements", className: className)
            }
            guard case let .map(digests)? = valueDigests[nameSpaceKey] else {
                throw InvalidData(message: "The MSO has no digests for namespace \(nameSpace)", className: className)
            }
            var seenElements: Set<String> = []
            for item in items {
                let (digestId, element) = try readIssuerSignedItem(item, nameSpace: nameSpace, className: className)
                guard seenElements.insert(element).inserted else {
                    throw InvalidData(message: "Data element \(element) appears twice in \(nameSpace)", className: className)
                }
                guard case let .byteString(expected)? = digests[.unsignedInt(digestId)] else {
                    throw InvalidData(message: "The MSO has no digest for \(element) in \(nameSpace)", className: className)
                }
                guard digest(encodeCanonicalCbor(item)) == expected else {
                    throw InvalidData(
                        message: "Data element \(element) in \(nameSpace) does not match its digest in the MSO",
                        className: className
                    )
                }
            }
        }
    }

    /// The MSO inside issuerAuth: its payload, MobileSecurityObjectBytes = #6.24(bstr .cbor MSO).
    static func getMso(_ issuerSigned: [CBOR: CBOR], className: String) throws -> [CBOR: CBOR] {
        guard case let .array(issuerAuth)? = issuerSigned[.utf8String("issuerAuth")], issuerAuth.count > 2,
              case let .byteString(payload) = issuerAuth[2] else {
            throw InvalidData(message: "issuerAuth payload missing", className: className)
        }
        var decoded = try decodeSingleCborItem(payload, className: className)
        if case let .tagged(tag, .byteString(inner)) = decoded, tag.rawValue == tagEncodedCbor {
            decoded = try decodeSingleCborItem(inner, className: className)
        }
        guard case let .map(mso) = decoded else {
            throw InvalidData(message: "MSO is not a map", className: className)
        }
        return mso
    }

    /// The digestID and elementIdentifier of one IssuerSignedItemBytes (tag 24).
    private static func readIssuerSignedItem(_ item: CBOR, nameSpace: String, className: String) throws -> (UInt64, String) {
        guard case let .tagged(tag, .byteString(bytes)) = item, tag.rawValue == tagEncodedCbor else {
            throw InvalidData(message: "An item in \(nameSpace) is not IssuerSignedItemBytes (tag 24)", className: className)
        }
        guard case let .map(decoded) = try decodeSingleCborItem(bytes, className: className) else {
            throw InvalidData(message: "An item in \(nameSpace) is not an IssuerSignedItem map", className: className)
        }
        guard case let .unsignedInt(digestId)? = decoded[.utf8String("digestID")] else {
            throw InvalidData(message: "An item in \(nameSpace) has no digestID", className: className)
        }
        guard case let .utf8String(element)? = decoded[.utf8String("elementIdentifier")] else {
            throw InvalidData(message: "An item in \(nameSpace) has no elementIdentifier", className: className)
        }
        return (digestId, element)
    }

    /// Table 21 digest algorithm identifiers.
    private static func digestFunction(_ identifier: String) -> (([UInt8]) -> [UInt8])? {
        switch identifier {
        case "SHA-256": return { [UInt8](SHA256.hash(data: $0)) }
        case "SHA-384": return { [UInt8](SHA384.hash(data: $0)) }
        case "SHA-512": return { [UInt8](SHA512.hash(data: $0)) }
        default: return nil
        }
    }
}
