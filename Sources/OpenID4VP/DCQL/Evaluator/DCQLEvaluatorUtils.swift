import Foundation
import SwiftCBOR

private let className = "DCQLUtils"

func expandCredentialTag(_ credential: Credential, jsonLdExpander: JsonLdExpanderCallback?) async throws -> TaggedCredential {
    switch credential.format {
    case .ldp_vc:
        guard let jsonLdExpander = jsonLdExpander else {
            throw InvalidData(message: "JsonLdExpander is required to process w3c credentials", className: className)
        }
        guard let credentialData = credential.data.value as? [String:Any] else {
            throw InvalidData(message: "Credential data is not in the expected format", className: className)
        }
        let credentialSubjectId: String? = (credentialData["credentialSubject"] as? [String:Any] ?? [:])["id"] as? String
        let expandedCredential = try await jsonLdExpander(credentialData)
        let isVcdm2 = (try? isVcdm2Credential(credential.data, className: className)) ?? false
        return W3cTaggedCredential(
            credentialFormat: credential.format,
            hasCryptographicHolderBinding: credentialSubjectId != nil,
            types: expandedCredential["@type"] as? [String] ?? [],
            holderId: credentialSubjectId,
            isVcdm2: isVcdm2
        )
    case .mso_mdoc:
        let (_, decodedMdocCredential) = try decodeMdoc(credential.data, className: className)
        let (_, docTypeString) = try extractMdocDocType(from: decodedMdocCredential, className: className)
        
        return MdocTaggedCredential(
            hasCryptographicHolderBinding: true,
            doctype: docTypeString
        )
    case .dc_sd_jwt, .vc_sd_jwt:
        let (_, sdJWTPayload, _ ) = try extractSdJwtPayload(credential.data, className: className)
        
        return SdJwtTaggedCredential(
            credentialFormat: credential.format,
            hasCryptographicHolderBinding: sdJWTPayload["cnf"] != nil,
            vct: sdJWTPayload["vct"] as? String ?? ""
        )
    }
}


private let supportedVcdm2Algorithms: Set<String> = [
    SignatureAlgorithm.edDsa.rawValue,
    SignatureAlgorithm.es256.rawValue
]

func canPreparePresentation(
    requireCryptographicHolderBinding: Bool,
    walletCredential: TaggedCredential,
    holderAlgorithmCache: HolderAlgorithmCache
) async -> Bool {
    // A query which does not request holder binding is presented as a bare credential with no
    // proof, so no holder key is involved.
    guard requireCryptographicHolderBinding else { return true }
    guard let w3cCredential = walletCredential as? W3cTaggedCredential,
          w3cCredential.isVcdm2,
          let holderId = w3cCredential.holderId else { return true }

    // An unresolvable holder key (e.g. a slow did:web) keeps the credential eligible; VP
    // construction reports the resolution error.
    guard let algorithm = await holderAlgorithmCache.algorithm(for: holderId) else { return true }

    return supportedVcdm2Algorithms.contains(algorithm)
}

/// Memoizes holder DID resolution for the duration of a single evaluation.
internal final class HolderAlgorithmCache {
    private var storage: [String: String?] = [:]

    func algorithm(for holderId: String) async -> String? {
        if let cached = storage[holderId] { return cached }

        let algorithm = try? await getJWSAlgorithm(from: holderId)
        storage[holderId] = algorithm

        return algorithm
    }
}

func convertToProcessedCredentials(_ filteredWalletCredentialIds: [String], _ credentialIdToCredential: [String: Credential]) throws -> [String: any ProcessedCredential] {
    var processedCredentials: [String: any ProcessedCredential] = [:]
    
    for credentialId in filteredWalletCredentialIds {
        guard let credential = credentialIdToCredential[credentialId] else { continue }
        
        switch credential.format {
        case .ldp_vc:
            guard let credentialData = credential.data.value as? [String:Any] else {
                throw InvalidData(message: "Credential data is not in the expected format", className: className)
            }
            
            processedCredentials[credentialId] = (W3cProcessedCredential(
                credentialId: credential.credentialId,
                credentialFormat: credential.format,
                claims: credentialData
            ))
            
        case .mso_mdoc:
            let (_, issuerSigned) = try getMdocDocTypeAndIssuerSigned(from: credential.data, className: className)
            
            var namespaces: [String: [String: Any]] = [:]
            if let nameSpacesCBOR = getValueFromCBORMap(cborMap: issuerSigned, key: "nameSpaces") {
                
                if case let .map(items) = nameSpacesCBOR {
                    for (nsKey, nsValue) in items {
                        if let nsString = extractStringFromCBOR(nsKey), case let .array(elementItems) = nsValue {
                            var elements: [String: Any] = [:]
                            for item in elementItems {
                                if case let .tagged(tag, .byteString(bstr)) = item, tag.rawValue == 24,
                                   let decodedItem = try? CBOR.decode(bstr) {
                                    
                                    if let elementIdCBOR = getValueFromCBORMap(cborMap: decodedItem, key: "elementIdentifier"),
                                       let elementId = extractStringFromCBOR(elementIdCBOR),
                                       let elementValueCBOR = getValueFromCBORMap(cborMap: decodedItem, key: "elementValue") {
                                        
                                        if let unwrappedValue = unwrapCbor(elementValueCBOR) {
                                            elements[elementId] = unwrappedValue
                                        }
                                    }
                                }
                            }
                            namespaces[nsString] = elements
                        }
                    }
                }
            }
            
            processedCredentials[credentialId] = (MdocProcessedCredential(
                credentialId: credential.credentialId,
                namespaces: namespaces
            ))
            
        case .dc_sd_jwt, .vc_sd_jwt:
            let (_, _, fullyResolvedClaims) = try extractSdJwtPayload(credential.data, className: className, decodeDisclosures: true)
            
            processedCredentials[credentialId] = (SdJwtProcessedCredential(
                credentialId: credential.credentialId,
                credentialFormat: credential.format,
                claims: fullyResolvedClaims
            ))
        }
    }
    
    return processedCredentials
}

func resolveClaimsPathPointer(_ path: [AnyCodable], in claims: [String: Any]) throws -> Any? {
    var selection: [Any] = [claims]
    var pathHasWildcard = false

    for pathPointer in path {
        var next: [Any] = []
        if let key = pathPointer.value as? String {
            for element in selection {
                guard let object = element as? [String: Any] else {
                    throw InvalidData(message: "currently selected element(s) is not an object", className: className)
                }
                if let value = object[key] {
                    next.append(value)
                }
            }
        } else if let index = pathPointer.value as? Int {
            for element in selection {
                guard let array = element as? [Any] else {
                    throw InvalidData(message: "currently selected element(s) is not an array", className: className)
                }
                if index >= 0 && index < array.count {
                    next.append(array[index])
                }
            }
        } else if isNullPathPointer(pathPointer.value) {
            pathHasWildcard = true
            for element in selection {
                guard let array = element as? [Any] else {
                    throw InvalidData(message: "currently selected element(s) is not an array", className: className)
                }
                next.append(contentsOf: array)
            }
        } else {
            throw InvalidData(message: "Unexpected path pointer component", className: className)
        }
        selection = next
        if selection.isEmpty {
            return nil
        }
    }
    return pathHasWildcard ? selection : selection.first
}

func isNullPathPointer(_ value: Any?) -> Bool {
    guard let value = value else { return true }
    if value is NSNull { return true }
    let mirror = Mirror(reflecting: value)
    return mirror.displayStyle == .optional && mirror.children.isEmpty
}
