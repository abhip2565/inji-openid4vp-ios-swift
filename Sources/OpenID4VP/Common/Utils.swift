import Foundation
import JSONWebKey
import CryptoKit
import SwiftCBOR

// COSE algorithm identifiers (RFC 8152 / COSE Algorithms)
private let COSE_ALG_ES256: Int = -7
private let COSE_ALG_EDDSA: Int = -8

// COSE curve identifiers (RFC 8152 / COSE Keys)
private let COSE_CRV_P256: Int = 1
private let COSE_CRV_ED25519: Int = 6

// CBOR tag identifiers (RFC 7049 / CBOR Tags)
private let CBOR_TAG_ENCODED_CBOR: Int = 24

enum JWSPart: Int {
    case header = 0, payload, signature
}

func isJWS(_ input: String) -> Bool {
    return input.split(separator: ".").count == 3
}

func base64URLEscaped(_ base64String: String) -> String {
    return base64String
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

func getStringValue(_ value: Any?) -> String? {
    return value as? String
}

// RFC 3986 (https://www.rfc-editor.org/rfc/rfc3986#section-3) https URI, compiled once
private let urlValidationRegex: NSRegularExpression? = {
    let pattern = #"^https://(?:[\w-]+\.)+[\w-]+(?::\d+)?(?:/(?:[\w\-.~!$&'()*+,;=:@]|%[0-9A-Fa-f]{2})*)*(?:\?(?:[\w\-.~!$&'()*+,;=:@/?]|%[0-9A-Fa-f]{2})*)?(?:#(?:[\w\-.~!$&'()*+,;=:@/?]|%[0-9A-Fa-f]{2})*)?$"#
    return try? NSRegularExpression(pattern: pattern)
}()

public func isValidUri(_ urlString: String) -> Bool {
    guard let regex = urlValidationRegex else { return false }
    let range = NSRange(urlString.startIndex..., in: urlString)
    guard let match = regex.firstMatch(in: urlString, options: [], range: range) else { return false }
    // require the match to span the whole string (ICU's `$` allows a trailing newline)
    return match.range == range
}

func convertToInstance<T: Decodable>(_ dictionary: [String: Any], as type: T.Type) throws -> T {
    let data = try JSONSerialization.data(withJSONObject: dictionary, options: [])
    return try JSONDecoder().decode(T.self, from: data)
}

func convertToInstance<T: Decodable>(_ input: String, as type: T.Type, fieldPath: [String] = [], className: String = "Utils") throws -> T {
    guard let jsonData = input.data(using: .utf8) else {
        throw UTF8EncodingFailed( fieldPath: fieldPath, className: className)
    }
    
    return try jsonData.toInstance(as: T.self)
}

func toData(_ input: [String: Any]) throws -> Data {
    var processedInput: [String: Any] = [:]
    
    for (key, value) in input {
        if let encodableValue = value as? Encodable {
            if let converted = encodableValue.toDictionary() {
                processedInput[key] = converted
            } else {
                processedInput[key] = value
            }
        } else {
            processedInput[key] = value
        }
    }
    guard JSONSerialization.isValidJSONObject(processedInput) else {
        throw JsonEncodingFailed(
            fieldPath: "processedInput",
            errorMessage: "Invalid JSON object",
            className: "utils"
        )
    }
    return try JSONSerialization.data(withJSONObject: processedInput, options: [])
}

func sha256Hash(from data: CBOR) -> [UInt8] {
    let hash: SHA256.Digest = SHA256.hash(data: CBOR.encode(data))
    return ([UInt8])(Data(hash))
}

func wrapError(_ error: Error, customError: (String) -> Error) -> Error {
    if type(of: error) == OpenID4VPException.self {
        return error
    } else {
        return customError(error.localizedDescription)
    }
}


func hashData(_ data: String, hashAlgorithm: String = HashAlgorithm.sha256.rawValue, className: String) throws -> Data {
    guard let inputData = data.data(using: .utf8) else {
        throw UTF8EncodingFailed(fieldPath: "hashInput", className: className)
    }
    
    let algorithm = HashAlgorithm(rawValue: hashAlgorithm)
    
    switch algorithm {
    case .sha256:
        let hash = SHA256.hash(data: inputData)
        return Data(hash)
    case .sha384:
        let hash = SHA384.hash(data: inputData)
        return Data(hash)
    case .sha512:
        let hash = SHA512.hash(data: inputData)
        return Data(hash)
    default:
        throw UnsupportedOperationException(message: "Hash algorithm \(hashAlgorithm) is not supported", className: className)
    }
}

func createNestedPath(id: String, nestedPath: String?, format: FormatType) -> PathNested? {
    guard let nestedPath = nestedPath else { return nil }
    return PathNested(id: id, format: format, path: nestedPath)
}

func createDescriptorMapPath(_ index: Int) -> String {
    return "$[\(index)]"
}

func resolveJwksFromUri(_ uri: String, networkManager: NetworkManaging, className: String) async throws -> JWKSet {
    do {
        let response = try await networkManager.sendHTTPRequest(url: uri, method: .get, bodyParams: nil, headers: nil)
        if(!response.isOK){
            throw InvalidData(
                message: "Error while fetching jwks information, status code: \(response.statusCode) with body: \(response.body)",
                className: className
            )
        }
        let data = try response.body.data(using: .utf8) ?? {
            throw InvalidData(
                message: "unable to convert the jwks response to data",
                className: className
            )
        }()
        return try data.toInstance(as: JWKSet.self)
    } catch {
        throw InvalidData(
            message: "Public key extraction failed - Unable to fetch/parse jwks from \(uri) due to \(error.localizedDescription)",
            className: className,
            code: OpenID4VPErrorCodes.invalidRequestObject
        )
    }
}

internal func validate(_ value: String, fieldPath: String,className: String) throws {
    if !isNeitherNullNorEmpty(field: value) || (value == "null") {
        throw InvalidInput(fieldPath: [fieldPath], className: className)
    }
}

func resolveMdocKeyAndAlg(_ mdocCredential: String) throws -> (keyRef: String, alg: String) {
    
    
    guard let data = Data(base64UrlEncoded: mdocCredential) else {
        throw InvalidData(
            message: "Invalid base64url mdoc credential",
            className: "OpenID4VPUtils"
        )
    }
    
    var decoded = try CBORDecoder(input: [UInt8](data)).decodeItem()
    guard let decodedMdoc = decoded else {
        throw InvalidData(
            message: "Invalid base64url mdoc credential",
            className: "OpenID4VPUtils"
        )
    }
    
    let issuerSigned = try getIssuerSigned(from: decodedMdoc, className: "OpenID4VPUtils")
    guard case let CBOR.map(issuerSignedMap) = issuerSigned else {
        throw InvalidData(message: "issuerSigned is not a map", className: "OpenID4VPUtils")
    }

    
    guard let issuerAuth = issuerSignedMap[CBOR.utf8String("issuerAuth")],
              case let CBOR.array(issuerAuthArray) = issuerAuth,
              issuerAuthArray.count > 2,
              case let CBOR.byteString(payloadBytes) = issuerAuthArray[2] else {
            throw InvalidData(message: "issuerAuth payload missing", className: "OpenID4VPUtils")
        }
    
    
    decoded = try CBORDecoder(input: payloadBytes).decodeItem()
    
    
    if case let CBOR.tagged(tag, inner)? = decoded, tag.rawValue == CBOR_TAG_ENCODED_CBOR {
        guard case let CBOR.byteString(innerBytes) = inner else {
            throw InvalidData(message: "cbor tag 24 inner not bstr", className: "OpenID4VPUtils")
        }
        decoded = try CBORDecoder(input: innerBytes).decodeItem()
    }
    
    
    guard case let CBOR.map(msoMap)? = decoded else {
        throw InvalidData(message: "deviceKey missing", className: "OpenID4VPUtils")
    }
    return try extractKeyReferenceAndAlg(fromMso: msoMap)
}

/// The holder key reference (base64url COSE_Key) and the signing algorithm of an MSO's deviceKey.
func extractKeyReferenceAndAlg(fromMso msoMap: [CBOR: CBOR]) throws -> (keyRef: String, alg: String) {
    guard let deviceKeyInfo = msoMap[CBOR.utf8String("deviceKeyInfo")],
          case let CBOR.map(deviceKeyInfoMap) = deviceKeyInfo,
          let deviceKey = deviceKeyInfoMap[CBOR.utf8String("deviceKey")],
          case let CBOR.map(deviceKeyMap) = deviceKey else {
        throw InvalidData(message: "deviceKey missing", className: "OpenID4VPUtils")
    }
    
    
    let keyBytes = Data(cborEncode(deviceKey))
    let keyRef = keyBytes.toBase64UrlEncoded()
    
    
    if let algItem = deviceKeyMap[CBOR.unsignedInt(3)]{
        let coseAlg = try readCoseInt(algItem)
        switch coseAlg {
        case COSE_ALG_ES256: return (keyRef, "ES256")
        case COSE_ALG_EDDSA: return (keyRef, "EdDSA")
        default:
            throw InvalidData(message: "Unsupported COSE alg \(coseAlg)", className: "OpenID4VPUtils")
        }
    }
    
    
    guard let crvItem = deviceKeyMap[CBOR.negativeInt(0)] else {
        throw InvalidData(message: "crv missing for alg inference", className: "OpenID4VPUtils")
    }
    
    let crv = try readCoseInt(crvItem)
    switch crv {
    case COSE_CRV_P256: return (keyRef, "ES256")
    case COSE_CRV_ED25519: return (keyRef, "EdDSA")
    default:
        throw InvalidData(message: "Unsupported crv \(crv)", className: "OpenID4VPUtils")
    }
}

func readCoseInt(_ cbor: CBOR) throws -> Int {
    switch cbor {
    case .unsignedInt(let v): return Int(v)
    case .negativeInt(let v): return -1 - Int(v)
    default:
        throw InvalidData(message: "Invalid COSE integer type", className: "OpenID4VPUtils")
    }
}

func constructSigningResults(
    unsignedVPTokenResults: [FormatType: (VPTokenSigningPayload, [UnsignedVPToken])],
    signingResults: [VPTokenSigningResult]
) throws -> [FormatType: [VPTokenSigningResult]] {
    let expectedIdentifiers = Set(unsignedVPTokenResults.values.flatMap { $0.1.map(\.id) })
    let unexpectedIdentifiers = Set(signingResults.map(\.id)).subtracting(expectedIdentifiers)
    guard unexpectedIdentifiers.isEmpty else {
        throw InvalidData(
            message: "Unexpected VP token signing result for credential identifier(s): \(unexpectedIdentifiers.sorted().joined(separator: ", "))",
            className: "Openid4VPUtils"
        )
    }
    
    var vpTokenSigningResultsByFormat: [FormatType: [VPTokenSigningResult]] = [:]

    for (format, unsignedVPTokenResultByFormat) in unsignedVPTokenResults {
        let unsignedTokens = unsignedVPTokenResultByFormat.1
        
        var resultsForFormat: [VPTokenSigningResult] = []
        for unsignedToken in unsignedTokens {
            let identifier = unsignedToken.id
            let vpTokenSigningResult = try getVPTokenSigningResult(vpTokenSigningResults: signingResults, identifier: identifier, className: "Openid4VPUtils")
            resultsForFormat.append(vpTokenSigningResult)
        }
        if(!resultsForFormat.isEmpty){
            vpTokenSigningResultsByFormat[format] = resultsForFormat
        }
    }

    return vpTokenSigningResultsByFormat
}

func resolveSdJwtKeyAndAlg(_ sdJwtCredential: String) async throws -> (keyRef: String, alg: String) {
    let parts = sdJwtCredential.split(separator: "~")
    guard let sdJwt = parts.first else {
        throw InvalidData(message: "Invalid SD-JWT credential format", className: "OpenID4VPUtils")
    }
    
    let jwsParts = sdJwt.split(separator: ".")
    guard jwsParts.count >= 2 else {
        throw InvalidData(message: "Invalid SD-JWT JWS format", className: "OpenID4VPUtils")
    }
    
    guard let payloadData = Data(base64UrlEncoded: String(jwsParts[1])) else {
        throw InvalidData(message: "Invalid SD-JWT payload encoding", className: "OpenID4VPUtils")
    }
    
    guard let json = try JSONSerialization.jsonObject(with: payloadData) as? [String: Any],
          let cnf = json["cnf"] as? [String: Any],
          let kid = cnf["kid"] as? String else {
        throw InvalidData(message: "cnf.kid missing in SD-JWT", className: "OpenID4VPUtils")
    }
    
    
    let resolver = DidPublicKeyResolver()
    let publicKey = try await resolver.resolve(
        uri: kid.trimmingCharacters(in: CharacterSet(charactersIn: "=")),
        keyId: nil
    )
    
    
    let alg: String
    
    switch publicKey {
    case .ed25519:
        alg = "EdDSA"
        
    case .secKey:
        alg = "ES256"
    }
    
    return (kid, alg)
}

func getEncryptionKey(_ jwks: JWKSet, _ supportedEncryptionAlgorithms: [String]) throws -> JWK {
    let matchingKeys = jwks.keys.filter { supportedEncryptionAlgorithms.contains($0.algorithm ?? "") }

    guard !matchingKeys.isEmpty else {
        throw InvalidData(
            message: "No jwk matching the specified algorithm found for encryption",
            className: "OpenID4VPUtils"
        )
    }

    if matchingKeys.count == 1 {
        return matchingKeys[0]
    }

    let encryptionKeys = matchingKeys.filter { $0.publicKeyUse == .encryption }

    if encryptionKeys.count == 1 {
        return encryptionKeys[0]
    }

    throw InvalidData(
        message: "Multiple jwks matching the specified algorithm found for encryption",
        className: "OpenID4VPUtils"
    )
}

func matchingDCQLCredentialQuery(_  authorizationRequest: AuthorizationRequest, for credentialQueryId: String, className: String) throws -> CredentialQuery {
    let matchingCredentialQuery = try (authorizationRequest as? AuthorizationDcqlRequest)?.dcqlQuery.credentials.first(where: { $0.id == credentialQueryId }) ?? {
        throw InvalidData(message: "No matching credential query found for credentialQueryId: \(credentialQueryId)", className: className)
    }()
    return matchingCredentialQuery
}

private enum DIDPrefix {
    static let key = "did:key:"
    static let jwk = "did:jwk:"
}

// MARK: - Utility Function
/// Extracts the JWS 'alg' string based on a Subject ID (DID) without hardcoded magic strings.
/// Reference: https://www.w3.org/TR/vc-data-model-1.1/#identifiers
func getJWSAlgorithm(from uri: String) async throws -> String {
    
    if(uri.hasPrefix("did:")) {
        return try await DidPublicKeyResolver().getJWSAlgorithm(uri: uri)
    }
    
    throw UnsupportedOperationException(message: "Unsupported identifier format for JWS algorithm resolution", className: "OpenID4VPUtils")
}

// MARK: - JWK Utility Functions

private let jwkUtilsClassName = "JwkUtils"

func resolveAlgFromJwk(_ jwk: [String: Any]) throws -> String {
    let parsedJwk: JWK
    do {
        parsedJwk = try convertToInstance(jwk, as: JWK.self)
    } catch {
        throw InvalidData(message: "Failed to decode JWK: \(error.localizedDescription)", className: jwkUtilsClassName)
    }

    return try parsedJwk.resolveJWSAlgorithm(className: jwkUtilsClassName)
}

func serializeJwkToJson(_ jwk: [String: Any]) throws -> String {
    let data = try JSONSerialization.data(withJSONObject: jwk, options: [.sortedKeys])
    guard let jsonString = String(data: data, encoding: .utf8) else {
        throw InvalidData(message: "Failed to serialize JWK to JSON string", className: jwkUtilsClassName)
    }
    return jsonString
}
