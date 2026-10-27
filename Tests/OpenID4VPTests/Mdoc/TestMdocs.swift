import CryptoKit
import Foundation
import SwiftCBOR
@testable import OpenID4VP

/// The shared ISO/OVP test vectors in Resources/mdoc/proximity-vectors.json (tuvali-iso-tools
/// generate_mdoc_response.py, cbor2 + cryptography), the same file the Kotlin library checks.
enum ProximityVectors {
    static let json: [String: Any] = {
        guard let url = Bundle.module.url(forResource: "proximity-vectors", withExtension: "json", subdirectory: "mdoc"),
              let data = try? Data(contentsOf: url),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { fatalError("mdoc/proximity-vectors.json not found in the test bundle") }
        return object
    }()

    /// The string at [path] (keys separated by dots).
    static func string(_ path: String) -> String {
        var value: Any = json
        for key in path.split(separator: ".") {
            guard let object = value as? [String: Any], let next = object[String(key)] else { fatalError("No vector \(path)") }
            value = next
        }
        guard let text = value as? String else { fatalError("Vector \(path) is not a string") }
        return text
    }

    static func bytes(_ path: String) -> Data { Data(string(path).hexBytes) }

    /// SessionTranscriptBytes of a QR + BLE session, as Tuvali hands them over.
    static var sessionTranscriptBytes: Data { bytes("sessionTranscriptBytes") }
}

extension String {
    var hexBytes: [UInt8] {
        stride(from: 0, to: count, by: 2).map { offset in
            let start = index(startIndex, offsetBy: offset)
            guard let byte = UInt8(self[start..<index(start, offsetBy: 2)], radix: 16) else { fatalError("Not hex: \(self)") }
            return byte
        }
    }
}

extension Data {
    var hex: String { map { String(format: "%02x", $0) }.joined() }
}

/// One data element of a test credential.
struct TestElement {
    let nameSpace: String
    let identifier: String
    let value: String
}

/// Builds mdoc credentials for tests: IssuerSigned with an MSO whose digests match the items, a
/// P-256 deviceKey and a placeholder issuer signature (OVP does not check the issuer signature).
enum TestMdocs {
    private static let deviceKey: CBOR = .map([
        1: 2,
        -1: 1,
        -2: .byteString([UInt8](repeating: 1, count: 32)),
        -3: .byteString([UInt8](repeating: 2, count: 32)),
    ])

    static func issuerSignedItem(digestId: UInt64, _ element: TestElement) -> CBOR {
        let item: CBOR = .map([
            "digestID": .unsignedInt(digestId),
            "random": .byteString([UInt8](repeating: UInt8(digestId), count: 16)),
            "elementIdentifier": .utf8String(element.identifier),
            "elementValue": .utf8String(element.value),
        ])
        return tag24(encodeCanonicalCbor(item))
    }

    /// IssuerSigned {nameSpaces, issuerAuth}; [items] replaces the generated items, e.g. to tamper with one.
    static func issuerSigned(
        docType: String,
        _ elements: [TestElement],
        digestAlgorithm: String = "SHA-256",
        items: (([String: [CBOR]]) -> [String: [CBOR]])? = nil
    ) -> CBOR {
        var generated: [String: [CBOR]] = [:]
        for (index, element) in elements.enumerated() {
            generated[element.nameSpace, default: []].append(issuerSignedItem(digestId: UInt64(index), element))
        }
        var valueDigests: [CBOR: CBOR] = [:]
        for (nameSpace, nameSpaceItems) in generated {
            var digests: [CBOR: CBOR] = [:]
            for item in nameSpaceItems {
                digests[.unsignedInt(digestId(of: item))] = .byteString([UInt8](SHA256.hash(data: encodeCanonicalCbor(item))))
            }
            valueDigests[.utf8String(nameSpace)] = .map(digests)
        }
        let mso: CBOR = .map([
            "version": "1.0",
            "digestAlgorithm": .utf8String(digestAlgorithm),
            "valueDigests": .map(valueDigests),
            "deviceKeyInfo": .map(["deviceKey": deviceKey]),
            "docType": .utf8String(docType),
        ])
        let issuerAuth: CBOR = [
            .byteString(encodeCanonicalCbor([1: -7])),
            .map([:]),
            .byteString(encodeCanonicalCbor(tag24(encodeCanonicalCbor(mso)))),
            .byteString([UInt8](repeating: 0, count: 64)),
        ]
        var nameSpaces: [CBOR: CBOR] = [:]
        for (nameSpace, nameSpaceItems) in items?(generated) ?? generated {
            nameSpaces[.utf8String(nameSpace)] = .array(nameSpaceItems)
        }
        return .map(["nameSpaces": .map(nameSpaces), "issuerAuth": issuerAuth])
    }

    static func credential(docType: String, _ elements: TestElement...) -> Data {
        Data(encodeCanonicalCbor(issuerSigned(docType: docType, elements)))
    }

    static func digestId(of item: CBOR) -> UInt64 {
        guard case let .tagged(_, .byteString(bytes)) = item,
              case let .map(decoded)? = try? CBOR.decode(bytes),
              case let .unsignedInt(digestId)? = decoded["digestID"] else { fatalError("Not an IssuerSignedItemBytes") }
        return digestId
    }

    static func tag24(_ encoded: [UInt8]) -> CBOR { .tagged(CBOR.Tag(rawValue: 24), .byteString(encoded)) }
}

extension CBOR {
    /// The value under text [key], or undefined when the key is missing.
    subscript(text key: String) -> CBOR {
        guard case let .map(entries) = self, let value = entries[.utf8String(key)] else { return .undefined }
        return value
    }

    var items: [CBOR] {
        guard case let .array(elements) = self else { return [] }
        return elements
    }
}
