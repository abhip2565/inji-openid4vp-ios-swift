import Foundation
import SwiftCBOR

fileprivate let className = "CBORUtils"

func decodeCBOR(base64EncodedInput : String) throws -> CBOR? {
    do{
        let decodedBase64Data = try Base64Decoder.decodeBase64ToData(base64EncodedInput)
        let inputToCBORDecode = Array(decodedBase64Data)
        let cborDecodedData = try CBOR.decode(inputToCBORDecode)
        return cborDecodedData
    }
    catch let error {
        throw InvalidData( message: "Error while decoding input - \(error)", className: String(describing: CBOR.self))
    }
}

func cborEncode(_ input: CBOR) -> [UInt8] {
    return CBOR.encode(input)
}

func toCBOR(_ input: Data) -> CBOR {
    return CBOR.byteString([UInt8](input))
}

// creates #6.24 (bstr .cbor input)
func wrapCBORInputWithTag24(input: CBOR) -> CBOR? {
    guard let encodedInput: [UInt8]? = SwiftCBOR.CBOR.encode(input) else {
        print("Failed to encode input CBOR")
        return nil
    }
    let cborTaggedValue: CBOR = .tagged(CBOR.Tag(rawValue: 24), .byteString(encodedInput!))
    
    return cborTaggedValue
}

internal func toCBORArray(_ input: [CBOR]) -> CBOR {
    return CBOR.array(input.map { ($0) })
}

func getValueFromCBORMap(cborMap: CBOR, key: String) -> CBOR? {
    guard case let .map(items) = cborMap else { return nil }
    
    let cborKey = CBOR.utf8String(key)
    return items[cborKey]
}

func extractStringFromCBOR(_ cbor: CBOR) -> String? {
    if case let .utf8String(str) = cbor {
        return str
    }
    return nil
}

func cborToByteString(cbor: CBOR) -> String {
    let encodedData : [UInt8] = CBOR.encode(cbor)
    
    return encodedData.map { String(format: "%02x", $0) }.joined()
}

//RFC 8610, 8230 ECDSA / EdDSA Algorithm Values
func mapSigningAlgorithmToProtectedAlg(algorithm: String) throws -> CBOR {
    switch algorithm {
    case "ES256":
        return .negativeInt(6)   // ECDSA w/ SHA-256 (-7 in COSE)
    case "ES384":
        return .negativeInt(34)  // ECDSA w/ SHA-384 (-35 in COSE)
    case "ES512":
        return .negativeInt(35)  // ECDSA w/ SHA-512 (-36 in COSE)
    case "EdDSA":
        return .negativeInt(7)   // EdDSA (-8 in COSE)
    case "PS256":
        return .negativeInt(36)  // RSASSA-PSS w/ SHA-256 (-37 in COSE)
    case "PS384":
        return .negativeInt(37)  // RSASSA-PSS w/ SHA-384 (-38 in COSE)
    case "PS512":
        return .negativeInt(38)  // RSASSA-PSS w/ SHA-512 (-39 in COSE)
    default:
        throw InvalidData(
            message: "Unsupported signing algorithm: \(algorithm)",
            className: className
        )
    }
}

func unwrapCbor(_ cbor: SwiftCBOR.CBOR) -> Any? {
    switch cbor {
    case let .utf8String(s): return s
    case let .boolean(b): return b
    case let .unsignedInt(u): return Int(exactly: u)
    case let .negativeInt(n):
        guard let magnitude = Int(exactly: n) else { return nil }
        return -magnitude - 1
    case let .double(d): return d
    case let .float(f): return f
    case let .half(h): return h
    case let .byteString(bytes): return Data(bytes)
    case let .map(m):
        var dict: [String: Any] = [:]
        for (k, v) in m {
            guard let strK = unwrapCbor(k) as? String,
                  let unwrappedV = unwrapCbor(v) else {
                return nil
            }
            dict[strK] = unwrappedV
        }
        return dict
    case let .array(a):
        var arr: [Any] = []
        for element in a {
            guard let unwrapped = unwrapCbor(element) else {
                return nil
            }
            arr.append(unwrapped)
        }
        return arr
    default:
        return nil
    }
}

// MARK: - Deterministic encoding and exact decoding

// CBOR initial byte: top 3 bits = major type, low 5 bits = additional information (RFC 8949 3)
private let cborMajorTypeArray: UInt8 = 4
private let cborMajorTypeMap: UInt8 = 5
private let cborMajorTypeTag: UInt8 = 6

/// Encodes [item] with map keys sorted bytewise by their encoding and integers and lengths in
/// their shortest form, so the same item always gives the same bytes. SwiftCBOR writes maps in
/// dictionary order, which changes from run to run, so containers and tags are written here and
/// only leaf values are left to SwiftCBOR.
func encodeCanonicalCbor(_ item: CBOR) -> [UInt8] {
    switch item {
    case let .array(elements):
        return cborHeader(majorType: cborMajorTypeArray, argument: UInt64(elements.count))
            + elements.flatMap { element in encodeCanonicalCbor(element) }
    case let .map(entries):
        let sortedEntries = entries
            .map { entry in (key: encodeCanonicalCbor(entry.key), value: encodeCanonicalCbor(entry.value)) }
            .sorted { first, second in first.key.lexicographicallyPrecedes(second.key) }
        return cborHeader(majorType: cborMajorTypeMap, argument: UInt64(entries.count))
            + sortedEntries.flatMap { entry in entry.key + entry.value }
    case let .tagged(tag, content):
        return cborHeader(majorType: cborMajorTypeTag, argument: tag.rawValue) + encodeCanonicalCbor(content)
    default:
        return item.encode()
    }
}

/// An initial byte plus the argument in its shortest form.
private func cborHeader(majorType: UInt8, argument: UInt64) -> [UInt8] {
    let initialByte = majorType << 5
    switch argument {
    case 0...23: return [initialByte | UInt8(argument)]
    case 0...0xff: return [initialByte | 24, UInt8(argument)]
    case 0...0xffff: return [initialByte | 25] + bigEndianBytes(argument, count: 2)
    case 0...0xffff_ffff: return [initialByte | 26] + bigEndianBytes(argument, count: 4)
    default: return [initialByte | 27] + bigEndianBytes(argument, count: 8)
    }
}

private func bigEndianBytes(_ value: UInt64, count: Int) -> [UInt8] {
    (0..<count).reversed().map { index in UInt8(truncatingIfNeeded: value >> (8 * UInt64(index))) }
}

/// Decodes [bytes] as exactly one CBOR item; nothing may follow it.
func decodeSingleCborItem(_ bytes: [UInt8], className: String) throws -> CBOR {
    // a class, so the decoder reads from this same instance and its count can be checked after
    let stream = CountingInputStream(bytes)
    let decoder = CBORDecoder(stream: stream)
    let item: CBOR?
    do {
        item = try decoder.decodeItem()
    } catch {
        throw InvalidData(message: "Not valid CBOR: \(error)", className: className)
    }
    guard let decoded = item else { throw InvalidData(message: "No CBOR item found", className: className) }
    guard stream.consumed == bytes.count else {
        throw InvalidData(message: "Bytes follow the CBOR item", className: className)
    }
    return decoded
}

/// A CBOR input stream that counts what the decoder took, so trailing bytes can be detected.
private final class CountingInputStream: CBORInputStream {
    private let bytes: [UInt8]
    private(set) var consumed = 0

    init(_ bytes: [UInt8]) {
        self.bytes = bytes
    }

    func popByte() throws -> UInt8 {
        guard consumed < bytes.count else { throw CBORError.unfinishedSequence }
        defer { consumed += 1 }
        return bytes[consumed]
    }

    func popBytes(_ n: Int) throws -> ArraySlice<UInt8> {
        guard n >= 0, bytes.count - consumed >= n else { throw CBORError.unfinishedSequence }
        defer { consumed += n }
        return bytes[consumed..<(consumed + n)]
    }
}
