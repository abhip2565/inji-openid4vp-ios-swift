import XCTest
@testable import OpenID4VP
import SwiftCBOR

final class CBORUtilsTests: XCTestCase {
    
    /// decodeCBOR Tests
    
    func testWrapEncodedCBORWithTag24KeepsTheBytesExactlyAsGiven() {
        // an array of 3 with its count in the long form (98 03), which re-encoding would shorten to 83
        let encoded: [UInt8] = [0x98, 0x03, 0xF6, 0xF6, 0xF6]

        let tagged = wrapEncodedCBORWithTag24(encoded).encode()

        // tag 24, then a byte string of length 5, then the bytes unchanged
        XCTAssertEqual(tagged, [0xD8, 0x18, 0x45] + encoded)
    }

    func testDecodeCBOR_ValidInput() {
        // Simple string encoded as CBOR and then base64URL
        let validBase64 = "o2F4AWF5AmF6Aw==" // {"x": 1, "y": 2, "z": 3} in CBOR
        
        XCTAssertNoThrow(try {
            let decoded = try decodeCBOR(base64EncodedInput: validBase64)
            
            XCTAssertNotNil(decoded)
            if case let .map(items) = decoded {
                XCTAssertEqual(items[.utf8String("x")], .unsignedInt(1))
                XCTAssertEqual(items[.utf8String("y")], .unsignedInt(2))
                XCTAssertEqual(items[.utf8String("z")], .unsignedInt(3))
            } else {
                XCTFail("Expected map but got different CBOR type")
            }
        }())
    }
    
    func testDecodeCBOR_InvalidBase64() {
        let invalidBase64 = "abc!@#123+"
        
        XCTAssertThrowsError(try decodeCBOR(base64EncodedInput: invalidBase64)) { error in
            assertOpenID4VPException(error,
                expectedMessage:"Error while decoding input - invalid_request : Base64 decoding failed",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testDecodeCBOR_InvalidCBOR() {
        // Valid base64 but not valid CBOR
        let invalidCBOR = "dGhpcyBpcyBub3QgQ0JPUg==" // "this is not CBOR"
        
        XCTAssertThrowsError(try decodeCBOR(base64EncodedInput: invalidCBOR)) { error in
            assertOpenID4VPException(error,
                expectedMessage:"Error while decoding input - unfinishedSequence",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    /// cborEncode Tests
    
    func testCBOREncode() {
        let input: CBOR = .map([
            .utf8String("test"): .unsignedInt(123)
        ])
        
        let encoded = cborEncode(input)
        
        // Decode back to verify
        let decoded = try? CBOR.decode(encoded)
        XCTAssertNotNil(decoded)
        if case let .map(items) = decoded {
            XCTAssertEqual(items[.utf8String("test")], .unsignedInt(123))
        } else {
            XCTFail("Expected map but got different CBOR type")
        }
    }
    
    /// toCBOR Tests
    
    func testToCBOR() {
        let testData = Data([0x01, 0x02, 0x03, 0x04])
        let result = toCBOR(testData)
        
        XCTAssertEqual(result, .byteString([0x01, 0x02, 0x03, 0x04]))
    }
    
    /// wrapCBORInputWithTag24 Tests
    
    func testWrapCBORInputWithTag24() {
        let input: CBOR = .utf8String("test")
        let wrapped = wrapCBORInputWithTag24(input: input)
        
        XCTAssertNotNil(wrapped)
        if case let .tagged(tag, value) = wrapped! {
            XCTAssertEqual(tag.rawValue, 24)
            if case .byteString(let bytes) = value {
                // Decode the embedded CBOR to verify
                let decodedInner = try? CBOR.decode(bytes)
                XCTAssertEqual(decodedInner, .utf8String("test"))
            } else {
                XCTFail("Expected byteString but got a different type")
            }
        } else {
            XCTFail("Expected tagged CBOR but got a different type")
        }
    }
    
    /// toCBORArray Tests
    
    func testToCBORArray() {
        let input = [CBOR.utf8String("one"), CBOR.unsignedInt(2), CBOR.boolean(true)]
        let result = toCBORArray(input)
        
        XCTAssertEqual(result, .array([.utf8String("one"), .unsignedInt(2), .boolean(true)]))
    }
    
    /// getValueFromCBORMap Tests
    
    func testGetValueFromCBORMap_ValidKey() {
        let map: CBOR = .map([
            .utf8String("key1"): .utf8String("value1"),
            .utf8String("key2"): .unsignedInt(42)
        ])
        
        let value = getValueFromCBORMap(cborMap: map, key: "key2")
        XCTAssertEqual(value, .unsignedInt(42))
    }
    
    func testGetValueFromCBORMap_InvalidKey() {
        let map: CBOR = .map([
            .utf8String("key1"): .utf8String("value1")
        ])
        
        let value = getValueFromCBORMap(cborMap: map, key: "nonexistent")
        XCTAssertNil(value)
    }
    
    func testGetValueFromCBORMap_NotAMap() {
        let notMap: CBOR = .array([.utf8String("value")])
        
        let value = getValueFromCBORMap(cborMap: notMap, key: "key")
        XCTAssertNil(value)
    }
    
    /// extractStringFromCBOR Tests
    
    func testExtractStringFromCBOR_ValidString() {
        let cbor: CBOR = .utf8String("test string")
        
        let result = extractStringFromCBOR(cbor)
        XCTAssertEqual(result, "test string")
    }
    
    func testExtractStringFromCBOR_NotString() {
        let cbor: CBOR = .unsignedInt(42)
        
        let result = extractStringFromCBOR(cbor)
        XCTAssertNil(result)
    }
    
    /// cborToByteString Tests
    
    func testCBORToByteString() {
        let cbor: CBOR = .unsignedInt(42)
        let byteString = cborToByteString(cbor: cbor)
        
        // CBOR encoding of 42 is 0x182a
        XCTAssertEqual(byteString, "182a")
    }
    
    /// mapSigningAlgorithmToProtectedAlg Tests
    
    func testMapSigningAlgorithmToProtectedAlg_ES256() throws {
        XCTAssertEqual(try mapSigningAlgorithmToProtectedAlg(algorithm: "ES256"),CBOR.negativeInt(6)) // ES256 (-7 in COSE)

        XCTAssertEqual(try mapSigningAlgorithmToProtectedAlg(algorithm: "ES384"), CBOR.negativeInt(34)) // ES384 (-35 in COSE)

        XCTAssertEqual(try mapSigningAlgorithmToProtectedAlg(algorithm: "ES512"), CBOR.negativeInt(35)) // ES512 (-36 in COSE)

        XCTAssertEqual(try mapSigningAlgorithmToProtectedAlg(algorithm: "EdDSA"), CBOR.negativeInt(7)) // EdDSA (-8 in COSE)
        
        XCTAssertEqual(try mapSigningAlgorithmToProtectedAlg(algorithm: "PS256"), CBOR.negativeInt(36)) // PS256 (-37 in COSE)

        XCTAssertEqual(try mapSigningAlgorithmToProtectedAlg(algorithm: "PS384"), CBOR.negativeInt(37)) // PS384 (-38 in COSE)

        XCTAssertEqual(try mapSigningAlgorithmToProtectedAlg(algorithm: "PS512"), CBOR.negativeInt(38)) // EdDSA (-39 in COSE)
    }
    
    func testMapSigningAlgorithmToProtectedAlg_UnsupportedAlgorithm() {
        XCTAssertThrowsError(try mapSigningAlgorithmToProtectedAlg(algorithm: "RS256")) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Unsupported signing algorithm: RS256",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
}
