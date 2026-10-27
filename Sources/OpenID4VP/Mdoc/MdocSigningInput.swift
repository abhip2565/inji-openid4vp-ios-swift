import Foundation

/// What the wallet signs for one document. Sign [dataToSign] with the private key matching
/// [holderKeyReference] (the credential's deviceKey as a base64url COSE_Key) using
/// [signatureAlgorithm] ("ES256" or "EdDSA"), and return the raw signature: r ‖ s for ES256.
public struct MdocSigningInput: Equatable {
    public let holderKeyReference: String
    public let signatureAlgorithm: String
    public let dataToSign: Data
}
