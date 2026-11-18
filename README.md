# INJI-OpenID4VP-ios-swift

A Swift package for **wallet-side** processing of [OpenID for Verifiable Presentations](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) (OpenID4VP). This library validates incoming authorization requests, helps build Verifiable Presentations (with signing delegated to your app), and sends responses to the verifier.

---

## Table of Contents

- [Overview](#overview)
- [Supported Features](#supported-features)
- [Which Spec Version Am I On?](#which-spec-version-am-i-on)
- [Requirements](#requirements)
- [Installation](#installation)
- [Getting Started](#getting-started)
- [Integration Guide](#integration-guide)
- [Limitations](#limitations)
- [Callout](#callout)
- [Migration Guides](#migration-guides)
- [Architecture Decisions](#architecture-decisions)
- [Library Implementations](#library-implementations-available-in)
- [Glossary](#glossary)

---

## Overview

The OpenID4VP Library is a ready-to-integrate wallet-side solution that accelerates secure Verifiable Credential exchange. It takes care of the complexity behind OpenID4VP — including authorization request validation, VP creation, response handling, and verifier communication — enabling faster integration with less engineering effort.

Library consumer remains in control of the user experience, consent, credential selection, and cryptographic signing. The library provides the trusted protocol foundation that transforms approved credentials into standards-compliant Verifiable Presentations.

**Key Responsibilities:**

* **OpenID4VP Library**

   * Handles OpenID4VP protocol workflows and compliance
   * Simplifies Verifiable Presentation creation and response exchange
   * Reduces development complexity and integration time

* **Library Consumer App**

   * Owns user consent and credential selection
   * Performs secure cryptographic signing

Build OpenID4VP capabilities faster with a library designed to remove protocol complexity, reduce implementation risk, and accelerate your journey toward interoperable digital credentials.

---

## Supported features

### Feature Matrix by Specification Version

**Legend:** ✅ = Supported | ❌ = Not Implemented | N/A = Not Applicable

| Feature                                       | Draft 23  | Version 1.0 | Notes                                                                                                                                                        |
|-----------------------------------------------|:---------:|:-----------:|--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Device Flow**                               |           |             |                                                                                                                                                              |
| — Cross device flow                           |     ✅     |      ✅      | Wallet scans QR code and passes data to this library                                                                                                         |
| — Same device flow                            |     ✅     |      ✅      | Wallet receives VP request via deeplink                                                                                                                      |
| **Client ID Prefix**                          |           |             | Equivalent to Client ID Scheme in draft 23                                                                                                                   |
| — pre-registered                              |     ✅     |      ✅      | Validated via `WalletConfig.trustedVerifiers`                                                                                                                |
| — redirect_uri                                |     ✅     |      ✅      |                                                                                                                                                              |
| — decentralized_identifier                    | ✅ (`did`) |      ✅      |                                                                                                                                                              |
| **Authorization Request Delivery**            |           |             | Per [RFC 9101](https://www.rfc-editor.org/info/rfc9101/#name-authorization-request)                                                                          |
| — By value (signed request)                   |     ✅     |      ✅      |                                                                                                                                                              |
| — By value (unsigned request)                 |     ✅     |      ✅      | Via URL-encoded parameters                                                                                                                                   |
| — By reference (request_uri)                  |     ✅     |      ✅      | Fetched via HTTP GET/POST                                                                                                                                    |
| — Request signing algorithms                  |     ✅     |      ✅      | Ed25519                                                                                                                                                      |
| **Presentation Request**                      |           |             |                                                                                                                                                              |
| — DCQL Query                                  |     ❌     |      ✅      |                                                                                                                                                              |
| — Presentation Definition                     |     ✅     |      ❌      | By value or via `presentation_definition_uri`                                                                                                                |
| — Scope parameter                             |     ❌     |      ❌      | Not implemented                                                                                                                                              |
| **VP Response Modes**                         |           |             |                                                                                                                                                              |
| — direct_post                                 |     ✅     |      ✅      |                                                                                                                                                              |
| — direct_post.jwt                             |     ✅     |      ✅      | Unsigned and Encrypted response                                                                                                                              |
| — iar-post                                    |     ✅     |      ✅      |                                                                                                                                                              |
| — iar-post.jwt                                |     ✅     |      ✅      | Unsigned and Encrypted response                                                                                                                              |
| **VP Response Type**                          |           |             |                                                                                                                                                              |
| — vp_token                                    |     ✅     |      ✅      |                                                                                                                                                              |
| — vp_token id_token                           |     ❌     |      ❌      | Not implemented                                                                                                                                              |
| — code                                        |     ❌     |      ❌      | Not implemented                                                                                                                                              |
| **Authorization Response Encryption**         |           |             | For `direct_post.jwt` and `iar-post.jwt` modes                                                                                                               |
| — Encryption algorithm (content)              |     ✅     |      ✅      | A256GCM                                                                                                                                                      |
| — Key agreement algorithm                     |     ✅     |      ✅      | ECDH-ES                                                                                                                                                      |
| **VP Token Generation**                       |           |             |                                                                                                                                                              |
| — DCQL Query-based                            |     ❌     |      ✅      |                                                                                                                                                              |
| — Presentation Definition-based               |     ✅     |      ❌      |                                                                                                                                                              |
| — Error responses                             |     ✅     |      ✅      | Any failure during VP request validation / user consent rejection / VP response preparation is prepared as Authorization Error response and sent to Verifier |
| **Supported Verifiable Presentation Formats** |           |             |                                                                                                                                                              |
| — ldp_vp                                      |     ✅     |      ✅      |                                                                                                                                                              |
| — mso_mdoc                                    |     ✅     |      ✅      |                                                                                                                                                              |
| — vc+sd-jwt / dc+sd-jwt                       |     ✅     |      ✅      |                                                                                                                                                              |

### Client ID Prefixes and Signed / Unsigned request support matrix

**Table: Client ID Scheme Support** - Shows how each client identifier scheme supports signed and unsigned authorization requests

| Client Id Scheme                      | Supports Unsigned request                                    | Supports Signed request | Notes                                                                                                                                                                                                                                                                       |
|---------------------------------------|--------------------------------------------------------------|-------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `pre-registered`                      | depends ⚖️ on trusted Verifier configuration in WalletConfig | ✅                       | When `validateTrustedVerifier` is true, unsigned requests are allowed only if the pre-registered verifier's `allowUnsignedRequest` is true. Otherwise, unsigned requests are always allowed. For signed requests, the trusted verifier's `jwks_uri` is used for validation. |
| `redirect_uri`                        | ✅                                                            | ❌                       | Signed request is not supported, since this client ID scheme mandates unsigned Authorization Request as per the specification. [(reference)](https://openid.net/specs/openid-4-verifiable-presentations-1_0-ID3.html#section-5.10.4-2.1)                                    |
| `decentralized_identifier` (or `did`) | ❌                                                            | ✅                       | Only signed Authorization Requests are allowed. Requests can be sent by value or by reference, but must always be signed.                                                                                                                                                   |

**Note:**
- All `By Reference` requests are fetched using HTTP GET / POST method and expected to be _**signed**_ JWT. 
- All `By Value` requests are either _**signed**_ JWT or URL-encoded parameters (_**unsigned**_).

### Notes on Supported response modes
1. `direct_post` :
    - Authorization Response is sent as a POST request to the `response_uri` endpoint. Authorization Response is attached as request body in `application/x-www-form-urlencoded` HTTP content type
2. `direct_post.jwt` :
    - Authorization Response is sent as a POST request to the `response_uri` endpoint.
    - Authorization Response is attached as request body in `application/x-www-form-urlencoded` HTTP content type.
    - The response is encrypted using the public key provided in the client_metadata of the authorization request.
    - The created JWE's header contains the `apu` (producer info) as wallet generated nonce (with entropy 16 bytes) and `apv` (recipient info) as the verifier nonce i.e., the nonce received in the authorization request.
   > Note: If the Authorization request includes an `mso_mdoc` format VP, it can only use the `direct_post.jwt` response mode, as required by the ISO-18013-7 specification. Other supported response mode (`direct_post`) is not applicable.
3. `iar-post` :
    - Authorization Response is constructed in unencrypted format.
    - Sample Authorization response structure of DIF Presentation Submission format:
   ```shell
    {
      "vp_token": <verifiable-presentation-token>,
      "presentation_submission": { ... } // presentation_submission if VP request contains Presentation Defintion
    }
    ```
4. `iar-post.jwt` :
    - Authorization Response is constructed in encrypted format (and unsigned) using the public key provided in the client_metadata of the authorization request.
    - The created JWE's header contains the apu (producer info) as wallet generated nonce (with entropy 16 bytes) and apv (recipient info) as the verifier nonce i.e., the nonce received in the authorization request.
    - Sample Authorization response structure:
   ```shell
    {
      "response": <encrypted data of vp_token & presentation_submission>  // presentation_submission if VP request contains Presentation Defintion
    }
    ```


---

## Which Spec Version Am I On?

**Supported Spec Versions:**
- OpenID for Verifiable Presentations - **Version 1.0** (uses `dcql_query`)
- OpenID for Verifiable Presentations - **Draft 23** (uses `presentation_definition` / `presentation_definition_uri`)

### Quick Version Identification

When your wallet receives an authorization request, check for these parameters to identify the spec version:

| Parameter Present                                          | Spec Version      |
|------------------------------------------------------------|-------------------|
| `dcql_query`                                               | **OpenID4VP 1.0** |
| `presentation_definition` or `presentation_definition_uri` | **Draft 23**      |

> **The library automatically detects the spec version after receiving the request.** You don't need to manually check.

**Important:** Parameter handling:
- ✅ If both `dcql_query` and `presentation_definition` (or `presentation_definition_uri`) are provided, `dcql_query` takes precedence, and `presentation_definition` / `presentation_definition_uri` are ignored.
- ❌ Both `dcql_query` AND `scope` = Error (rejected by SDK)
- ❌ Both `presentation_definition` (or `presentation_definition_uri`) AND `scope` = Error (rejected by SDK)

---

## Requirements

- **Swift** 5.9 or later (see `Package.swift`)
- **iOS** 14.0 or later
- **macOS** 12.0 or later

---

## Installation

The OpenID4VP SDK can be integrated into your iOS application using Swift Package Manager (SPM), either through Xcode or by manually updating your `Package.swift`.

### Option 1: Add the Package Using Xcode

1. Open your project in Xcode.
2. Navigate to **File > Add Package Dependencies...**.
3. Enter the repository URL:
   ```text
   https://github.com/inji/inji-openid4vp-ios-swift.git
   ```
4. Select the package version you would like to use.
   * For production applications, it is recommended to use the latest stable release.
   * You may also choose a specific version or branch depending on your project's requirements.
5. Add the package to the desired application target.
6. Once the package has been resolved successfully, verify that:
   * The package appears under **Package Dependencies** in Xcode.
   * The framework is linked to your application target.
7. Import the SDK in any Swift file where you intend to use OpenID4VP functionality:
   ```swift
   import OpenID4VP
   ```

The SDK is now installed and ready to be initialized within your application.

### Option 2: Add the Package Using `Package.swift`

If your project manages dependencies directly through Swift Package Manager, add the package to the `dependencies` section of your `Package.swift` file:
```swift
dependencies: [
    .package(
        url: "https://github.com/inji/inji-openid4vp-ios-swift.git",
        from: "1.0.0"
    )
]
```

Then add the package as a dependency of the target that requires OpenID4VP support:
```swift
.target(
    name: "YourApp",
    dependencies: [
        "OpenID4VP"
    ]
)
```

After resolving package dependencies, import the SDK where required:

```swift
import OpenID4VP
```

---

## Getting Started

### Typical Workflow

**Standard Pattern (Recommended):**
```
1. Receive VP request → authenticateVerifier()
2. Match credentials → getMatchingCredentials() [DCQL] or custom logic [Presentation Exchange]
3. Get user consent (your wallet handles this)
4. Prepare VP → constructUnsignedVPToken()
5. Sign data (your wallet handles this)
6. Submit response → sendVPResponseToVerifier()
```

**Alternative Pattern (Advanced - Manual VP Response Submission):**
```
1-5. Same as above
6. Construct response → constructVPResponse()
7. Submit to verifier (Library consumer handles VP Response submission)
```

### Quick Start Example

This section provides a minimal example to help you get started with the library.

**Scenario:** Basic OpenID4VP flow with DCQL or Presentation Exchange request

```swift
import Foundation
import OpenID4VP

// 1. Configure your wallet
let walletConfig = WalletConfig(
    vpFormatsSupported: [
        .ldp_vc: LdpVpFormatSupported(),
        .mso_mdoc: MsoMdocVpFormatSupported(),
        .dc_sd_jwt: SdJwtVpFormatSupported()
    ],
    clientIdPrefixesSupported: [.preRegistered, .redirectUri, .decentralizedIdentifier],
    trustedVerifiers: [
        Verifier(
            clientId: "trusted-verifier",
            responseUris: ["https://verifier.example/response"],
            jwksUri: "https://verifier.example/keys.json"
        )
    ]
)

// 2. Initialize the library
let openID4VP = OpenID4VP(
    traceabilityId: UUID().uuidString,
    walletConfig: walletConfig
)

// 3. Receive and authenticate an authorization request
let authRequest = try await openID4VP.authenticateVerifier(
    urlEncodedAuthorizationRequest: deepLinkFromQRCode
)

// 4. Get matching credentials

let matchingVcsResult: MatchingCredentialsResult

if let vpRequest = authRequest as? AuthorizationDcqlRequest {
    // DCQL flow
    let dcqlHelper = DCQLHelper()

    matchingVcsResult = try await dcqlHelper.getMatchingCredentials(
        inputCredentials: walletAvailableCredentials,
        dcqlQuery: vpRequest.dcqlQuery
    )
} else {
    // Handle Presentation Exchange flow
    return
}

// ... your credential selection logic ...

// User selects and consents to a subset of `matchingVcsResult`.
// `selectedCredentials` is of type `[String: [Credential]]`.

// 5. Prepare VP data to sign
let unsignedVPTokens = try await openID4VP.constructUnsignedVPToken(
    selectedCredentials: selectedCredentials
)

// 6. Sign the tokens (using your secure key storage)
let signingResults = unsignedVPTokens.map { unsignedVPToken in
    VPTokenSigningResult(id: unsignedVPToken.id, signedData: sign(unsignedVPToken.dataToSign, keyReference: unsignedVPToken.holderKeyReference, algorithm: unsignedVPToken.signatureAlgorithm))
}

// 7. Send VP response to verifier
let response = try await openID4VP.sendVPResponseToVerifier(
    vpTokenSigningResults: signingResults
)
print("VP submitted successfully, status: \(response.statusCode)")
```

For detailed information on wallet configuration, initialization, complete example and integration workflows, refer to the [Integration Guide](./docs/integration-guide.md).

> **Note**
> 
> - The crypto implementations like signing data is kept in your wallet app while the SDK focuses on VP request validation/VP response construction and sending to Verifier.
> - **Each SDK instance handles one flow at a time.** For concurrent VP requests, create separate instances (see [Limitations](#limitations)).

---

## Integration Guide

### Core Methods

The library provides the following methods organized into different workflow patterns:

#### Primary Flow Methods

| Method                           | Purpose                                                                                                                                    | Returns                                                |
|----------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------|
| **`authenticateVerifier()`**     | Validates incoming authorization requests from verifiers. Resolves request objects, verifies signatures, and returns a structured request. | `AuthorizationRequest` (DCQL or Presentation Exchange) |
| **`getMatchingCredentials()`**   | *(DCQL Helper)* Evaluates DCQL queries against your wallet's credentials to determine which satisfy the verifier's requirements.           | `MatchingCredentialsResult`                            |
| **`constructUnsignedVPToken()`** | Prepares VP tokens based on selected credentials. Returns unsigned data that your wallet must sign.                                        | `[UnsignedVPToken]`                                    |

#### Response Submission — Two Patterns Available

**Option 1: Construct & Send (Recommended)** — SDK handles VP Response submission

| Method                           | Purpose                                                                                                  | Returns            |
|----------------------------------|----------------------------------------------------------------------------------------------------------|--------------------|
| **`sendVPResponseToVerifier()`** | Assembles signed VP tokens into an OpenID4VP response **and submits it** to the verifier.                | `VerifierResponse` |
| **`sendErrorInfoToVerifier()`**  | Constructs and sends error/rejection responses to the verifier (e.g., user denial, validation failures). | `VerifierResponse` |

**Option 2: Construct Only (Advanced)** — You handle VP Response submission yourself

| Method                      | Purpose                                                                              | Returns         |
|-----------------------------|--------------------------------------------------------------------------------------|-----------------|
| **`constructVPResponse()`** | Constructs the VP response **without sending**. You handle VP Response submission.   | `[String: Any]` |
| **`constructErrorInfo()`**  | Constructs an error response **without sending**. You handle VP Response submission. | `[String: Any]` |

For detailed implementation guidance including wallet configuration, VP construction details, and step-by-step integration workflows, see the [Integration Guide](./docs/integration-guide.md).

#### In-person mdoc presentation (ISO/IEC 18013-5)

For proximity sharing there is no authorization request and no verifier URL: the session runs over a
transport such as Bluetooth (for example Tuvali's `MdocPresenter`), and this library only builds the
answer (`DeviceResponse`).

| Method                                         | Purpose                                                                                                     | Returns                    |
|------------------------------------------------|-------------------------------------------------------------------------------------------------------------|----------------------------|
| **`MdocProximity.buildDeviceResponse()`**      | Builds a CBOR `DeviceResponse` for the given session, asking the wallet to sign device authentication.      | `Data` (CBOR DeviceResponse) |

```swift
let deviceResponse = try await MdocProximity.buildDeviceResponse(
    sessionTranscriptBytes: request.sessionTranscript, // from the transport, unchanged
    credentials: approvedMdocs,                        // base64url IssuerSigned, one per docType
    sign: { input in
        // input.holderKeyReference, input.signatureAlgorithm, input.dataToSign
        try await wallet.sign(input.dataToSign, keyReference: input.holderKeyReference)
    }
)
```

- `sessionTranscriptBytes` are the SessionTranscriptBytes (tag 24 around the SessionTranscript)
  exactly as the transport produced them; they are never decoded and re-encoded.
- `credentials` are `IssuerSigned` mdocs as `[Data]` (CBOR) or `[String]` (base64url). Reduce each
  to the approved elements before calling; issuer-signed items and `issuerAuth` are kept byte for
  byte, and every kept item is checked against its MSO digest.
- `sign` receives one `MdocSigningInput` per document and must return the raw signature.
  An error thrown by `sign` fails the call unchanged.
- The response has `version` `"1.0"`, the documents, and `status` 0. Send it through the transport;
  nothing is sent by this library.
- Throws `InvalidData` when a credential is not valid CBOR or base64url, its MSO has no docType,
  a kept item does not match its digest, two credentials share a docType, or a signature has the
  wrong length.

---

# Limitations

1. **`scope` parameter support**
   The `scope` parameter defined in the specification is currently not supported.

# Callout

1. **Single flow instance usage (One Flow Per Instance)**
   
   A single library instance supports only one OpenID4VP flow execution at a time. Concurrent flows using the same instance are not supported.
   
   **Why this matters:**
   - Each `OpenID4VP` instance maintains internal state for the current flow (authorization request, response mode, nonce, etc.)
   - Calling methods from a different flow on the same instance will corrupt the state and lead to unpredictable behavior
   - The library does not perform thread-safety checks or flow isolation between concurrent operations
   
   **When can you reuse an instance?**
   - After a flow completes successfully (response sent to verifier)
   - After a flow terminates with an error (error sent to verifier or thrown)
   - When you're certain the previous flow is fully finished

2. **`constructUnsignedVPToken` input validation**
   The `selectedCredentials` provided to `constructUnsignedVPToken` are expected to comply with the OpenID4VP specification requirements. The SDK does not perform additional validations on the provided credential selection.

   For example, in the case of DCQL-based requests, if a credential query ID does not support multiple credentials but the Wallet provides multiple credentials for that query ID, the SDK does not validate or reject this condition. Ensuring that the provided credential selection is valid according to the presentation request is the responsibility of the Wallet.


---

# Migration Guides

For information on upgrading between versions of the SDK, see the [Migration Guides](./docs/migration-guides/README.md).

---

# Architecture decisions

Architecture decisions are documented in the [INJI OpenID4VP ADR directory](https://github.com/inji/inji-openid4vp/tree/master/doc).

# Library implementations available in:


This library is officially supported and available in both Kotlin and Swift, ensuring seamless integration across Android and iOS platforms. The references for both implementations are provided below:

- [Kotlin](https://github.com/inji/inji-openid4vp/tree/master/kotlin)
- [Swift](https://github.com/inji/inji-openid4vp-ios-swift)

---

## Glossary

* **Credential:** A verifiable piece of information, typically issued by a trusted issuer, that can be presented to a verifier.
* **Verifiable Credential (VC):** A tamper-evident credential that includes cryptographic proofs of its authenticity and integrity.
* **Holder:** The entity that owns, controls, and can present Verifiable Credentials.
* **Wallet:** An application that holds Verifiable Credentials and creates Verifiable Presentations to share with Verifiers. This library provides the OpenID4VP handling for Wallet applications.

* **Verifier:** An external entity that requests Verifiable Presentations from a Holder (Wallet). Examples: banks, government agencies, identity verification services.
* **Presentation:** A structured format containing Verifiable Credentials selected by the user in response to an Authorization Request. Created by the Wallet and sent to the Verifier.
* **Verifiable Presentation (VP):** A presentation containing one or more Verifiable Credentials that may include cryptographic proof of authorization from the Holder. Created in response to a Verifier's request.
* **OpenID4VP:** OpenID for Verifiable Presentations. A standard protocol for secure presentation of Verifiable Credentials.
* **Cryptographic Holder Binding:** A mechanism that cryptographically binds a Verifiable Presentation to the holder (credential owner) to prevent misuse or unauthorized sharing.

* **JWT:** JSON Web Token. A digitally signed token format used for secure transmission of claims.

* **Authorization Request:** A request sent by the Verifier to the Wallet asking for specific Verifiable Presentations. Includes credential requirements, response type, client ID, and other parameters.
* **Authorization Response:** The Wallet's response to an Authorization Request, containing the Verifiable Presentation(s) and related data.

* **DCQL:** Digital Credentials Query Language (DCQL). OpenID4VP 1.0 standard format for expressing complex credential queries using a JSON-based query language.
* **Presentation Definition:** DIF Presentation Exchange format (Draft 23) for expressing credential requirements as a structured JSON object.
* **Presentation Exchange:** Draft 23 OpenID4VP approach using `presentation_definition` or `presentation_definition_uri` for credential queries.

* **LDP-VP (Linked Data Verifiable Presentation):** A Verifiable Presentation format based on JSON-LD and W3C Verifiable Credentials specifications.
* **mso_mdoc:** Mobile Security Object as specified in ISO/IEC 18013-5. Used for mobile document credentials like mobile driver's licenses.
* **SD-JWT:** Selective Disclosure JSON Web Token. A credential format allowing selective disclosure of claims.

* **SpecVersion:** Internal enum distinguishing between spec versions (`.v1` for OpenID4VP 1.0/DCQL, `.draft23` for Draft 23/Presentation Exchange).
