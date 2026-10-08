import Foundation

public class OpenID4VP {
    public let traceabilityId: String
    let networkManager: NetworkManaging
    var authorizationRequest: AuthorizationRequest!
    private var responseDispatchInfo: ResponseDispatchInfo?
    private var authorizationResponseHandler: AuthorizationResponseHandler
    private let walletConfig: WalletConfig
    private var walletNonce: String = ""
    private let nonceProvider: NonceProvider

    private let className = String(describing: type(of: OpenID4VP.self))

    public init(traceabilityId: String, walletConfig: WalletConfig = WalletConfig(), jsonLdCanonicalizer: JsonLdCanonicalizerCallback? = nil) {
        self.traceabilityId = traceabilityId
        networkManager = NetworkManager.shared
        authorizationResponseHandler = AuthorizationResponseHandler(networkManager: networkManager, walletConfig: walletConfig)
        self.walletConfig = walletConfig
        OpenID4VPException.setTraceabilityId(className: String(describing: type(of: self)), traceabilityId: traceabilityId)
        nonceProvider = NonceProvider()
        walletNonce = nonceProvider.generateNonce()
        
        JsonLd.setCanonicalizer(jsonLdCanonicalizer)
    }

    internal init(traceabilityId: String, networkManager: NetworkManaging? = nil, walletConfig: WalletConfig = WalletConfig(), nonceProvider: NonceProvider = NonceProvider(), authorizationResponseHandler: AuthorizationResponseHandler? = nil, jsonLdCanonicalizer: JsonLdCanonicalizerCallback? = nil) {
        self.networkManager = networkManager ?? NetworkManager.shared
        self.nonceProvider = nonceProvider

        self.traceabilityId = traceabilityId
        self.authorizationResponseHandler = authorizationResponseHandler ?? AuthorizationResponseHandler(networkManager: networkManager ?? NetworkManager.shared, walletConfig: walletConfig)
        self.walletConfig = walletConfig
        OpenID4VPException.setTraceabilityId(className: String(describing: type(of: self)), traceabilityId: traceabilityId)
    }
    
    internal func setResponseDispatchInfo(_ responseDispatchInfo: ResponseDispatchInfo) {
        self.responseDispatchInfo = responseDispatchInfo
    }
    
    public func authenticateVerifier(
        urlEncodedAuthorizationRequest: String
    ) async throws -> AuthorizationRequest {
        // Create a new wallet nonce for each request
        walletNonce = nonceProvider.generateNonce()
        authorizationRequest = nil
        responseDispatchInfo = nil
        authorizationResponseHandler = AuthorizationResponseHandler(networkManager: networkManager, walletConfig: walletConfig)

        do {
            authorizationRequest = try await AuthorizationRequest.validateAndCreateAuthorizationRequest(
                urlEncodedAuthorizationRequest: urlEncodedAuthorizationRequest,
                walletConfig: walletConfig,
                setResponseDispatchInfo: setResponseDispatchInfo,
                walletNonce: walletNonce,
                networkManager: networkManager
            )
            return authorizationRequest
        } catch let exception {
            await safeSendError(error: exception)
            throw exception
        }
    }


    public func authenticateVerifier(
        authorizationRequest: [String: Any]
    ) async throws -> AuthorizationRequest {
        do {
            walletNonce = nonceProvider.generateNonce()
            self.authorizationRequest = nil
            responseDispatchInfo = nil
            authorizationResponseHandler = AuthorizationResponseHandler(networkManager: networkManager, walletConfig: walletConfig)

            let validatedAuthorizationRequest = try await AuthorizationRequest.validateAndCreateAuthorizationRequest(
                authRequest: authorizationRequest,
                walletConfig: walletConfig,
                setResponseDispatchInfo: setResponseDispatchInfo,
                walletNonce: walletNonce,
                networkManager: networkManager
            )

            self.authorizationRequest = validatedAuthorizationRequest
            return validatedAuthorizationRequest
        } catch let error as OpenID4VPException {
            await safeSendError(error: error)
            throw error
        }
    }
    
    /**
     inputs
         1. verifiableCredentials: Selected credentials in the form of a map of credential query IDs for DCQL request OR Input descriptor IDs for Presentation Exchange Request  to lists of verifiable credentials
 
     Output
        - [UnsignedVPToken] : Array of unsigned VP tokens which includes the data to sign, signing algorithm and key reference along with VC format for which the data is to be signed
 
     Responsibility:
        - This method focuses on building the data to be signed (UnsignedVPToken) which is required for the eventual VP construction
     */
    public func constructUnsignedVPToken(
        selectedCredentials: [String: [Credential]]
    ) async throws -> [UnsignedVPToken] {
        do {
            return try await authorizationResponseHandler.constructUnsignedVPToken(
                selectedCredentials: selectedCredentials,
                authorizationRequest: try requireAuthorizationRequest(),
                walletNonce: walletNonce
            )
        } catch {
            await safeSendError(error: error)
            throw error
        }
    }

    public func constructVPResponse(vpTokenSigningResults: [VPTokenSigningResult]) -> [String: Any] {
        do {
            return try authorizationResponseHandler.constructVPResponse(
                signingResults: vpTokenSigningResults,
                authorizationRequest: try requireAuthorizationRequest(),
                dispatchInfo: responseDispatchInfo
            )
        } catch let exception {
            return constructErrorInfo(exception: exception)
        }
    }

    public func sendVPResponseToVerifier(
        vpTokenSigningResults: [VPTokenSigningResult]
    ) async throws -> VerifierResponse {
        do {
            return try await authorizationResponseHandler.constructAndSendAuthorizationResponseToVerifier(
                authorizationRequest: try requireAuthorizationRequest(),
                vpTokenSigningResults: vpTokenSigningResults,
                dispatchInfo: responseDispatchInfo
            )
        } catch {
             await safeSendError(error: error)
            throw error
        }
    }
    
    public func constructErrorInfo(exception: Error) -> [String: Any] {
        return authorizationResponseHandler.constructAuthorizationErrorResponse(
            dispatchInfo: responseDispatchInfo,
            error: exception,
            walletNonce: walletNonce,
            authorizationRequest: authorizationRequest
        )
    }

    public func sendErrorInfoToVerifier(error: Error) async throws -> VerifierResponse {
        return try await authorizationResponseHandler.sendAuthorizationError(dispatchInfo: responseDispatchInfo, authorizationRequest: authorizationRequest, error: error)
        
    }

    private func safeSendError(error: Error) async {
        if let exception = error as? OpenID4VPException, !exception.notifyVerifier { return }
        do {
            let verifierResponse = try await sendErrorInfoToVerifier(error: error)
            (error as? OpenID4VPException)?.setVerifierResponse(verifierResponse)
        } catch {
            OpenID4VPException.error(error, className: className)
        }
    }

    private func requireAuthorizationRequest() throws -> AuthorizationRequest {
        guard let authorizationRequest else {
            throw InvalidData(
                message: "Authorization request is not available. Call authenticateVerifier before constructing or sending the VP response.",
                className: className,
                notifyVerifier: false
            )
        }
        return authorizationRequest
    }
}
 
 
