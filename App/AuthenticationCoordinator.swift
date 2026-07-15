import AuthenticationServices
import CryptoKit
import Foundation
import Observation
import Security
import UIKit
import HikerData

enum AuthenticationState: Sendable, Equatable {
    case signedOut
    case signingIn
    case signedIn
    case cancelled
    case expired
    case error(AuthenticationFailure)
}

enum AuthenticationFailure: Sendable, Equatable {
    case unavailableConfiguration
    case randomnessUnavailable
    case signInAlreadyInProgress
    case sessionStartFailed
    case invalidCallback
    case invalidState
    case replayedCallback
    case missingAuthorizationCode
    case providerRejected
    case exchangeFailed
    case checkpointFailed
    case sessionStorageFailed
}

struct AuthenticationSession: Sendable {
    fileprivate let keychainPayload: Data
    fileprivate let checkpointAuthorization: String
    let expiresAt: Date?

    init(
        keychainPayload: Data,
        checkpointAuthorization: String,
        expiresAt: Date?
    ) throws {
        guard !keychainPayload.isEmpty, !checkpointAuthorization.isEmpty else {
            throw AuthenticationSessionError.invalidPayload
        }
        self.keychainPayload = keychainPayload
        self.checkpointAuthorization = checkpointAuthorization
        self.expiresAt = expiresAt
    }
}

enum AuthenticationSessionError: Error {
    case invalidPayload
}

protocol AppleSupabaseCodeExchanging: Sendable {
    func exchange(
        authorizationCode: String,
        codeVerifier: String
    ) async throws -> AuthenticationSession
}
struct AppleAuthenticationCheckpointChallenge: Sendable {
    let transactionID: UUID
    let state: String
    let nonce: String
    let expiresAt: Date
}

protocol AppleAuthenticationCheckpointing: Sendable {
    func begin() async throws -> AppleAuthenticationCheckpointChallenge

    func complete(
        transactionID: UUID,
        state: String,
        nonce: String,
        callbackSHA256: Data,
        sessionAuthorization: String
    ) async throws
}

protocol AuthenticationSessionStoring: Sendable {
    func storedState(at date: Date) throws -> StoredAuthenticationState
    func currentBearer(at date: Date) throws -> String?
    func save(_ session: AuthenticationSession) throws
    func remove() throws
}


enum StoredAuthenticationState: Sendable, Equatable {
    case signedOut
    case signedIn
    case expired
}

protocol AuthenticationRandomness: Sendable {
    func bytes(count: Int) throws -> Data
}

protocol AuthenticationDigesting: Sendable {
    func sha256(_ value: Data) -> Data
}

enum WebAuthenticationSessionResult: Sendable {
    case callback(URL)
    case cancelled
    case failed
}

@MainActor
protocol OAuthWebAuthenticationSession: AnyObject {
    func start() -> Bool
    func cancel()
}

@MainActor
protocol OAuthWebAuthenticationSessionFactory: AnyObject {
    func makeSession(
        authorizationURL: URL,
        callbackURLScheme: String,
        completion: @escaping @MainActor @Sendable (WebAuthenticationSessionResult) -> Void
    ) -> any OAuthWebAuthenticationSession
}

struct AuthenticationConfiguration: Sendable, Equatable {
    static let authorizationURLKey = "HikerAppleSupabaseAuthorizationURL"
    static let exchangeURLKey = "HikerAppleSupabaseSessionExchangeURL"
    static let publishableKeyKey = "HikerAppleSupabasePublishableKey"
    static let checkpointURLKey = "HikerAppleAuthenticationCheckpointURL"
    static let callbackSchemeKey = "HikerAppleSupabaseCallbackScheme"
    static let callbackHostKey = "HikerAppleSupabaseCallbackHost"
    static let callbackPathKey = "HikerAppleSupabaseCallbackPath"

    let authorizationURL: URL
    let exchangeURL: URL
    let publishableKey: String
    let checkpointURL: URL
    let callback: AuthenticationCallbackContract

    init(
        authorizationURL: URL,
        exchangeURL: URL,
        checkpointURL: URL,
        publishableKey: String,
        callback: AuthenticationCallbackContract
    ) throws {
        guard Self.isHTTPS(authorizationURL),
              Self.isHTTPS(exchangeURL),
              Self.isHTTPS(checkpointURL),
              !publishableKey.isEmpty else {
            throw AuthenticationConfigurationError.invalidEndpoint
        }
        self.authorizationURL = authorizationURL
        self.exchangeURL = exchangeURL
        self.checkpointURL = checkpointURL
        self.publishableKey = publishableKey
        self.callback = callback
    }

    static func load(from bundle: Bundle = .main) throws -> AuthenticationConfiguration {
        let authorizationURL = try url(
            for: authorizationURLKey,
            in: bundle
        )
        let exchangeURL = try url(
            for: exchangeURLKey,
            in: bundle
        )
        let checkpointURL = try url(
            for: checkpointURLKey,
            in: bundle
        )
        let publishableKey = try value(for: publishableKeyKey, in: bundle)
        let callback = try AuthenticationCallbackContract(
            scheme: try value(for: callbackSchemeKey, in: bundle),
            host: try value(for: callbackHostKey, in: bundle),
            path: try value(for: callbackPathKey, in: bundle)
        )

        guard bundle.declaredURLSchemes.contains(callback.scheme) else {
            throw AuthenticationConfigurationError.callbackSchemeNotRegistered
        }

        return try AuthenticationConfiguration(
            authorizationURL: authorizationURL,
            exchangeURL: exchangeURL,
            checkpointURL: checkpointURL,
            publishableKey: publishableKey,
            callback: callback
        )
    }
    var selfPassportRESTURL: URL? {
        guard var components = URLComponents(
            url: exchangeURL,
            resolvingAgainstBaseURL: false
        ) else {
            return nil
        }
        components.path = "/rest/v1"
        components.query = nil
        components.fragment = nil
        return components.url
    }


    private static func value(for key: String, in bundle: Bundle) throws -> String {
        guard let value = bundle.object(forInfoDictionaryKey: key) as? String else {
            throw AuthenticationConfigurationError.missingValue
        }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !trimmed.contains("$("), !trimmed.contains("${") else {
            throw AuthenticationConfigurationError.missingValue
        }
        return trimmed
    }

    private static func url(for key: String, in bundle: Bundle) throws -> URL {
        let value = try value(for: key, in: bundle)
        guard let url = URL(string: value) else {
            throw AuthenticationConfigurationError.invalidEndpoint
        }
        return url
    }

    private static func isHTTPS(_ url: URL) -> Bool {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            return false
        }
        return components.scheme?.lowercased() == "https"
            && components.host != nil
            && components.user == nil
            && components.password == nil
            && components.fragment == nil
    }
}

enum AuthenticationConfigurationError: Error {
    case missingValue
    case invalidEndpoint
    case callbackSchemeNotRegistered
}

struct AuthenticationCallbackContract: Sendable, Equatable {
    let scheme: String
    let host: String
    let path: String

    init(scheme: String, host: String, path: String) throws {
        let normalizedScheme = scheme.lowercased()
        let normalizedHost = host.lowercased()
        guard Self.isValidScheme(normalizedScheme),
              scheme == normalizedScheme,
              !normalizedHost.isEmpty,
              host == normalizedHost,
              path.hasPrefix("/"),
              path.count > 1,
              !path.hasSuffix("/"),
              !path.contains("?") && !path.contains("#") else {
            throw AuthenticationCallbackContractError.invalidValue
        }
        self.scheme = normalizedScheme
        self.host = normalizedHost
        self.path = path
    }

    func accepts(_ url: URL) -> Bool {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            return false
        }
        return components.scheme == scheme
            && components.host == host
            && components.path == path
            && components.port == nil
            && components.user == nil
            && components.password == nil
            && components.fragment == nil
    }

    private static func isValidScheme(_ value: String) -> Bool {
        guard let first = value.unicodeScalars.first,
              CharacterSet.letters.contains(first) else {
            return false
        }
        return value.unicodeScalars.allSatisfy {
            CharacterSet.alphanumerics.contains($0) || $0 == "+" || $0 == "-" || $0 == "."
        }
    }
}

enum AuthenticationCallbackContractError: Error {
    case invalidValue
}

@MainActor
@Observable
final class AuthenticationCoordinator {
    private static let replayCacheLimit = 16

    private(set) var state: AuthenticationState

    private let configuration: AuthenticationConfiguration?
    private let webAuthenticationSessionFactory: any OAuthWebAuthenticationSessionFactory
    private let codeExchanger: any AppleSupabaseCodeExchanging
    private let authenticationCheckpoint: any AppleAuthenticationCheckpointing
    private let sessionStore: any AuthenticationSessionStoring
    private let randomness: any AuthenticationRandomness
    private let digesting: any AuthenticationDigesting
    private let now: @Sendable () -> Date

    private var beginningSignInIdentifier: UUID?
    private var beginSignInTask: Task<Void, Never>?
    private var activeAttempt: ActiveAuthenticationAttempt?
    private var webAuthenticationSession: (any OAuthWebAuthenticationSession)?
    private var consumedStateDigests: [Data] = []

    init(
        configuration: AuthenticationConfiguration?,
        webAuthenticationSessionFactory: any OAuthWebAuthenticationSessionFactory,
        codeExchanger: any AppleSupabaseCodeExchanging,
        authenticationCheckpoint: any AppleAuthenticationCheckpointing,
        sessionStore: any AuthenticationSessionStoring,
        randomness: any AuthenticationRandomness = SecureAuthenticationRandomness(),
        digesting: any AuthenticationDigesting = SHA256AuthenticationDigest(),
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.configuration = configuration
        self.webAuthenticationSessionFactory = webAuthenticationSessionFactory
        self.codeExchanger = codeExchanger
        self.authenticationCheckpoint = authenticationCheckpoint
        self.sessionStore = sessionStore
        self.randomness = randomness
        self.digesting = digesting
        self.now = now

        guard configuration != nil else {
            state = .error(.unavailableConfiguration)
            return
        }
        state = Self.storedState(from: sessionStore, at: now())
    }

    static func production(bundle: Bundle = .main) -> AuthenticationCoordinator {
        let configuration = try? AuthenticationConfiguration.load(from: bundle)
        let bundleIdentifier = bundle.bundleIdentifier ?? "unconfigured.hiker"
        return AuthenticationCoordinator(
            configuration: configuration,
            webAuthenticationSessionFactory: SystemOAuthWebAuthenticationSessionFactory(),
            codeExchanger: URLSessionAppleSupabaseCodeExchanger(configuration: configuration),
            authenticationCheckpoint: URLSessionAppleAuthenticationCheckpointClient(
                configuration: configuration
            ),
            sessionStore: KeychainAuthenticationSessionStore(
                service: "\(bundleIdentifier).apple-supabase-oauth-v1"
            )
        )
    }

    func beginSignIn() {
        expireActiveAttemptIfNeeded()

        guard let configuration else {
            state = .error(.unavailableConfiguration)
            return
        }
        guard activeAttempt == nil, beginningSignInIdentifier == nil else {
            state = .error(.signInAlreadyInProgress)
            return
        }

        let beginningIdentifier = UUID()
        beginningSignInIdentifier = beginningIdentifier
        state = .signingIn
        beginSignInTask = Task { @MainActor [weak self] in
            guard let self else {
                return
            }
            await self.beginCheckpointAndStartSession(
                configuration: configuration,
                beginningIdentifier: beginningIdentifier
            )
        }
    }

    func cancelSignIn() {
        guard activeAttempt != nil || beginningSignInIdentifier != nil else {
            return
        }
        let session = webAuthenticationSession
        clearBeginningSignIn()
        clearActiveAttempt()
        session?.cancel()
        state = .cancelled
    }

    func signOut() {
        let session = webAuthenticationSession
        clearBeginningSignIn()
        clearActiveAttempt()
        session?.cancel()

        do {
            try sessionStore.remove()
            state = .signedOut
        } catch {
            state = .error(.sessionStorageFailed)
        }
    }

    func refreshStoredSessionState() {
        if expireActiveAttemptIfNeeded() {
            return
        }
        guard activeAttempt == nil, beginningSignInIdentifier == nil else {
            return
        }
        guard configuration != nil else {
            state = .error(.unavailableConfiguration)
            return
        }
        state = Self.storedState(from: sessionStore, at: now())
    }
    /// Builds an authenticated transport without exposing the bearer to UI state.
    func makeSelfPassportSyncTransport(
        datasetSHA256: String
    ) throws -> SupabaseSelfPassportSyncTransport {
        guard let configuration,
              let restURL = configuration.selfPassportRESTURL else {
            throw SupabaseSelfPassportSyncTransportError.invalidConfiguration
        }
        let expectedActorID = try currentSessionActorID()
        return try SupabaseSelfPassportSyncTransport(
            restURL: restURL,
            publishableKey: configuration.publishableKey,
            datasetSHA256: datasetSHA256,
            currentBearer: { [weak self] in
                guard let self else {
                    return nil
                }
                return await self.currentBearer(boundTo: expectedActorID)
            }
        )
    }

    func currentSessionActorID() throws -> UUID {
        guard let bearer = currentSessionBearer() else {
            throw AuthenticationSessionError.invalidPayload
        }
        return try Self.actorID(from: bearer)
    }

    private func currentBearer(boundTo expectedActorID: UUID) -> String? {
        guard let bearer = currentSessionBearer(),
              let actorID = try? Self.actorID(from: bearer),
              actorID == expectedActorID else {
            return nil
        }
        return bearer
    }

    private static func actorID(from bearer: String) throws -> UUID {
        let segments = bearer.split(separator: ".", omittingEmptySubsequences: false)
        guard segments.count == 3,
              let payload = Data(base64URLEncodedString: String(segments[1])),
              let object = try? JSONSerialization.jsonObject(with: payload) as? [String: Any],
              let subject = object["sub"] as? String,
              let actorID = UUID(uuidString: subject) else {
            throw AuthenticationSessionError.invalidPayload
        }
        return actorID
    }

    private func currentSessionBearer() -> String? {
        guard state == .signedIn else {
            return nil
        }
        let currentDate = now()
        do {
            switch try sessionStore.storedState(at: currentDate) {
            case .signedIn:
                guard let bearer = try sessionStore.currentBearer(at: currentDate) else {
                    state = Self.storedState(from: sessionStore, at: currentDate)
                    return nil
                }
                return bearer
            case .signedOut:
                state = .signedOut
                return nil
            case .expired:
                try sessionStore.remove()
                state = .expired
                return nil
            }
        } catch {
            state = .error(.sessionStorageFailed)
            return nil
        }
    }


    private func beginCheckpointAndStartSession(
        configuration: AuthenticationConfiguration,
        beginningIdentifier: UUID
    ) async {
        do {
            let challenge = try await authenticationCheckpoint.begin()
            guard beginningSignInIdentifier == beginningIdentifier else {
                return
            }
            guard challenge.expiresAt > now(),
                  !challenge.state.isEmpty,
                  !challenge.nonce.isEmpty else {
                finishBeginningSignIn(beginningIdentifier)
                state = .error(.checkpointFailed)
                return
            }

            let codeVerifier: String
            do {
                codeVerifier = try randomURLSafeValue()
            } catch {
                finishBeginningSignIn(beginningIdentifier)
                state = .error(.randomnessUnavailable)
                return
            }

            let stateDigest = digesting.sha256(Data(challenge.state.utf8))
            let codeChallenge = digesting.sha256(Data(codeVerifier.utf8))
            let authorizationURL: URL
            do {
                authorizationURL = try makeAuthorizationURL(
                    configuration: configuration,
                    rawState: challenge.state,
                    rawNonce: challenge.nonce,
                    codeChallenge: codeChallenge
                )
            } catch {
                finishBeginningSignIn(beginningIdentifier)
                state = .error(.checkpointFailed)
                return
            }

            let attempt = ActiveAuthenticationAttempt(
                identifier: UUID(),
                checkpointTransactionID: challenge.transactionID,
                rawState: challenge.state,
                rawNonce: challenge.nonce,
                stateDigest: stateDigest,
                codeVerifier: codeVerifier,
                expiresAt: challenge.expiresAt
            )
            let session = webAuthenticationSessionFactory.makeSession(
                authorizationURL: authorizationURL,
                callbackURLScheme: configuration.callback.scheme,
                completion: { [weak self] result in
                    self?.handleWebAuthenticationResult(
                        result,
                        attemptIdentifier: attempt.identifier
                    )
                }
            )

            guard beginningSignInIdentifier == beginningIdentifier else {
                return
            }
            finishBeginningSignIn(beginningIdentifier)
            activeAttempt = attempt
            webAuthenticationSession = session

            guard session.start() else {
                clearActiveAttempt()
                state = .error(.sessionStartFailed)
                return
            }
        } catch {
            guard beginningSignInIdentifier == beginningIdentifier else {
                return
            }
            finishBeginningSignIn(beginningIdentifier)
            state = .error(.checkpointFailed)
        }
    }

    func handleCallbackURL(_ callbackURL: URL) {
        guard let activeAttempt else {
            rejectCallbackWithoutActiveAttempt(callbackURL)
            return
        }
        handleCallback(callbackURL, for: activeAttempt.identifier)
    }

    private func handleWebAuthenticationResult(
        _ result: WebAuthenticationSessionResult,
        attemptIdentifier: UUID
    ) {
        guard activeAttempt?.identifier == attemptIdentifier else {
            return
        }
        switch result {
        case let .callback(callbackURL):
            handleCallback(callbackURL, for: attemptIdentifier)
        case .cancelled:
            clearActiveAttempt()
            state = .cancelled
        case .failed:
            clearActiveAttempt()
            state = .error(.invalidCallback)
        }
    }

    private func handleCallback(_ callbackURL: URL, for attemptIdentifier: UUID) {
        guard !expireActiveAttemptIfNeeded() else {
            return
        }

        guard let configuration,
              configuration.callback.accepts(callbackURL),
              let callback = CallbackParameters(url: callbackURL) else {
            clearActiveAttempt()
            state = .error(.invalidCallback)
            return
        }

        let returnedStateDigest = digesting.sha256(Data(callback.state.utf8))
        if containsConsumedStateDigest(returnedStateDigest) {
            return
        }

        guard var attempt = activeAttempt,
              attempt.identifier == attemptIdentifier else {
            state = .error(.invalidState)
            return
        }
        guard !attempt.completionStarted else {
            return
        }
        guard securelyEquals(returnedStateDigest, attempt.stateDigest) else {
            clearActiveAttempt()
            state = .error(.invalidState)
            return
        }

        attempt.completionStarted = true
        activeAttempt = attempt
        rememberConsumedStateDigest(attempt.stateDigest)

        if callback.hasProviderError {
            clearActiveAttempt()
            state = .error(.providerRejected)
            return
        }
        guard let authorizationCode = callback.authorizationCode else {
            clearActiveAttempt()
            state = .error(.missingAuthorizationCode)
            return
        }

        let callbackSHA256 = digesting.sha256(Data(callbackURL.absoluteString.utf8))
        Task { @MainActor [weak self] in
            await self?.exchangeAuthorizationCode(
                authorizationCode,
                codeVerifier: attempt.codeVerifier,
                callbackSHA256: callbackSHA256,
                attemptIdentifier: attempt.identifier
            )
        }
    }

    private func exchangeAuthorizationCode(
        _ authorizationCode: String,
        codeVerifier: String,
        callbackSHA256: Data,
        attemptIdentifier: UUID
    ) async {
        let session: AuthenticationSession
        do {
            session = try await codeExchanger.exchange(
                authorizationCode: authorizationCode,
                codeVerifier: codeVerifier
            )
        } catch {
            guard activeAttempt?.identifier == attemptIdentifier else {
                return
            }
            clearActiveAttempt()
            state = .error(.exchangeFailed)
            return
        }

        guard !expireActiveAttemptIfNeeded(),
              let attempt = activeAttempt,
              attempt.identifier == attemptIdentifier,
              attempt.completionStarted else {
            return
        }
        guard session.expiresAt.map({ $0 > now() }) ?? true else {
            clearActiveAttempt()
            state = .expired
            return
        }

        do {
            try await authenticationCheckpoint.complete(
                transactionID: attempt.checkpointTransactionID,
                state: attempt.rawState,
                nonce: attempt.rawNonce,
                callbackSHA256: callbackSHA256,
                sessionAuthorization: session.checkpointAuthorization
            )
        } catch {
            guard activeAttempt?.identifier == attemptIdentifier else {
                return
            }
            clearActiveAttempt()
            state = .error(.checkpointFailed)
            return
        }

        guard !expireActiveAttemptIfNeeded(),
              activeAttempt?.identifier == attemptIdentifier else {
            return
        }

        do {
            try sessionStore.save(session)
            clearActiveAttempt()
            state = .signedIn
        } catch {
            clearActiveAttempt()
            state = .error(.sessionStorageFailed)
        }
    }

    private func rejectCallbackWithoutActiveAttempt(_ callbackURL: URL) {
        guard let components = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false),
              let stateValue = uniqueQueryValue(named: "state", in: components) else {
            state = .error(.invalidState)
            return
        }
        guard !containsConsumedStateDigest(digesting.sha256(Data(stateValue.utf8))) else {
            return
        }
        state = .error(.invalidState)
    }

    @discardableResult
    private func expireActiveAttemptIfNeeded() -> Bool {
        guard let activeAttempt, now() >= activeAttempt.expiresAt else {
            return false
        }
        rememberConsumedStateDigest(activeAttempt.stateDigest)
        let session = webAuthenticationSession
        clearActiveAttempt()
        session?.cancel()
        state = .expired
        return true
    }

    private func clearBeginningSignIn() {
        beginningSignInIdentifier = nil
        beginSignInTask?.cancel()
        beginSignInTask = nil
    }
    private func finishBeginningSignIn(_ beginningIdentifier: UUID) {
        guard beginningSignInIdentifier == beginningIdentifier else {
            return
        }
        beginningSignInIdentifier = nil
        beginSignInTask = nil
    }

    private func clearActiveAttempt() {
        activeAttempt = nil
        webAuthenticationSession = nil
    }

    private func randomURLSafeValue() throws -> String {
        try randomness.bytes(count: 32).base64URLEncodedString()
    }

    private func makeAuthorizationURL(
        configuration: AuthenticationConfiguration,
        rawState: String,
        rawNonce: String,
        codeChallenge: Data
    ) throws -> URL {
        guard var components = URLComponents(
            url: configuration.authorizationURL,
            resolvingAgainstBaseURL: false
        ) else {
            throw AuthenticationConfigurationError.invalidEndpoint
        }
        let requiredNames: Set<String> = [
            "provider",
            "redirect_to",
            "state",
            "nonce",
            "code_challenge",
            "code_challenge_method",
        ]
        guard !(components.queryItems ?? []).contains(where: {
            requiredNames.contains($0.name)
        }) else {
            throw AuthenticationConfigurationError.invalidEndpoint
        }

        components.queryItems = (components.queryItems ?? []) + [
            URLQueryItem(name: "provider", value: "apple"),
            URLQueryItem(name: "redirect_to", value: callbackURL(configuration.callback).absoluteString),
            URLQueryItem(name: "state", value: rawState),
            URLQueryItem(name: "nonce", value: rawNonce),
            URLQueryItem(name: "code_challenge", value: codeChallenge.base64URLEncodedString()),
            URLQueryItem(name: "code_challenge_method", value: "S256"),
        ]
        guard let url = components.url else {
            throw AuthenticationConfigurationError.invalidEndpoint
        }
        return url
    }

    private func callbackURL(_ callback: AuthenticationCallbackContract) -> URL {
        var components = URLComponents()
        components.scheme = callback.scheme
        components.host = callback.host
        components.path = callback.path
        guard let url = components.url else {
            preconditionFailure("A validated authentication callback contract must build a URL.")
        }
        return url
    }

    private func rememberConsumedStateDigest(_ digest: Data) {
        consumedStateDigests.append(digest)
        if consumedStateDigests.count > Self.replayCacheLimit {
            consumedStateDigests.removeFirst(consumedStateDigests.count - Self.replayCacheLimit)
        }
    }

    private func containsConsumedStateDigest(_ candidate: Data) -> Bool {
        consumedStateDigests.contains { securelyEquals($0, candidate) }
    }

    private static func storedState(
        from sessionStore: any AuthenticationSessionStoring,
        at date: Date
    ) -> AuthenticationState {
        do {
            switch try sessionStore.storedState(at: date) {
            case .signedOut:
                return .signedOut
            case .signedIn:
                return .signedIn
            case .expired:
                try sessionStore.remove()
                return .expired
            }
        } catch {
            return .error(.sessionStorageFailed)
        }
    }
}

private struct ActiveAuthenticationAttempt: Sendable {
    let identifier: UUID
    let checkpointTransactionID: UUID
    let rawState: String
    let rawNonce: String
    let stateDigest: Data
    let codeVerifier: String
    let expiresAt: Date
    var completionStarted = false
}

private struct CallbackParameters {
    let authorizationCode: String?
    let state: String
    let hasProviderError: Bool

    init?(url: URL) {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            return nil
        }
        let stateItems = (components.queryItems ?? []).filter { $0.name == "state" }
        let errorItems = (components.queryItems ?? []).filter { $0.name == "error" }
        let codeItems = (components.queryItems ?? []).filter { $0.name == "code" }
        guard stateItems.count == 1,
              errorItems.count <= 1,
              codeItems.count <= 1,
              let state = stateItems[0].value,
              !state.isEmpty else {
            return nil
        }

        authorizationCode = codeItems.first?.value.flatMap { $0.isEmpty ? nil : $0 }
        self.state = state
        hasProviderError = !errorItems.isEmpty
    }
}

private func uniqueQueryValue(
    named name: String,
    in components: URLComponents
) -> String? {
    let matchingItems = (components.queryItems ?? []).filter { $0.name == name }
    guard matchingItems.count == 1 else {
        return nil
    }
    return matchingItems[0].value
}

private func securelyEquals(_ lhs: Data, _ rhs: Data) -> Bool {
    guard lhs.count == rhs.count else {
        return false
    }
    return lhs.withUnsafeBytes { lhsBuffer in
        rhs.withUnsafeBytes { rhsBuffer in
            let lhsBytes = lhsBuffer.bindMemory(to: UInt8.self)
            let rhsBytes = rhsBuffer.bindMemory(to: UInt8.self)
            var difference: UInt8 = 0
            for index in lhsBytes.indices {
                difference |= lhsBytes[index] ^ rhsBytes[index]
            }
            return difference == 0
        }
    }
}

private func isCancellation(_ error: Error) -> Bool {
    let error = error as NSError
    return error.domain == ASWebAuthenticationSessionErrorDomain && error.code == 1
}

private struct SecureAuthenticationRandomness: AuthenticationRandomness {
    func bytes(count: Int) throws -> Data {
        guard count > 0 else {
            throw AuthenticationRandomnessError.invalidByteCount
        }
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, count, buffer.baseAddress!)
        }
        guard status == errSecSuccess else {
            throw AuthenticationRandomnessError.unavailable
        }
        return data
    }
}

private enum AuthenticationRandomnessError: Error {
    case invalidByteCount
    case unavailable
}

private struct SHA256AuthenticationDigest: AuthenticationDigesting {
    func sha256(_ value: Data) -> Data {
        Data(SHA256.hash(data: value))
    }
}

private struct URLSessionAppleAuthenticationCheckpointClient: AppleAuthenticationCheckpointing {
    private static let timeout: TimeInterval = 10

    private let checkpointURL: URL?
    private let publishableKey: String?
    private let session: URLSession

    init(configuration: AuthenticationConfiguration?) {
        checkpointURL = configuration?.checkpointURL
        publishableKey = configuration?.publishableKey

        let sessionConfiguration = URLSessionConfiguration.ephemeral
        sessionConfiguration.timeoutIntervalForRequest = Self.timeout
        sessionConfiguration.timeoutIntervalForResource = Self.timeout
        session = URLSession(configuration: sessionConfiguration)
    }

    func begin() async throws -> AppleAuthenticationCheckpointChallenge {
        let request = try makeRequest(
            body: AppleAuthenticationCheckpointBeginRequest()
        )
        let data = try await responseData(for: request)
        return try decodeAppleAuthenticationCheckpointBeginResponse(data)
    }

    func complete(
        transactionID: UUID,
        state: String,
        nonce: String,
        callbackSHA256: Data,
        sessionAuthorization: String
    ) async throws {
        guard isValidRawChallenge(state),
              isValidRawChallenge(nonce),
              callbackSHA256.count == 32,
              !sessionAuthorization.isEmpty else {
            throw AppleAuthenticationCheckpointError.invalidRequest
        }
        let request = try makeRequest(
            body: AppleAuthenticationCheckpointCompleteRequest(
                transactionID: transactionID.uuidString.lowercased(),
                state: state,
                nonce: nonce,
                callbackSHA256: callbackSHA256.hexEncodedString()
            ),
            sessionAuthorization: sessionAuthorization
        )
        let data = try await responseData(for: request)
        try validateAppleAuthenticationCheckpointCompletionResponse(data)
    }

    private func makeRequest(
        body: some Encodable,
        sessionAuthorization: String? = nil
    ) throws -> URLRequest {
        guard let checkpointURL, let publishableKey else {
            throw AppleAuthenticationCheckpointError.unavailable
        }
        var request = URLRequest(url: checkpointURL)
        request.httpMethod = "POST"
        request.timeoutInterval = Self.timeout
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        request.setValue(publishableKey, forHTTPHeaderField: "apikey")
        if let sessionAuthorization {
            request.setValue(
                "Bearer \(sessionAuthorization)",
                forHTTPHeaderField: "Authorization"
            )
        }
        request.httpBody = try JSONEncoder().encode(body)
        return request
    }

    private func responseData(for request: URLRequest) async throws -> Data {
        let (data, response) = try await session.data(for: request)
        guard let response = response as? HTTPURLResponse,
              (200...299).contains(response.statusCode) else {
            throw AppleAuthenticationCheckpointError.rejected
        }
        return data
    }
}

private struct AppleAuthenticationCheckpointBeginRequest: Encodable {
    let action = "begin"
}

private struct AppleAuthenticationCheckpointCompleteRequest: Encodable {
    let action = "complete"
    let transactionID: String
    let state: String
    let nonce: String
    let callbackSHA256: String

    private enum CodingKeys: String, CodingKey {
        case action
        case transactionID = "transactionId"
        case state
        case nonce
        case callbackSHA256 = "callbackSha256"
    }
}

private struct AppleAuthenticationCheckpointBeginResponse: Decodable {
    let transactionID: String
    let state: String
    let nonce: String
    let expiresAt: String

    private enum CodingKeys: String, CodingKey {
        case transactionID = "transactionId"
        case state
        case nonce
        case expiresAt
    }
}

private struct AppleAuthenticationCheckpointCompleteResponse: Decodable {
    let receiptCorrelation: String
    let receiptDigest: String
    let status: String
}
func decodeAppleAuthenticationCheckpointBeginResponse(
    _ data: Data
) throws -> AppleAuthenticationCheckpointChallenge {
    let response = try decodeExact(
        AppleAuthenticationCheckpointBeginResponse.self,
        from: data,
        allowedKeys: ["transactionId", "state", "nonce", "expiresAt"]
    )
    guard let transactionID = UUID(uuidString: response.transactionID),
          isValidRawChallenge(response.state),
          isValidRawChallenge(response.nonce),
          let expiresAt = checkpointDate(from: response.expiresAt) else {
        throw AppleAuthenticationCheckpointError.invalidResponse
    }
    return AppleAuthenticationCheckpointChallenge(
        transactionID: transactionID,
        state: response.state,
        nonce: response.nonce,
        expiresAt: expiresAt
    )
}

func encodeAppleAuthenticationCheckpointCompleteRequest(
    transactionID: UUID,
    state: String,
    nonce: String,
    callbackSHA256: Data
) throws -> Data {
    try JSONEncoder().encode(
        AppleAuthenticationCheckpointCompleteRequest(
            transactionID: transactionID.uuidString.lowercased(),
            state: state,
            nonce: nonce,
            callbackSHA256: callbackSHA256.hexEncodedString()
        )
    )
}
func validateAppleAuthenticationCheckpointCompletionResponse(_ data: Data) throws {
    let response = try decodeExact(
        AppleAuthenticationCheckpointCompleteResponse.self,
        from: data,
        allowedKeys: ["receiptCorrelation", "receiptDigest", "status"]
    )
    guard UUID(uuidString: response.receiptCorrelation) != nil,
          isValidSHA256Hex(response.receiptDigest),
          response.status == "completed" else {
        throw AppleAuthenticationCheckpointError.invalidResponse
    }
}

private enum AppleAuthenticationCheckpointError: Error {
    case unavailable
    case invalidRequest
    case rejected
    case invalidResponse
}

private func decodeExact<T: Decodable>(
    _ type: T.Type,
    from data: Data,
    allowedKeys: Set<String>
) throws -> T {
    guard let response = try JSONSerialization.jsonObject(with: data) as? [String: Any],
          Set(response.keys) == allowedKeys else {
        throw AppleAuthenticationCheckpointError.invalidResponse
    }
    return try JSONDecoder().decode(type, from: data)
}

private func isValidRawChallenge(_ value: String) -> Bool {
    !value.isEmpty
        && value.utf8.count <= 512
        && value.unicodeScalars.allSatisfy { !CharacterSet.controlCharacters.contains($0) }
}
private func isValidSHA256Hex(_ value: String) -> Bool {
    value.utf8.count == 64
        && value.unicodeScalars.allSatisfy {
            CharacterSet(charactersIn: "0123456789abcdef").contains($0)
        }
}

private func checkpointDate(from value: String) -> Date? {
    let fractionalFormatter = ISO8601DateFormatter()
    fractionalFormatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return fractionalFormatter.date(from: value) ?? ISO8601DateFormatter().date(from: value)
}

private extension Data {
    func hexEncodedString() -> String {
        map { String(format: "%02x", $0) }.joined()
    }
}
private struct URLSessionAppleSupabaseCodeExchanger: AppleSupabaseCodeExchanging {
    private let exchangeURL: URL?
    private let publishableKey: String?
    private let session: URLSession

    init(configuration: AuthenticationConfiguration?) {
        exchangeURL = configuration?.exchangeURL
        publishableKey = configuration?.publishableKey
        let sessionConfiguration = URLSessionConfiguration.ephemeral
        sessionConfiguration.requestCachePolicy = .reloadIgnoringLocalCacheData
        sessionConfiguration.urlCache = nil
        sessionConfiguration.httpCookieStorage = nil
        session = URLSession(configuration: sessionConfiguration)
    }

    func exchange(
        authorizationCode: String,
        codeVerifier: String
    ) async throws -> AuthenticationSession {
        guard let exchangeURL, let publishableKey else {
            throw AppleSupabaseCodeExchangeError.unavailable
        }
        var request = URLRequest(url: exchangeURL)
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue(publishableKey, forHTTPHeaderField: "apikey")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        request.setValue("no-cache", forHTTPHeaderField: "Pragma")
        request.httpBody = try JSONEncoder().encode(
            AppleSupabaseCodeExchangeRequest(
                authorizationCode: authorizationCode,
                codeVerifier: codeVerifier
            )
        )

        let (data, response) = try await session.data(for: request)
        guard let response = response as? HTTPURLResponse,
              (200...299).contains(response.statusCode) else {
            throw AppleSupabaseCodeExchangeError.rejected
        }
        let exchangeResponse = try JSONDecoder().decode(
            SupabasePKCESessionResponse.self,
            from: data
        )
        guard !exchangeResponse.accessToken.isEmpty,
              !exchangeResponse.refreshToken.isEmpty,
              exchangeResponse.tokenType.caseInsensitiveCompare("bearer") == .orderedSame,
              exchangeResponse.expiresIn > 0 else {
            throw AppleSupabaseCodeExchangeError.invalidResponse
        }

        let keychainPayload = try JSONEncoder().encode(
            KeychainSupabaseSession(
                accessToken: exchangeResponse.accessToken,
                refreshToken: exchangeResponse.refreshToken,
                tokenType: exchangeResponse.tokenType
            )
        )
        return try AuthenticationSession(
            keychainPayload: keychainPayload,
            checkpointAuthorization: exchangeResponse.accessToken,
            expiresAt: Date().addingTimeInterval(exchangeResponse.expiresIn)
        )
    }
}

private struct AppleSupabaseCodeExchangeRequest: Encodable {
    let authorizationCode: String
    let codeVerifier: String

    enum CodingKeys: String, CodingKey {
        case authorizationCode = "auth_code"
        case codeVerifier = "code_verifier"
    }
}

private struct ExactAuthenticationCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int? = nil

    init?(stringValue: String) {
        self.stringValue = stringValue
    }

    init?(intValue: Int) {
        return nil
    }
}

private struct SupabasePKCESessionResponse: Decodable {
    let accessToken: String
    let refreshToken: String
    let tokenType: String
    let expiresIn: TimeInterval

    init(from decoder: any Decoder) throws {
        let raw = try decoder.container(keyedBy: ExactAuthenticationCodingKey.self)
        guard Set(raw.allKeys.map(\.stringValue)) == Set([
            "access_token",
            "refresh_token",
            "token_type",
            "expires_in",
        ]) else {
            throw AppleSupabaseCodeExchangeError.invalidResponse
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        accessToken = try container.decode(String.self, forKey: .accessToken)
        refreshToken = try container.decode(String.self, forKey: .refreshToken)
        tokenType = try container.decode(String.self, forKey: .tokenType)
        expiresIn = try container.decode(TimeInterval.self, forKey: .expiresIn)
    }

    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case refreshToken = "refresh_token"
        case tokenType = "token_type"
        case expiresIn = "expires_in"
    }
}

private struct KeychainSupabaseSession: Codable {
    let accessToken: String
    let refreshToken: String
    let tokenType: String

    init(accessToken: String, refreshToken: String, tokenType: String) {
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        self.tokenType = tokenType
    }

    init(from decoder: any Decoder) throws {
        let raw = try decoder.container(keyedBy: ExactAuthenticationCodingKey.self)
        guard Set(raw.allKeys.map(\.stringValue)) == Set([
            "accessToken",
            "refreshToken",
            "tokenType",
        ]) else {
            throw AuthenticationSessionStorageError.invalidStoredSession
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        accessToken = try container.decode(String.self, forKey: .accessToken)
        refreshToken = try container.decode(String.self, forKey: .refreshToken)
        tokenType = try container.decode(String.self, forKey: .tokenType)
    }

    private enum CodingKeys: String, CodingKey {
        case accessToken
        case refreshToken
        case tokenType
    }
}

private enum AppleSupabaseCodeExchangeError: Error {
    case unavailable
    case rejected
    case invalidResponse
}

private struct KeychainAuthenticationSessionStore: AuthenticationSessionStoring {
    private static let account = "session"

    let service: String

    func storedState(at date: Date) throws -> StoredAuthenticationState {
        var query = baseQuery
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecItemNotFound:
            return .signedOut
        case errSecSuccess:
            guard let data = item as? Data else {
                throw AuthenticationSessionStorageError.invalidStoredSession
            }
            let storedSession = try JSONDecoder().decode(StoredKeychainSession.self, from: data)
            guard !storedSession.payload.isEmpty else {
                throw AuthenticationSessionStorageError.invalidStoredSession
            }
            if let expiresAt = storedSession.expiresAt, expiresAt <= date {
                return .expired
            }
            return .signedIn
        default:
            throw AuthenticationSessionStorageError.keychainUnavailable
        }
    }
    func currentBearer(at date: Date) throws -> String? {
        var query = baseQuery
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecItemNotFound:
            return nil
        case errSecSuccess:
            guard let data = item as? Data else {
                throw AuthenticationSessionStorageError.invalidStoredSession
            }
            let storedSession = try JSONDecoder().decode(StoredKeychainSession.self, from: data)
            guard !storedSession.payload.isEmpty,
                  storedSession.expiresAt.map({ $0 > date }) ?? true else {
                return nil
            }
            let session = try JSONDecoder().decode(
                KeychainSupabaseSession.self,
                from: storedSession.payload
            )
            guard !session.accessToken.isEmpty,
                  session.tokenType.caseInsensitiveCompare("bearer") == .orderedSame else {
                throw AuthenticationSessionStorageError.invalidStoredSession
            }
            return session.accessToken
        default:
            throw AuthenticationSessionStorageError.keychainUnavailable
        }
    }

    func save(_ session: AuthenticationSession) throws {
        let data = try JSONEncoder().encode(
            StoredKeychainSession(
                payload: session.keychainPayload,
                expiresAt: session.expiresAt
            )
        )
        var addQuery = baseQuery
        addQuery[kSecValueData] = data
        addQuery[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly

        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        if addStatus == errSecSuccess {
            return
        }
        guard addStatus == errSecDuplicateItem else {
            throw AuthenticationSessionStorageError.keychainUnavailable
        }

        let attributes: [CFString: Any] = [
            kSecValueData: data,
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        guard SecItemUpdate(baseQuery as CFDictionary, attributes as CFDictionary) == errSecSuccess else {
            throw AuthenticationSessionStorageError.keychainUnavailable
        }
    }

    func remove() throws {
        let status = SecItemDelete(baseQuery as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw AuthenticationSessionStorageError.keychainUnavailable
        }
    }

    private var baseQuery: [CFString: Any] {
        [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: Self.account,
            kSecAttrSynchronizable: kCFBooleanFalse as Any,
        ]
    }
}

private struct StoredKeychainSession: Codable {
    let payload: Data
    let expiresAt: Date?

    init(payload: Data, expiresAt: Date?) {
        self.payload = payload
        self.expiresAt = expiresAt
    }

    init(from decoder: any Decoder) throws {
        let raw = try decoder.container(keyedBy: ExactAuthenticationCodingKey.self)
        guard Set(raw.allKeys.map(\.stringValue)) == Set([
            "payload",
            "expiresAt",
        ]) else {
            throw AuthenticationSessionStorageError.invalidStoredSession
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        payload = try container.decode(Data.self, forKey: .payload)
        expiresAt = try container.decodeIfPresent(Date.self, forKey: .expiresAt)
    }

    private enum CodingKeys: String, CodingKey {
        case payload
        case expiresAt
    }
}

private enum AuthenticationSessionStorageError: Error {
    case invalidStoredSession
    case keychainUnavailable
}

@MainActor
private final class SystemOAuthWebAuthenticationSessionFactory: OAuthWebAuthenticationSessionFactory {
    func makeSession(
        authorizationURL: URL,
        callbackURLScheme: String,
        completion: @escaping @MainActor @Sendable (WebAuthenticationSessionResult) -> Void
    ) -> any OAuthWebAuthenticationSession {
        SystemOAuthWebAuthenticationSession(
            authorizationURL: authorizationURL,
            callbackURLScheme: callbackURLScheme,
            completion: completion
        )
    }
}

@MainActor
private final class SystemOAuthWebAuthenticationSession: NSObject, OAuthWebAuthenticationSession {
    private let presentationContextProvider = WebAuthenticationPresentationContextProvider()
    private let session: ASWebAuthenticationSession

    init(
        authorizationURL: URL,
        callbackURLScheme: String,
        completion: @escaping @MainActor @Sendable (WebAuthenticationSessionResult) -> Void
    ) {
        session = ASWebAuthenticationSession(
            url: authorizationURL,
            callbackURLScheme: callbackURLScheme,
            completionHandler: { callbackURL, error in
                let result: WebAuthenticationSessionResult
                if let error {
                    result = isCancellation(error) ? .cancelled : .failed
                } else if let callbackURL {
                    result = .callback(callbackURL)
                } else {
                    result = .failed
                }
                Task { @MainActor in
                    completion(result)
                }
            }
        )
        super.init()
        session.presentationContextProvider = presentationContextProvider
        session.prefersEphemeralWebBrowserSession = true
    }

    func start() -> Bool {
        session.start()
    }

    func cancel() {
        session.cancel()
    }
}

@MainActor
private final class WebAuthenticationPresentationContextProvider: NSObject,
    ASWebAuthenticationPresentationContextProviding {
    func presentationAnchor(
        for session: ASWebAuthenticationSession
    ) -> ASPresentationAnchor {
        UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap(\.windows)
            .first(where: \.isKeyWindow) ?? UIWindow()
    }
}

private extension Bundle {
    var declaredURLSchemes: Set<String> {
        let urlTypes = object(forInfoDictionaryKey: "CFBundleURLTypes") as? [[String: Any]] ?? []
        return Set<String>(
            urlTypes
                .flatMap { $0["CFBundleURLSchemes"] as? [String] ?? [] }
                .map { $0.lowercased() }
        )
    }
}

private extension Data {
    init?(base64URLEncodedString value: String) {
        var normalized = value
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = normalized.count % 4
        if remainder != 0 {
            normalized.append(String(repeating: "=", count: 4 - remainder))
        }
        self.init(base64Encoded: normalized)
    }
    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
