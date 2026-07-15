import CryptoKit
import Foundation
import XCTest
@testable import HikerApp

@MainActor
final class AuthenticationCoordinatorTests: XCTestCase {
    func testAuthorizationURLUsesServerChallengeAndPKCEValuesWithoutPublishingRawValues() async throws {
        let randomValues = makeRandomValues()
        let harness = try makeHarness(randomValues: randomValues)

        harness.coordinator.beginSignIn()

        let authorizationURL = try await authorizationURL(from: harness.factory)
        let components = try XCTUnwrap(
            URLComponents(url: authorizationURL, resolvingAgainstBaseURL: false)
        )
        let items = components.queryItems ?? []
        let rawVerifier = randomValues[0].base64URLEncodedForTest()
        let challenge = FakeCheckpoint.defaultChallenge
        let digest = TestAuthenticationDigest()

        XCTAssertEqual(queryValue(named: "provider", in: items), "apple")
        XCTAssertEqual(queryValue(named: "state", in: items), challenge.state)
        XCTAssertEqual(queryValue(named: "nonce", in: items), challenge.nonce)
        XCTAssertEqual(
            queryValue(named: "code_challenge", in: items),
            digest.sha256(Data(rawVerifier.utf8)).base64URLEncodedForTest()
        )
        XCTAssertEqual(queryValue(named: "code_challenge_method", in: items), "S256")
        XCTAssertNotEqual(queryValue(named: "code_challenge", in: items), rawVerifier)
        XCTAssertEqual(harness.coordinator.state, .signingIn)

        let publicState = String(describing: harness.coordinator.state)
        for rawValue in [challenge.state, challenge.nonce, rawVerifier] {
            XCTAssertFalse(publicState.contains(rawValue))
        }
    }
    func testProductionCheckpointCompletionDecoderAcceptsOnlyExactValidatedContract() throws {
        let receiptID = "11111111-1111-4111-8111-111111111111"
        let digest = String(repeating: "a", count: 64)
        let valid = Data(
            """
            {"receiptCorrelation":"\(receiptID)","receiptDigest":"\(digest)","status":"completed"}
            """.utf8
        )

        XCTAssertNoThrow(
            try validateAppleAuthenticationCheckpointCompletionResponse(valid)
        )

        let snakeCase = Data(
            """
            {"receipt_correlation":"\(receiptID)","receipt_digest":"\(digest)","status":"completed"}
            """.utf8
        )
        let extraKey = Data(
            """
            {"receiptCorrelation":"\(receiptID)","receiptDigest":"\(digest)","status":"completed","extra":true}
            """.utf8
        )
        let invalidDigest = Data(
            """
            {"receiptCorrelation":"\(receiptID)","receiptDigest":"invalid","status":"completed"}
            """.utf8
        )

        XCTAssertThrowsError(
            try validateAppleAuthenticationCheckpointCompletionResponse(snakeCase)
        )
        XCTAssertThrowsError(
            try validateAppleAuthenticationCheckpointCompletionResponse(extraKey)
        )
        XCTAssertThrowsError(
            try validateAppleAuthenticationCheckpointCompletionResponse(invalidDigest)
        )
    }
    func testProductionCheckpointBeginAndCompleteTransportKeysMatchEdgeContract() throws {
        let transactionID = try XCTUnwrap(
            UUID(uuidString: "11111111-1111-4111-8111-111111111111")
        )
        let beginData = Data(
            """
            {"transactionId":"\(transactionID.uuidString.lowercased())","state":"server-state","nonce":"server-nonce","expiresAt":"2030-01-01T00:00:00Z"}
            """.utf8
        )
        let challenge = try decodeAppleAuthenticationCheckpointBeginResponse(beginData)

        XCTAssertEqual(challenge.transactionID, transactionID)
        XCTAssertEqual(challenge.state, "server-state")
        XCTAssertEqual(challenge.nonce, "server-nonce")

        let callbackDigest = Data(repeating: 0xab, count: 32)
        let completeData = try encodeAppleAuthenticationCheckpointCompleteRequest(
            transactionID: transactionID,
            state: challenge.state,
            nonce: challenge.nonce,
            callbackSHA256: callbackDigest
        )
        let encoded = try XCTUnwrap(
            JSONSerialization.jsonObject(with: completeData) as? [String: Any]
        )

        XCTAssertEqual(
            Set(encoded.keys),
            Set(["action", "transactionId", "state", "nonce", "callbackSha256"])
        )
        XCTAssertEqual(encoded["action"] as? String, "complete")
        XCTAssertEqual(
            encoded["transactionId"] as? String,
            transactionID.uuidString.lowercased()
        )
        XCTAssertEqual(encoded["callbackSha256"] as? String, String(repeating: "ab", count: 32))
        XCTAssertNil(encoded["transactionID"])
        XCTAssertNil(encoded["callbackSHA256"])
    }
    func testMissingConfigurationFailsClosed() throws {
        let factory = FakeWebAuthenticationSessionFactory()
        let store = FakeSessionStore(storedState: .signedOut, failOnSave: false)
        let exchanger = FakeCodeExchanger(result: .success(try makeSession()))
        let checkpoint = FakeCheckpoint()
        let coordinator = AuthenticationCoordinator(
            configuration: nil,
            webAuthenticationSessionFactory: factory,
            codeExchanger: exchanger,
            authenticationCheckpoint: checkpoint,
            sessionStore: store,
            randomness: FixedAuthenticationRandomness(values: makeRandomValues()),
            digesting: TestAuthenticationDigest(),
            now: { Date(timeIntervalSinceReferenceDate: 1_000) }
        )

        XCTAssertEqual(coordinator.state, .error(.unavailableConfiguration))
        coordinator.beginSignIn()

        XCTAssertEqual(coordinator.state, .error(.unavailableConfiguration))
        XCTAssertNil(factory.authorizationURL)
        XCTAssertEqual(checkpoint.snapshot().beginCount, 0)
        XCTAssertEqual(exchanger.snapshot().exchangeCount, 0)
        XCTAssertEqual(store.snapshot().savedSessionCount, 0)
    }

    func testCallbackRequiresExactConfiguredOrigin() async throws {
        for origin in [
            (scheme: "other-auth", host: "callback", path: "/oauth/callback", port: nil),
            (scheme: "hiker-auth", host: "other-callback", path: "/oauth/callback", port: nil),
            (scheme: "hiker-auth", host: "callback", path: "/oauth/other", port: nil),
            (scheme: "hiker-auth", host: "callback", path: "/oauth/callback", port: 443),
        ] {
            let harness = try makeHarness()
            harness.coordinator.beginSignIn()
            let returnedState = try await authorizationState(from: harness.factory)
            let callback = try makeCallbackURL(
                state: returnedState,
                scheme: origin.scheme,
                host: origin.host,
                path: origin.path,
                port: origin.port
            )

            harness.coordinator.handleCallbackURL(callback)

            XCTAssertEqual(harness.coordinator.state, .error(.invalidCallback))
            XCTAssertEqual(harness.exchanger.snapshot().exchangeCount, 0)
            XCTAssertEqual(harness.store.snapshot().savedSessionCount, 0)
        }
    }

    func testCallbackRejectsMismatchedStateWithoutExchangingOrSaving() async throws {
        let harness = try makeHarness()
        harness.coordinator.beginSignIn()
        let returnedState = try await authorizationState(from: harness.factory)
        let callback = try makeCallbackURL(state: returnedState + "-mismatch")

        harness.coordinator.handleCallbackURL(callback)

        XCTAssertEqual(harness.coordinator.state, .error(.invalidState))
        XCTAssertEqual(harness.exchanger.snapshot().exchangeCount, 0)
        XCTAssertEqual(harness.store.snapshot().savedSessionCount, 0)
    }

    func testCallbackRejectsMissingAndMalformedAuthorizationCodes() async throws {
        let missingCodeHarness = try makeHarness()
        missingCodeHarness.coordinator.beginSignIn()
        let missingCodeCallback = try makeCallbackURL(
            state: try await authorizationState(from: missingCodeHarness.factory),
            codeValues: []
        )

        missingCodeHarness.coordinator.handleCallbackURL(missingCodeCallback)

        XCTAssertEqual(missingCodeHarness.coordinator.state, .error(.missingAuthorizationCode))
        XCTAssertEqual(missingCodeHarness.exchanger.snapshot().exchangeCount, 0)

        let malformedCodeHarness = try makeHarness()
        malformedCodeHarness.coordinator.beginSignIn()
        let malformedCodeCallback = try makeCallbackURL(
            state: try await authorizationState(from: malformedCodeHarness.factory),
            codeValues: ["first", "second"]
        )

        malformedCodeHarness.coordinator.handleCallbackURL(malformedCodeCallback)

        XCTAssertEqual(malformedCodeHarness.coordinator.state, .error(.invalidCallback))
        XCTAssertEqual(malformedCodeHarness.exchanger.snapshot().exchangeCount, 0)
        XCTAssertEqual(malformedCodeHarness.store.snapshot().savedSessionCount, 0)
    }

    func testWebCancellationClearsActiveAttemptWithoutExchangingOrSaving() async throws {
        let harness = try makeHarness()
        harness.coordinator.beginSignIn()

        _ = try await authorizationState(from: harness.factory)
        harness.factory.complete(.cancelled)

        XCTAssertEqual(harness.coordinator.state, .cancelled)
        XCTAssertEqual(harness.exchanger.snapshot().exchangeCount, 0)
        XCTAssertEqual(harness.store.snapshot().savedSessionCount, 0)
        XCTAssertTrue(harness.checkpoint.snapshot().completions.isEmpty)
    }

    func testReplayedCallbackDoesNotExchangeOrSaveAgain() async throws {
        let harness = try makeHarness()
        harness.coordinator.beginSignIn()
        let callback = try makeCallbackURL(
            state: try await authorizationState(from: harness.factory)
        )

        harness.factory.complete(.callback(callback))
        await assertState(harness.coordinator, equals: .signedIn)

        harness.coordinator.handleCallbackURL(callback)

        XCTAssertEqual(harness.coordinator.state, .signedIn)
        XCTAssertEqual(harness.exchanger.snapshot().exchangeCount, 1)
        XCTAssertEqual(harness.store.snapshot().saveAttemptCount, 1)
        XCTAssertEqual(harness.store.snapshot().savedSessionCount, 1)
        XCTAssertEqual(harness.checkpoint.snapshot().completions.count, 1)
    }

    func testExpiredStoredSessionIsClearedAndNotPublishedAsSignedIn() throws {
        let harness = try makeHarness(storedState: .expired)

        XCTAssertEqual(harness.coordinator.state, .expired)
        XCTAssertNotEqual(harness.coordinator.state, .signedIn)
        XCTAssertEqual(harness.store.snapshot().removeCount, 1)
        XCTAssertEqual(harness.store.snapshot().savedSessionCount, 0)
    }

    func testSessionLifecycle() async throws {
        let harness = try makeHarness()
        XCTAssertEqual(harness.coordinator.state, .signedOut)

        harness.coordinator.beginSignIn()
        let callback = try makeCallbackURL(
            state: try await authorizationState(from: harness.factory)
        )
        harness.factory.complete(.callback(callback))
        await assertState(harness.coordinator, equals: .signedIn)

        XCTAssertEqual(harness.checkpoint.snapshot().completions.count, 1)
        XCTAssertEqual(harness.store.snapshot().savedSessionCount, 1)

        harness.coordinator.signOut()
        XCTAssertEqual(harness.coordinator.state, .signedOut)
        XCTAssertEqual(harness.store.snapshot().removeCount, 1)
    }
    func testSignOutClearsStoredSession() throws {
        let harness = try makeHarness(storedState: .signedIn)

        XCTAssertEqual(harness.coordinator.state, .signedIn)
        harness.coordinator.signOut()

        XCTAssertEqual(harness.coordinator.state, .signedOut)
        XCTAssertEqual(harness.store.snapshot().removeCount, 1)
    }

    func testExchangeFailureDoesNotPublishOrStoreSession() async throws {
        let harness = try makeHarness(exchangeResult: .failure)
        harness.coordinator.beginSignIn()
        let callback = try makeCallbackURL(
            state: try await authorizationState(from: harness.factory)
        )

        harness.factory.complete(.callback(callback))
        await assertState(harness.coordinator, equals: .error(.exchangeFailed))

        XCTAssertNotEqual(harness.coordinator.state, .signedIn)
        XCTAssertEqual(harness.exchanger.snapshot().exchangeCount, 1)
        XCTAssertEqual(harness.store.snapshot().saveAttemptCount, 0)
        XCTAssertEqual(harness.store.snapshot().savedSessionCount, 0)
    }

    func testStorageFailureDoesNotPublishSignedInSession() async throws {
        let harness = try makeHarness(failOnSave: true)
        harness.coordinator.beginSignIn()
        let callback = try makeCallbackURL(
            state: try await authorizationState(from: harness.factory)
        )

        harness.factory.complete(.callback(callback))
        await assertState(harness.coordinator, equals: .error(.sessionStorageFailed))

        XCTAssertNotEqual(harness.coordinator.state, .signedIn)
        XCTAssertEqual(harness.exchanger.snapshot().exchangeCount, 1)
        XCTAssertEqual(harness.store.snapshot().saveAttemptCount, 1)
        XCTAssertEqual(harness.store.snapshot().savedSessionCount, 0)
    }

    func testCheckpointCompletionReceivesExactAuthorizationBindingsBeforeSessionIsSaved() async throws {
        let randomValues = makeRandomValues()
        let harness = try makeHarness(randomValues: randomValues)
        harness.coordinator.beginSignIn()

        let state = try await authorizationState(from: harness.factory)
        let callback = try makeCallbackURL(state: state, codeValues: ["exact-authorization-code"])
        harness.factory.complete(.callback(callback))
        await assertState(harness.coordinator, equals: .signedIn)

        let exchange = try XCTUnwrap(harness.exchanger.snapshot().invocations.only)
        XCTAssertEqual(exchange.authorizationCode, "exact-authorization-code")
        XCTAssertEqual(exchange.codeVerifier, randomValues[0].base64URLEncodedForTest())

        let completion = try XCTUnwrap(harness.checkpoint.snapshot().completions.only)
        XCTAssertEqual(completion.transactionID, FakeCheckpoint.defaultChallenge.transactionID)
        XCTAssertEqual(completion.state, FakeCheckpoint.defaultChallenge.state)
        XCTAssertEqual(completion.nonce, FakeCheckpoint.defaultChallenge.nonce)
        XCTAssertEqual(
            completion.callbackSHA256,
            TestAuthenticationDigest().sha256(Data(callback.absoluteString.utf8))
        )
        XCTAssertEqual(completion.sessionAuthorization, "issued-session-authorization")
        XCTAssertEqual(harness.store.snapshot().savedSessionCount, 1)
    }

    func testCheckpointBeginFailureDoesNotStartWebAuthenticationOrSaveSession() async throws {
        let harness = try makeHarness(failCheckpointBegin: true)
        harness.coordinator.beginSignIn()
        await assertState(harness.coordinator, equals: .error(.checkpointFailed))

        XCTAssertNil(harness.factory.authorizationURL)
        XCTAssertEqual(harness.checkpoint.snapshot().beginCount, 1)
        XCTAssertTrue(harness.checkpoint.snapshot().completions.isEmpty)
        XCTAssertEqual(harness.exchanger.snapshot().exchangeCount, 0)
        XCTAssertEqual(harness.store.snapshot().saveAttemptCount, 0)
        XCTAssertNotEqual(harness.coordinator.state, .signedIn)
    }

    func testCheckpointCompletionFailureDoesNotSaveOrPublishSession() async throws {
        let harness = try makeHarness(failCheckpointCompletion: true)
        harness.coordinator.beginSignIn()
        let callback = try makeCallbackURL(
            state: try await authorizationState(from: harness.factory)
        )

        harness.factory.complete(.callback(callback))
        await assertState(harness.coordinator, equals: .error(.checkpointFailed))

        XCTAssertEqual(harness.exchanger.snapshot().exchangeCount, 1)
        XCTAssertEqual(harness.checkpoint.snapshot().completions.count, 1)
        XCTAssertEqual(harness.store.snapshot().saveAttemptCount, 0)
        XCTAssertEqual(harness.store.snapshot().savedSessionCount, 0)
        XCTAssertNotEqual(harness.coordinator.state, .signedIn)
    }

    func testSessionStartFailureDoesNotExchangeCheckpointOrSave() async throws {
        let harness = try makeHarness(sessionStarts: false)
        harness.coordinator.beginSignIn()
        _ = try await authorizationURL(from: harness.factory)
        await assertState(harness.coordinator, equals: .error(.sessionStartFailed))

        XCTAssertEqual(harness.exchanger.snapshot().exchangeCount, 0)
        XCTAssertTrue(harness.checkpoint.snapshot().completions.isEmpty)
        XCTAssertEqual(harness.store.snapshot().saveAttemptCount, 0)
    }

    func testRandomnessFailureDoesNotStartWebAuthenticationOrSaveSession() async throws {
        let harness = try makeHarness(randomValues: [])
        harness.coordinator.beginSignIn()
        await assertState(harness.coordinator, equals: .error(.randomnessUnavailable))

        XCTAssertEqual(harness.checkpoint.snapshot().beginCount, 1)
        XCTAssertNil(harness.factory.authorizationURL)
        XCTAssertEqual(harness.exchanger.snapshot().exchangeCount, 0)
        XCTAssertTrue(harness.checkpoint.snapshot().completions.isEmpty)
        XCTAssertEqual(harness.store.snapshot().saveAttemptCount, 0)
    }

    func testProviderErrorDoesNotExchangeCompleteOrSave() async throws {
        let harness = try makeHarness()
        harness.coordinator.beginSignIn()
        let callback = try makeCallbackURL(
            state: try await authorizationState(from: harness.factory),
            codeValues: [],
            providerError: "access_denied"
        )

        harness.factory.complete(.callback(callback))

        XCTAssertEqual(harness.coordinator.state, .error(.providerRejected))
        XCTAssertEqual(harness.exchanger.snapshot().exchangeCount, 0)
        XCTAssertTrue(harness.checkpoint.snapshot().completions.isEmpty)
        XCTAssertEqual(harness.store.snapshot().saveAttemptCount, 0)
    }

    func testForegroundRefreshExpiresLiveAttemptWithoutSavingSession() async throws {
        let clock = TestDateSource(Date(timeIntervalSinceReferenceDate: 1_000))
        let harness = try makeHarness(now: { clock.value() })
        harness.coordinator.beginSignIn()
        _ = try await authorizationState(from: harness.factory)

        clock.set(Date(timeIntervalSinceReferenceDate: 1_200))
        harness.coordinator.refreshStoredSessionState()

        XCTAssertEqual(harness.coordinator.state, .expired)
        XCTAssertEqual(harness.exchanger.snapshot().exchangeCount, 0)
        XCTAssertTrue(harness.checkpoint.snapshot().completions.isEmpty)
        XCTAssertEqual(harness.store.snapshot().saveAttemptCount, 0)
    }

    func testSignOutWinsAgainstQueuedCallbackCompletion() async throws {
        let harness = try makeHarness()
        harness.coordinator.beginSignIn()
        let callback = try makeCallbackURL(
            state: try await authorizationState(from: harness.factory)
        )

        harness.factory.complete(.callback(callback))
        harness.coordinator.signOut()
        await Task.yield()
        await Task.yield()

        XCTAssertEqual(harness.coordinator.state, .signedOut)
        XCTAssertTrue(harness.checkpoint.snapshot().completions.isEmpty)
        XCTAssertEqual(harness.store.snapshot().saveAttemptCount, 0)
        XCTAssertEqual(harness.store.snapshot().savedSessionCount, 0)
    }
    func testAccountPublicationPolicyRejectsCrossAccountAndUnboundExistingState() throws {
        let actorA = try XCTUnwrap(UUID(uuidString: "11111111-1111-4111-8111-111111111111"))
        let actorB = try XCTUnwrap(UUID(uuidString: "22222222-2222-4222-8222-222222222222"))

        XCTAssertThrowsError(
            try LocalPassportAccountPublicationPolicy.resolvedActorID(
                currentActorID: actorB,
                snapshotActorID: actorA,
                hasExistingState: true
            )
        )
        XCTAssertThrowsError(
            try LocalPassportAccountPublicationPolicy.resolvedActorID(
                currentActorID: actorA,
                snapshotActorID: nil,
                hasExistingState: true
            )
        )
    }

    func testAccountPublicationPolicyBindsOnlyEmptyStateAndRetainsMatchingActor() throws {
        let actor = try XCTUnwrap(UUID(uuidString: "11111111-1111-4111-8111-111111111111"))

        XCTAssertEqual(
            try LocalPassportAccountPublicationPolicy.resolvedActorID(
                currentActorID: actor,
                snapshotActorID: nil,
                hasExistingState: false
            ),
            actor
        )
        XCTAssertEqual(
            try LocalPassportAccountPublicationPolicy.resolvedActorID(
                currentActorID: actor,
                snapshotActorID: actor,
                hasExistingState: true
            ),
            actor
        )
        XCTAssertThrowsError(
            try LocalPassportAccountPublicationPolicy.resolvedActorID(
                currentActorID: nil,
                snapshotActorID: nil,
                hasExistingState: true
            )
        )
    }
    private func makeHarness(
        storedState: StoredAuthenticationState = .signedOut,
        exchangeResult: FakeExchangeResult? = nil,
        failOnSave: Bool = false,
        failCheckpointBegin: Bool = false,
        failCheckpointCompletion: Bool = false,
        randomValues: [Data]? = nil,
        sessionStarts: Bool = true,
        now: @escaping @Sendable () -> Date = {
            Date(timeIntervalSinceReferenceDate: 1_000)
        }
    ) throws -> AuthenticationHarness {
        let factory = FakeWebAuthenticationSessionFactory(starts: sessionStarts)
        let store = FakeSessionStore(storedState: storedState, failOnSave: failOnSave)
        let resolvedExchangeResult: FakeExchangeResult
        if let exchangeResult {
            resolvedExchangeResult = exchangeResult
        } else {
            resolvedExchangeResult = .success(try makeSession())
        }
        let exchanger = FakeCodeExchanger(result: resolvedExchangeResult)
        let checkpoint = FakeCheckpoint(
            failBegin: failCheckpointBegin,
            failCompletion: failCheckpointCompletion
        )
        let coordinator = AuthenticationCoordinator(
            configuration: try makeConfiguration(),
            webAuthenticationSessionFactory: factory,
            codeExchanger: exchanger,
            authenticationCheckpoint: checkpoint,
            sessionStore: store,
            randomness: FixedAuthenticationRandomness(values: randomValues ?? makeRandomValues()),
            digesting: TestAuthenticationDigest(),
            now: now
        )
        return AuthenticationHarness(
            coordinator: coordinator,
            factory: factory,
            exchanger: exchanger,
            checkpoint: checkpoint,
            store: store
        )
    }

    private func makeConfiguration() throws -> AuthenticationConfiguration {
        try AuthenticationConfiguration(
            authorizationURL: try XCTUnwrap(URL(string: "https://auth.example.test/authorize")),
            exchangeURL: try XCTUnwrap(URL(string: "https://auth.example.test/exchange")),
            checkpointURL: try XCTUnwrap(
                URL(string: "https://auth.example.test/checkpoint")
            ),
            publishableKey: "test-publishable-key",
            callback: try AuthenticationCallbackContract(
                scheme: "hiker-auth",
                host: "callback",
                path: "/oauth/callback"
            )
        )
    }

    private func makeSession() throws -> AuthenticationSession {
        try AuthenticationSession(
            keychainPayload: Data([0x01]),
            checkpointAuthorization: "issued-session-authorization",
            expiresAt: Date(timeIntervalSinceReferenceDate: 2_000)
        )
    }

    private func makeRandomValues() -> [Data] {
        [
            Data(repeating: 0x11, count: 32),
            Data(repeating: 0x22, count: 32),
            Data(repeating: 0x33, count: 32),
        ]
    }

    private func authorizationState(
        from factory: FakeWebAuthenticationSessionFactory
    ) async throws -> String {
        let authorizationURL = try await authorizationURL(from: factory)
        let components = try XCTUnwrap(
            URLComponents(url: authorizationURL, resolvingAgainstBaseURL: false)
        )
        return try XCTUnwrap(queryValue(named: "state", in: components.queryItems ?? []))
    }

    private func authorizationURL(
        from factory: FakeWebAuthenticationSessionFactory
    ) async throws -> URL {
        for _ in 0..<100 {
            if let authorizationURL = factory.authorizationURL {
                return authorizationURL
            }
            await Task.yield()
        }
        throw FakeAuthenticationError.expected
    }

    private func makeCallbackURL(
        state: String,
        scheme: String = "hiker-auth",
        host: String = "callback",
        path: String = "/oauth/callback",
        port: Int? = nil,
        codeValues: [String] = ["opaque"],
        providerError: String? = nil
    ) throws -> URL {
        var components = URLComponents()
        components.scheme = scheme
        components.host = host
        components.path = path
        components.port = port
        components.queryItems = [URLQueryItem(name: "state", value: state)]
            + codeValues.map { URLQueryItem(name: "code", value: $0) }
            + (providerError.map { [URLQueryItem(name: "error", value: $0)] } ?? [])
        return try XCTUnwrap(components.url)
    }

    private func queryValue(named name: String, in items: [URLQueryItem]) -> String? {
        let matchingItems = items.filter { $0.name == name }
        guard matchingItems.count == 1 else {
            return nil
        }
        return matchingItems[0].value
    }

    private func assertState(
        _ coordinator: AuthenticationCoordinator,
        equals expected: AuthenticationState,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async {
        for _ in 0..<100 {
            if coordinator.state == expected {
                return
            }
            await Task.yield()
        }
        XCTFail(
            "Expected authentication state \(expected), got \(coordinator.state).",
            file: file,
            line: line
        )
    }
}

@MainActor
private struct AuthenticationHarness {
    let coordinator: AuthenticationCoordinator
    let factory: FakeWebAuthenticationSessionFactory
    let exchanger: FakeCodeExchanger
    let checkpoint: FakeCheckpoint
    let store: FakeSessionStore
}

private enum FakeExchangeResult: Sendable {
    case success(AuthenticationSession)
    case failure
}

private enum FakeAuthenticationError: Error {
    case expected
}
private final class TestDateSource: @unchecked Sendable {
    private let lock = NSLock()
    private var date: Date

    init(_ date: Date) {
        self.date = date
    }

    func value() -> Date {
        lock.lock()
        defer { lock.unlock() }
        return date
    }

    func set(_ date: Date) {
        lock.lock()
        defer { lock.unlock() }
        self.date = date
    }
}

private struct ExchangeInvocation: Equatable {
    let authorizationCode: String
    let codeVerifier: String
}

private struct ExchangeSnapshot: Equatable {
    let exchangeCount: Int
    let invocations: [ExchangeInvocation]
}

private final class FakeCodeExchanger: AppleSupabaseCodeExchanging, @unchecked Sendable {
    private let lock = NSLock()
    private let result: FakeExchangeResult
    private var invocations: [ExchangeInvocation] = []

    init(result: FakeExchangeResult) {
        self.result = result
    }

    func exchange(
        authorizationCode: String,
        codeVerifier: String
    ) async throws -> AuthenticationSession {
        let result = recordExchange(
            authorizationCode: authorizationCode,
            codeVerifier: codeVerifier
        )

        switch result {
        case let .success(session):
            return session
        case .failure:
            throw FakeAuthenticationError.expected
        }
    }

    private func recordExchange(
        authorizationCode: String,
        codeVerifier: String
    ) -> FakeExchangeResult {
        lock.lock()
        defer { lock.unlock() }
        invocations.append(
            ExchangeInvocation(
                authorizationCode: authorizationCode,
                codeVerifier: codeVerifier
            )
        )
        return result
    }

    func snapshot() -> ExchangeSnapshot {
        lock.lock()
        defer { lock.unlock() }
        return ExchangeSnapshot(
            exchangeCount: invocations.count,
            invocations: invocations
        )
    }
}

private struct CheckpointCompletion: Equatable {
    let transactionID: UUID
    let state: String
    let nonce: String
    let callbackSHA256: Data
    let sessionAuthorization: String
}

private struct CheckpointSnapshot: Equatable {
    let beginCount: Int
    let completions: [CheckpointCompletion]
}

private final class FakeCheckpoint: AppleAuthenticationCheckpointing, @unchecked Sendable {
    static let defaultChallenge = AppleAuthenticationCheckpointChallenge(
        transactionID: UUID(uuidString: "00000000-0000-4000-8000-000000000001")!,
        state: "server-generated-state",
        nonce: "server-generated-nonce",
        expiresAt: Date(timeIntervalSinceReferenceDate: 1_200)
    )

    private let lock = NSLock()
    private let challenge: AppleAuthenticationCheckpointChallenge
    private let failBegin: Bool
    private let failCompletion: Bool
    private var beginCount = 0
    private var completions: [CheckpointCompletion] = []

    init(
        challenge: AppleAuthenticationCheckpointChallenge = FakeCheckpoint.defaultChallenge,
        failBegin: Bool = false,
        failCompletion: Bool = false
    ) {
        self.challenge = challenge
        self.failBegin = failBegin
        self.failCompletion = failCompletion
    }

    func begin() async throws -> AppleAuthenticationCheckpointChallenge {
        try recordBegin()
    }

    func complete(
        transactionID: UUID,
        state: String,
        nonce: String,
        callbackSHA256: Data,
        sessionAuthorization: String
    ) async throws {
        try recordCompletion(
            CheckpointCompletion(
                transactionID: transactionID,
                state: state,
                nonce: nonce,
                callbackSHA256: callbackSHA256,
                sessionAuthorization: sessionAuthorization
            )
        )
    }

    private func recordBegin() throws -> AppleAuthenticationCheckpointChallenge {
        lock.lock()
        defer { lock.unlock() }
        beginCount += 1
        guard !failBegin else {
            throw FakeAuthenticationError.expected
        }
        return challenge
    }

    private func recordCompletion(_ completion: CheckpointCompletion) throws {
        lock.lock()
        defer { lock.unlock() }
        completions.append(completion)
        guard !failCompletion else {
            throw FakeAuthenticationError.expected
        }
    }

    func snapshot() -> CheckpointSnapshot {
        lock.lock()
        defer { lock.unlock() }
        return CheckpointSnapshot(beginCount: beginCount, completions: completions)
    }
}

private struct StoreSnapshot: Equatable {
    let saveAttemptCount: Int
    let savedSessionCount: Int
    let removeCount: Int
}

private final class FakeSessionStore: AuthenticationSessionStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var storedStateValue: StoredAuthenticationState
    private let failOnSave: Bool
    private var saveAttemptCount = 0
    private var savedSessionCount = 0
    private var removeCount = 0

    init(storedState: StoredAuthenticationState, failOnSave: Bool) {
        storedStateValue = storedState
        self.failOnSave = failOnSave
    }

    func storedState(at date: Date) throws -> StoredAuthenticationState {
        lock.lock()
        defer { lock.unlock() }
        return storedStateValue
    }

    func currentBearer(at _: Date) throws -> String? {
        nil
    }

    func save(_ session: AuthenticationSession) throws {
        lock.lock()
        defer { lock.unlock() }
        saveAttemptCount += 1
        guard !failOnSave else {
            throw FakeAuthenticationError.expected
        }
        savedSessionCount += 1
        storedStateValue = .signedIn
    }

    func remove() throws {
        lock.lock()
        defer { lock.unlock() }
        removeCount += 1
        storedStateValue = .signedOut
    }

    func snapshot() -> StoreSnapshot {
        lock.lock()
        defer { lock.unlock() }
        return StoreSnapshot(
            saveAttemptCount: saveAttemptCount,
            savedSessionCount: savedSessionCount,
            removeCount: removeCount
        )
    }
}

private final class FixedAuthenticationRandomness: AuthenticationRandomness, @unchecked Sendable {
    private let lock = NSLock()
    private let values: [Data]
    private var nextIndex = 0

    init(values: [Data]) {
        self.values = values
    }

    func bytes(count: Int) throws -> Data {
        lock.lock()
        defer { lock.unlock() }
        guard nextIndex < values.count, values[nextIndex].count == count else {
            throw FakeAuthenticationError.expected
        }
        defer { nextIndex += 1 }
        return values[nextIndex]
    }
}

private struct TestAuthenticationDigest: AuthenticationDigesting {
    func sha256(_ value: Data) -> Data {
        Data(SHA256.hash(data: value))
    }
}

@MainActor
private final class FakeWebAuthenticationSessionFactory: OAuthWebAuthenticationSessionFactory {
    private let session: FakeWebAuthenticationSession
    private var completion: (@MainActor @Sendable (WebAuthenticationSessionResult) -> Void)?
    private(set) var authorizationURL: URL?

    init(starts: Bool = true) {
        session = FakeWebAuthenticationSession(starts: starts)
    }

    func makeSession(
        authorizationURL: URL,
        callbackURLScheme: String,
        completion: @escaping @MainActor @Sendable (WebAuthenticationSessionResult) -> Void
    ) -> any OAuthWebAuthenticationSession {
        self.authorizationURL = authorizationURL
        self.completion = completion
        return session
    }

    func complete(_ result: WebAuthenticationSessionResult) {
        completion?(result)
    }
}

@MainActor
private final class FakeWebAuthenticationSession: OAuthWebAuthenticationSession {
    private let starts: Bool

    init(starts: Bool) {
        self.starts = starts
    }

    func start() -> Bool {
        starts
    }

    func cancel() {}
}

private extension Data {
    func base64URLEncodedForTest() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
private extension Collection {
    var only: Element? {
        count == 1 ? first : nil
    }
}
