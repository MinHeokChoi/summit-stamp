import SwiftUI

/// The availability boundary for the online-only social surface.
public enum SocialFeatureAvailability: Equatable, Sendable {
    case unavailable
    case ready
}

/// A local UI handle for an incoming request. It is intentionally not a server
/// reference and is never rendered as identity information.
public struct SocialIncomingRequest: Equatable, Identifiable, Sendable {
    public let id: String

    public init(id: String) {
        self.id = id
    }
}

/// A local UI handle for an accepted friend. `displayLabel` must be a generic
/// local label, never a profile or contact field.
public struct SocialFriend: Equatable, Identifiable, Sendable {
    public let id: String
    public let displayLabel: String

    public init(id: String, displayLabel: String) {
        self.id = id
        self.displayLabel = displayLabel
    }
}

/// A locally hydrated aggregate-only mountain fact. The label is supplied by
/// the app's bundled official catalog, not a social transport.
public struct SocialFriendPassportMountain: Equatable, Identifiable, Sendable {
    public let id: String
    public let localMountainLabel: String
    public let visitCount: Int
    public let isPlanned: Bool
    public let stampLabel: String?

    public init(
        id: String,
        localMountainLabel: String,
        visitCount: Int,
        isPlanned: Bool,
        stampLabel: String?
    ) {
        self.id = id
        self.localMountainLabel = localMountainLabel
        self.visitCount = visitCount
        self.isPlanned = isPlanned
        self.stampLabel = stampLabel
    }
}

/// An in-memory presentation of one authorized friend passport. It carries no
/// friend identity, visit history, timestamps, plans times, or mutation APIs.
public struct SocialFriendPassport: Equatable, Sendable {
    public let mountains: [SocialFriendPassportMountain]

    public init(mountains: [SocialFriendPassportMountain]) {
        self.mountains = mountains
    }
}

public enum SocialFriendCodeLookupStatus: Equatable, Sendable {
    case idle
    case available
    case unavailable
    case requestSent
}

/// Explicit, immutable social state supplied by the app composition root.
/// Unavailable state deliberately strips every previously visible social fact.
public struct SocialFeatureState: Equatable, Sendable {
    public let availability: SocialFeatureAvailability
    public let currentFriendCode: String?
    public let friendCodeInput: String
    public let friendCodeLookupStatus: SocialFriendCodeLookupStatus
    public let incomingRequests: [SocialIncomingRequest]
    public let friends: [SocialFriend]
    public let selectedFriendID: String?
    public let selectedPassport: SocialFriendPassport?
    public let isPerformingAction: Bool

    public init(
        availability: SocialFeatureAvailability,
        currentFriendCode: String? = nil,
        friendCodeInput: String = "",
        friendCodeLookupStatus: SocialFriendCodeLookupStatus = .idle,
        incomingRequests: [SocialIncomingRequest] = [],
        friends: [SocialFriend] = [],
        selectedFriendID: String? = nil,
        selectedPassport: SocialFriendPassport? = nil,
        isPerformingAction: Bool = false
    ) {
        self.availability = availability

        switch availability {
        case .unavailable:
            self.currentFriendCode = nil
            self.friendCodeInput = ""
            self.friendCodeLookupStatus = .idle
            self.incomingRequests = []
            self.friends = []
            self.selectedFriendID = nil
            self.selectedPassport = nil
            self.isPerformingAction = false
        case .ready:
            self.currentFriendCode = currentFriendCode
            self.friendCodeInput = friendCodeInput
            self.friendCodeLookupStatus = friendCodeLookupStatus
            self.incomingRequests = incomingRequests
            self.friends = friends
            self.selectedFriendID = selectedFriendID
            self.selectedPassport = selectedPassport
            self.isPerformingAction = isPerformingAction
        }
    }

    public static let unavailable = SocialFeatureState(availability: .unavailable)

    public var canRegenerateFriendCode: Bool {
        availability == .ready && !isPerformingAction
    }

    public var canLookupFriendCode: Bool {
        availability == .ready && !isPerformingAction
    }

    public var canSendFriendRequest: Bool {
        availability == .ready
            && friendCodeLookupStatus == .available
            && !isPerformingAction
    }

    public var canRespondToRequests: Bool {
        availability == .ready && !isPerformingAction
    }

    public var canManageFriends: Bool {
        availability == .ready && !isPerformingAction
    }
}

/// All social intent is sent to the app composition root. This feature owns no
/// transport, persistence, actor identity, or background synchronization.
public struct SocialFeatureActions: Sendable {
    public let regenerateFriendCode: @MainActor @Sendable () async -> Void
    public let lookupFriendCode: @MainActor @Sendable (String) async -> Void
    public let updateFriendCodeInput: @MainActor @Sendable (String) -> Void
    public let sendFriendRequest: @MainActor @Sendable () async -> Void
    public let acceptIncomingRequest: @MainActor @Sendable (String) async -> Void
    public let declineIncomingRequest: @MainActor @Sendable (String) async -> Void
    public let selectFriend: @MainActor @Sendable (String) async -> Void
    public let unfriend: @MainActor @Sendable (String) async -> Void
    public let blockFriend: @MainActor @Sendable (String) async -> Void

    public init(
        regenerateFriendCode: @escaping @MainActor @Sendable () async -> Void,
        lookupFriendCode: @escaping @MainActor @Sendable (String) async -> Void,
        updateFriendCodeInput: @escaping @MainActor @Sendable (String) -> Void,
        sendFriendRequest: @escaping @MainActor @Sendable () async -> Void,
        acceptIncomingRequest: @escaping @MainActor @Sendable (String) async -> Void,
        declineIncomingRequest: @escaping @MainActor @Sendable (String) async -> Void,
        selectFriend: @escaping @MainActor @Sendable (String) async -> Void,
        unfriend: @escaping @MainActor @Sendable (String) async -> Void,
        blockFriend: @escaping @MainActor @Sendable (String) async -> Void
    ) {
        self.regenerateFriendCode = regenerateFriendCode
        self.lookupFriendCode = lookupFriendCode
        self.updateFriendCodeInput = updateFriendCodeInput
        self.sendFriendRequest = sendFriendRequest
        self.acceptIncomingRequest = acceptIncomingRequest
        self.declineIncomingRequest = declineIncomingRequest
        self.selectFriend = selectFriend
        self.unfriend = unfriend
        self.blockFriend = blockFriend
    }
}

public struct SocialFeatureView: View {
    private let state: SocialFeatureState
    private let actions: SocialFeatureActions

    public init(state: SocialFeatureState, actions: SocialFeatureActions) {
        self.state = state
        self.actions = actions
    }

    public var body: some View {
        Group {
            switch state.availability {
            case .unavailable:
                unavailableContent
            case .ready:
                socialContent
            }
        }
    }

    private var unavailableContent: some View {
        ContentUnavailableView(
            "Friends unavailable",
            systemImage: "person.2.slash",
            description: Text("Social features are unavailable.")
        )
        .accessibilityIdentifier("social.unavailable")
    }

    private var socialContent: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text("Friends")
                    .font(.largeTitle.bold())
                    .accessibilityIdentifier("social.title")

                friendCodeSection
                requestSection
                incomingRequestsSection
                friendsSection
                passportSection
            }
            .padding()
        }
        .accessibilityIdentifier("social.ready")
    }

    private var friendCodeSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Your friend code")
                .font(.headline)

            if let currentFriendCode = state.currentFriendCode {
                Text(currentFriendCode)
                    .textSelection(.enabled)
                    .accessibilityIdentifier("social.current-code")
                    .accessibilityLabel("Current friend code")
            }

            Button("Regenerate code") {
                Task { await actions.regenerateFriendCode() }
            }
            .accessibilityIdentifier("social.code.regenerate")
            .disabled(!state.canRegenerateFriendCode)
        }
        .accessibilityElement(children: .contain)
    }

    private var requestSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Add by friend code")
                .font(.headline)

            TextField(
                "Friend code",
                text: Binding(
                    get: { state.friendCodeInput },
                    set: { actions.updateFriendCodeInput($0) }
                )
            )
                .textInputAutocapitalization(.characters)
                .autocorrectionDisabled()
                .accessibilityIdentifier("social.friend-code.input")
                .disabled(!state.canLookupFriendCode)

            HStack {
                Button("Check code") {
                    Task { await actions.lookupFriendCode(state.friendCodeInput) }
                }
                .accessibilityIdentifier("social.friend-code.lookup")
                .disabled(!state.canLookupFriendCode || state.friendCodeInput.isEmpty)

                Button("Send request") {
                    Task { await actions.sendFriendRequest() }
                }
                .accessibilityIdentifier("social.friend-code.request")
                .disabled(!state.canSendFriendRequest)
            }
            .buttonStyle(.bordered)

            lookupStatus
        }
        .accessibilityElement(children: .contain)
    }

    @ViewBuilder
    private var lookupStatus: some View {
        switch state.friendCodeLookupStatus {
        case .idle:
            EmptyView()
        case .available:
            Text("Code is ready for a request.")
                .accessibilityIdentifier("social.friend-code.available")
        case .unavailable:
            Text("Code is unavailable.")
                .accessibilityIdentifier("social.friend-code.unavailable")
        case .requestSent:
            Text("Friend request sent.")
                .accessibilityIdentifier("social.friend-code.request-sent")
        }
    }

    private var incomingRequestsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Incoming requests")
                .font(.headline)

            if state.incomingRequests.isEmpty {
                Text("No incoming requests.")
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("social.incoming.empty")
            } else {
                ForEach(state.incomingRequests) { request in
                    HStack {
                        Text("Incoming request")
                            .accessibilityIdentifier("social.incoming.item.\(request.id)")

                        Button("Accept") {
                            Task { await actions.acceptIncomingRequest(request.id) }
                        }
                        .accessibilityIdentifier("social.incoming.accept.\(request.id)")
                        .disabled(!state.canRespondToRequests)

                        Button("Decline") {
                            Task { await actions.declineIncomingRequest(request.id) }
                        }
                        .accessibilityIdentifier("social.incoming.decline.\(request.id)")
                        .disabled(!state.canRespondToRequests)
                    }
                    .buttonStyle(.bordered)
                }
            }
        }
    }

    private var friendsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Accepted friends")
                .font(.headline)

            if state.friends.isEmpty {
                Text("No accepted friends.")
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("social.friends.empty")
            } else {
                ForEach(state.friends) { friend in
                    HStack {
                        Button(friend.displayLabel) {
                            Task { await actions.selectFriend(friend.id) }
                        }
                        .accessibilityIdentifier("social.friend.select.\(friend.id)")
                        .disabled(!state.canManageFriends)

                        Button("Unfriend") {
                            Task { await actions.unfriend(friend.id) }
                        }
                        .accessibilityIdentifier("social.friend.unfriend.\(friend.id)")
                        .disabled(!state.canManageFriends)

                        Button("Block") {
                            Task { await actions.blockFriend(friend.id) }
                        }
                        .accessibilityIdentifier("social.friend.block.\(friend.id)")
                        .disabled(!state.canManageFriends)
                    }
                    .buttonStyle(.bordered)
                }
            }
        }
    }

    @ViewBuilder
    private var passportSection: some View {
        if let selectedPassport = state.selectedPassport {
            VStack(alignment: .leading, spacing: 8) {
                Text("Friend passport")
                    .font(.headline)
                    .accessibilityIdentifier("social.friend.passport")

                ForEach(selectedPassport.mountains) { mountain in
                    VStack(alignment: .leading, spacing: 4) {
                        Text(mountain.localMountainLabel)
                            .font(.subheadline.bold())
                        Text("Visits: \(mountain.visitCount)")
                        Text("Planned: \(mountain.isPlanned ? "Yes" : "No")")
                        if let stampLabel = mountain.stampLabel {
                            Text("Stamp: \(stampLabel)")
                        }
                    }
                    .accessibilityIdentifier("social.friend.passport.mountain.\(mountain.id)")
                }
            }
        }
    }
}
