import SwiftUI
import HikerDomain

public struct PassportFeatureState: Equatable, Sendable {
    public let mountains: [Mountain]
    public let projections: [MountainPassportProjection]
    public let pendingManualMutationCount: Int
    public let gpsVerificationFeedback: [MountainID: PassportGPSVerificationFeedback]

    public init(
        mountains: [Mountain],
        projections: [MountainPassportProjection],
        pendingManualMutationCount: Int,
        gpsVerificationFeedback: [MountainID: PassportGPSVerificationFeedback] = [:]
    ) {
        self.mountains = mountains.sorted { $0.id.rawValue < $1.id.rawValue }
        self.projections = projections.sorted { $0.mountainID.rawValue < $1.mountainID.rawValue }
        self.pendingManualMutationCount = pendingManualMutationCount
        self.gpsVerificationFeedback = gpsVerificationFeedback
    }

    public func projection(for mountainID: MountainID) -> MountainPassportProjection? {
        projections.first { $0.mountainID == mountainID }
    }

    public func gpsFeedback(for mountainID: MountainID) -> PassportGPSVerificationFeedback {
        gpsVerificationFeedback[mountainID] ?? .idle
    }

    public var hasGPSVerificationInFlight: Bool {
        gpsVerificationFeedback.values.contains(where: \.isInFlight)
    }
    public var hasGPSManualVisitBlock: Bool {
        gpsVerificationFeedback.values.contains(where: \.blocksManualVisit)
    }
}

public enum PassportGPSVerificationFeedback: Equatable, Sendable {
    case idle
    case preparing
    case permissionRequested
    case permissionReady
    case requesting
    case confirmed
    case manualFallback
    case indeterminate

    public var isInFlight: Bool {
        switch self {
        case .preparing, .requesting:
            true
        case .idle, .permissionRequested, .permissionReady, .confirmed, .manualFallback, .indeterminate:
            false
        }
    }
    public var blocksManualVisit: Bool {
        isInFlight || self == .indeterminate
    }

    var message: String? {
        switch self {
        case .idle:
            nil
        case .preparing:
            "Preparing secure online GPS confirmation."
        case .permissionRequested:
            "Allow location access, then tap Confirm with GPS again. You can record this visit manually."
        case .permissionReady:
            "Location access is enabled. Confirm with GPS when ready."
        case .requesting:
            "Confirming with GPS."
        case .confirmed:
            "GPS confirmation recorded."
        case .manualFallback:
            "GPS confirmation was not accepted. You can record this visit manually."
        case .indeterminate:
            "GPS confirmation may have been recorded. Refresh your passport before retrying GPS confirmation."
        }
    }
}

public struct PassportFeatureView: View {
    private let state: PassportFeatureState
    private let isReady: Bool
    private let errorMessage: String?
    private let onAddPlan: @MainActor (MountainID) async -> Void
    private let onRemovePlan: @MainActor (MountainID) async -> Void
    private let onRecordManualVisit: @MainActor (MountainID) async -> Void
    private let onRecordGPSVisit: @MainActor (MountainID) async -> Void
    private let onDeleteManualVisit: @MainActor (VisitID) async -> Void

    public init(
        state: PassportFeatureState,
        isReady: Bool,
        errorMessage: String?,
        onAddPlan: @escaping @MainActor (MountainID) async -> Void,
        onRemovePlan: @escaping @MainActor (MountainID) async -> Void,
        onRecordManualVisit: @escaping @MainActor (MountainID) async -> Void,
        onRecordGPSVisit: @escaping @MainActor (MountainID) async -> Void,
        onDeleteManualVisit: @escaping @MainActor (VisitID) async -> Void
    ) {
        self.state = state
        self.isReady = isReady
        self.errorMessage = errorMessage
        self.onAddPlan = onAddPlan
        self.onRemovePlan = onRemovePlan
        self.onRecordManualVisit = onRecordManualVisit
        self.onRecordGPSVisit = onRecordGPSVisit
        self.onDeleteManualVisit = onDeleteManualVisit
    }

    public var body: some View {
        Group {
            if isReady {
                passportContent
            } else if let errorMessage {
                Text(errorMessage)
                    .accessibilityIdentifier("passport.error")
                    .accessibilityLabel(errorMessage)
            } else {
                ProgressView("Loading local passport")
                    .accessibilityIdentifier("passport.loading")
            }
        }
    }

    private var passportContent: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Passport")
                    .font(.largeTitle.bold())
                    .accessibilityIdentifier("Passport")

                Text("Passport ready")
                    .accessibilityIdentifier("passport.ready")
                    .accessibilityLabel("Local passport ready")

                if let errorMessage {
                    Text(errorMessage)
                        .foregroundStyle(.red)
                        .accessibilityIdentifier("passport.error")
                        .accessibilityLabel(errorMessage)
                }

                Text("Pending manual mutations: \(state.pendingManualMutationCount)")
                    .accessibilityIdentifier("passport.pending.count")
                    .accessibilityLabel(
                        "\(state.pendingManualMutationCount) pending manual mutations"
                    )

                ForEach(state.mountains, id: \.id) { mountain in
                    mountainView(mountain)
                }
            }
            .padding()
        }
    }

    private func mountainView(_ mountain: Mountain) -> some View {
        let projection = state.projection(for: mountain.id)
        let history = projection?.history ?? []

        return VStack(alignment: .leading, spacing: 8) {
            Text(mountain.koreanName)
                .font(.headline)
                .accessibilityIdentifier("passport.mountain.\(mountain.id.rawValue)")
            Text(mountain.region)
                .foregroundStyle(.secondary)
            Text("Planned: \(projection?.planned == true ? "Yes" : "No")")
            Text("Visited: \(projection?.isVisited == true ? "Yes" : "No")")
            Text("Visit count: \(projection?.visitCount ?? 0)")
            Text(stampDescription(projection?.stamp))
            Text("Visit history: \(history.count)")

            Text("GPS confirmation is advisory and available only while online.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .accessibilityIdentifier("passport.gps.advisory.\(mountain.id.rawValue)")
                .accessibilityLabel("GPS confirmation is advisory and available only while online")

            if let message = state.gpsFeedback(for: mountain.id).message {
                Text(message)
                    .foregroundStyle(
                        state.gpsFeedback(for: mountain.id) == .manualFallback
                            ? Color.red
                            : Color.secondary
                    )
                    .accessibilityIdentifier("passport.gps.status.\(mountain.id.rawValue)")
                    .accessibilityLabel(message)
            }

            HStack {
                if projection?.planned == true {
                    Button("Remove plan") {
                        Task {
                            await onRemovePlan(mountain.id)
                        }
                    }
                    .accessibilityIdentifier("passport.plan.remove.\(mountain.id.rawValue)")
                } else if history.isEmpty {
                    Button("Add plan") {
                        Task {
                            await onAddPlan(mountain.id)
                        }
                    }
                    .accessibilityIdentifier("passport.plan.add.\(mountain.id.rawValue)")
                }

                Button("Confirm with GPS") {
                    Task {
                        await onRecordGPSVisit(mountain.id)
                    }
                }
                .accessibilityIdentifier("passport.gps.verify.\(mountain.id.rawValue)")
                .disabled(state.hasGPSVerificationInFlight)

                Button("Record manual visit") {
                    Task {
                        await onRecordManualVisit(mountain.id)
                    }
                }
                .accessibilityIdentifier("passport.visit.add.\(mountain.id.rawValue)")
                .disabled(state.hasGPSManualVisitBlock)
            }
            .buttonStyle(.bordered)

            ForEach(history, id: \.id) { visit in
                HStack {
                    Text(visitDescription(visit))

                    switch visit.verificationMethod {
                    case .manual:
                        Text("Manual")
                            .accessibilityIdentifier("passport.visit.badge.\(visit.id.rawValue)")
                            .accessibilityLabel("Manual visit")

                        Button("Delete visit") {
                            Task {
                                await onDeleteManualVisit(visit.id)
                            }
                        }
                        .accessibilityIdentifier("passport.visit.delete.\(visit.id.rawValue)")

                    case .gpsVerified:
                        Text("GPS confirmed")
                            .accessibilityIdentifier("passport.visit.badge.\(visit.id.rawValue)")
                            .accessibilityLabel("GPS confirmed visit")
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
    }

    private func stampDescription(_ stamp: Stamp?) -> String {
        guard let stamp else {
            return "Stamp: None"
        }
        return "Stamp: \(stamp.sourceVisitID.rawValue)"
    }

    private func visitDescription(_ visit: VisitRecord) -> String {
        "Visit \(visit.id.rawValue)"
    }
}