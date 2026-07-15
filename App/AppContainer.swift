import Foundation
import Observation
import Security
import UIKit
import HikerData
import HikerDataset
import HikerLocation
import HikerDomain
import HikerMapFeature
import HikerObservability
import HikerPassportFeature
import HikerSocialFeature
private final class ApplicationForegroundObserver: @unchecked Sendable {
    private var action: (@Sendable () -> Void)?
    private var token: NSObjectProtocol?

    init() {
        token = NotificationCenter.default.addObserver(
            forName: UIApplication.didBecomeActiveNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            self?.action?()
        }
    }

    func setAction(_ action: @escaping @Sendable () -> Void) {
        self.action = action
    }

    deinit {
        if let token {
            NotificationCenter.default.removeObserver(token)
        }
    }
}


@MainActor
@Observable
final class AppContainer {
    let dataset: HikerDataset.Type
    let eventSink: OSLogEventSink
    let authenticationCoordinator: AuthenticationCoordinator
    let officialMountains: [Mountain]
    private let catalogError: String?
    private let officialMountainIDs: Set<MountainID>
    private let officialDatasetSHA256: String?
    private let encryptedLocalPassportStore: EncryptedLocalPassportStore?
    private let gpsLocationRequester = OneShotLocationRequester()
    private var localSnapshotActorID: UUID?
    private var localWritePauseReason: SelfPassportWritePauseReason?

    private(set) var passportStateMachine = PassportStateMachine()
    private(set) var manualVisitOutbox = AppContainer.emptyOutbox()
    private(set) var planMutationOutbox: [PlanMutationOutboxNode] = []
    private var synchronizedAggregates: [SelfPassportAggregate] = []
    private var synchronizedHistories: [SelfPassportVisitHistory] = []
    private var selfPassportSyncEngine: SelfPassportSyncEngine<EncryptedLocalPassportStore>?
    private(set) var projectionRevision: UInt64 = 0
    private(set) var currentMapViewModel = MapViewModel.loading
    private(set) var isLocalPassportReady = false
    private(set) var localStateError: String?
    private(set) var actionError: String?
    private var gpsVerificationFeedback: [MountainID: PassportGPSVerificationFeedback] = [:]

    private var didStartLocalPassportLoad = false
    private let authenticationForegroundObserver: ApplicationForegroundObserver
    private var isPersistingLocalPassport = false
    private var isSynchronizingSelfPassport = false
    private var authenticationTransitionGeneration: UInt64 = 0
    private(set) var socialFeatureState = SocialFeatureState.unavailable
    private var socialFriendCode: HikerData.FriendCode?
    private var socialFriendCodeInput = ""
    private var socialPendingFriendCode: HikerData.FriendCode?
    private var socialIncomingRequestReferences: [String: FriendRequestReference] = [:]
    private var socialFriendReferences: [String: FriendReference] = [:]
    private var socialIncomingRequestIDs: [String] = []
    private var socialFriendIDs: [String] = []
    private var socialFriendCodeLookupStatus: SocialFriendCodeLookupStatus = .idle
    private var socialSelectedFriendID: String?
    private var socialSelectedPassport: SocialFriendPassport?
    private var socialPassportSession: FriendPassportSession?
    private var socialEventPollingTask: Task<Void, Never>?
    private var socialPassportExpiryTask: Task<Void, Never>?
    private var socialPassportLeaseExpiresAt: Date?
    private var isPerformingSocialAction = false
    private var socialGeneration: UInt64 = 0
    private enum LocalPassportStateError: Error {
        case catalogIncompatible
        case mapProjectionIncompatible
    }


    init() {
        dataset = HikerDataset.self

        guard let bundleIdentifier = Bundle.main.bundleIdentifier else {
            preconditionFailure("The application bundle identifier is required.")
        }
        localSnapshotActorID = nil
        eventSink = OSLogEventSink(subsystem: bundleIdentifier)
        let coordinator = AuthenticationCoordinator.production()
        authenticationCoordinator = coordinator
        authenticationForegroundObserver = ApplicationForegroundObserver()

        do {
            let mountains = try dataset.loadMountains()
            let manifest = try dataset.loadManifest()
            let mountainIDs = Set(mountains.map(\.id))
            guard mountains.count == 100,
                  mountainIDs.count == 100,
                  manifest.content.sha256.count == 64 else {
                throw LocalPassportStateError.catalogIncompatible
            }
            officialMountains = mountains
            officialMountainIDs = mountainIDs
            officialDatasetSHA256 = manifest.content.sha256
            catalogError = nil
        } catch {
            officialMountains = []
            officialMountainIDs = []
            officialDatasetSHA256 = nil
            catalogError = "The bundled mountain catalog failed integrity validation."
        }

        do {
            let key = try LocalPassportKeychain.loadOrCreate(
                service: "\(bundleIdentifier).local-passport-v1"
            )
            encryptedLocalPassportStore = EncryptedLocalPassportStore(
                fileURL: URL.applicationSupportDirectory
                    .appending(path: "local-passport-v1.bin", directoryHint: .notDirectory),
                key: key
            )
        } catch {
            encryptedLocalPassportStore = nil
            localStateError = Self.unavailableLocalStateMessage
        }
        refreshMapViewModel()
        authenticationForegroundObserver.setAction { [weak self, coordinator] in
            Task { @MainActor in
                coordinator.refreshStoredSessionState()
                self?.refreshGPSPermissionFeedback()
            }
        }
    }

    func loadLocalPassportState(
        expectedAuthenticationGeneration: UInt64? = nil
    ) async {
        guard !didStartLocalPassportLoad else {
            return
        }
        didStartLocalPassportLoad = true

        guard let encryptedLocalPassportStore else {
            advanceProjectionRevision()
            refreshMapViewModel()
            return
        }

        do {
            let loadedSnapshot = try await encryptedLocalPassportStore.load()
            if let expectedAuthenticationGeneration,
               expectedAuthenticationGeneration != authenticationTransitionGeneration {
                return
            }
            let loadedPassportState = loadedSnapshot?.passportState ?? passportStateMachine
            let loadedManualVisitOutbox = loadedSnapshot?.manualVisitOutbox ?? manualVisitOutbox
            let loadedPlanMutationOutbox = loadedSnapshot?.planMutationOutbox ?? planMutationOutbox

            try validateCatalogCompatibility(
                passportState: loadedPassportState,
                manualVisitOutbox: loadedManualVisitOutbox,
                planMutationOutbox: loadedPlanMutationOutbox
            )
            try validateActorForPublication(loadedSnapshot)
            let nextMapViewModel = try makeMapViewModel(from: loadedPassportState)

            localSnapshotActorID = loadedSnapshot?.actorID
            localWritePauseReason = loadedSnapshot?.writePauseReason
            passportStateMachine = loadedPassportState
            manualVisitOutbox = loadedManualVisitOutbox
            planMutationOutbox = loadedPlanMutationOutbox
            currentMapViewModel = nextMapViewModel
            isLocalPassportReady = true
            actionError = localWritePauseReason.map(writePauseMessage)
            advanceProjectionRevision()
        } catch is LocalPassportAccountBindingError {
            hideAccountBoundPresentation()
        } catch {
            failClosedForLocalState()
            advanceProjectionRevision()
        }
    }

    @discardableResult
    func authenticationStateWillChange(_ state: AuthenticationState) -> UInt64 {
        precondition(authenticationTransitionGeneration < UInt64.max)
        authenticationTransitionGeneration += 1
        failClosedSocial()
        switch state {
        case .signedIn:
            return authenticationTransitionGeneration
        case .signedOut, .signingIn, .cancelled, .expired, .error:
            selfPassportSyncEngine = nil
            synchronizedAggregates = []
            synchronizedHistories = []
            didStartLocalPassportLoad = false
            hideAccountBoundPresentation()
        }
        return authenticationTransitionGeneration
    }

    func authenticationStateDidChange(
        _ state: AuthenticationState,
        generation: UInt64
    ) async {
        guard generation == authenticationTransitionGeneration,
              case .signedIn = state else {
            return
        }

        selfPassportSyncEngine = nil
        synchronizedAggregates = []
        synchronizedHistories = []
        didStartLocalPassportLoad = false
        await loadLocalPassportState(
            expectedAuthenticationGeneration: generation
        )
        guard generation == authenticationTransitionGeneration,
              authenticationCoordinator.state == .signedIn else {
            return
        }
        await synchronizeSelfPassportIfAuthenticated()
        await refreshSocialIfAuthenticated()
    }

    func addPlan(for mountainID: MountainID) async {
        guard beginLocalMutation() else {
            return
        }
        defer { isPersistingLocalPassport = false }

        if let selfPassportSyncEngine {
            do {
                _ = try await selfPassportSyncEngine.enqueuePlanAdd(
                    for: mountainID,
                    clientMutationID: ClientMutationID()
                )
                try await publishSynchronizedState(from: selfPassportSyncEngine)
                return
            } catch {
                handleLocalMutationFailure(
                    error,
                    message: "This plan change could not be saved locally. Check device storage and retry."
                )
                return
            }
        }

        do {
            var updatedPassport = passportStateMachine
            var updatedPlanOutbox = planMutationOutbox
            updatedPlanOutbox.append(
                PlanMutationOutboxNode(
                    clientMutationID: ClientMutationID(),
                    mountainID: mountainID,
                    operation: .add,
                    enqueuedAt: .now
                )
            )
            try updatedPassport.addPlan(for: mountainID)
            try await saveAndPublish(
                passportState: updatedPassport,
                manualVisitOutbox: manualVisitOutbox,
                planMutationOutbox: updatedPlanOutbox
            )
        } catch {
            handleLocalMutationFailure(
                error,
                message: "This plan change could not be saved locally. Check device storage and retry."
            )
        }
    }

    func removePlan(for mountainID: MountainID) async {
        guard beginLocalMutation() else {
            return
        }
        defer { isPersistingLocalPassport = false }

        if let selfPassportSyncEngine {
            do {
                _ = try await selfPassportSyncEngine.enqueuePlanRemove(
                    for: mountainID,
                    clientMutationID: ClientMutationID()
                )
                try await publishSynchronizedState(from: selfPassportSyncEngine)
                return
            } catch {
                handleLocalMutationFailure(
                    error,
                    message: "This plan change could not be saved locally. Check device storage and retry."
                )
                return
            }
        }

        do {
            var updatedPassport = passportStateMachine
            var updatedPlanOutbox = planMutationOutbox
            updatedPlanOutbox.append(
                PlanMutationOutboxNode(
                    clientMutationID: ClientMutationID(),
                    mountainID: mountainID,
                    operation: .remove,
                    enqueuedAt: .now
                )
            )
            try updatedPassport.removePlan(for: mountainID)
            try await saveAndPublish(
                passportState: updatedPassport,
                manualVisitOutbox: manualVisitOutbox,
                planMutationOutbox: updatedPlanOutbox
            )
        } catch {
            handleLocalMutationFailure(
                error,
                message: "This plan change could not be saved locally. Check device storage and retry."
            )
        }
    }

    func recordManualVisit(for mountainID: MountainID) async {
        guard beginLocalMutation() else {
            return
        }
        defer { isPersistingLocalPassport = false }

        if let selfPassportSyncEngine {
            do {
                let now = Date()
                let visit = VisitRecord(
                    id: VisitID(),
                    mountainID: mountainID,
                    visitedAt: now,
                    recordedAt: now,
                    verificationMethod: .manual
                )
                _ = try await selfPassportSyncEngine.enqueueManualCreate(
                    visit,
                    clientMutationID: ClientMutationID(),
                    at: now
                )
                try await publishSynchronizedState(from: selfPassportSyncEngine)
                return
            } catch {
                handleLocalMutationFailure(
                    error,
                    message: "This manual visit could not be saved locally. Check device storage and retry."
                )
                return
            }
        }

        do {
            let now = Date()
            let visit = VisitRecord(
                id: VisitID(),
                mountainID: mountainID,
                visitedAt: now,
                recordedAt: now,
                verificationMethod: .manual
            )
            var updatedPassport = passportStateMachine
            var updatedOutbox = manualVisitOutbox

            try updatedPassport.recordVisit(visit)
            try updatedOutbox.enqueueCreate(
                visit,
                clientMutationID: ClientMutationID(),
                at: now
            )
            try await saveAndPublish(
                passportState: updatedPassport,
                manualVisitOutbox: updatedOutbox,
                planMutationOutbox: planMutationOutbox
            )
        } catch {
            handleLocalMutationFailure(
                error,
                message: "This manual visit could not be saved locally. Check device storage and retry."
            )
        }
    }

    func recordGPSVisit(for mountainID: MountainID) async {
        refreshGPSPermissionFeedback()
        let isResolvingIndeterminateGPSResult =
            gpsVerificationFeedback[mountainID] == .indeterminate

        guard isLocalPassportReady,
              catalogError == nil,
              localStateError == nil,
              authenticationCoordinator.state == .signedIn,
              officialMountainIDs.contains(mountainID) else {
            gpsVerificationFeedback[mountainID] =
                isResolvingIndeterminateGPSResult ? .indeterminate : .manualFallback
            return
        }
        guard !isPersistingLocalPassport,
              !isSynchronizingSelfPassport,
              !isGPSVerificationInFlight else {
            return
        }

        gpsVerificationFeedback[mountainID] = .preparing
        guard await synchronizeSelfPassportIfAuthenticated(),
              let selfPassportSyncEngine else {
            gpsVerificationFeedback[mountainID] =
                isResolvingIndeterminateGPSResult ? .indeterminate : .manualFallback
            return
        }
        if isResolvingIndeterminateGPSResult {
            gpsVerificationFeedback[mountainID] = .idle
            return
        }

        switch gpsLocationRequester.permission.oneShotRequestPreflight {
        case .requiresWhenInUseAuthorization:
            gpsLocationRequester.requestWhenInUseAuthorization()
            gpsVerificationFeedback[mountainID] = .permissionRequested
            return

        case .denied, .restricted:
            gpsVerificationFeedback[mountainID] = .manualFallback
            return

        case .ready:
            break
        }

        gpsVerificationFeedback[mountainID] = .requesting

        do {
            let sample = try await gpsLocationRequester.requestOneShotLocation()
            guard let mountain = officialMountains.first(where: { $0.id == mountainID }),
                  GPSVerificationPolicy.evaluate(
                    sample: sample,
                    summit: GPSSummitCoordinate(
                        latitude: mountain.summitCoordinate.latitude,
                        longitude: mountain.summitCoordinate.longitude
                    ),
                    now: .now
                  ) == .eligible else {
                gpsVerificationFeedback[mountainID] = .manualFallback
                return
            }

            let now = Date()
            let outcome = try await selfPassportSyncEngine.verifyGPSVisit(
                mountainID: mountainID,
                visitID: VisitID(),
                visitedAt: now,
                clientMutationID: ClientMutationID(),
                latitude: sample.latitude,
                longitude: sample.longitude,
                horizontalAccuracyMeters: sample.horizontalAccuracy,
                sampledAt: sample.timestamp
            )

            switch outcome {
            case .gpsVerified:
                do {
                    try await publishSynchronizedState(from: selfPassportSyncEngine)
                    gpsVerificationFeedback[mountainID] = .confirmed
                } catch {
                    gpsVerificationFeedback[mountainID] = .indeterminate
                }
            case .manualFallback, .rejected:
                gpsVerificationFeedback[mountainID] = .manualFallback
            case .indeterminate:
                gpsVerificationFeedback[mountainID] = .indeterminate
            }
        } catch is OneShotLocationRequestError {
            gpsVerificationFeedback[mountainID] = .manualFallback
        } catch {
            gpsVerificationFeedback[mountainID] = .indeterminate
        }
    }

    func deleteManualVisit(id: VisitID) async {
        guard beginLocalMutation() else {
            return
        }
        defer { isPersistingLocalPassport = false }

        do {
            guard let visit = manualVisit(id: id) else {
                throw PassportValidationError.visitNotFound(id)
            }
            guard visit.verificationMethod == .manual else {
                throw ManualVisitOutboxError.gpsVerifiedVisitsAreNotQueueable
            }

            let now = Date()
            if let selfPassportSyncEngine {
                _ = try await selfPassportSyncEngine.enqueueManualDelete(
                    visitID: id,
                    mountainID: visit.mountainID,
                    clientMutationID: ClientMutationID(),
                    at: now
                )
                try await publishSynchronizedState(from: selfPassportSyncEngine)
                do {
                    _ = try await selfPassportSyncEngine.uploadNextOutboxOperation(at: now)
                    try await publishSynchronizedState(from: selfPassportSyncEngine)
                } catch SelfPassportTransportFailure.mutationConflict {
                    actionError =
                        "The deletion is saved, but synchronization is paused because it conflicts with the server receipt."
                    advanceProjectionRevision()
                } catch SelfPassportTransportFailure.mutationRejected {
                    actionError =
                        "The deletion is saved, but synchronization is paused because the server rejected it."
                    advanceProjectionRevision()
                } catch {
                    actionError =
                        "The deletion is saved on this device and will synchronize when the service is available."
                    advanceProjectionRevision()
                }
            } else {
                var updatedPassport = passportStateMachine
                var updatedOutbox = manualVisitOutbox

                try updatedPassport.deleteVisit(id: id)
                try updatedOutbox.enqueueDelete(
                    visitID: id,
                    mountainID: visit.mountainID,
                    clientMutationID: ClientMutationID(),
                    at: now
                )
                try await saveAndPublish(
                    passportState: updatedPassport,
                    manualVisitOutbox: updatedOutbox,
                    planMutationOutbox: planMutationOutbox
                )
            }
        } catch {
            handleLocalMutationFailure(
                error,
                message: "This manual visit could not be deleted locally. Check device storage and retry."
            )
        }
    }

    func makeMapFeatureView() -> MapFeatureView {
        MapFeatureView(
            viewModelProvider: { self.currentMapViewModel },
            revision: projectionRevision
        )
    }

    func makePassportFeatureView() -> PassportFeatureView {
        refreshGPSPermissionFeedback()
        return PassportFeatureView(
            state: PassportFeatureState(
                mountains: officialMountains,
                projections: visiblePassportProjections(),
                pendingManualMutationCount: manualVisitOutbox.nodes.count,
                gpsVerificationFeedback: gpsVerificationFeedback
            ),
            isReady: isLocalPassportReady && catalogError == nil,
            errorMessage: catalogError ?? localStateError ?? actionError,
            onAddPlan: { [weak self] mountainID in
                await self?.addPlan(for: mountainID)
            },
            onRemovePlan: { [weak self] mountainID in
                await self?.removePlan(for: mountainID)
            },
            onRecordManualVisit: { [weak self] mountainID in
                await self?.recordManualVisit(for: mountainID)
            },
            onRecordGPSVisit: { [weak self] mountainID in
                await self?.recordGPSVisit(for: mountainID)
            },
            onDeleteManualVisit: { [weak self] visitID in
                await self?.deleteManualVisit(id: visitID)
            }
        )
    }
    func makeSocialFeatureView() -> SocialFeatureView {
        SocialFeatureView(
            state: socialFeatureState,
            actions: SocialFeatureActions(
                regenerateFriendCode: { [weak self] in
                    await self?.regenerateSocialFriendCode()
                },
                lookupFriendCode: { [weak self] code in
                    await self?.lookupSocialFriendCode(code)
                },
                updateFriendCodeInput: { [weak self] code in
                    self?.updateSocialFriendCodeInput(code)
                },
                sendFriendRequest: { [weak self] in
                    await self?.sendSocialFriendRequest()
                },
                acceptIncomingRequest: { [weak self] requestID in
                    await self?.respondToSocialIncomingRequest(
                        requestID,
                        response: .accept
                    )
                },
                declineIncomingRequest: { [weak self] requestID in
                    await self?.respondToSocialIncomingRequest(
                        requestID,
                        response: .decline
                    )
                },
                selectFriend: { [weak self] friendID in
                    await self?.selectSocialFriend(friendID)
                },
                unfriend: { [weak self] friendID in
                    await self?.unfriendSocialFriend(friendID)
                },
                blockFriend: { [weak self] friendID in
                    await self?.blockSocialFriend(friendID)
                }
            )
        )
    }

    func socialAppDidBecomeInactive() {
        failClosedSocial()
    }

    func refreshSocialIfAuthenticated(
        friendCodeLookupStatus: SocialFriendCodeLookupStatus = .idle
    ) async {
        guard case .signedIn = authenticationCoordinator.state,
              catalogError == nil,
              officialMountainIDs.count == 100,
              let officialDatasetSHA256 else {
            failClosedSocial()
            return
        }

        failClosedSocial()
        let generation = socialGeneration

        do {
            let transport = try authenticationCoordinator.makeSelfPassportSyncTransport(
                datasetSHA256: officialDatasetSHA256
            )
            let friendCode = try await transport.friendCode()
            let incomingRequests = try await transport.incomingFriendRequests()
            let friends = try await transport.friends()

            guard isCurrentSocialGeneration(generation),
                  case .signedIn = authenticationCoordinator.state else {
                return
            }

            try installSocialReferences(
                incomingRequests: incomingRequests,
                friends: friends
            )
            socialFriendCode = friendCode
            socialFriendCodeLookupStatus = friendCodeLookupStatus
            isPerformingSocialAction = false
            publishReadySocialState()
        } catch {
            failClosedSocial(ifCurrent: generation)
        }
    }

    private func regenerateSocialFriendCode() async {
        guard let action = beginSocialAction() else {
            return
        }

        do {
            let friendCode = try await action.transport.regenerateFriendCode()
            guard completeSocialAction(generation: action.generation) else {
                return
            }
            socialFriendCode = friendCode
            socialFriendCodeLookupStatus = .idle
            publishReadySocialState()
        } catch {
            failClosedSocial(ifCurrent: action.generation)
        }
    }

    private func lookupSocialFriendCode(_ rawValue: String) async {
        guard let action = beginSocialAction() else {
            return
        }
        guard let friendCode = try? HikerData.FriendCode(rawValue: rawValue) else {
            guard completeSocialAction(generation: action.generation) else {
                return
            }
            socialPendingFriendCode = nil
            socialFriendCodeLookupStatus = .unavailable
            publishReadySocialState()
            return
        }

        do {
            let result = try await action.transport.lookupFriendCode(friendCode)
            guard completeSocialAction(generation: action.generation) else {
                return
            }

            switch result {
            case .available:
                socialPendingFriendCode = friendCode
                socialFriendCodeLookupStatus = .available
            case .unavailable:
                socialPendingFriendCode = nil
                socialFriendCodeLookupStatus = .unavailable
            }
            publishReadySocialState()
        } catch {
            failClosedSocial(ifCurrent: action.generation)
        }
    }
    private func updateSocialFriendCodeInput(_ value: String) {
        guard socialFeatureState.availability == .ready,
              case .signedIn = authenticationCoordinator.state,
              !isPerformingSocialAction else {
            return
        }

        socialFriendCodeInput = value
        socialPendingFriendCode = nil
        socialFriendCodeLookupStatus = .idle
        publishReadySocialState()
    }


    private func sendSocialFriendRequest() async {
        guard let friendCode = socialPendingFriendCode,
              let action = beginSocialRelationshipMutation() else {
            return
        }

        do {
            let result = try await action.transport.sendFriendRequest(using: friendCode)
            guard isCurrentSocialGeneration(action.generation) else {
                return
            }

            if case .pending(_) = result {
                await refreshSocialIfAuthenticated(friendCodeLookupStatus: .requestSent)
            } else if case .incomingRequest(_) = result {
                await refreshSocialIfAuthenticated(friendCodeLookupStatus: .requestSent)
            } else if case .friends(_) = result {
                await refreshSocialIfAuthenticated(friendCodeLookupStatus: .requestSent)
            }
        } catch {
            // Relationship mutation failures remain in the zeroized unavailable state.
        }
    }

    private func respondToSocialIncomingRequest(
        _ requestID: String,
        response: FriendRequestResponse
    ) async {
        guard let request = socialIncomingRequestReferences[requestID],
              let action = beginSocialRelationshipMutation() else {
            return
        }

        do {
            let result = try await action.transport.respondToFriendRequest(
                request,
                response: response
            )
            guard isCurrentSocialGeneration(action.generation) else {
                return
            }

            if case .accepted(_) = result {
                await refreshSocialIfAuthenticated()
            } else if case .declined(_) = result {
                await refreshSocialIfAuthenticated()
            }
        } catch {
            // Relationship mutation failures remain in the zeroized unavailable state.
        }
    }

    private func selectSocialFriend(_ friendID: String) async {
        guard let friend = socialFriendReferences[friendID] else {
            failClosedSocial()
            return
        }

        zeroizeSocialPassport()
        guard let action = beginSocialAction() else {
            return
        }

        let session = FriendPassportSession(friendReference: friend)
        socialPassportSession = session
        socialSelectedFriendID = friendID
        publishReadySocialState()

        do {
            guard let refreshedPublication = try await session.refresh(using: action.transport),
                  let revalidatedPublication = await session.publication(),
                  revalidatedPublication == refreshedPublication,
                  isCurrentSocialGeneration(action.generation),
                  case .signedIn = authenticationCoordinator.state else {
                failClosedSocial(ifCurrent: action.generation)
                return
            }

            let hydratedPassport = try hydrateSocialPassport(revalidatedPublication.passport)
            guard let currentPublication = await session.publication(),
                  currentPublication == revalidatedPublication,
                  socialPassportSession === session,
                  isCurrentSocialGeneration(action.generation),
                  case .signedIn = authenticationCoordinator.state,
                  currentPublication.leaseExpiresAt > Date(),
                  completeSocialAction(generation: action.generation) else {
                failClosedSocial(ifCurrent: action.generation)
                return
            }

            socialPassportLeaseExpiresAt = currentPublication.leaseExpiresAt
            scheduleSocialPassportExpiry(
                at: currentPublication.leaseExpiresAt,
                session: session,
                generation: action.generation
            )
            socialSelectedPassport = hydratedPassport
            publishReadySocialState()
            startSocialEventPolling(
                session: session,
                transport: action.transport,
                generation: action.generation
            )
        } catch {
            failClosedSocial(ifCurrent: action.generation)
        }
    }

    private func unfriendSocialFriend(_ friendID: String) async {
        guard let friend = socialFriendReferences[friendID],
              let action = beginSocialRelationshipMutation() else {
            return
        }

        do {
            let result = try await action.transport.unfriend(friend)
            guard isCurrentSocialGeneration(action.generation) else {
                return
            }

            if case .unfriended(_) = result {
                await refreshSocialIfAuthenticated()
            }
        } catch {
            // Relationship mutation failures remain in the zeroized unavailable state.
        }
    }

    private func blockSocialFriend(_ friendID: String) async {
        guard let friend = socialFriendReferences[friendID],
              let action = beginSocialRelationshipMutation() else {
            return
        }

        do {
            let result = try await action.transport.block(.friend(friend))
            guard isCurrentSocialGeneration(action.generation) else {
                return
            }

            if case .blocked(_) = result {
                await refreshSocialIfAuthenticated()
            }
        } catch {
            // Relationship mutation failures remain in the zeroized unavailable state.
        }
    }

    private func beginSocialAction() -> (
        transport: SupabaseSelfPassportSyncTransport,
        generation: UInt64
    )? {
        guard !isPerformingSocialAction else {
            return nil
        }
        guard socialFeatureState.availability == .ready,
              case .signedIn = authenticationCoordinator.state,
              catalogError == nil,
              officialMountainIDs.count == 100,
              let officialDatasetSHA256 else {
            failClosedSocial()
            return nil
        }

        do {
            let transport = try authenticationCoordinator.makeSelfPassportSyncTransport(
                datasetSHA256: officialDatasetSHA256
            )
            isPerformingSocialAction = true
            publishReadySocialState()
            return (transport, socialGeneration)
        } catch {
            failClosedSocial()
            return nil
        }
    }
    private func beginSocialRelationshipMutation() -> (
        transport: SupabaseSelfPassportSyncTransport,
        generation: UInt64
    )? {
        guard let action = beginSocialAction() else {
            return nil
        }

        failClosedSocial()
        return (action.transport, socialGeneration)
    }

    private func completeSocialAction(generation: UInt64) -> Bool {
        guard isCurrentSocialGeneration(generation) else {
            return false
        }
        isPerformingSocialAction = false
        return true
    }

    private func installSocialReferences(
        incomingRequests: [FriendRequestReference],
        friends: [FriendReference]
    ) throws {
        guard Set(incomingRequests).count == incomingRequests.count,
              Set(friends).count == friends.count else {
            throw FriendSocialTransportFailure.malformedResponse
        }

        socialIncomingRequestIDs = incomingRequests.indices.map { "request-\($0)" }
        socialIncomingRequestReferences = Dictionary(
            uniqueKeysWithValues: zip(socialIncomingRequestIDs, incomingRequests)
        )
        socialFriendIDs = friends.indices.map { "friend-\($0)" }
        socialFriendReferences = Dictionary(
            uniqueKeysWithValues: zip(socialFriendIDs, friends)
        )
    }

    private func hydrateSocialPassport(
        _ passport: FriendPassportDTO
    ) throws -> SocialFriendPassport {
        let labels = Dictionary(
            uniqueKeysWithValues: officialMountains.map { ($0.id, $0.koreanName) }
        )
        let mountains = try passport.mountains.enumerated().map { index, aggregate in
            guard let label = labels[aggregate.mountainID] else {
                throw FriendSocialTransportFailure.malformedResponse
            }
            let stampLabel: String?
            switch aggregate.stampVerificationMethod {
            case .none:
                stampLabel = nil
            case .some(.manual):
                stampLabel = "Manual"
            case .some(.gpsVerified):
                stampLabel = "GPS confirmed"
            }

            return SocialFriendPassportMountain(
                id: "mountain-\(index)",
                localMountainLabel: label,
                visitCount: aggregate.visitCount,
                isPlanned: aggregate.isPlanned,
                stampLabel: stampLabel
            )
        }
        return SocialFriendPassport(mountains: mountains)
    }

    private func startSocialEventPolling(
        session: FriendPassportSession,
        transport: SupabaseSelfPassportSyncTransport,
        generation: UInt64
    ) {
        socialEventPollingTask?.cancel()
        socialEventPollingTask = Task { [weak self] in
            while !Task.isCancelled {
                do {
                    try await Task.sleep(for: .seconds(1))
                    _ = try await session.pollEvents(using: transport)

                    guard let publication = await session.publication() else {
                        self?.failClosedSocial(ifCurrent: generation)
                        return
                    }
                    guard self?.reseedSocialPassportExpiry(
                        from: publication,
                        session: session,
                        generation: generation
                    ) == true else {
                        return
                    }
                } catch is CancellationError {
                    return
                } catch {
                    self?.failClosedSocial(ifCurrent: generation)
                    return
                }
            }
        }
    }

    private func reseedSocialPassportExpiry(
        from publication: FriendPassportSessionPublication,
        session: FriendPassportSession,
        generation: UInt64
    ) -> Bool {
        guard isCurrentSocialGeneration(generation),
              socialPassportSession === session,
              socialSelectedPassport != nil else {
            return false
        }
        guard publication.leaseExpiresAt > Date() else {
            zeroizeSocialPassport()
            return false
        }

        socialPassportLeaseExpiresAt = publication.leaseExpiresAt
        scheduleSocialPassportExpiry(
            at: publication.leaseExpiresAt,
            session: session,
            generation: generation
        )
        return true
    }

    private func scheduleSocialPassportExpiry(
        at deadline: Date,
        session: FriendPassportSession,
        generation: UInt64
    ) {
        socialPassportExpiryTask?.cancel()
        socialPassportExpiryTask = Task { [weak self] in
            do {
                try await Task.sleep(
                    for: .seconds(max(0, deadline.timeIntervalSinceNow))
                )
            } catch is CancellationError {
                return
            } catch {
                return
            }

            guard !Task.isCancelled else {
                return
            }
            self?.expireSocialPassport(
                at: deadline,
                session: session,
                generation: generation
            )
        }
    }

    private func expireSocialPassport(
        at deadline: Date,
        session: FriendPassportSession,
        generation: UInt64
    ) {
        guard isCurrentSocialGeneration(generation),
              socialPassportSession === session,
              socialPassportLeaseExpiresAt == deadline else {
            return
        }
        guard deadline <= Date() else {
            scheduleSocialPassportExpiry(
                at: deadline,
                session: session,
                generation: generation
            )
            return
        }

        zeroizeSocialPassport()
    }

    private func zeroizeSocialPassport() {
        socialGeneration &+= 1
        socialEventPollingTask?.cancel()
        socialEventPollingTask = nil
        socialPassportExpiryTask?.cancel()
        socialPassportExpiryTask = nil
        socialPassportLeaseExpiresAt = nil
        let session = socialPassportSession
        socialPassportSession = nil
        if let session {
            Task {
                await session.streamLost()
            }
        }
        socialSelectedFriendID = nil
        socialSelectedPassport = nil
        isPerformingSocialAction = false
        if socialFeatureState.availability == .ready {
            publishReadySocialState()
        }
    }

    private func failClosedSocial(ifCurrent generation: UInt64? = nil) {
        if let generation, !isCurrentSocialGeneration(generation) {
            return
        }

        socialGeneration &+= 1
        socialEventPollingTask?.cancel()
        socialEventPollingTask = nil
        socialPassportExpiryTask?.cancel()
        socialPassportExpiryTask = nil
        socialPassportLeaseExpiresAt = nil
        let session = socialPassportSession
        socialPassportSession = nil
        if let session {
            Task {
                await session.handleLifecycle(.signedOut)
            }
        }
        socialFriendCode = nil
        socialFriendCodeInput = ""
        socialPendingFriendCode = nil
        socialIncomingRequestReferences = [:]
        socialFriendReferences = [:]
        socialIncomingRequestIDs = []
        socialFriendIDs = []
        socialFriendCodeLookupStatus = .idle
        socialSelectedFriendID = nil
        socialSelectedPassport = nil
        isPerformingSocialAction = false
        socialFeatureState = .unavailable
    }

    private func isCurrentSocialGeneration(_ generation: UInt64) -> Bool {
        generation == socialGeneration
    }

    private func publishReadySocialState() {
        if socialSelectedPassport != nil,
           socialPassportLeaseExpiresAt.map({ $0 > Date() }) != true {
            zeroizeSocialPassport()
            return
        }
        socialFeatureState = SocialFeatureState(
            availability: .ready,
            currentFriendCode: socialFriendCode?.rawValue,
            friendCodeInput: socialFriendCodeInput,
            friendCodeLookupStatus: socialFriendCodeLookupStatus,
            incomingRequests: socialIncomingRequestIDs.map(SocialIncomingRequest.init),
            friends: socialFriendIDs.enumerated().map {
                SocialFriend(
                    id: $0.element,
                    displayLabel: "Friend \($0.offset + 1)"
                )
            },
            selectedFriendID: socialSelectedFriendID,
            selectedPassport: socialSelectedPassport,
            isPerformingAction: isPerformingSocialAction
        )
    }


    private var isGPSVerificationInFlight: Bool {
        gpsVerificationFeedback.values.contains(where: \.isInFlight)
    }

    private var isGPSManualVisitBlocked: Bool {
        gpsVerificationFeedback.values.contains(where: \.blocksManualVisit)
    }

    private func refreshGPSPermissionFeedback() {
        switch gpsLocationRequester.permission.oneShotRequestPreflight {
        case .ready:
            for mountainID in gpsVerificationFeedback.compactMap({
                $0.value == .permissionRequested ? $0.key : nil
            }) {
                gpsVerificationFeedback[mountainID] = .permissionReady
            }
        case .denied, .restricted:
            for mountainID in gpsVerificationFeedback.compactMap({
                $0.value == .permissionRequested || $0.value == .permissionReady
                    ? $0.key
                    : nil
            }) {
                gpsVerificationFeedback[mountainID] = .manualFallback
            }
        case .requiresWhenInUseAuthorization:
            break
        }
    }
    private func clearIndeterminateGPSFeedback() {
        for mountainID in gpsVerificationFeedback.compactMap({
            $0.value == .indeterminate ? $0.key : nil
        }) {
            gpsVerificationFeedback[mountainID] = .idle
        }
    }


    private func beginLocalMutation() -> Bool {
        guard isLocalPassportReady,
              localStateError == nil,
              !isPersistingLocalPassport,
              !isSynchronizingSelfPassport,
              !isGPSManualVisitBlocked,
              localWritePauseReason == nil else {
            if let localWritePauseReason {
                actionError = writePauseMessage(localWritePauseReason)
            }
            return false
        }
        guard authenticationCoordinator.state == .signedIn else {
            actionError = "Sign in before changing your passport."
            return false
        }
        do {
            localSnapshotActorID = try requireCurrentAccountBinding(
                snapshotActorID: localSnapshotActorID,
                hasExistingState: !passportStateMachine.allProjections().isEmpty
                    || !manualVisitOutbox.nodes.isEmpty
                    || !planMutationOutbox.isEmpty
            )
        } catch {
            actionError =
                "This local passport belongs to a different account or predates secure account binding."
            return false
        }
        isPersistingLocalPassport = true
        return true
    }

    @discardableResult
    func synchronizeSelfPassportIfAuthenticated() async -> Bool {
        guard authenticationCoordinator.state == .signedIn,
              isLocalPassportReady,
              catalogError == nil,
              localStateError == nil,
              !isPersistingLocalPassport,
              !isSynchronizingSelfPassport,
              let encryptedLocalPassportStore,
              officialMountainIDs.count == 100,
              let officialDatasetSHA256 else {
            return false
        }

        isSynchronizingSelfPassport = true
        defer { isSynchronizingSelfPassport = false }

        do {
            let loadedSnapshot = try await encryptedLocalPassportStore.load()
            let currentSnapshot = try loadedSnapshot ?? LocalPassportSnapshot(
                passportState: passportStateMachine,
                manualVisitOutbox: manualVisitOutbox,
                planMutationOutbox: planMutationOutbox
            )
            let actorID = try requireCurrentAccountBinding(
                snapshotActorID: currentSnapshot.actorID,
                hasExistingState: currentSnapshot.syncBase != nil
                    || !currentSnapshot.passportState.allProjections().isEmpty
                    || !currentSnapshot.manualVisitOutbox.nodes.isEmpty
                    || !currentSnapshot.planMutationOutbox.isEmpty
            )
            if currentSnapshot.actorID == nil {
                let boundSnapshot = try LocalPassportSnapshot(
                    passportState: currentSnapshot.passportState,
                    manualVisitOutbox: currentSnapshot.manualVisitOutbox,
                    planMutationOutbox: currentSnapshot.planMutationOutbox,
                    syncBase: currentSnapshot.syncBase,
                    writePauseReason: currentSnapshot.writePauseReason,
                    actorID: actorID
                )
                guard try await encryptedLocalPassportStore.saveIfUnchanged(
                    boundSnapshot,
                    expected: loadedSnapshot
                ) else {
                    throw SelfPassportTransportFailure.fullRefreshRequired
                }
            }
            localSnapshotActorID = actorID
            let transport = try authenticationCoordinator.makeSelfPassportSyncTransport(
                datasetSHA256: officialDatasetSHA256
            )
            let engine = SelfPassportSyncEngine(
                store: encryptedLocalPassportStore,
                transport: transport,
                expectedMountainIDs: officialMountainIDs,
                expectedDatasetVersion: officialDatasetSHA256
            )
            selfPassportSyncEngine = engine

            _ = try await engine.restore()
            _ = try await engine.bootstrap()
            if await engine.writePauseReason() == .unauthenticated {
                try await engine.resumeWrites()
            }
            _ = try await engine.refreshChanges()
            for _ in 0..<100 {
                guard try await engine.uploadNextOutboxOperation() else {
                    break
                }
            }

            let aggregates = try await engine.effectiveAggregates()
            let canonicalBase = try await engine.canonicalBase()
            for aggregate in aggregates where aggregate.visitCount > 0 {
                let completedHistory = canonicalBase?
                    .completedHistory(for: aggregate.mountainID)
                if completedHistory?.aggregateVersionAtSnapshot != aggregate.aggregateVersion {
                    _ = try await engine.loadCompleteHistory(for: aggregate.mountainID)
                }
            }
            try await publishSynchronizedState(from: engine)
            let persistedPauseReason = await engine.writePauseReason()
            actionError = persistedPauseReason.map(writePauseMessage)
            clearIndeterminateGPSFeedback()
            return true
        } catch is LocalPassportAccountBindingError {
            hideAccountBoundPresentation()
            return false
        } catch SelfPassportTransportFailure.mutationConflict {
            actionError =
                "Synchronization is paused because a saved change conflicts with its server receipt."
            advanceProjectionRevision()
            return false
        } catch SelfPassportTransportFailure.mutationRejected {
            actionError =
                "Synchronization is paused because the server rejected a saved change."
            advanceProjectionRevision()
            return false
        } catch SelfPassportSyncError.writePaused(let reason) {
            actionError = writePauseMessage(reason)
            advanceProjectionRevision()
            return false
        } catch SelfPassportTransportFailure.forbidden {
            actionError =
                "Synchronization is paused because this account is not authorized for the requested operation."
            advanceProjectionRevision()
            return false
        } catch SelfPassportTransportFailure.upgradeRequired {
            actionError =
                "Synchronization requires a compatible app and server version before saved changes can continue."
            advanceProjectionRevision()
            return false
        } catch {
            actionError =
                "Your local passport is safe, but synchronization is temporarily unavailable."
            advanceProjectionRevision()
            return false
        }
    }

    private func publishSynchronizedState(
        from engine: SelfPassportSyncEngine<EncryptedLocalPassportStore>
    ) async throws {
        let effectiveAggregates = try await engine.effectiveAggregates()
        let canonicalBase = try await engine.canonicalBase()
        guard let encryptedLocalPassportStore,
              let snapshot = try await encryptedLocalPassportStore.load() else {
            throw EncryptedLocalPassportStoreError.invalidSnapshot
        }
        try validateCatalogCompatibility(
            passportState: snapshot.passportState,
            manualVisitOutbox: snapshot.manualVisitOutbox,
            planMutationOutbox: snapshot.planMutationOutbox
        )
        try validateActorForPublication(snapshot)
        localWritePauseReason = snapshot.writePauseReason
        passportStateMachine = snapshot.passportState
        manualVisitOutbox = snapshot.manualVisitOutbox
        planMutationOutbox = snapshot.planMutationOutbox
        synchronizedAggregates = effectiveAggregates
        synchronizedHistories = canonicalBase?.histories ?? []
        currentMapViewModel = try makeVisibleMapViewModel(from: snapshot.passportState)
        advanceProjectionRevision()
    }

    private func saveAndPublish(
        passportState: PassportStateMachine,
        manualVisitOutbox: ManualVisitOutboxGraph,
        planMutationOutbox: [PlanMutationOutboxNode]
    ) async throws {
        guard let encryptedLocalPassportStore else {
            throw EncryptedLocalPassportStoreError.invalidSnapshot
        }

        try validateCatalogCompatibility(
            passportState: passportState,
            manualVisitOutbox: manualVisitOutbox,
            planMutationOutbox: planMutationOutbox
        )
        let storedSnapshot = try await encryptedLocalPassportStore.load()
        var actorID = storedSnapshot?.actorID ?? localSnapshotActorID
        if authenticationCoordinator.state == .signedIn {
            actorID = try requireCurrentAccountBinding(
                snapshotActorID: actorID,
                hasExistingState: storedSnapshot != nil
                    && actorID == nil
                    && (!passportState.allProjections().isEmpty
                        || !manualVisitOutbox.nodes.isEmpty
                        || !planMutationOutbox.isEmpty)
            )
        }
        let writePauseReason = storedSnapshot?.writePauseReason
        let snapshot = try LocalPassportSnapshot(
            passportState: passportState,
            manualVisitOutbox: manualVisitOutbox,
            planMutationOutbox: planMutationOutbox,
            syncBase: storedSnapshot?.syncBase,
            writePauseReason: writePauseReason,
            actorID: actorID
        )
        let nextMapViewModel = try makeVisibleMapViewModel(from: passportState)

        guard try await encryptedLocalPassportStore.saveIfUnchanged(
            snapshot,
            expected: storedSnapshot
        ) else {
            throw SelfPassportTransportFailure.fullRefreshRequired
        }
        try validateActorForPublication(snapshot)
        localSnapshotActorID = actorID
        localWritePauseReason = writePauseReason

        currentMapViewModel = nextMapViewModel
        passportStateMachine = passportState
        self.manualVisitOutbox = manualVisitOutbox
        self.planMutationOutbox = planMutationOutbox
        actionError = nil
        advanceProjectionRevision()
    }

    private func projectedProgress(
        from passportState: PassportStateMachine
    ) throws -> [MountainID: MountainProgress] {
        var progress: [MountainID: MountainProgress] = [:]
        progress.reserveCapacity(officialMountains.count)

        for mountain in officialMountains {
            let projection = passportState.projection(for: mountain.id)
            progress[mountain.id] = try MountainProgress(
                visitCount: projection?.visitCount ?? 0,
                planned: projection?.planned ?? false
            )
        }

        return progress
    }

    private func refreshMapViewModel() {
        if let catalogError {
            currentMapViewModel = .invalidCatalog(message: catalogError)
        } else if let localStateError {
            currentMapViewModel = .localStateUnavailable(message: localStateError)
        } else if !isLocalPassportReady {
            currentMapViewModel = .loading
        } else {
            do {
                try validateCatalogCompatibility(
                    passportState: passportStateMachine,
                    manualVisitOutbox: manualVisitOutbox,
                    planMutationOutbox: planMutationOutbox
                )
                currentMapViewModel = try makeVisibleMapViewModel(from: passportStateMachine)
            } catch {
                failClosedForLocalState()
            }
        }
    }

    private func validateCatalogCompatibility(
        passportState: PassportStateMachine,
        manualVisitOutbox: ManualVisitOutboxGraph,
        planMutationOutbox: [PlanMutationOutboxNode]
    ) throws {
        let officialMountainIDs = Set(officialMountains.map(\.id))

        for projection in passportState.allProjections() {
            guard officialMountainIDs.contains(projection.mountainID),
                  projection.history.allSatisfy({
                      $0.mountainID == projection.mountainID
                          && officialMountainIDs.contains($0.mountainID)
                  }) else {
                throw LocalPassportStateError.catalogIncompatible
            }
        }

        guard manualVisitOutbox.nodes.allSatisfy({
            officialMountainIDs.contains($0.aggregateMountainID)
                && officialMountainIDs.contains($0.request.mountainID)
        }) else {
            throw LocalPassportStateError.catalogIncompatible
        }

        guard planMutationOutbox.allSatisfy({
            officialMountainIDs.contains($0.mountainID)
        }) else {
            throw LocalPassportStateError.catalogIncompatible
        }
    }

    private func visiblePassportProjections() -> [MountainPassportProjection] {
        var projections = Dictionary(
            uniqueKeysWithValues: synchronizedAggregates.map { aggregate in
                let history = visibleHistory(for: aggregate)
                return (
                    aggregate.mountainID,
                    MountainPassportProjection(
                        mountainID: aggregate.mountainID,
                        visitCount: aggregate.visitCount,
                        history: history,
                        stamp: aggregate.stamp,
                        planDisposition: aggregate.planDisposition
                    )
                )
            }
        )
        for projection in passportStateMachine.allProjections()
        where projections[projection.mountainID] == nil {
            projections[projection.mountainID] = projection
        }
        return projections.values.sorted {
            $0.mountainID.rawValue < $1.mountainID.rawValue
        }
    }

    private func visibleHistory(
        for aggregate: SelfPassportAggregate
    ) -> [VisitRecord] {
        var visits = synchronizedHistories.first {
            $0.mountainID == aggregate.mountainID
                && $0.aggregateVersionAtSnapshot == aggregate.aggregateVersion
        }?.visits ?? []

        for node in manualVisitOutbox.nodes
        where node.aggregateMountainID == aggregate.mountainID {
            switch node.request.operation {
            case .create:
                if let localVisit = localManualVisit(id: node.request.visitID),
                   !visits.contains(where: { $0.id == localVisit.id }) {
                    visits.append(localVisit)
                }
            case .delete:
                visits.removeAll { $0.id == node.request.visitID }
            }
        }

        return visits.sorted {
            if $0.visitedAt != $1.visitedAt {
                return $0.visitedAt > $1.visitedAt
            }
            if $0.recordedAt != $1.recordedAt {
                return $0.recordedAt > $1.recordedAt
            }
            return $0.id.rawValue < $1.id.rawValue
        }
    }

    private func makeVisibleMapViewModel(
        from passportState: PassportStateMachine
    ) throws -> MapViewModel {
        var progress = Dictionary(
            uniqueKeysWithValues: try synchronizedAggregates.map { aggregate in
                (
                    aggregate.mountainID,
                    try MountainProgress(
                        visitCount: aggregate.visitCount,
                        planned: aggregate.planDisposition?.isPlanned ?? false
                    )
                )
            }
        )
        for (mountainID, localProgress) in try projectedProgress(from: passportState)
        where progress[mountainID] == nil {
            progress[mountainID] = localProgress
        }
        let viewModel = MapViewModel(mountains: officialMountains, progress: progress)
        guard viewModel.state == .ready else {
            throw LocalPassportStateError.mapProjectionIncompatible
        }
        return viewModel
    }
    private func makeMapViewModel(
        from passportState: PassportStateMachine
    ) throws -> MapViewModel {
        let mapViewModel = MapViewModel(
            mountains: officialMountains,
            progress: try projectedProgress(from: passportState)
        )
        try validateMapProjectionInvariant(
            passportState: passportState,
            mapViewModel: mapViewModel
        )
        return mapViewModel
    }

    private func validateMapProjectionInvariant(
        passportState: PassportStateMachine,
        mapViewModel: MapViewModel
    ) throws {
        guard mapViewModel.state == .ready else {
            return
        }

        for projection in passportState.allProjections() {
            guard let pin = mapViewModel.pins.first(where: {
                $0.id == projection.mountainID
            }),
            pin.visitCount == projection.visitCount,
            pin.isPlanned == projection.planned else {
                throw LocalPassportStateError.mapProjectionIncompatible
            }
        }
    }

    private func writePauseMessage(_ reason: SelfPassportWritePauseReason) -> String {
        switch reason {
        case .unauthenticated:
            return "Synchronization is paused until you sign in again."
        case .authorization:
            return "Synchronization is paused because this account is not authorized."
        case .continuity:
            return "Synchronization needs a complete server refresh before saved changes can continue."
        case .compatibility:
            return "Synchronization requires a compatible app and server version."
        case .mutationConflict:
            return "Synchronization is paused because a saved change conflicts with its server receipt."
        case .mutationRejected:
            return "Synchronization is paused because the server rejected a saved change."
        }
    }

    private func handleLocalMutationFailure(_ error: Error, message: String) {
        if case let SelfPassportSyncError.writePaused(reason) = error {
            actionError = writePauseMessage(reason)
            advanceProjectionRevision()
            return
        }
        guard error is LocalPassportStateError else {
            actionError = message
            return
        }

        failClosedForLocalState()
        advanceProjectionRevision()
    }

    private func failClosedForLocalState() {
        localStateError = Self.unavailableLocalStateMessage
        isLocalPassportReady = false
        actionError = nil
        gpsVerificationFeedback = [:]
        currentMapViewModel = .localStateUnavailable(message: Self.unavailableLocalStateMessage)
    }

    private func manualVisit(id: VisitID) -> VisitRecord? {
        localManualVisit(id: id)
            ?? synchronizedHistories
                .lazy
                .flatMap(\.visits)
                .first(where: { $0.id == id })
    }

    private func localManualVisit(id: VisitID) -> VisitRecord? {
        passportStateMachine.allProjections()
            .lazy
            .flatMap(\.history)
            .first(where: { $0.id == id })
    }

    private func requireCurrentAccountBinding(
        snapshotActorID: UUID?,
        hasExistingState: Bool
    ) throws -> UUID {
        let currentActorID = try authenticationCoordinator.currentSessionActorID()
        return try LocalPassportAccountPublicationPolicy.resolvedActorID(
            currentActorID: currentActorID,
            snapshotActorID: snapshotActorID,
            hasExistingState: hasExistingState
        )!
    }

    private func validateActorForPublication(
        _ snapshot: LocalPassportSnapshot?
    ) throws {
        guard let snapshot else {
            return
        }
        let currentActorID: UUID?
        if authenticationCoordinator.state == .signedIn {
            currentActorID = try authenticationCoordinator.currentSessionActorID()
        } else {
            currentActorID = nil
        }
        let hasExistingState = snapshot.syncBase != nil
            || !snapshot.passportState.allProjections().isEmpty
            || !snapshot.manualVisitOutbox.nodes.isEmpty
            || !snapshot.planMutationOutbox.isEmpty
        let resolvedActorID = try LocalPassportAccountPublicationPolicy.resolvedActorID(
            currentActorID: currentActorID,
            snapshotActorID: snapshot.actorID,
            hasExistingState: hasExistingState
        )
        guard resolvedActorID == snapshot.actorID else {
            throw LocalPassportAccountBindingError.accountMismatch
        }
    }

    private func hideAccountBoundPresentation() {
        passportStateMachine = PassportStateMachine()
        manualVisitOutbox = Self.emptyOutbox()
        planMutationOutbox = []
        synchronizedAggregates = []
        synchronizedHistories = []
        selfPassportSyncEngine = nil
        gpsVerificationFeedback = [:]
        localSnapshotActorID = nil
        localWritePauseReason = nil
        isLocalPassportReady = false
        let message =
            "Sign in with the account that owns this local passport to view or synchronize it."
        actionError = message
        currentMapViewModel = .localStateUnavailable(message: message)
        advanceProjectionRevision()
    }
    private func advanceProjectionRevision() {
        precondition(projectionRevision < UInt64.max)
        projectionRevision += 1
    }

    private static func emptyOutbox() -> ManualVisitOutboxGraph {
        do {
            return try ManualVisitOutboxGraph()
        } catch {
            preconditionFailure("An empty manual visit outbox must be valid.")
        }
    }

    private static let unavailableLocalStateMessage =
        "Local passport state could not be verified. Restore this device's local state from backup and relaunch before recording changes."
}

private enum LocalPassportKeychain {
    private static let account = "local-passport-v1.encryption-key"

    static func loadOrCreate(service: String) throws -> LocalPassportEncryptionKey {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
        ]

        var matchingQuery = query
        matchingQuery[kSecReturnData] = true
        matchingQuery[kSecMatchLimit] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(matchingQuery as CFDictionary, &item)

        switch status {
        case errSecSuccess:
            guard let keyData = item as? Data else {
                throw LocalPassportKeychainError.invalidStoredKey
            }
            return try LocalPassportEncryptionKey(data: keyData)

        case errSecItemNotFound:
            let keyData = try randomKeyData()
            var addQuery = query
            addQuery[kSecValueData] = keyData
            addQuery[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly

            let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
            if addStatus == errSecSuccess {
                return try LocalPassportEncryptionKey(data: keyData)
            }
            if addStatus == errSecDuplicateItem {
                return try loadExistingKey(matchingQuery)
            }
            throw LocalPassportKeychainError.keychainFailure

        default:
            throw LocalPassportKeychainError.keychainFailure
        }
    }

    private static func loadExistingKey(
        _ matchingQuery: [CFString: Any]
    ) throws -> LocalPassportEncryptionKey {
        var item: CFTypeRef?
        guard SecItemCopyMatching(matchingQuery as CFDictionary, &item) == errSecSuccess,
              let keyData = item as? Data else {
            throw LocalPassportKeychainError.keychainFailure
        }
        return try LocalPassportEncryptionKey(data: keyData)
    }

    private static func randomKeyData() throws -> Data {
        let keyByteCount = 32
        var keyData = Data(count: keyByteCount)
        let status = keyData.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, keyByteCount, buffer.baseAddress!)
        }
        guard status == errSecSuccess else {
            throw LocalPassportKeychainError.keychainFailure
        }
        return keyData
    }
}

enum LocalPassportAccountPublicationPolicy {
    static func resolvedActorID(
        currentActorID: UUID?,
        snapshotActorID: UUID?,
        hasExistingState: Bool
    ) throws -> UUID? {
        switch (currentActorID, snapshotActorID) {
        case let (.some(current), .some(snapshot)):
            guard current == snapshot else {
                throw LocalPassportAccountBindingError.accountMismatch
            }
            return snapshot
        case (.none, .some):
            throw LocalPassportAccountBindingError.accountMismatch
        case let (.some(current), .none):
            guard !hasExistingState else {
                throw LocalPassportAccountBindingError.unboundExistingState
            }
            return current
        case (.none, .none):
            guard !hasExistingState else {
                throw LocalPassportAccountBindingError.unboundExistingState
            }
            return nil
        }
    }
}
private enum LocalPassportAccountBindingError: Error {
    case accountMismatch
    case unboundExistingState
}
private enum LocalPassportKeychainError: Error {
    case invalidStoredKey
    case keychainFailure
}