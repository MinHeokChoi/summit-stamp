import Foundation
import HikerDomain

public enum SupabaseSelfPassportSyncTransportError: Error, Equatable, Sendable {
    case invalidConfiguration
    case malformedResponse
    case unsupportedMutation
}

public enum SupabaseSelfPassportMutationOperation: String, Equatable, Sendable {
    case addPlan
    case removePlan
    case createManualVisit
    case deleteManualVisit
}

public struct SupabaseSelfPassportMutationResult: Equatable, Sendable {
    public let operation: SupabaseSelfPassportMutationOperation
    public let mountainID: MountainID
    public let visitID: VisitID?
    public let aggregate: SelfPassportAggregate
    public let snapshotVersion: Int64
    public let historyToken: OpaqueHistoryToken

    public init(
        operation: SupabaseSelfPassportMutationOperation,
        mountainID: MountainID,
        visitID: VisitID?,
        aggregate: SelfPassportAggregate,
        snapshotVersion: Int64,
        historyToken: OpaqueHistoryToken
    ) {
        self.operation = operation
        self.mountainID = mountainID
        self.visitID = visitID
        self.aggregate = aggregate
        self.snapshotVersion = snapshotVersion
        self.historyToken = historyToken
    }
}

/// Authenticated, actor-bound access to the public M3 sync and M4 GPS RPC
/// surfaces. The caller supplies only a current user bearer; this transport
/// never stores refresh credentials and never accepts a service-role key.
public actor SupabaseSelfPassportSyncTransport: SelfPassportSyncTransport, GPSVisitVerificationTransport {
    public typealias CurrentBearer = @Sendable () async throws -> String?

    public static let apiVersion = "m3-v1"
    public static let gpsAPIVersion = "m4-v1"

    private let restURL: URL
    private let publishableKey: String
    private let datasetSHA256: String
    private let currentBearer: CurrentBearer
    private let session: URLSession

    private var activeHistoryContext: HistoryContext?
    private var changeContexts: [String: ChangeContext] = [:]

    public init(
        restURL: URL,
        publishableKey: String,
        datasetSHA256: String,
        currentBearer: @escaping CurrentBearer,
        session: URLSession? = nil
    ) throws {
        guard Self.isRESTURL(restURL),
              Self.isPublishableKey(publishableKey),
              Self.isSHA256(datasetSHA256) else {
            throw SupabaseSelfPassportSyncTransportError.invalidConfiguration
        }

        self.restURL = restURL
        self.publishableKey = publishableKey
        self.datasetSHA256 = datasetSHA256
        self.currentBearer = currentBearer
        if let session {
            self.session = session
        } else {
            let configuration = URLSessionConfiguration.ephemeral
            configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
            configuration.urlCache = nil
            configuration.httpCookieStorage = nil
            configuration.httpShouldSetCookies = false
            self.session = URLSession(configuration: configuration)
        }
    }

    public func bootstrap() async throws -> SelfPassportBootstrapResponse {
        let wire: BootstrapWireResponse = try await rpc(
            named: "m3_self_bootstrap",
            body: BootstrapWireRequest(
                apiVersion: Self.apiVersion,
                datasetSHA256: datasetSHA256
            )
        )
        let response = try mapBootstrap(wire)
        let aggregates = Dictionary(
            uniqueKeysWithValues: response.aggregates.map { ($0.mountainID, $0) }
        )
        activeHistoryContext = HistoryContext(
            token: response.historyToken,
            snapshotVersion: response.snapshotVersion,
            aggregates: aggregates
        )
        changeContexts.removeAll()
        return response
    }

    public func historyPage(
        _ request: SelfPassportHistoryRequest
    ) async throws -> SelfPassportHistoryPage {
        guard let context = activeHistoryContext,
              context.token == request.historyToken,
              context.snapshotVersion == request.snapshotVersion,
              let aggregate = context.aggregates[request.mountainID] else {
            throw SelfPassportTransportFailure.fullRefreshRequired
        }

        let wire: HistoryWireResponse = try await rpc(
            named: "m3_self_history_page",
            body: HistoryWireRequest(
                historyToken: request.historyToken.rawValue,
                cursor: request.continuationToken?.rawValue,
                mountainID: request.mountainID.rawValue,
                pageSize: 100
            )
        )
        guard wire.snapshotVersion == context.snapshotVersion,
              wire.complete == (wire.nextCursor == nil) else {
            throw SupabaseSelfPassportSyncTransportError.malformedResponse
        }

        let visits = try wire.items.map(mapVisit)
        let continuation = try wire.nextCursor.map(OpaqueHistoryToken.init(rawValue:))
        return SelfPassportHistoryPage(
            mountainID: request.mountainID,
            snapshotVersion: wire.snapshotVersion,
            aggregateVersionAtSnapshot: aggregate.aggregateVersion,
            visits: visits,
            nextContinuationToken: continuation
        )
    }

    public func changePage(
        _ request: SelfPassportChangeRequest
    ) async throws -> SelfPassportChangePage {
        let context: ChangeContext
        let historyToken: OpaqueHistoryToken
        if let cursor = request.continuationToken {
            guard let stored = changeContexts.removeValue(forKey: cursor.rawValue),
                  stored.baselineVersion == request.afterSnapshotVersion else {
                throw SelfPassportTransportFailure.fullRefreshRequired
            }
            context = stored
            historyToken = stored.historyToken
        } else {
            changeContexts.removeAll(keepingCapacity: true)
            guard let history = activeHistoryContext,
                  history.snapshotVersion == request.afterSnapshotVersion else {
                throw SelfPassportTransportFailure.fullRefreshRequired
            }
            historyToken = history.token
            context = ChangeContext(
                historyToken: history.token,
                baselineVersion: request.afterSnapshotVersion,
                expectedFromVersion: request.afterSnapshotVersion,
                aggregates: history.aggregates
            )
        }

        let wire: ChangeWireResponse = try await rpc(
            named: "m3_self_changes",
            body: ChangeWireRequest(
                historyToken: historyToken.rawValue,
                cursor: request.continuationToken?.rawValue,
                limit: 500
            )
        )
        guard !wire.resyncRequired else {
            throw SelfPassportTransportFailure.fullRefreshRequired
        }
        guard wire.fromVersion == context.expectedFromVersion,
              wire.throughVersion >= wire.fromVersion,
              wire.changes.count <= 500,
              wire.complete == (wire.nextCursor == nil) else {
            throw SupabaseSelfPassportSyncTransportError.malformedResponse
        }

        var expectedVersion = wire.fromVersion
        var aggregates = context.aggregates
        var changes: [SelfPassportChange] = []
        changes.reserveCapacity(wire.changes.count)
        for wireChange in wire.changes {
            guard wireChange.globalVersion == expectedVersion + 1 else {
                throw SupabaseSelfPassportSyncTransportError.malformedResponse
            }
            let mutation = try mapMutation(
                wireChange.result,
                expectedOperation: wireChange.operation,
                expectedMountainID: wireChange.mountainID,
                expectedGlobalVersion: wireChange.globalVersion,
                expectedAggregateVersion: wireChange.aggregateVersion,
                expectedVisitID: nil
            )
            guard aggregates[mutation.aggregate.mountainID] != nil else {
                throw SupabaseSelfPassportSyncTransportError.malformedResponse
            }
            aggregates[mutation.aggregate.mountainID] = mutation.aggregate
            changes.append(
                SelfPassportChange(
                    globalSnapshotVersion: wireChange.globalVersion,
                    aggregate: mutation.aggregate
                )
            )
            expectedVersion = wireChange.globalVersion
        }

        guard wire.nextVersion == expectedVersion else {
            throw SupabaseSelfPassportSyncTransportError.malformedResponse
        }

        if let nextCursor = wire.nextCursor {
            guard !wire.complete else {
                throw SupabaseSelfPassportSyncTransportError.malformedResponse
            }
            let continuation = try OpaqueChangeToken(rawValue: nextCursor)
            changeContexts[continuation.rawValue] = ChangeContext(
                historyToken: context.historyToken,
                baselineVersion: context.baselineVersion,
                expectedFromVersion: wire.nextVersion,
                aggregates: aggregates
            )
            return SelfPassportChangePage(
                afterSnapshotVersion: context.baselineVersion,
                changes: changes,
                nextContinuationToken: continuation,
                nextSnapshotVersion: wire.nextVersion,
                historyToken: context.historyToken
            )
        }

        guard wire.complete,
              wire.throughVersion == wire.nextVersion else {
            throw SupabaseSelfPassportSyncTransportError.malformedResponse
        }

        // M3 change pages intentionally retain the bootstrap capability. Issue a
        // fresh bootstrap at the completed target so the next incremental poll is
        // bound to the newly accepted snapshot rather than an obsolete token.
        let refreshed = try await bootstrap()
        guard refreshed.snapshotVersion == wire.nextVersion,
              Dictionary(uniqueKeysWithValues: refreshed.aggregates.map { ($0.mountainID, $0) })
                == aggregates else {
            throw SelfPassportTransportFailure.fullRefreshRequired
        }
        return SelfPassportChangePage(
            afterSnapshotVersion: context.baselineVersion,
            changes: changes,
            nextContinuationToken: nil,
            nextSnapshotVersion: wire.nextVersion,
            historyToken: refreshed.historyToken
        )
    }

    public func upload(
        _ node: ManualVisitOutboxNode
    ) async throws -> SelfPassportMutationReceipt {
        switch node.request.operation {
        case .create:
            guard let visit = try node.request.validatedCreateVisit() else {
                throw SupabaseSelfPassportSyncTransportError.unsupportedMutation
            }
            let result = try await createManualVisit(
                visit,
                clientMutationID: node.id
            )
            guard result.mountainID == node.aggregateMountainID,
                  result.visitID == node.request.visitID else {
                throw SupabaseSelfPassportSyncTransportError.malformedResponse
            }
            return SelfPassportMutationReceipt(
                clientMutationID: node.id,
                operation: .create,
                visitID: node.request.visitID,
                mountainID: node.aggregateMountainID,
                aggregate: result.aggregate,
                snapshotVersion: result.snapshotVersion,
                historyToken: result.historyToken
            )

        case .delete:
            let result = try await deleteManualVisit(
                node.request.visitID,
                clientMutationID: node.id
            )
            guard result.mountainID == node.aggregateMountainID,
                  result.visitID == node.request.visitID else {
                throw SupabaseSelfPassportSyncTransportError.malformedResponse
            }
            return SelfPassportMutationReceipt(
                clientMutationID: node.id,
                operation: .delete,
                visitID: node.request.visitID,
                mountainID: node.aggregateMountainID,
                aggregate: result.aggregate,
                snapshotVersion: result.snapshotVersion,
                historyToken: result.historyToken
            )
        }
    }

    public func uploadPlan(
        _ node: PlanMutationOutboxNode
    ) async throws -> SelfPassportPlanMutationReceipt {
        let result: SupabaseSelfPassportMutationResult
        switch node.operation {
        case .add:
            result = try await addPlan(
                for: node.mountainID,
                clientMutationID: node.clientMutationID
            )
        case .remove:
            result = try await removePlan(
                for: node.mountainID,
                clientMutationID: node.clientMutationID
            )
        }
        guard result.mountainID == node.mountainID else {
            throw SupabaseSelfPassportSyncTransportError.malformedResponse
        }
        return SelfPassportPlanMutationReceipt(
            clientMutationID: node.clientMutationID,
            operation: node.operation,
            mountainID: node.mountainID,
            aggregate: result.aggregate,
            snapshotVersion: result.snapshotVersion,
            historyToken: result.historyToken
        )
    }

    public func addPlan(
        for mountainID: MountainID,
        clientMutationID: ClientMutationID
    ) async throws -> SupabaseSelfPassportMutationResult {
        try await performMutation(
            clientMutationID: clientMutationID,
            operation: .addPlan,
            payload: ["mountainID": mountainID.rawValue],
            expectedMountainID: mountainID,
            expectedVisitID: nil
        )
    }

    public func removePlan(
        for mountainID: MountainID,
        clientMutationID: ClientMutationID
    ) async throws -> SupabaseSelfPassportMutationResult {
        try await performMutation(
            clientMutationID: clientMutationID,
            operation: .removePlan,
            payload: ["mountainID": mountainID.rawValue],
            expectedMountainID: mountainID,
            expectedVisitID: nil
        )
    }

    public func createManualVisit(
        _ visit: VisitRecord,
        clientMutationID: ClientMutationID
    ) async throws -> SupabaseSelfPassportMutationResult {
        guard visit.verificationMethod == .manual else {
            throw SupabaseSelfPassportSyncTransportError.unsupportedMutation
        }
        return try await performMutation(
            clientMutationID: clientMutationID,
            operation: .createManualVisit,
            payload: [
                "mountainID": visit.mountainID.rawValue,
                "visitID": visit.id.rawValue,
                "visitedAt": Self.timestampString(visit.visitedAt),
            ],
            expectedMountainID: visit.mountainID,
            expectedVisitID: visit.id
        )
    }

    public func deleteManualVisit(
        _ visitID: VisitID,
        clientMutationID: ClientMutationID
    ) async throws -> SupabaseSelfPassportMutationResult {
        try await performMutation(
            clientMutationID: clientMutationID,
            operation: .deleteManualVisit,
            payload: ["visitID": visitID.rawValue],
            expectedMountainID: nil,
            expectedVisitID: visitID
        )
    }
    /// M4 consumes the current bootstrap history token as an actor-bound,
    /// dataset-bound online capability. Raw sample fields are constructed only
    /// in the request body and are never retained by this actor or its contexts.
    public func verifyGPSVisit(
        mountainID: MountainID,
        visitID: VisitID,
        visitedAt: Date,
        clientMutationID: ClientMutationID,
        latitude: Double,
        longitude: Double,
        horizontalAccuracyMeters: Double,
        sampledAt: Date
    ) async throws -> GPSVisitVerificationOutcome {
        guard latitude.isFinite,
              longitude.isFinite,
              horizontalAccuracyMeters.isFinite else {
            return .manualFallback(.sampleInvalid)
        }
        guard let capability = activeHistoryContext else {
            return .rejected(.precondition)
        }

        let wire: GPSVisitVerificationWireResponse
        do {
            wire = try await rpc(
                named: "m4_create_gps_visit",
                body: GPSVisitVerificationWireRequest(
                    apiVersion: Self.gpsAPIVersion,
                    datasetSHA256: datasetSHA256,
                    historyToken: capability.token.rawValue,
                    mountainID: mountainID.rawValue,
                    visitID: visitID.rawValue,
                    visitedAt: Self.timestampString(visitedAt),
                    mutationID: clientMutationID.rawValue,
                    latitude: latitude,
                    longitude: longitude,
                    horizontalAccuracyMeters: horizontalAccuracyMeters,
                    sampledAt: Self.timestampString(sampledAt)
                )
            )
        } catch let failure as SelfPassportTransportFailure {
            switch failure {
            case .unauthenticated, .forbidden:
                return .rejected(.authorization)
            case .mutationRejected:
                return .rejected(.server)
            case .upgradeRequired:
                return .rejected(.policy)
            case .refreshRequired, .fullRefreshRequired, .mutationConflict, .transient:
                return .indeterminate
            }
        } catch {
            return .indeterminate
        }

        switch wire {
        case let .manualFallback(reason):
            return .manualFallback(reason)
        case let .gpsVerified(response):
            do {
                guard response.status == "gps_verified",
                      !response.manualFallback,
                      response.verificationMethod == "gps_verified" else {
                    return .indeterminate
                }
                let mutation = try mapMutation(
                    response,
                    expectedOperation: "gps_visit_create",
                    expectedMountainID: mountainID.rawValue,
                    expectedGlobalVersion: nil,
                    expectedAggregateVersion: nil,
                    expectedVisitID: visitID
                )
                let refreshed = try await bootstrap()
                guard refreshed.snapshotVersion >= mutation.globalVersion,
                      let refreshedAggregate = refreshed.aggregates.first(where: {
                          $0.mountainID == mutation.aggregate.mountainID
                      }),
                      refreshedAggregate.aggregateVersion >= mutation.aggregate.aggregateVersion,
                      let refreshedHistoryToken = activeHistoryContext?.token,
                      refreshedHistoryToken == refreshed.historyToken else {
                    return .indeterminate
                }
                return .gpsVerified(
                    GPSVisitVerificationReceipt(
                        clientMutationID: clientMutationID,
                        visitID: visitID,
                        mountainID: mutation.aggregate.mountainID,
                        aggregate: refreshedAggregate,
                        snapshotVersion: refreshed.snapshotVersion,
                        historyToken: refreshedHistoryToken
                    )
                )
            } catch {
                return .indeterminate
            }
        }
    }

    private func performMutation(
        clientMutationID: ClientMutationID,
        operation: SupabaseSelfPassportMutationOperation,
        payload: [String: String],
        expectedMountainID: MountainID?,
        expectedVisitID: VisitID?
    ) async throws -> SupabaseSelfPassportMutationResult {
        let expectedOperation = switch operation {
        case .addPlan: "plan_add"
        case .removePlan: "plan_remove"
        case .createManualVisit: "manual_visit_create"
        case .deleteManualVisit: "manual_visit_delete"
        }
        let wire: MutationWireResponse = try await rpc(
            named: "m3_apply_passport_mutation",
            body: ApplyMutationWireRequest(
                apiVersion: Self.apiVersion,
                datasetSHA256: datasetSHA256,
                mutationID: clientMutationID.rawValue,
                operation: expectedOperation,
                payload: payload
            )
        )

        let mutation = try mapMutation(
            wire,
            expectedOperation: expectedOperation,
            expectedMountainID: expectedMountainID?.rawValue,
            expectedGlobalVersion: nil,
            expectedAggregateVersion: nil,
            expectedVisitID: expectedVisitID
        )
        let refreshed = try await bootstrap()
        guard refreshed.snapshotVersion >= mutation.globalVersion,
              let refreshedAggregate = refreshed.aggregates.first(where: {
                  $0.mountainID == mutation.aggregate.mountainID
              }),
              refreshedAggregate.aggregateVersion >= mutation.aggregate.aggregateVersion,
              let refreshedHistoryToken = activeHistoryContext?.token,
              refreshedHistoryToken == refreshed.historyToken else {
            throw SelfPassportTransportFailure.fullRefreshRequired
        }
        return SupabaseSelfPassportMutationResult(
            operation: operation,
            mountainID: mutation.aggregate.mountainID,
            visitID: mutation.visitID,
            aggregate: refreshedAggregate,
            snapshotVersion: refreshed.snapshotVersion,
            historyToken: refreshedHistoryToken
        )
    }

    private func rpc<Body: Encodable, Response: Decodable>(
        named name: String,
        body: Body
    ) async throws -> Response {
        let bearer: String
        do {
            guard let current = try await currentBearer(), Self.isBearer(current) else {
                throw SelfPassportTransportFailure.unauthenticated
            }
            bearer = current
        } catch let failure as SelfPassportTransportFailure {
            throw failure
        } catch {
            throw SelfPassportTransportFailure.unauthenticated
        }

        var request = URLRequest(
            url: restURL
                .appendingPathComponent("rpc", isDirectory: true)
                .appendingPathComponent(name, isDirectory: false)
        )
        request.httpMethod = "POST"
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue(publishableKey, forHTTPHeaderField: "apikey")
        request.setValue("Bearer \(bearer)", forHTTPHeaderField: "Authorization")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        request.setValue("no-cache", forHTTPHeaderField: "Pragma")
        request.httpBody = try JSONEncoder().encode(body)

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            throw SelfPassportTransportFailure.transient
        }
        guard let httpResponse = response as? HTTPURLResponse else {
            throw SelfPassportTransportFailure.transient
        }
        guard (200...299).contains(httpResponse.statusCode) else {
            throw failure(for: httpResponse.statusCode, rpcName: name)
        }
        do {
            return try JSONDecoder().decode(Response.self, from: data)
        } catch {
            throw SupabaseSelfPassportSyncTransportError.malformedResponse
        }
    }

    private func mapBootstrap(
        _ wire: BootstrapWireResponse
    ) throws -> SelfPassportBootstrapResponse {
        guard wire.datasetSHA256 == datasetSHA256,
              wire.snapshotVersion >= 0,
              wire.mountains.count == 100,
              Set(wire.mountains).count == 100,
              wire.aggregates.count == 100,
              Set(wire.aggregates.map(\.mountainID)).count == 100,
              Set(wire.mountains) == Set(wire.aggregates.map(\.mountainID)),
              Set(wire.plans.map(\.mountainID)).count == wire.plans.count,
              Set(wire.stamps.map(\.mountainID)).count == wire.stamps.count else {
            throw SupabaseSelfPassportSyncTransportError.malformedResponse
        }

        let mountainIDs = try Set(wire.mountains.map(MountainID.init(rawValue:)))
        guard mountainIDs.count == 100 else {
            throw SupabaseSelfPassportSyncTransportError.malformedResponse
        }
        let rawMountainIDs = Set(wire.mountains)
        guard Set(wire.plans.map(\.mountainID)).isSubset(of: rawMountainIDs),
              Set(wire.stamps.map(\.mountainID)).isSubset(of: rawMountainIDs) else {
            throw SupabaseSelfPassportSyncTransportError.malformedResponse
        }
        let plans = Dictionary(uniqueKeysWithValues: wire.plans.map { ($0.mountainID, $0) })
        let stamps = Dictionary(uniqueKeysWithValues: wire.stamps.map { ($0.mountainID, $0) })
        var aggregates: [SelfPassportAggregate] = []
        aggregates.reserveCapacity(wire.aggregates.count)

        for rawAggregate in wire.aggregates {
            let mountainID = try MountainID(rawValue: rawAggregate.mountainID)
            guard mountainIDs.contains(mountainID),
                  rawAggregate.visitCount >= 0,
                  rawAggregate.aggregateVersion >= 0,
                  rawAggregate.globalVersion >= 0,
                  rawAggregate.globalVersion <= wire.snapshotVersion else {
                throw SupabaseSelfPassportSyncTransportError.malformedResponse
            }
            let plan = try mapPlan(
                state: rawAggregate.planState,
                firstVisitID: plans[rawAggregate.mountainID]?.firstVisitID,
                plan: plans[rawAggregate.mountainID],
                aggregate: rawAggregate
            )
            let stamp = try stamps[rawAggregate.mountainID].map {
                try mapBootstrapStamp($0, mountainID: mountainID, aggregate: rawAggregate)
            }
            guard (rawAggregate.visitCount > 0) == (stamp != nil) else {
                throw SupabaseSelfPassportSyncTransportError.malformedResponse
            }
            aggregates.append(
                try SelfPassportAggregate(
                    mountainID: mountainID,
                    aggregateVersion: rawAggregate.aggregateVersion,
                    visitCount: rawAggregate.visitCount,
                    planDisposition: plan,
                    stamp: stamp
                )
            )
        }

        return SelfPassportBootstrapResponse(
            snapshotVersion: wire.snapshotVersion,
            datasetVersion: wire.datasetSHA256,
            // The SQL M3 response is the v1 wire schema; the number is a client
            // decoding contract, not server-provided catalog authority.
            schemaVersion: 1,
            historyToken: try OpaqueHistoryToken(rawValue: wire.historyToken),
            aggregates: aggregates.sorted { $0.mountainID.rawValue < $1.mountainID.rawValue }
        )
    }

    private func mapPlan(
        state: String?,
        firstVisitID: String?,
        plan: BootstrapPlanWire?,
        aggregate: BootstrapAggregateWire
    ) throws -> PlanDisposition? {
        guard state == plan?.planState else {
            throw SupabaseSelfPassportSyncTransportError.malformedResponse
        }
        guard let state else {
            return nil
        }
        guard let plan,
              plan.aggregateVersion == aggregate.aggregateVersion,
              plan.globalVersion == aggregate.globalVersion else {
            throw SupabaseSelfPassportSyncTransportError.malformedResponse
        }
        switch state {
        case "active_manual":
            guard firstVisitID == nil else {
                throw SupabaseSelfPassportSyncTransportError.malformedResponse
            }
            return .active(.manual)
        case "active_auto_completed":
            guard let firstVisitID else {
                throw SupabaseSelfPassportSyncTransportError.malformedResponse
            }
            return .active(.autoCompleted(firstVisitID: try VisitID(rawValue: firstVisitID)))
        case "manually_removed":
            guard firstVisitID == nil else {
                throw SupabaseSelfPassportSyncTransportError.malformedResponse
            }
            return .manuallyRemoved
        default:
            throw SupabaseSelfPassportSyncTransportError.malformedResponse
        }
    }

    private func mapBootstrapStamp(
        _ stamp: BootstrapStampWire,
        mountainID: MountainID,
        aggregate: BootstrapAggregateWire
    ) throws -> Stamp {
        guard stamp.aggregateVersion == aggregate.aggregateVersion,
              stamp.globalVersion == aggregate.globalVersion else {
            throw SupabaseSelfPassportSyncTransportError.malformedResponse
        }
        return Stamp(
            mountainID: mountainID,
            sourceVisitID: try VisitID(rawValue: stamp.sourceVisitID),
            earnedAt: stamp.earnedAt.value,
            method: try mapVerificationMethod(stamp.verificationMethod)
        )
    }

    private func mapVisit(_ wire: HistoryVisitWire) throws -> VisitRecord {
        guard wire.createdAggregateVersion >= 0,
              wire.createdGlobalVersion >= 0 else {
            throw SupabaseSelfPassportSyncTransportError.malformedResponse
        }
        return VisitRecord(
            id: try VisitID(rawValue: wire.visitID),
            mountainID: try MountainID(rawValue: wire.mountainID),
            visitedAt: wire.visitedAt.value,
            recordedAt: wire.recordedAt.value,
            verificationMethod: try mapVerificationMethod(wire.verificationMethod)
        )
    }

    private func mapMutation<Wire: MutationWirePayload>(
        _ wire: Wire,
        expectedOperation: String,
        expectedMountainID: String?,
        expectedGlobalVersion: Int64?,
        expectedAggregateVersion: Int64?,
        expectedVisitID: VisitID?
    ) throws -> MappedMutation {
        guard wire.operation == expectedOperation,
              (expectedMountainID.map({ wire.mountainID == $0 }) ?? true),
              wire.globalVersion >= 0,
              wire.aggregateVersion >= 0,
              wire.visitCount >= 0,
              expectedGlobalVersion == nil || wire.globalVersion == expectedGlobalVersion,
              expectedAggregateVersion == nil || wire.aggregateVersion == expectedAggregateVersion else {
            throw SupabaseSelfPassportSyncTransportError.malformedResponse
        }

        let mountainID = try MountainID(rawValue: wire.mountainID)
        let visitID: VisitID?
        switch expectedOperation {
        case "manual_visit_create", "gps_visit_create":
            guard let rawVisitID = wire.visitID,
                  wire.deletedVisitID == nil else {
                throw SupabaseSelfPassportSyncTransportError.malformedResponse
            }
            visitID = try VisitID(rawValue: rawVisitID)
        case "manual_visit_delete":
            guard let rawVisitID = wire.deletedVisitID,
                  wire.visitID == nil else {
                throw SupabaseSelfPassportSyncTransportError.malformedResponse
            }
            visitID = try VisitID(rawValue: rawVisitID)
        case "plan_add", "plan_remove":
            guard wire.visitID == nil, wire.deletedVisitID == nil else {
                throw SupabaseSelfPassportSyncTransportError.malformedResponse
            }
            visitID = nil
        default:
            throw SupabaseSelfPassportSyncTransportError.malformedResponse
        }
        guard expectedVisitID == nil || expectedVisitID == visitID else {
            throw SupabaseSelfPassportSyncTransportError.malformedResponse
        }

        let plan = try mapMutationPlan(
            state: wire.planState,
            firstVisitID: wire.planFirstVisitID
        )
        let stamp = try wire.stamp.map {
            try Stamp(
                mountainID: mountainID,
                sourceVisitID: VisitID(rawValue: $0.sourceVisitID),
                earnedAt: $0.earnedAt.value,
                method: mapVerificationMethod($0.verificationMethod)
            )
        }
        guard (wire.visitCount > 0) == (stamp != nil) else {
            throw SupabaseSelfPassportSyncTransportError.malformedResponse
        }
        let aggregate = try SelfPassportAggregate(
            mountainID: mountainID,
            aggregateVersion: wire.aggregateVersion,
            visitCount: wire.visitCount,
            planDisposition: plan,
            stamp: stamp
        )
        return MappedMutation(
            aggregate: aggregate,
            visitID: visitID,
            globalVersion: wire.globalVersion
        )
    }

    private func mapMutationPlan(
        state: String?,
        firstVisitID: String?
    ) throws -> PlanDisposition? {
        switch state {
        case nil:
            guard firstVisitID == nil else {
                throw SupabaseSelfPassportSyncTransportError.malformedResponse
            }
            return nil
        case "active_manual":
            guard firstVisitID == nil else {
                throw SupabaseSelfPassportSyncTransportError.malformedResponse
            }
            return .active(.manual)
        case "active_auto_completed":
            guard let firstVisitID else {
                throw SupabaseSelfPassportSyncTransportError.malformedResponse
            }
            return .active(.autoCompleted(firstVisitID: try VisitID(rawValue: firstVisitID)))
        case "manually_removed":
            guard firstVisitID == nil else {
                throw SupabaseSelfPassportSyncTransportError.malformedResponse
            }
            return .manuallyRemoved
        default:
            throw SupabaseSelfPassportSyncTransportError.malformedResponse
        }
    }

    private func mapVerificationMethod(_ rawValue: String) throws -> VisitVerificationMethod {
        switch rawValue {
        case "manual":
            return .manual
        case "gps_verified":
            return .gpsVerified
        default:
            throw SupabaseSelfPassportSyncTransportError.malformedResponse
        }
    }

    private func failure(
        for statusCode: Int,
        rpcName: String
    ) -> SelfPassportTransportFailure {
        if rpcName == "m3_apply_passport_mutation"
            || rpcName == "m4_create_gps_visit" {
            switch statusCode {
            case 401:
                return .unauthenticated
            case 403:
                return .forbidden
            case 409:
                return .mutationConflict
            case 400, 422:
                return .mutationRejected
            case 404:
                return .upgradeRequired
            case 426:
                return .upgradeRequired
            default:
                return .transient
            }
        }

        switch statusCode {
        case 401:
            return .unauthenticated
        case 403:
            return .forbidden
        case 409, 410:
            return .fullRefreshRequired
        case 426:
            return .upgradeRequired
        case 400, 404, 422:
            return .refreshRequired
        default:
            return .transient
        }
    }

    private static func isRESTURL(_ url: URL) -> Bool {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            return false
        }
        return components.scheme?.lowercased() == "https"
            && components.host != nil
            && components.user == nil
            && components.password == nil
            && components.query == nil
            && components.fragment == nil
            && components.path == "/rest/v1"
    }

    private static func isPublishableKey(_ value: String) -> Bool {
        guard !value.isEmpty,
              value == value.trimmingCharacters(in: .whitespacesAndNewlines),
              !value.contains(where: \.isWhitespace) else {
            return false
        }
        if value.hasPrefix("sb_publishable_") {
            return true
        }
        let parts = value.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3,
              let payload = Data(base64URLEncoded: String(parts[1])),
              let object = try? JSONSerialization.jsonObject(with: payload) as? [String: Any],
              let role = object["role"] as? String else {
            return false
        }
        return role == "anon"
    }

    private static func isSHA256(_ value: String) -> Bool {
        value.count == 64 && value.allSatisfy { $0.isHexDigit && !$0.isUppercase }
    }

    private static func isBearer(_ value: String) -> Bool {
        !value.isEmpty
            && value == value.trimmingCharacters(in: .whitespacesAndNewlines)
            && !value.contains("\r")
            && !value.contains("\n")
    }

    private static func timestampString(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: date)
    }
}
extension SupabaseSelfPassportSyncTransport: FriendSocialTransport {
    public func friendCode() async throws -> FriendCode {
        let wire: FriendCodeWireResponse = try await friendRPC(
            named: "m5_get_friend_code",
            body: EmptyFriendWireRequest()
        )
        return try mapFriendCode(wire)
    }

    public func regenerateFriendCode() async throws -> FriendCode {
        let wire: FriendCodeWireResponse = try await friendRPC(
            named: "m5_regenerate_friend_code",
            body: EmptyFriendWireRequest()
        )
        return try mapFriendCode(wire)
    }

    public func lookupFriendCode(_ code: FriendCode) async throws -> FriendCodeLookupResult {
        let wire: FriendLookupWireResponse = try await friendRPC(
            named: "m5_lookup_friend_code",
            body: FriendCodeWireRequest(friendCode: code.rawValue)
        )
        switch wire.status {
        case "available":
            return .available
        case "unavailable":
            return .unavailable
        default:
            throw FriendSocialTransportFailure.malformedResponse
        }
    }

    public func sendFriendRequest(
        using code: FriendCode
    ) async throws -> FriendRequestSendResult {
        let wire: FriendRequestSendWireResponse = try await friendRPC(
            named: "m5_send_friend_request",
            body: FriendCodeWireRequest(friendCode: code.rawValue)
        )
        switch wire.status {
        case "pending":
            return .pending(try friendRequestReference(wire.requestRef))
        case "incomingRequest":
            return .incomingRequest(try friendRequestReference(wire.requestRef))
        case "friends":
            return .friends(try friendReference(wire.friendRef))
        case "unavailable":
            return .unavailable
        default:
            throw FriendSocialTransportFailure.malformedResponse
        }
    }

    public func incomingFriendRequests() async throws -> [FriendRequestReference] {
        let wire: IncomingFriendRequestsWireResponse = try await friendRPC(
            named: "m5_list_incoming_friend_requests",
            body: EmptyFriendWireRequest()
        )
        guard wire.status == "ok" else {
            throw FriendSocialTransportFailure.malformedResponse
        }
        return try wire.requests.map { try friendRequestReference($0.requestRef) }
    }

    public func respondToFriendRequest(
        _ request: FriendRequestReference,
        response: FriendRequestResponse
    ) async throws -> FriendRequestResponseResult {
        let wire: FriendRequestResponseWireResponse = try await friendRPC(
            named: "m5_respond_to_friend_request",
            body: FriendRequestResponseWireRequest(
                requestReference: request.rawValue,
                response: response.rawValue
            )
        )
        switch wire.status {
        case "accepted":
            return .accepted(try friendReference(wire.friendRef))
        case "declined":
            return .declined(try friendRequestReference(wire.requestRef))
        case "unavailable":
            return .unavailable
        default:
            throw FriendSocialTransportFailure.malformedResponse
        }
    }

    public func cancelFriendRequest(
        _ request: FriendRequestReference
    ) async throws -> FriendRequestCancellationResult {
        let wire: FriendRequestCancellationWireResponse = try await friendRPC(
            named: "m5_cancel_friend_request",
            body: FriendRequestReferenceWireRequest(requestReference: request.rawValue)
        )
        switch wire.status {
        case "cancelled":
            return .cancelled(try friendRequestReference(wire.requestRef))
        case "unavailable":
            return .unavailable
        default:
            throw FriendSocialTransportFailure.malformedResponse
        }
    }

    public func friends() async throws -> [FriendReference] {
        let wire: FriendsWireResponse = try await friendRPC(
            named: "m5_list_friends",
            body: EmptyFriendWireRequest()
        )
        guard wire.status == "ok" else {
            throw FriendSocialTransportFailure.malformedResponse
        }
        return try wire.friends.map { try friendReference($0.friendRef) }
    }

    public func unfriend(_ friend: FriendReference) async throws -> FriendUnfriendResult {
        let wire: FriendUnfriendWireResponse = try await friendRPC(
            named: "m5_unfriend",
            body: FriendReferenceWireRequest(friendReference: friend.rawValue)
        )
        switch wire.status {
        case "unfriended":
            let returnedFriend = try friendReference(wire.friendRef)
            guard returnedFriend == friend else {
                throw FriendSocialTransportFailure.malformedResponse
            }
            return .unfriended(returnedFriend)
        case "unavailable":
            return .unavailable
        default:
            throw FriendSocialTransportFailure.malformedResponse
        }
    }

    public func block(_ reference: FriendBlockReference) async throws -> FriendBlockResult {
        let wire: FriendBlockWireResponse = try await friendRPC(
            named: "m5_block_friend",
            body: FriendBlockWireRequest(reference: reference.rawValue)
        )
        switch wire.status {
        case "blocked":
            return .blocked(try wire.friendRef.map { try friendReference($0) })
        case "unavailable":
            return .unavailable
        default:
            throw FriendSocialTransportFailure.malformedResponse
        }
    }

    public func friendPassport(
        for friend: FriendReference
    ) async throws -> FriendPassportAuthorizationEnvelope {
        let wire: FriendPassportWireResponse = try await friendRPC(
            named: "m5_read_friend_passport",
            body: FriendReferenceWireRequest(friendReference: friend.rawValue)
        )
        guard wire.status == "ok" else {
            if wire.status == "unavailable" {
                throw FriendSocialTransportFailure.unavailable
            }
            throw FriendSocialTransportFailure.malformedResponse
        }
        guard let mountains = wire.mountains,
              let authorizationGeneration = wire.authorizationGeneration,
              let leaseExpiresAt = wire.leaseExpiresAt else {
            throw FriendSocialTransportFailure.malformedResponse
        }
        let returnedFriend = try friendReference(wire.friendRef)
        guard returnedFriend == friend else {
            throw FriendSocialTransportFailure.malformedResponse
        }
        let aggregates = try mountains.map(mapFriendAggregate)
        return try FriendPassportAuthorizationEnvelope(
            passport: FriendPassportDTO(
                friendReference: returnedFriend,
                mountains: aggregates
            ),
            authorizationGeneration: authorizationGeneration,
            leaseExpiresAt: leaseExpiresAt.value
        )
    }

    public func socialEvents(
        after cursor: FriendSocialEventCursor
    ) async throws -> FriendSocialEventPage {
        let wire: FriendSocialEventsWireResponse = try await friendRPC(
            named: "m5_read_revocations",
            body: FriendSocialEventsWireRequest(
                generation: cursor.generation,
                afterSequence: cursor.sequence
            )
        )
        let requiresResynchronization: Bool
        switch wire.status {
        case "ok":
            requiresResynchronization = false
        case "gap":
            requiresResynchronization = true
        default:
            throw FriendSocialTransportFailure.malformedResponse
        }
        return try FriendSocialEventPage(
            generation: wire.generation,
            sequence: wire.sequence,
            requiresResynchronization: requiresResynchronization,
            events: wire.events.map {
                try FriendSocialEvent(
                    friendReference: friendReference($0.friendRef),
                    generation: $0.generation,
                    sequence: $0.sequence
                )
            }
        )
    }

    private func friendRPC<Body: Encodable, Response: Decodable>(
        named name: String,
        body: Body
    ) async throws -> Response {
        do {
            return try await rpc(named: name, body: body)
        } catch let failure as SelfPassportTransportFailure {
            throw switch failure {
            case .unauthenticated:
                FriendSocialTransportFailure.unauthenticated
            case .forbidden:
                FriendSocialTransportFailure.forbidden
            case .refreshRequired, .fullRefreshRequired, .mutationConflict,
                 .mutationRejected, .upgradeRequired:
                FriendSocialTransportFailure.rejected
            case .transient:
                FriendSocialTransportFailure.unavailable
            }
        } catch is SupabaseSelfPassportSyncTransportError {
            throw FriendSocialTransportFailure.malformedResponse
        } catch {
            throw error
        }
    }

    private func mapFriendCode(_ wire: FriendCodeWireResponse) throws -> FriendCode {
        guard wire.status == "ok", wire.codeGeneration > 0 else {
            throw FriendSocialTransportFailure.malformedResponse
        }
        return try FriendCode(rawValue: wire.friendCode)
    }

    private func friendReference(_ rawValue: String?) throws -> FriendReference {
        guard let rawValue, let value = UUID(uuidString: rawValue) else {
            throw FriendSocialTransportFailure.malformedResponse
        }
        return FriendReference(rawValue: value)
    }

    private func friendRequestReference(_ rawValue: String?) throws -> FriendRequestReference {
        guard let rawValue, let value = UUID(uuidString: rawValue) else {
            throw FriendSocialTransportFailure.malformedResponse
        }
        return FriendRequestReference(rawValue: value)
    }

    private func mapFriendAggregate(
        _ wire: FriendPassportMountainWire
    ) throws -> FriendPassportMountainAggregate {
        let isPlanned: Bool
        switch wire.planState {
        case nil, "manually_removed", "active_auto_completed":
            isPlanned = false
        case "active_manual":
            isPlanned = true
        default:
            throw FriendSocialTransportFailure.malformedResponse
        }

        let stampVerificationMethod: FriendPassportStampVerificationMethod?
        switch wire.stampVerificationMethod {
        case nil:
            stampVerificationMethod = nil
        case "manual":
            stampVerificationMethod = .manual
        case "gps_verified":
            stampVerificationMethod = .gpsVerified
        default:
            throw FriendSocialTransportFailure.malformedResponse
        }

        do {
            return try FriendPassportMountainAggregate(
                mountainID: MountainID(rawValue: wire.mountainID),
                visitCount: wire.visitCount,
                isPlanned: isPlanned,
                hasStamp: wire.hasStamp,
                stampVerificationMethod: stampVerificationMethod
            )
        } catch {
            throw FriendSocialTransportFailure.malformedResponse
        }
    }
}

private struct EmptyFriendWireRequest: Encodable {}

private struct FriendCodeWireRequest: Encodable {
    let friendCode: String

    enum CodingKeys: String, CodingKey {
        case friendCode = "p_friend_code"
    }
}

private struct FriendRequestResponseWireRequest: Encodable {
    let requestReference: UUID
    let response: String

    enum CodingKeys: String, CodingKey {
        case requestReference = "p_request_ref"
        case response = "p_response"
    }
}

private struct FriendRequestReferenceWireRequest: Encodable {
    let requestReference: UUID

    enum CodingKeys: String, CodingKey {
        case requestReference = "p_request_ref"
    }
}

private struct FriendReferenceWireRequest: Encodable {
    let friendReference: UUID

    enum CodingKeys: String, CodingKey {
        case friendReference = "p_friend_ref"
    }
}

private struct FriendBlockWireRequest: Encodable {
    let reference: UUID

    enum CodingKeys: String, CodingKey {
        case reference = "p_reference"
    }
}

private struct FriendSocialEventsWireRequest: Encodable {
    let generation: Int64
    let afterSequence: Int64

    enum CodingKeys: String, CodingKey {
        case generation = "p_generation"
        case afterSequence = "p_after_sequence"
    }
}

private struct FriendCodeWireResponse: Decodable {
    let status: String
    let friendCode: String
    let codeGeneration: Int64

    enum CodingKeys: String, CodingKey {
        case status
        case friendCode
        case codeGeneration
    }

    init(from decoder: any Decoder) throws {
        try requireExactKeys(decoder, ["status", "friendCode", "codeGeneration"])
        let container = try decoder.container(keyedBy: CodingKeys.self)
        status = try container.decode(String.self, forKey: .status)
        friendCode = try container.decode(String.self, forKey: .friendCode)
        codeGeneration = try container.decode(Int64.self, forKey: .codeGeneration)
    }
}

private struct FriendLookupWireResponse: Decodable {
    let status: String

    private enum CodingKeys: String, CodingKey {
        case status
    }

    init(from decoder: any Decoder) throws {
        try requireExactKeys(decoder, ["status"])
        status = try decoder.container(keyedBy: CodingKeys.self).decode(String.self, forKey: .status)
    }
}

private struct FriendRequestSendWireResponse: Decodable {
    let status: String
    let requestRef: String?
    let friendRef: String?

    private enum CodingKeys: String, CodingKey {
        case status
        case requestRef
        case friendRef
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        status = try container.decode(String.self, forKey: .status)
        switch status {
        case "pending", "incomingRequest":
            try requireExactKeys(decoder, ["status", "requestRef"])
            requestRef = try container.decode(String.self, forKey: .requestRef)
            friendRef = nil
        case "friends":
            try requireExactKeys(decoder, ["status", "friendRef"])
            requestRef = nil
            friendRef = try container.decode(String.self, forKey: .friendRef)
        case "unavailable":
            try requireExactKeys(decoder, ["status"])
            requestRef = nil
            friendRef = nil
        default:
            throw FriendSocialTransportFailure.malformedResponse
        }
    }
}

private struct FriendRequestReferenceWire: Decodable {
    let requestRef: String

    private enum CodingKeys: String, CodingKey {
        case requestRef
    }

    init(from decoder: any Decoder) throws {
        try requireExactKeys(decoder, ["requestRef"])
        requestRef = try decoder.container(keyedBy: CodingKeys.self).decode(String.self, forKey: .requestRef)
    }
}

private struct IncomingFriendRequestsWireResponse: Decodable {
    let status: String
    let requests: [FriendRequestReferenceWire]

    private enum CodingKeys: String, CodingKey {
        case status
        case requests
    }

    init(from decoder: any Decoder) throws {
        try requireExactKeys(decoder, ["status", "requests"])
        let container = try decoder.container(keyedBy: CodingKeys.self)
        status = try container.decode(String.self, forKey: .status)
        requests = try container.decode([FriendRequestReferenceWire].self, forKey: .requests)
    }
}

private struct FriendRequestResponseWireResponse: Decodable {
    let status: String
    let requestRef: String?
    let friendRef: String?

    private enum CodingKeys: String, CodingKey {
        case status
        case requestRef
        case friendRef
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        status = try container.decode(String.self, forKey: .status)
        switch status {
        case "accepted":
            try requireExactKeys(decoder, ["status", "friendRef"])
            requestRef = nil
            friendRef = try container.decode(String.self, forKey: .friendRef)
        case "declined":
            try requireExactKeys(decoder, ["status", "requestRef"])
            requestRef = try container.decode(String.self, forKey: .requestRef)
            friendRef = nil
        case "unavailable":
            try requireExactKeys(decoder, ["status"])
            requestRef = nil
            friendRef = nil
        default:
            throw FriendSocialTransportFailure.malformedResponse
        }
    }
}

private struct FriendRequestCancellationWireResponse: Decodable {
    let status: String
    let requestRef: String?

    private enum CodingKeys: String, CodingKey {
        case status
        case requestRef
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        status = try container.decode(String.self, forKey: .status)
        switch status {
        case "cancelled":
            try requireExactKeys(decoder, ["status", "requestRef"])
            requestRef = try container.decode(String.self, forKey: .requestRef)
        case "unavailable":
            try requireExactKeys(decoder, ["status"])
            requestRef = nil
        default:
            throw FriendSocialTransportFailure.malformedResponse
        }
    }
}

private struct FriendReferenceWire: Decodable {
    let friendRef: String

    private enum CodingKeys: String, CodingKey {
        case friendRef
    }

    init(from decoder: any Decoder) throws {
        try requireExactKeys(decoder, ["friendRef"])
        friendRef = try decoder.container(keyedBy: CodingKeys.self).decode(String.self, forKey: .friendRef)
    }
}

private struct FriendsWireResponse: Decodable {
    let status: String
    let friends: [FriendReferenceWire]

    private enum CodingKeys: String, CodingKey {
        case status
        case friends
    }

    init(from decoder: any Decoder) throws {
        try requireExactKeys(decoder, ["status", "friends"])
        let container = try decoder.container(keyedBy: CodingKeys.self)
        status = try container.decode(String.self, forKey: .status)
        friends = try container.decode([FriendReferenceWire].self, forKey: .friends)
    }
}

private struct FriendUnfriendWireResponse: Decodable {
    let status: String
    let friendRef: String?

    private enum CodingKeys: String, CodingKey {
        case status
        case friendRef
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        status = try container.decode(String.self, forKey: .status)
        switch status {
        case "unfriended":
            try requireExactKeys(decoder, ["status", "friendRef"])
            friendRef = try container.decode(String.self, forKey: .friendRef)
        case "unavailable":
            try requireExactKeys(decoder, ["status"])
            friendRef = nil
        default:
            throw FriendSocialTransportFailure.malformedResponse
        }
    }
}

private struct FriendBlockWireResponse: Decodable {
    let status: String
    let friendRef: String?

    private enum CodingKeys: String, CodingKey {
        case status
        case friendRef
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        status = try container.decode(String.self, forKey: .status)
        switch status {
        case "blocked":
            let rawContainer = try decoder.container(keyedBy: AnyCodingKey.self)
            let keys = Set(rawContainer.allKeys.map(\.stringValue))
            guard keys == Set(["status"]) || keys == Set(["status", "friendRef"]) else {
                throw FriendSocialTransportFailure.malformedResponse
            }
            friendRef = try container.decodeIfPresent(String.self, forKey: .friendRef)
        case "unavailable":
            try requireExactKeys(decoder, ["status"])
            friendRef = nil
        default:
            throw FriendSocialTransportFailure.malformedResponse
        }
    }
}

private struct FriendPassportWireResponse: Decodable {
    let status: String
    let friendRef: String?
    let authorizationGeneration: Int64?
    let leaseExpiresAt: StrictTimestamp?
    let mountains: [FriendPassportMountainWire]?

    private enum CodingKeys: String, CodingKey {
        case status
        case friendRef
        case authorizationGeneration
        case leaseExpiresAt
        case mountains
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        status = try container.decode(String.self, forKey: .status)
        switch status {
        case "ok":
            try requireExactKeys(
                decoder,
                ["status", "friendRef", "authorizationGeneration", "leaseExpiresAt", "mountains"]
            )
            friendRef = try container.decode(String.self, forKey: .friendRef)
            authorizationGeneration = try container.decode(Int64.self, forKey: .authorizationGeneration)
            leaseExpiresAt = try container.decode(StrictTimestamp.self, forKey: .leaseExpiresAt)
            mountains = try container.decode([FriendPassportMountainWire].self, forKey: .mountains)
        case "unavailable":
            try requireExactKeys(decoder, ["status"])
            friendRef = nil
            authorizationGeneration = nil
            leaseExpiresAt = nil
            mountains = nil
        default:
            throw FriendSocialTransportFailure.malformedResponse
        }
    }
}

private struct FriendPassportMountainWire: Decodable {
    let mountainID: String
    let visitCount: Int
    let planState: String?
    let hasStamp: Bool
    let stampVerificationMethod: String?

    private enum CodingKeys: String, CodingKey {
        case mountainID = "mountainId"
        case visitCount
        case planState
        case hasStamp
        case stampVerificationMethod
    }

    init(from decoder: any Decoder) throws {
        try requireExactKeys(
            decoder,
            ["mountainId", "visitCount", "planState", "hasStamp", "stampVerificationMethod"]
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        mountainID = try container.decode(String.self, forKey: .mountainID)
        visitCount = try container.decode(Int.self, forKey: .visitCount)
        planState = try container.decodeIfPresent(String.self, forKey: .planState)
        hasStamp = try container.decode(Bool.self, forKey: .hasStamp)
        stampVerificationMethod = try container.decodeIfPresent(
            String.self,
            forKey: .stampVerificationMethod
        )
    }
}

private struct FriendSocialEventWire: Decodable {
    let friendRef: String
    let generation: Int64
    let sequence: Int64

    private enum CodingKeys: String, CodingKey {
        case friendRef
        case generation
        case sequence
    }

    init(from decoder: any Decoder) throws {
        try requireExactKeys(decoder, ["friendRef", "generation", "sequence"])
        let container = try decoder.container(keyedBy: CodingKeys.self)
        friendRef = try container.decode(String.self, forKey: .friendRef)
        generation = try container.decode(Int64.self, forKey: .generation)
        sequence = try container.decode(Int64.self, forKey: .sequence)
    }
}

private struct FriendSocialEventsWireResponse: Decodable {
    let status: String
    let generation: Int64
    let sequence: Int64
    let events: [FriendSocialEventWire]

    private enum CodingKeys: String, CodingKey {
        case status
        case generation
        case sequence
        case events
    }

    init(from decoder: any Decoder) throws {
        try requireExactKeys(decoder, ["status", "generation", "sequence", "events"])
        let container = try decoder.container(keyedBy: CodingKeys.self)
        status = try container.decode(String.self, forKey: .status)
        generation = try container.decode(Int64.self, forKey: .generation)
        sequence = try container.decode(Int64.self, forKey: .sequence)
        events = try container.decode([FriendSocialEventWire].self, forKey: .events)
    }
}

private struct HistoryContext: Sendable {
    let token: OpaqueHistoryToken
    let snapshotVersion: Int64
    let aggregates: [MountainID: SelfPassportAggregate]
}

private struct ChangeContext: Sendable {
    let historyToken: OpaqueHistoryToken
    let baselineVersion: Int64
    let expectedFromVersion: Int64
    let aggregates: [MountainID: SelfPassportAggregate]
}

private struct MappedMutation: Sendable {
    let aggregate: SelfPassportAggregate
    let visitID: VisitID?
    let globalVersion: Int64
}

private struct BootstrapWireRequest: Encodable {
    let apiVersion: String
    let datasetSHA256: String

    enum CodingKeys: String, CodingKey {
        case apiVersion = "p_api_version"
        case datasetSHA256 = "p_dataset_sha256"
    }
}

private struct HistoryWireRequest: Encodable {
    let historyToken: String
    let cursor: String?
    let mountainID: String
    let pageSize: Int

    enum CodingKeys: String, CodingKey {
        case historyToken = "p_history_token"
        case cursor = "p_cursor"
        case mountainID = "p_mountain_id"
        case pageSize = "p_page_size"
    }

    func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(historyToken, forKey: .historyToken)
        if let cursor {
            try container.encode(cursor, forKey: .cursor)
        } else {
            try container.encodeNil(forKey: .cursor)
        }
        try container.encode(mountainID, forKey: .mountainID)
        try container.encode(pageSize, forKey: .pageSize)
    }
}

private struct ChangeWireRequest: Encodable {
    let historyToken: String
    let cursor: String?
    let limit: Int

    enum CodingKeys: String, CodingKey {
        case historyToken = "p_history_token"
        case cursor = "p_cursor"
        case limit = "p_limit"
    }

    func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(historyToken, forKey: .historyToken)
        if let cursor {
            try container.encode(cursor, forKey: .cursor)
        } else {
            try container.encodeNil(forKey: .cursor)
        }
        try container.encode(limit, forKey: .limit)
    }
}

private struct ApplyMutationWireRequest: Encodable {
    let apiVersion: String
    let datasetSHA256: String
    let mutationID: String
    let operation: String
    let payload: [String: String]

    enum CodingKeys: String, CodingKey {
        case apiVersion = "p_api_version"
        case datasetSHA256 = "p_dataset_sha256"
        case mutationID = "p_mutation_id"
        case operation = "p_operation"
        case payload = "p_payload"
    }
}
private struct GPSVisitVerificationWireRequest: Encodable {
    let apiVersion: String
    let datasetSHA256: String
    let historyToken: String
    let mountainID: String
    let visitID: String
    let visitedAt: String
    let mutationID: String
    let latitude: Double
    let longitude: Double
    let horizontalAccuracyMeters: Double
    let sampledAt: String

    enum CodingKeys: String, CodingKey {
        case apiVersion = "p_api_version"
        case datasetSHA256 = "p_dataset_sha256"
        case historyToken = "p_history_token"
        case mountainID = "p_mountain_id"
        case visitID = "p_visit_id"
        case visitedAt = "p_visited_at"
        case mutationID = "p_mutation_id"
        case latitude = "p_latitude"
        case longitude = "p_longitude"
        case horizontalAccuracyMeters = "p_horizontal_accuracy_m"
        case sampledAt = "p_sampled_at"
    }
}

private struct BootstrapWireResponse: Decodable {
    let snapshotVersion: Int64
    let datasetSHA256: String
    let mountains: [String]
    let aggregates: [BootstrapAggregateWire]
    let plans: [BootstrapPlanWire]
    let stamps: [BootstrapStampWire]
    let historyToken: String

    enum CodingKeys: String, CodingKey {
        case snapshotVersion
        case datasetSHA256
        case mountains
        case aggregates
        case plans
        case stamps
        case historyToken
    }

    init(from decoder: any Decoder) throws {
        try requireExactKeys(
            decoder,
            ["snapshotVersion", "datasetSHA256", "mountains", "aggregates", "plans", "stamps", "historyToken"]
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        snapshotVersion = try container.decode(Int64.self, forKey: .snapshotVersion)
        datasetSHA256 = try container.decode(String.self, forKey: .datasetSHA256)
        mountains = try container.decode([String].self, forKey: .mountains)
        aggregates = try container.decode([BootstrapAggregateWire].self, forKey: .aggregates)
        plans = try container.decode([BootstrapPlanWire].self, forKey: .plans)
        stamps = try container.decode([BootstrapStampWire].self, forKey: .stamps)
        historyToken = try container.decode(String.self, forKey: .historyToken)
    }
}

private struct BootstrapAggregateWire: Decodable {
    let mountainID: String
    let visitCount: Int
    let planState: String?
    let aggregateVersion: Int64
    let globalVersion: Int64

    enum CodingKeys: String, CodingKey {
        case mountainID
        case visitCount
        case planState
        case aggregateVersion
        case globalVersion
    }

    init(from decoder: any Decoder) throws {
        try requireExactKeys(
            decoder,
            ["mountainID", "visitCount", "planState", "aggregateVersion", "globalVersion"]
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        mountainID = try container.decode(String.self, forKey: .mountainID)
        visitCount = try container.decode(Int.self, forKey: .visitCount)
        planState = try container.decodeIfPresent(String.self, forKey: .planState)
        aggregateVersion = try container.decode(Int64.self, forKey: .aggregateVersion)
        globalVersion = try container.decode(Int64.self, forKey: .globalVersion)
    }
}

private struct BootstrapPlanWire: Decodable {
    let mountainID: String
    let planState: String
    let firstVisitID: String?
    let aggregateVersion: Int64
    let globalVersion: Int64
    let createdAt: StrictTimestamp
    let updatedAt: StrictTimestamp

    enum CodingKeys: String, CodingKey {
        case mountainID
        case planState
        case firstVisitID
        case aggregateVersion
        case globalVersion
        case createdAt
        case updatedAt
    }

    init(from decoder: any Decoder) throws {
        try requireExactKeys(
            decoder,
            ["mountainID", "planState", "firstVisitID", "aggregateVersion", "globalVersion", "createdAt", "updatedAt"]
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        mountainID = try container.decode(String.self, forKey: .mountainID)
        planState = try container.decode(String.self, forKey: .planState)
        firstVisitID = try container.decodeIfPresent(String.self, forKey: .firstVisitID)
        aggregateVersion = try container.decode(Int64.self, forKey: .aggregateVersion)
        globalVersion = try container.decode(Int64.self, forKey: .globalVersion)
        createdAt = try container.decode(StrictTimestamp.self, forKey: .createdAt)
        updatedAt = try container.decode(StrictTimestamp.self, forKey: .updatedAt)
    }
}

private struct BootstrapStampWire: Decodable {
    let mountainID: String
    let sourceVisitID: String
    let earnedAt: StrictTimestamp
    let verificationMethod: String
    let aggregateVersion: Int64
    let globalVersion: Int64
    let updatedAt: StrictTimestamp

    enum CodingKeys: String, CodingKey {
        case mountainID
        case sourceVisitID
        case earnedAt
        case verificationMethod
        case aggregateVersion
        case globalVersion
        case updatedAt
    }

    init(from decoder: any Decoder) throws {
        try requireExactKeys(
            decoder,
            ["mountainID", "sourceVisitID", "earnedAt", "verificationMethod", "aggregateVersion", "globalVersion", "updatedAt"]
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        mountainID = try container.decode(String.self, forKey: .mountainID)
        sourceVisitID = try container.decode(String.self, forKey: .sourceVisitID)
        earnedAt = try container.decode(StrictTimestamp.self, forKey: .earnedAt)
        verificationMethod = try container.decode(String.self, forKey: .verificationMethod)
        aggregateVersion = try container.decode(Int64.self, forKey: .aggregateVersion)
        globalVersion = try container.decode(Int64.self, forKey: .globalVersion)
        updatedAt = try container.decode(StrictTimestamp.self, forKey: .updatedAt)
    }
}

private struct HistoryWireResponse: Decodable {
    let snapshotVersion: Int64
    let items: [HistoryVisitWire]
    let nextCursor: String?
    let complete: Bool

    enum CodingKeys: String, CodingKey {
        case snapshotVersion
        case items
        case nextCursor
        case complete
    }

    init(from decoder: any Decoder) throws {
        try requireExactKeys(decoder, ["snapshotVersion", "items", "nextCursor", "complete"])
        let container = try decoder.container(keyedBy: CodingKeys.self)
        snapshotVersion = try container.decode(Int64.self, forKey: .snapshotVersion)
        items = try container.decode([HistoryVisitWire].self, forKey: .items)
        nextCursor = try container.decodeIfPresent(String.self, forKey: .nextCursor)
        complete = try container.decode(Bool.self, forKey: .complete)
    }
}

private struct HistoryVisitWire: Decodable {
    let visitID: String
    let mountainID: String
    let visitedAt: StrictTimestamp
    let recordedAt: StrictTimestamp
    let verificationMethod: String
    let createdAggregateVersion: Int64
    let createdGlobalVersion: Int64

    enum CodingKeys: String, CodingKey {
        case visitID
        case mountainID
        case visitedAt
        case recordedAt
        case verificationMethod
        case createdAggregateVersion
        case createdGlobalVersion
    }

    init(from decoder: any Decoder) throws {
        try requireExactKeys(
            decoder,
            ["visitID", "mountainID", "visitedAt", "recordedAt", "verificationMethod", "createdAggregateVersion", "createdGlobalVersion"]
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        visitID = try container.decode(String.self, forKey: .visitID)
        mountainID = try container.decode(String.self, forKey: .mountainID)
        visitedAt = try container.decode(StrictTimestamp.self, forKey: .visitedAt)
        recordedAt = try container.decode(StrictTimestamp.self, forKey: .recordedAt)
        verificationMethod = try container.decode(String.self, forKey: .verificationMethod)
        createdAggregateVersion = try container.decode(Int64.self, forKey: .createdAggregateVersion)
        createdGlobalVersion = try container.decode(Int64.self, forKey: .createdGlobalVersion)
    }
}

private struct ChangeWireResponse: Decodable {
    let fromVersion: Int64
    let throughVersion: Int64
    let changes: [ChangeWire]
    let nextVersion: Int64
    let nextCursor: String?
    let complete: Bool
    let resyncRequired: Bool

    enum CodingKeys: String, CodingKey {
        case fromVersion
        case throughVersion
        case changes
        case nextVersion
        case nextCursor
        case complete
        case resyncRequired
    }

    init(from decoder: any Decoder) throws {
        try requireExactKeys(
            decoder,
            ["fromVersion", "throughVersion", "changes", "nextVersion", "nextCursor", "complete", "resyncRequired"]
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        fromVersion = try container.decode(Int64.self, forKey: .fromVersion)
        throughVersion = try container.decode(Int64.self, forKey: .throughVersion)
        changes = try container.decode([ChangeWire].self, forKey: .changes)
        nextVersion = try container.decode(Int64.self, forKey: .nextVersion)
        nextCursor = try container.decodeIfPresent(String.self, forKey: .nextCursor)
        complete = try container.decode(Bool.self, forKey: .complete)
        resyncRequired = try container.decode(Bool.self, forKey: .resyncRequired)
    }
}

private struct ChangeWire: Decodable {
    let globalVersion: Int64
    let mountainID: String
    let operation: String
    let aggregateVersion: Int64
    let result: ChangeMutationWireResponse

    enum CodingKeys: String, CodingKey {
        case globalVersion
        case mountainID
        case operation
        case aggregateVersion
        case result
    }

    init(from decoder: any Decoder) throws {
        try requireExactKeys(
            decoder,
            ["globalVersion", "mountainID", "operation", "aggregateVersion", "result"]
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        globalVersion = try container.decode(Int64.self, forKey: .globalVersion)
        mountainID = try container.decode(String.self, forKey: .mountainID)
        operation = try container.decode(String.self, forKey: .operation)
        aggregateVersion = try container.decode(Int64.self, forKey: .aggregateVersion)
        result = try container.decode(ChangeMutationWireResponse.self, forKey: .result)
    }
}

private protocol MutationWirePayload {
    var operation: String { get }
    var mountainID: String { get }
    var visitID: String? { get }
    var deletedVisitID: String? { get }
    var visitCount: Int { get }
    var planState: String? { get }
    var planFirstVisitID: String? { get }
    var stamp: MutationStampWire? { get }
    var aggregateVersion: Int64 { get }
    var globalVersion: Int64 { get }
}

private struct MutationWireResponse: Decodable, MutationWirePayload {
    let operation: String
    let mountainID: String
    let visitID: String?
    let deletedVisitID: String?
    let visitCount: Int
    let planState: String?
    let planFirstVisitID: String?
    let stamp: MutationStampWire?
    let aggregateVersion: Int64
    let globalVersion: Int64
    let historyToken: OpaqueHistoryToken

    enum CodingKeys: String, CodingKey {
        case operation
        case mountainID = "mountain_id"
        case visitID = "visit_id"
        case deletedVisitID = "deleted_visit_id"
        case visitCount = "visit_count"
        case planState = "plan_state"
        case planFirstVisitID = "plan_first_visit_id"
        case stamp
        case aggregateVersion = "aggregate_version"
        case globalVersion = "global_version"
        case historyToken = "history_token"
    }

    init(from decoder: any Decoder) throws {
        try requireExactKeys(
            decoder,
            [
                "operation", "mountain_id", "visit_id", "deleted_visit_id", "visit_count",
                "plan_state", "plan_first_visit_id", "stamp", "aggregate_version",
                "global_version", "history_token",
            ]
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        operation = try container.decode(String.self, forKey: .operation)
        mountainID = try container.decode(String.self, forKey: .mountainID)
        visitID = try container.decodeIfPresent(String.self, forKey: .visitID)
        deletedVisitID = try container.decodeIfPresent(String.self, forKey: .deletedVisitID)
        visitCount = try container.decode(Int.self, forKey: .visitCount)
        planState = try container.decodeIfPresent(String.self, forKey: .planState)
        planFirstVisitID = try container.decodeIfPresent(String.self, forKey: .planFirstVisitID)
        stamp = try container.decodeIfPresent(MutationStampWire.self, forKey: .stamp)
        aggregateVersion = try container.decode(Int64.self, forKey: .aggregateVersion)
        globalVersion = try container.decode(Int64.self, forKey: .globalVersion)
        historyToken = try OpaqueHistoryToken(
            rawValue: container.decode(String.self, forKey: .historyToken)
        )
    }
}
private enum GPSVisitVerificationWireResponse: Decodable {
    case manualFallback(GPSVisitManualFallbackReason)
    case gpsVerified(GPSVerifiedMutationWireResponse)

    private enum CodingKeys: String, CodingKey {
        case status
        case manualFallback = "manual_fallback"
        case reason
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(String.self, forKey: .status) {
        case "manual_fallback":
            try requireExactKeys(decoder, ["status", "manual_fallback", "reason"])
            guard try container.decode(Bool.self, forKey: .manualFallback) else {
                throw SupabaseSelfPassportSyncTransportError.malformedResponse
            }
            self = .manualFallback(
                try container.decode(GPSVisitManualFallbackReason.self, forKey: .reason)
            )
        case "gps_verified":
            self = .gpsVerified(try GPSVerifiedMutationWireResponse(from: decoder))
        default:
            throw SupabaseSelfPassportSyncTransportError.malformedResponse
        }
    }
}

private struct GPSVerifiedMutationWireResponse: Decodable, MutationWirePayload {
    let operation: String
    let mountainID: String
    let visitID: String?
    let deletedVisitID: String?
    let visitCount: Int
    let planState: String?
    let planFirstVisitID: String?
    let stamp: MutationStampWire?
    let aggregateVersion: Int64
    let globalVersion: Int64
    let status: String
    let manualFallback: Bool
    let verificationMethod: String

    enum CodingKeys: String, CodingKey {
        case operation
        case mountainID = "mountain_id"
        case visitID = "visit_id"
        case deletedVisitID = "deleted_visit_id"
        case visitCount = "visit_count"
        case planState = "plan_state"
        case planFirstVisitID = "plan_first_visit_id"
        case stamp
        case aggregateVersion = "aggregate_version"
        case globalVersion = "global_version"
        case status
        case manualFallback = "manual_fallback"
        case verificationMethod = "verification_method"
    }

    init(from decoder: any Decoder) throws {
        try requireExactKeys(
            decoder,
            [
                "operation", "mountain_id", "visit_id", "deleted_visit_id", "visit_count",
                "plan_state", "plan_first_visit_id", "stamp", "aggregate_version",
                "global_version", "status", "manual_fallback", "verification_method",
            ]
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        operation = try container.decode(String.self, forKey: .operation)
        mountainID = try container.decode(String.self, forKey: .mountainID)
        visitID = try container.decodeIfPresent(String.self, forKey: .visitID)
        deletedVisitID = try container.decodeIfPresent(String.self, forKey: .deletedVisitID)
        visitCount = try container.decode(Int.self, forKey: .visitCount)
        planState = try container.decodeIfPresent(String.self, forKey: .planState)
        planFirstVisitID = try container.decodeIfPresent(String.self, forKey: .planFirstVisitID)
        stamp = try container.decodeIfPresent(MutationStampWire.self, forKey: .stamp)
        aggregateVersion = try container.decode(Int64.self, forKey: .aggregateVersion)
        globalVersion = try container.decode(Int64.self, forKey: .globalVersion)
        status = try container.decode(String.self, forKey: .status)
        manualFallback = try container.decode(Bool.self, forKey: .manualFallback)
        verificationMethod = try container.decode(String.self, forKey: .verificationMethod)
    }
}

private struct ChangeMutationWireResponse: Decodable, MutationWirePayload {
    let operation: String
    let mountainID: String
    let visitID: String?
    let deletedVisitID: String?
    let visitCount: Int
    let planState: String?
    let planFirstVisitID: String?
    let stamp: MutationStampWire?
    let aggregateVersion: Int64
    let globalVersion: Int64

    enum CodingKeys: String, CodingKey {
        case operation
        case mountainID = "mountain_id"
        case visitID = "visit_id"
        case deletedVisitID = "deleted_visit_id"
        case visitCount = "visit_count"
        case planState = "plan_state"
        case planFirstVisitID = "plan_first_visit_id"
        case stamp
        case aggregateVersion = "aggregate_version"
        case globalVersion = "global_version"
    }

    init(from decoder: any Decoder) throws {
        try requireExactKeys(
            decoder,
            [
                "operation", "mountain_id", "visit_id", "deleted_visit_id", "visit_count",
                "plan_state", "plan_first_visit_id", "stamp", "aggregate_version",
                "global_version",
            ]
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        operation = try container.decode(String.self, forKey: .operation)
        mountainID = try container.decode(String.self, forKey: .mountainID)
        visitID = try container.decodeIfPresent(String.self, forKey: .visitID)
        deletedVisitID = try container.decodeIfPresent(String.self, forKey: .deletedVisitID)
        visitCount = try container.decode(Int.self, forKey: .visitCount)
        planState = try container.decodeIfPresent(String.self, forKey: .planState)
        planFirstVisitID = try container.decodeIfPresent(String.self, forKey: .planFirstVisitID)
        stamp = try container.decodeIfPresent(MutationStampWire.self, forKey: .stamp)
        aggregateVersion = try container.decode(Int64.self, forKey: .aggregateVersion)
        globalVersion = try container.decode(Int64.self, forKey: .globalVersion)
    }
}

private struct MutationStampWire: Decodable {
    let sourceVisitID: String
    let earnedAt: StrictTimestamp
    let verificationMethod: String

    enum CodingKeys: String, CodingKey {
        case sourceVisitID = "source_visit_id"
        case earnedAt = "earned_at"
        case verificationMethod = "verification_method"
    }

    init(from decoder: any Decoder) throws {
        try requireExactKeys(decoder, ["source_visit_id", "earned_at", "verification_method"])
        let container = try decoder.container(keyedBy: CodingKeys.self)
        sourceVisitID = try container.decode(String.self, forKey: .sourceVisitID)
        earnedAt = try container.decode(StrictTimestamp.self, forKey: .earnedAt)
        verificationMethod = try container.decode(String.self, forKey: .verificationMethod)
    }
}

private struct StrictTimestamp: Decodable {
    let value: Date

    init(from decoder: any Decoder) throws {
        let rawValue = try decoder.singleValueContainer().decode(String.self)
        let options: [ISO8601DateFormatter.Options] = [
            [.withInternetDateTime, .withFractionalSeconds],
            [.withInternetDateTime],
        ]
        for formatOptions in options {
            let formatter = ISO8601DateFormatter()
            formatter.formatOptions = formatOptions
            if let date = formatter.date(from: rawValue) {
                value = date
                return
            }
        }
        throw SupabaseSelfPassportSyncTransportError.malformedResponse
    }
}

private struct AnyCodingKey: CodingKey, Hashable {
    let stringValue: String
    let intValue: Int?

    init?(stringValue: String) {
        self.stringValue = stringValue
        intValue = nil
    }

    init?(intValue: Int) {
        stringValue = String(intValue)
        self.intValue = intValue
    }
}

private func requireExactKeys(
    _ decoder: any Decoder,
    _ expected: Set<String>
) throws {
    let container = try decoder.container(keyedBy: AnyCodingKey.self)
    guard Set(container.allKeys.map(\.stringValue)) == expected else {
        throw SupabaseSelfPassportSyncTransportError.malformedResponse
    }
}

private extension Data {
    init?(base64URLEncoded value: String) {
        var normalized = value
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        normalized += String(repeating: "=", count: (4 - normalized.count % 4) % 4)
        self.init(base64Encoded: normalized)
    }
}
