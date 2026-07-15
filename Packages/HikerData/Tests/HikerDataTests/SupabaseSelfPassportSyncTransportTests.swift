import Foundation
import XCTest
@testable import HikerData
import HikerDomain

final class SupabaseSelfPassportSyncTransportTests: XCTestCase {
    private let datasetSHA256 = String(repeating: "a", count: 64)
    private let mountainID = "mountain-001"
    private let mutationID = "00000000-0000-4000-8000-000000000001"
    private let visitID = "00000000-0000-4000-8000-000000000002"

    override func tearDown() {
        RPCURLProtocol.handler = nil
        super.tearDown()
    }

    func testBootstrapHistoryAndChangesUseCurrentSQLWireShapes() async throws {
        let sequence = RPCSequence([
            .init(
                name: "m3_self_bootstrap",
                body: [
                    "p_api_version": "m3-v1",
                    "p_dataset_sha256": datasetSHA256,
                ],
                response: bootstrap(snapshotVersion: 7, historyToken: "history-token-1")
            ),
            .init(
                name: "m3_self_history_page",
                body: [
                    "p_history_token": "history-token-1",
                    "p_cursor": NSNull(),
                    "p_mountain_id": mountainID,
                    "p_page_size": 100,
                ],
                response: [
                    "snapshotVersion": 7,
                    "items": [],
                    "nextCursor": NSNull(),
                    "complete": true,
                ]
            ),
            .init(
                name: "m3_self_changes",
                body: [
                    "p_history_token": "history-token-1",
                    "p_cursor": NSNull(),
                    "p_limit": 500,
                ],
                response: [
                    "fromVersion": 7,
                    "throughVersion": 7,
                    "changes": [],
                    "nextVersion": 7,
                    "nextCursor": NSNull(),
                    "complete": true,
                    "resyncRequired": false,
                ]
            ),
            .init(
                name: "m3_self_bootstrap",
                body: [
                    "p_api_version": "m3-v1",
                    "p_dataset_sha256": datasetSHA256,
                ],
                response: bootstrap(snapshotVersion: 7, historyToken: "history-token-2")
            ),
        ])
        let transport = try makeTransport(sequence: sequence)

        let bootstrap = try await transport.bootstrap()
        let mountain = try MountainID(rawValue: mountainID)
        let history = try await transport.historyPage(
            SelfPassportHistoryRequest(
                mountainID: mountain,
                snapshotVersion: bootstrap.snapshotVersion,
                historyToken: bootstrap.historyToken,
                continuationToken: nil
            )
        )
        let change = try await transport.changePage(
            SelfPassportChangeRequest(
                afterSnapshotVersion: bootstrap.snapshotVersion,
                continuationToken: nil
            )
        )

        XCTAssertTrue(history.visits.isEmpty)
        XCTAssertEqual(history.aggregateVersionAtSnapshot, 0)
        XCTAssertEqual(change.nextSnapshotVersion, 7)
        XCTAssertEqual(change.historyToken.rawValue, "history-token-2")
        XCTAssertTrue(sequence.isConsumed)
    }

    func testFourMutationRPCsUseExactSQLParametersAndCoherentBootstraps() async throws {
        let mountain = try MountainID(rawValue: mountainID)
        let addMutationID = try ClientMutationID(rawValue: mutationID)
        let removeMutationID = try ClientMutationID(
            rawValue: "00000000-0000-4000-8000-000000000003"
        )
        let createMutationID = try ClientMutationID(
            rawValue: "00000000-0000-4000-8000-000000000004"
        )
        let deleteMutationID = try ClientMutationID(
            rawValue: "00000000-0000-4000-8000-000000000005"
        )
        let visit = VisitRecord(
            id: try VisitID(rawValue: visitID),
            mountainID: mountain,
            visitedAt: Date(timeIntervalSince1970: 0),
            recordedAt: Date(timeIntervalSince1970: 0),
            verificationMethod: .manual
        )
        let sequence = RPCSequence([
            .init(
                name: "m3_apply_passport_mutation",
                body: [
                    "p_api_version": "m3-v1",
                    "p_dataset_sha256": datasetSHA256,
                    "p_mutation_id": addMutationID.rawValue,
                    "p_operation": "plan_add",
                    "p_payload": ["mountainID": mountainID],
                ],
                response: mutation(
                    operation: "plan_add",
                    globalVersion: 1,
                    aggregateVersion: 1,
                    visitCount: 0,
                    planState: "active_manual"
                )
            ),
            .init(
                name: "m3_self_bootstrap",
                body: bootstrapRequestBody,
                response: bootstrap(
                    snapshotVersion: 1,
                    historyToken: "history-token-1",
                    visitCount: 0,
                    aggregateVersion: 1,
                    globalVersion: 1,
                    planState: "active_manual"
                )
            ),
            .init(
                name: "m3_apply_passport_mutation",
                body: [
                    "p_api_version": "m3-v1",
                    "p_dataset_sha256": datasetSHA256,
                    "p_mutation_id": removeMutationID.rawValue,
                    "p_operation": "plan_remove",
                    "p_payload": ["mountainID": mountainID],
                ],
                response: mutation(
                    operation: "plan_remove",
                    globalVersion: 2,
                    aggregateVersion: 2,
                    visitCount: 0,
                    planState: "manually_removed"
                )
            ),
            .init(
                name: "m3_self_bootstrap",
                body: bootstrapRequestBody,
                response: bootstrap(
                    snapshotVersion: 2,
                    historyToken: "history-token-2",
                    visitCount: 0,
                    aggregateVersion: 2,
                    globalVersion: 2,
                    planState: "manually_removed"
                )
            ),
            .init(
                name: "m3_apply_passport_mutation",
                body: [
                    "p_api_version": "m3-v1",
                    "p_dataset_sha256": datasetSHA256,
                    "p_mutation_id": createMutationID.rawValue,
                    "p_operation": "manual_visit_create",
                    "p_payload": [
                        "mountainID": mountainID,
                        "visitID": visitID,
                        "visitedAt": "1970-01-01T00:00:00.000Z",
                    ],
                ],
                response: mutation(
                    operation: "manual_visit_create",
                    globalVersion: 3,
                    aggregateVersion: 3,
                    visitCount: 1,
                    planState: "manually_removed",
                    visitID: visitID,
                    stampVisitID: visitID
                )
            ),
            .init(
                name: "m3_self_bootstrap",
                body: bootstrapRequestBody,
                response: bootstrap(
                    snapshotVersion: 3,
                    historyToken: "history-token-3",
                    visitCount: 1,
                    aggregateVersion: 3,
                    globalVersion: 3,
                    planState: "manually_removed",
                    stampVisitID: visitID
                )
            ),
            .init(
                name: "m3_apply_passport_mutation",
                body: [
                    "p_api_version": "m3-v1",
                    "p_dataset_sha256": datasetSHA256,
                    "p_mutation_id": deleteMutationID.rawValue,
                    "p_operation": "manual_visit_delete",
                    "p_payload": ["visitID": visitID],
                ],
                response: mutation(
                    operation: "manual_visit_delete",
                    globalVersion: 4,
                    aggregateVersion: 4,
                    visitCount: 0,
                    planState: "manually_removed",
                    deletedVisitID: visitID
                )
            ),
            .init(
                name: "m3_self_bootstrap",
                body: bootstrapRequestBody,
                response: bootstrap(
                    snapshotVersion: 4,
                    historyToken: "history-token-4",
                    visitCount: 0,
                    aggregateVersion: 4,
                    globalVersion: 4,
                    planState: "manually_removed"
                )
            ),
        ])
        let transport = try makeTransport(sequence: sequence)

        let added = try await transport.addPlan(for: mountain, clientMutationID: addMutationID)
        let removed = try await transport.removePlan(for: mountain, clientMutationID: removeMutationID)
        let created = try await transport.createManualVisit(visit, clientMutationID: createMutationID)
        let deleted = try await transport.deleteManualVisit(visit.id, clientMutationID: deleteMutationID)

        XCTAssertEqual(added.aggregate.planDisposition, .active(.manual))
        XCTAssertEqual(removed.aggregate.planDisposition, .manuallyRemoved)
        XCTAssertEqual(created.visitID, visit.id)
        XCTAssertEqual(deleted.visitID, visit.id)
        XCTAssertEqual(added.snapshotVersion, 1)
        XCTAssertEqual(added.historyToken.rawValue, "history-token-1")
        XCTAssertEqual(removed.snapshotVersion, 2)
        XCTAssertEqual(removed.historyToken.rawValue, "history-token-2")
        XCTAssertEqual(created.snapshotVersion, 3)
        XCTAssertEqual(created.historyToken.rawValue, "history-token-3")
        XCTAssertEqual(deleted.snapshotVersion, 4)
        XCTAssertEqual(deleted.historyToken.rawValue, "history-token-4")
        XCTAssertTrue(sequence.isConsumed)
    }
    func testGPSVisitUsesCurrentCapabilityAndConvergesToRefreshedBase() async throws {
        let mountain = try MountainID(rawValue: mountainID)
        let visit = try VisitID(rawValue: visitID)
        let mutation = try ClientMutationID(rawValue: mutationID)
        let sequence = RPCSequence([
            .init(
                name: "m3_self_bootstrap",
                body: bootstrapRequestBody,
                response: bootstrap(snapshotVersion: 0, historyToken: "history-token-0")
            ),
            .init(
                name: "m4_create_gps_visit",
                body: [
                    "p_api_version": "m4-v1",
                    "p_dataset_sha256": datasetSHA256,
                    "p_history_token": "history-token-0",
                    "p_mountain_id": mountainID,
                    "p_visit_id": visitID,
                    "p_visited_at": "1970-01-01T00:00:00.000Z",
                    "p_mutation_id": mutationID,
                    "p_latitude": 37.0,
                    "p_longitude": 127.0,
                    "p_horizontal_accuracy_m": 100.0,
                    "p_sampled_at": "1970-01-01T00:00:00.000Z",
                ],
                response: gpsMutation(
                    globalVersion: 1,
                    aggregateVersion: 1,
                    visitCount: 1,
                    visitID: visitID,
                    stampVisitID: visitID
                )
            ),
            .init(
                name: "m3_self_bootstrap",
                body: bootstrapRequestBody,
                response: bootstrap(
                    snapshotVersion: 1,
                    historyToken: "history-token-1",
                    visitCount: 1,
                    aggregateVersion: 1,
                    globalVersion: 1,
                    stampVisitID: visitID,
                    stampVerificationMethod: "gps_verified"
                )
            ),
        ])
        let transport = try makeTransport(sequence: sequence)

        _ = try await transport.bootstrap()
        let outcome = try await transport.verifyGPSVisit(
            mountainID: mountain,
            visitID: visit,
            visitedAt: Date(timeIntervalSince1970: 0),
            clientMutationID: mutation,
            latitude: 37,
            longitude: 127,
            horizontalAccuracyMeters: 100,
            sampledAt: Date(timeIntervalSince1970: 0)
        )

        guard case let .gpsVerified(receipt) = outcome else {
            return XCTFail("A verified M4 response must produce a GPS receipt.")
        }
        XCTAssertEqual(receipt.clientMutationID, mutation)
        XCTAssertEqual(receipt.visitID, visit)
        XCTAssertEqual(receipt.mountainID, mountain)
        XCTAssertEqual(receipt.aggregate.visitCount, 1)
        XCTAssertEqual(receipt.aggregate.stamp?.method, .gpsVerified)
        XCTAssertEqual(receipt.snapshotVersion, 1)
        XCTAssertEqual(receipt.historyToken.rawValue, "history-token-1")
        XCTAssertTrue(sequence.isConsumed)
    }

    func testGPSVisitManualFallbackAndMalformedEnvelopeAreExplicit() async throws {
        let mountain = try MountainID(rawValue: mountainID)
        let visit = try VisitID(rawValue: visitID)
        let mutation = try ClientMutationID(rawValue: mutationID)
        let fallbackSequence = RPCSequence([
            .init(
                name: "m3_self_bootstrap",
                body: bootstrapRequestBody,
                response: bootstrap(snapshotVersion: 0, historyToken: "history-token-0")
            ),
            .init(
                name: "m4_create_gps_visit",
                body: gpsRequestBody(
                    historyToken: "history-token-0",
                    visitID: visitID,
                    mutationID: mutationID
                ),
                response: [
                    "status": "manual_fallback",
                    "manual_fallback": true,
                    "reason": "gps_distance_rejected",
                ]
            ),
        ])
        let fallbackTransport = try makeTransport(sequence: fallbackSequence)

        _ = try await fallbackTransport.bootstrap()
        let fallback = try await fallbackTransport.verifyGPSVisit(
            mountainID: mountain,
            visitID: visit,
            visitedAt: Date(timeIntervalSince1970: 0),
            clientMutationID: mutation,
            latitude: 37,
            longitude: 127,
            horizontalAccuracyMeters: 1,
            sampledAt: Date(timeIntervalSince1970: 0)
        )
        XCTAssertEqual(fallback, .manualFallback(.distanceRejected))
        XCTAssertTrue(fallbackSequence.isConsumed)

        var malformed = gpsMutation(
            globalVersion: 1,
            aggregateVersion: 1,
            visitCount: 1,
            visitID: visitID,
            stampVisitID: visitID
        )
        malformed["unexpected"] = true
        let malformedSequence = RPCSequence([
            .init(
                name: "m3_self_bootstrap",
                body: bootstrapRequestBody,
                response: bootstrap(snapshotVersion: 0, historyToken: "history-token-0")
            ),
            .init(
                name: "m4_create_gps_visit",
                body: gpsRequestBody(
                    historyToken: "history-token-0",
                    visitID: visitID,
                    mutationID: mutationID
                ),
                response: malformed
            ),
        ])
        let malformedTransport = try makeTransport(sequence: malformedSequence)

        _ = try await malformedTransport.bootstrap()
        let malformedOutcome = try await malformedTransport.verifyGPSVisit(
            mountainID: mountain,
            visitID: visit,
            visitedAt: Date(timeIntervalSince1970: 0),
            clientMutationID: mutation,
            latitude: 37,
            longitude: 127,
            horizontalAccuracyMeters: 1,
            sampledAt: Date(timeIntervalSince1970: 0)
        )
        XCTAssertEqual(malformedOutcome, .indeterminate)
        XCTAssertTrue(malformedSequence.isConsumed)
    }

    func testGPSVisitRequiresBoundCapabilityAndClassifiesTransportFailures() async throws {
        let mountain = try MountainID(rawValue: mountainID)
        let visit = try VisitID(rawValue: visitID)
        let mutation = try ClientMutationID(rawValue: mutationID)
        let unbound = try makeTransport(sequence: RPCSequence([]))

        let unboundOutcome = try await unbound.verifyGPSVisit(
            mountainID: mountain,
            visitID: visit,
            visitedAt: Date(timeIntervalSince1970: 0),
            clientMutationID: mutation,
            latitude: 37,
            longitude: 127,
            horizontalAccuracyMeters: 1,
            sampledAt: Date(timeIntervalSince1970: 0)
        )
        XCTAssertEqual(unboundOutcome, .rejected(.precondition))

        for (statusCode, expected) in [
            (401, GPSVisitVerificationOutcome.rejected(.authorization)),
            (403, .rejected(.authorization)),
            (404, .rejected(.policy)),
            (409, .indeterminate),
            (426, .rejected(.policy)),
            (500, .indeterminate),
        ] {
            let sequence = RPCSequence([
                .init(
                    name: "m3_self_bootstrap",
                    body: bootstrapRequestBody,
                    response: bootstrap(snapshotVersion: 0, historyToken: "history-token-0")
                ),
                .init(
                    name: "m4_create_gps_visit",
                    body: gpsRequestBody(
                        historyToken: "history-token-0",
                        visitID: visitID,
                        mutationID: mutationID
                    ),
                    statusCode: statusCode,
                    response: ["message": "rejected"]
                ),
            ])
            let transport = try makeTransport(sequence: sequence)

            _ = try await transport.bootstrap()
            let outcome = try await transport.verifyGPSVisit(
                mountainID: mountain,
                visitID: visit,
                visitedAt: Date(timeIntervalSince1970: 0),
                clientMutationID: mutation,
                latitude: 37,
                longitude: 127,
                horizontalAccuracyMeters: 1,
                sampledAt: Date(timeIntervalSince1970: 0)
            )
            XCTAssertEqual(outcome, expected)
            XCTAssertTrue(sequence.isConsumed)
        }

        let networkSequence = RPCSequence([
            .init(
                name: "m3_self_bootstrap",
                body: bootstrapRequestBody,
                response: bootstrap(snapshotVersion: 0, historyToken: "history-token-0")
            ),
            .init(
                name: "m4_create_gps_visit",
                body: gpsRequestBody(
                    historyToken: "history-token-0",
                    visitID: visitID,
                    mutationID: mutationID
                ),
                response: [:],
                networkError: .notConnectedToInternet
            ),
        ])
        let networkTransport = try makeTransport(sequence: networkSequence)

        _ = try await networkTransport.bootstrap()
        let networkOutcome = try await networkTransport.verifyGPSVisit(
            mountainID: mountain,
            visitID: visit,
            visitedAt: Date(timeIntervalSince1970: 0),
            clientMutationID: mutation,
            latitude: 37,
            longitude: 127,
            horizontalAccuracyMeters: 1,
            sampledAt: Date(timeIntervalSince1970: 0)
        )
        XCTAssertEqual(networkOutcome, .indeterminate)
        XCTAssertTrue(networkSequence.isConsumed)
        let postCommitRefreshSequence = RPCSequence([
            .init(
                name: "m3_self_bootstrap",
                body: bootstrapRequestBody,
                response: bootstrap(snapshotVersion: 0, historyToken: "history-token-0")
            ),
            .init(
                name: "m4_create_gps_visit",
                body: gpsRequestBody(
                    historyToken: "history-token-0",
                    visitID: visitID,
                    mutationID: mutationID
                ),
                response: gpsMutation(
                    globalVersion: 1,
                    aggregateVersion: 1,
                    visitCount: 1,
                    visitID: visitID,
                    stampVisitID: visitID
                )
            ),
            .init(
                name: "m3_self_bootstrap",
                body: bootstrapRequestBody,
                statusCode: 500,
                response: ["message": "refresh unavailable"]
            ),
        ])
        let postCommitRefreshTransport = try makeTransport(sequence: postCommitRefreshSequence)

        _ = try await postCommitRefreshTransport.bootstrap()
        let postCommitRefreshOutcome = try await postCommitRefreshTransport.verifyGPSVisit(
            mountainID: mountain,
            visitID: visit,
            visitedAt: Date(timeIntervalSince1970: 0),
            clientMutationID: mutation,
            latitude: 37,
            longitude: 127,
            horizontalAccuracyMeters: 1,
            sampledAt: Date(timeIntervalSince1970: 0)
        )
        XCTAssertEqual(postCommitRefreshOutcome, .indeterminate)
        XCTAssertTrue(postCommitRefreshSequence.isConsumed)
    }

    func testHTTPErrorStatusesFailClosed() async throws {
        let cases: [(Int, SelfPassportTransportFailure)] = [
            (401, .unauthenticated),
            (403, .forbidden),
            (409, .fullRefreshRequired),
            (426, .upgradeRequired),
            (500, .transient),
        ]

        for (statusCode, expectedFailure) in cases {
            let sequence = RPCSequence([
                .init(
                    name: "m3_self_bootstrap",
                    body: bootstrapRequestBody,
                    statusCode: statusCode,
                    response: ["message": "rejected"]
                ),
            ])
            let transport = try makeTransport(sequence: sequence)

            do {
                _ = try await transport.bootstrap()
                XCTFail("A non-success HTTP response must not publish a bootstrap.")
            } catch let error as SelfPassportTransportFailure {
                XCTAssertEqual(error, expectedFailure)
            }
            XCTAssertTrue(sequence.isConsumed)
        }
    }

    func testMutationHTTPStatusesDistinguishConflictAndRejection() async throws {
        let mountain = try MountainID(rawValue: mountainID)
        let mutation = try ClientMutationID(rawValue: mutationID)
        let cases: [(Int, SelfPassportTransportFailure)] = [
            (409, .mutationConflict),
            (422, .mutationRejected),
            (404, .upgradeRequired),
        ]

        for (statusCode, expectedFailure) in cases {
            let sequence = RPCSequence([
                .init(
                    name: "m3_apply_passport_mutation",
                    body: [
                        "p_api_version": "m3-v1",
                        "p_dataset_sha256": datasetSHA256,
                        "p_mutation_id": mutation.rawValue,
                        "p_operation": "plan_add",
                        "p_payload": ["mountainID": mountainID],
                    ],
                    statusCode: statusCode,
                    response: ["message": "rejected"]
                ),
            ])
            let transport = try makeTransport(sequence: sequence)

            do {
                _ = try await transport.addPlan(
                    for: mountain,
                    clientMutationID: mutation
                )
                XCTFail("A terminal mutation response must not be retried as a read refresh.")
            } catch let error as SelfPassportTransportFailure {
                XCTAssertEqual(error, expectedFailure)
            }
            XCTAssertTrue(sequence.isConsumed)
        }
    }

    func testMalformedOrExtraResponseFieldFailsClosed() async throws {
        var malformed = bootstrap(snapshotVersion: 0, historyToken: "history-token")
        malformed["unrecognized"] = true
        let sequence = RPCSequence([
            .init(
                name: "m3_self_bootstrap",
                body: bootstrapRequestBody,
                response: malformed
            ),
        ])
        let transport = try makeTransport(sequence: sequence)

        do {
            _ = try await transport.bootstrap()
            XCTFail("Unknown fields must be rejected before bootstrap publication.")
        } catch let error as SupabaseSelfPassportSyncTransportError {
            XCTAssertEqual(error, .malformedResponse)
        }
        XCTAssertTrue(sequence.isConsumed)
    }

    private var bootstrapRequestBody: [String: Any] {
        [
            "p_api_version": "m3-v1",
            "p_dataset_sha256": datasetSHA256,
        ]
    }

    private func makeTransport(
        sequence: RPCSequence
    ) throws -> SupabaseSelfPassportSyncTransport {
        RPCURLProtocol.handler = { request in
            sequence.response(for: request)
        }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [RPCURLProtocol.self]
        let session = URLSession(configuration: configuration)
        return try SupabaseSelfPassportSyncTransport(
            restURL: URL(string: "https://project.supabase.co/rest/v1")!,
            publishableKey: "sb_publishable_test-key",
            datasetSHA256: datasetSHA256,
            currentBearer: { "user-bearer" },
            session: session
        )
    }

    private func bootstrap(
        snapshotVersion: Int64,
        historyToken: String,
        visitCount: Int = 0,
        aggregateVersion: Int64 = 0,
        globalVersion: Int64 = 0,
        planState: String? = nil,
        stampVisitID: String? = nil,
        stampVerificationMethod: String = "manual"
    ) -> [String: Any] {
        let mountainIDs = (1...100).map { String(format: "mountain-%03d", $0) }
        let aggregates = mountainIDs.map { id -> [String: Any] in
            if id == mountainID {
                return [
                    "mountainID": id,
                    "visitCount": visitCount,
                    "planState": planState ?? NSNull(),
                    "aggregateVersion": aggregateVersion,
                    "globalVersion": globalVersion,
                ]
            }
            return [
                "mountainID": id,
                "visitCount": 0,
                "planState": NSNull(),
                "aggregateVersion": 0,
                "globalVersion": 0,
            ]
        }
        let plans: [[String: Any]]
        if let planState {
            plans = [[
                "mountainID": mountainID,
                "planState": planState,
                "firstVisitID": NSNull(),
                "aggregateVersion": aggregateVersion,
                "globalVersion": globalVersion,
                "createdAt": "2026-01-01T00:00:00.000Z",
                "updatedAt": "2026-01-01T00:00:00.000Z",
            ]]
        } else {
            plans = []
        }
        let stamps: [[String: Any]]
        if let stampVisitID {
            stamps = [[
                "mountainID": mountainID,
                "sourceVisitID": stampVisitID,
                "earnedAt": "2026-01-01T00:00:00.000Z",
                "verificationMethod": stampVerificationMethod,
                "aggregateVersion": aggregateVersion,
                "globalVersion": globalVersion,
                "updatedAt": "2026-01-01T00:00:00.000Z",
            ]]
        } else {
            stamps = []
        }
        return [
            "snapshotVersion": snapshotVersion,
            "datasetSHA256": datasetSHA256,
            "mountains": mountainIDs,
            "aggregates": aggregates,
            "plans": plans,
            "stamps": stamps,
            "historyToken": historyToken,
        ]
    }

    private func mutation(
        operation: String,
        globalVersion: Int64,
        aggregateVersion: Int64,
        visitCount: Int,
        planState: String?,
        visitID: String? = nil,
        deletedVisitID: String? = nil,
        stampVisitID: String? = nil,
        stampVerificationMethod: String = "manual"
    ) -> [String: Any] {
        let stamp: Any = stampVisitID.map {
            [
                "source_visit_id": $0,
                "earned_at": "2026-01-01T00:00:00.000Z",
                "verification_method": stampVerificationMethod,
            ]
        } ?? NSNull()
        return [
            "operation": operation,
            "mountain_id": mountainID,
            "visit_id": visitID ?? NSNull(),
            "deleted_visit_id": deletedVisitID ?? NSNull(),
            "visit_count": visitCount,
            "plan_state": planState ?? NSNull(),
            "plan_first_visit_id": NSNull(),
            "stamp": stamp,
            "aggregate_version": aggregateVersion,
            "global_version": globalVersion,
            "history_token": "history-token-\(globalVersion)",
        ]
    }
    private func gpsRequestBody(
        historyToken: String,
        visitID: String,
        mutationID: String
    ) -> [String: Any] {
        [
            "p_api_version": "m4-v1",
            "p_dataset_sha256": datasetSHA256,
            "p_history_token": historyToken,
            "p_mountain_id": mountainID,
            "p_visit_id": visitID,
            "p_visited_at": "1970-01-01T00:00:00.000Z",
            "p_mutation_id": mutationID,
            "p_latitude": 37.0,
            "p_longitude": 127.0,
            "p_horizontal_accuracy_m": 1.0,
            "p_sampled_at": "1970-01-01T00:00:00.000Z",
        ]
    }

    private func gpsMutation(
        globalVersion: Int64,
        aggregateVersion: Int64,
        visitCount: Int,
        visitID: String,
        stampVisitID: String
    ) -> [String: Any] {
        var response = mutation(
            operation: "gps_visit_create",
            globalVersion: globalVersion,
            aggregateVersion: aggregateVersion,
            visitCount: visitCount,
            planState: nil,
            visitID: visitID,
            stampVisitID: stampVisitID,
            stampVerificationMethod: "gps_verified"
        )
        response.removeValue(forKey: "history_token")
        response["status"] = "gps_verified"
        response["manual_fallback"] = false
        response["verification_method"] = "gps_verified"
        return response
    }
}

private final class RPCSequence: @unchecked Sendable {
    struct Entry {
        let name: String
        let body: [String: Any]
        let statusCode: Int
        let response: [String: Any]
        let networkError: URLError.Code?

        init(
            name: String,
            body: [String: Any],
            statusCode: Int = 200,
            response: [String: Any],
            networkError: URLError.Code? = nil
        ) {
            self.name = name
            self.body = body
            self.statusCode = statusCode
            self.response = response
            self.networkError = networkError
        }
    }

    private let lock = NSLock()
    private var entries: [Entry]

    init(_ entries: [Entry]) {
        self.entries = entries
    }

    var isConsumed: Bool {
        lock.lock()
        defer { lock.unlock() }
        return entries.isEmpty
    }

    func response(
        for request: URLRequest
    ) -> Result<(statusCode: Int, data: Data), URLError> {
        lock.lock()
        guard !entries.isEmpty else {
            lock.unlock()
            XCTFail("Received an unexpected RPC request.")
            return .success((statusCode: 500, data: Data()))
        }
        let entry = entries.removeFirst()
        lock.unlock()

        XCTAssertEqual(request.url?.path, "/rest/v1/rpc/\(entry.name)")
        XCTAssertEqual(request.httpMethod, "POST")
        XCTAssertEqual(request.value(forHTTPHeaderField: "apikey"), "sb_publishable_test-key")
        XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer user-bearer")
        XCTAssertEqual(request.value(forHTTPHeaderField: "Cache-Control"), "no-store")
        XCTAssertEqual(request.value(forHTTPHeaderField: "Pragma"), "no-cache")
        XCTAssertNil(request.value(forHTTPHeaderField: "Cookie"))

        let requestBody = request.httpBody ?? Self.readBodyStream(request.httpBodyStream)
        let body = requestBody.flatMap {
            try? JSONSerialization.jsonObject(with: $0) as? [String: Any]
        }
        XCTAssertNotNil(body)
        XCTAssertEqual(body as NSDictionary?, entry.body as NSDictionary)

        if let networkError = entry.networkError {
            return .failure(URLError(networkError))
        }

        let data = try! JSONSerialization.data(withJSONObject: entry.response)
        return .success((statusCode: entry.statusCode, data: data))
    }

    private static func readBodyStream(_ stream: InputStream?) -> Data? {
        guard let stream else {
            return nil
        }
        stream.open()
        defer { stream.close() }

        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4_096)
        while stream.hasBytesAvailable {
            let count = stream.read(&buffer, maxLength: buffer.count)
            guard count >= 0 else {
                return nil
            }
            if count == 0 {
                break
            }
            data.append(buffer, count: count)
        }
        return data
    }
}

private final class RPCURLProtocol: URLProtocol {
    nonisolated(unsafe) static var handler: (
        (URLRequest) -> Result<(statusCode: Int, data: Data), URLError>
    )?

    override class func canInit(with request: URLRequest) -> Bool {
        request.url?.host == "project.supabase.co"
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        guard let handler = Self.handler,
              let url = request.url else {
            client?.urlProtocol(self, didFailWithError: URLError(.badServerResponse))
            return
        }
        switch handler(request) {
        case let .success(result):
            let response = HTTPURLResponse(
                url: url,
                statusCode: result.statusCode,
                httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "application/json"]
            )!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: result.data)
            client?.urlProtocolDidFinishLoading(self)
        case let .failure(error):
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}
final class FriendPassportDTOContractTests: XCTestCase {
    func testForbiddenFields() throws {
        let mountain = try MountainID(rawValue: "mountain-001")
        let aggregate = try FriendPassportMountainAggregate(
            mountainID: mountain,
            visitCount: 2,
            isPlanned: true,
            hasStamp: false,
            stampVerificationMethod: nil
        )
        let passport = try FriendPassportDTO(
            friendReference: FriendReference(
                rawValue: UUID(uuidString: "00000000-0000-4000-8000-000000000010")!
            ),
            mountains: [aggregate]
        )

        XCTAssertEqual(
            Set(Mirror(reflecting: passport).children.compactMap(\.label)),
            ["friendReference", "mountains"]
        )
        XCTAssertEqual(
            Set(Mirror(reflecting: aggregate).children.compactMap(\.label)),
            [
                "mountainID",
                "visitCount",
                "isPlanned",
                "hasStamp",
                "stampVerificationMethod",
            ]
        )
    }
}

final class FriendPassportSessionTests: XCTestCase {
    private let friendReference = FriendReference(
        rawValue: UUID(uuidString: "00000000-0000-4000-8000-000000000010")!
    )
    private let generation: Int64 = 1

    func testEventBeforeFetch() async throws {
        let clock = FriendSessionTestClock(now: Date(timeIntervalSince1970: 1_000))
        let session = FriendPassportSession(
            friendReference: friendReference,
            now: { clock.now() }
        )
        let transport = FriendSocialTransportStub(
            passportResponses: [
                .success(try envelope(leaseExpiresAt: clock.now().addingTimeInterval(30)))
            ]
        )

        await session.consume(
            try FriendSocialEvent(
                friendReference: friendReference,
                generation: generation,
                sequence: 1
            )
        )
        let fetched = try await session.refresh(using: transport)

        XCTAssertNil(fetched)
        let published = await session.publication()
        XCTAssertNil(published)
        let requests = await transport.passportRequestCount()
        XCTAssertEqual(requests, 0)
    }

    func testResponseBeforeEvent() async throws {
        let clock = FriendSessionTestClock(now: Date(timeIntervalSince1970: 1_000))
        let session = FriendPassportSession(
            friendReference: friendReference,
            now: { clock.now() }
        )
        let transport = FriendSocialTransportStub(
            passportResponses: [
                .success(try envelope(leaseExpiresAt: clock.now().addingTimeInterval(30)))
            ]
        )

        let fetched = try await session.refresh(using: transport)
        XCTAssertNotNil(fetched)

        await session.consume(
            try FriendSocialEvent(
                friendReference: friendReference,
                generation: generation,
                sequence: 1
            )
        )

        let published = await session.publication()
        XCTAssertNil(published)
    }
    func testEventGapZeroizesPublishedPassport() async throws {
        let clock = FriendSessionTestClock(now: Date(timeIntervalSince1970: 1_000))
        let session = FriendPassportSession(
            friendReference: friendReference,
            now: { clock.now() }
        )
        let transport = FriendSocialTransportStub(
            passportResponses: [
                .success(try envelope(leaseExpiresAt: clock.now().addingTimeInterval(30)))
            ]
        )

        _ = try await session.refresh(using: transport)
        await session.consume(
            try FriendSocialEventPage(
                generation: generation,
                sequence: 2,
                requiresResynchronization: false,
                events: []
            )
        )

        let published = await session.publication()
        XCTAssertNil(published)
    }

    func testRevocationDuringFetchDiscardsResponse() async throws {
        let clock = FriendSessionTestClock(now: Date(timeIntervalSince1970: 1_000))
        let session = FriendPassportSession(
            friendReference: friendReference,
            now: { clock.now() }
        )
        let transport = DeferredFriendSocialTransport()
        let refreshing = Task {
            try await session.refresh(using: transport)
        }

        await transport.waitForPassportRequest()
        await session.consume(
            try FriendSocialEvent(
                friendReference: friendReference,
                generation: generation,
                sequence: 1
            )
        )
        await transport.resolve(
            try envelope(leaseExpiresAt: clock.now().addingTimeInterval(30))
        )

        let fetched = try await refreshing.value
        XCTAssertNil(fetched)
        let published = await session.publication()
        XCTAssertNil(published)
    }

    func testForbiddenFailureAndLeaseExpiryZeroize() async throws {
        let clock = FriendSessionTestClock(now: Date(timeIntervalSince1970: 1_000))
        let expirySession = FriendPassportSession(
            friendReference: friendReference,
            now: { clock.now() }
        )
        let leaseExpiresAt = clock.now().addingTimeInterval(5)
        let expiryTransport = FriendSocialTransportStub(
            passportResponses: [
                .success(try envelope(leaseExpiresAt: leaseExpiresAt))
            ]
        )

        let initial = try await expirySession.refresh(using: expiryTransport)
        XCTAssertEqual(initial?.leaseExpiresAt, leaseExpiresAt)
        XCTAssertEqual(initial?.authorizationGeneration, generation)
        XCTAssertEqual(initial?.passport.friendReference, friendReference)
        clock.advance(by: 5)
        let expiredPublication = await expirySession.publication()
        XCTAssertNil(expiredPublication)
        let oversizedLeaseSession = FriendPassportSession(
            friendReference: friendReference,
            now: { clock.now() }
        )
        let oversizedLeaseTransport = FriendSocialTransportStub(
            passportResponses: [
                .success(try envelope(leaseExpiresAt: clock.now().addingTimeInterval(31)))
            ]
        )
        do {
            _ = try await oversizedLeaseSession.refresh(using: oversizedLeaseTransport)
            XCTFail("A friend passport lease must not exceed 30 seconds.")
        } catch let error as FriendPassportSessionError {
            XCTAssertEqual(error, .invalidAuthorizationEnvelope)
        }
        let oversizedLease = await oversizedLeaseSession.publication()
        XCTAssertNil(oversizedLease)

        let forbiddenSession = FriendPassportSession(
            friendReference: friendReference,
            now: { clock.now() }
        )
        let forbiddenTransport = FriendSocialTransportStub(
            passportResponses: [
                .success(try envelope(leaseExpiresAt: clock.now().addingTimeInterval(30))),
                .failure(.forbidden),
            ]
        )

        let authorized = try await forbiddenSession.refresh(using: forbiddenTransport)
        XCTAssertNotNil(authorized)
        do {
            _ = try await forbiddenSession.refresh(using: forbiddenTransport)
            XCTFail("A 403 must clear the in-memory friend passport.")
        } catch let error as FriendSocialTransportFailure {
            XCTAssertEqual(error, .forbidden)
        }
        let forbidden = await forbiddenSession.publication()
        XCTAssertNil(forbidden)
    }

    private func envelope(
        leaseExpiresAt: Date
    ) throws -> FriendPassportAuthorizationEnvelope {
        let mountain = try MountainID(rawValue: "mountain-001")
        let aggregate = try FriendPassportMountainAggregate(
            mountainID: mountain,
            visitCount: 1,
            isPlanned: false,
            hasStamp: false,
            stampVerificationMethod: nil
        )
        let passport = try FriendPassportDTO(
            friendReference: friendReference,
            mountains: [aggregate]
        )
        return try FriendPassportAuthorizationEnvelope(
            passport: passport,
            authorizationGeneration: 1,
            leaseExpiresAt: leaseExpiresAt
        )
    }
}

private final class FriendSessionTestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Date

    init(now: Date) {
        value = now
    }

    func now() -> Date {
        lock.lock()
        defer { lock.unlock() }
        return value
    }

    func advance(by interval: TimeInterval) {
        lock.lock()
        value = value.addingTimeInterval(interval)
        lock.unlock()
    }
}


private actor FriendSocialTransportStub: FriendSocialTransport {
    private var passportResponses: [Result<FriendPassportAuthorizationEnvelope, FriendSocialTransportFailure>]
    private var requestCount = 0

    init(
        passportResponses: [Result<FriendPassportAuthorizationEnvelope, FriendSocialTransportFailure>]
    ) {
        self.passportResponses = passportResponses
    }
    func friendCode() async throws -> HikerData.FriendCode {
        throw FriendSocialTransportFailure.unavailable
    }

    func regenerateFriendCode() async throws -> HikerData.FriendCode {
        throw FriendSocialTransportFailure.unavailable
    }

    func lookupFriendCode(_ code: HikerData.FriendCode) async throws -> FriendCodeLookupResult {
        throw FriendSocialTransportFailure.unavailable
    }

    func sendFriendRequest(using code: HikerData.FriendCode) async throws -> FriendRequestSendResult {
        throw FriendSocialTransportFailure.unavailable
    }

    func incomingFriendRequests() async throws -> [FriendRequestReference] {
        throw FriendSocialTransportFailure.unavailable
    }

    func respondToFriendRequest(
        _ request: FriendRequestReference,
        response: FriendRequestResponse
    ) async throws -> FriendRequestResponseResult {
        throw FriendSocialTransportFailure.unavailable
    }

    func cancelFriendRequest(
        _ request: FriendRequestReference
    ) async throws -> FriendRequestCancellationResult {
        throw FriendSocialTransportFailure.unavailable
    }

    func friends() async throws -> [FriendReference] {
        throw FriendSocialTransportFailure.unavailable
    }

    func unfriend(_ friend: FriendReference) async throws -> FriendUnfriendResult {
        throw FriendSocialTransportFailure.unavailable
    }

    func block(_ reference: FriendBlockReference) async throws -> FriendBlockResult {
        throw FriendSocialTransportFailure.unavailable
    }

    func friendPassport(
        for friend: FriendReference
    ) async throws -> FriendPassportAuthorizationEnvelope {
        requestCount += 1
        guard !passportResponses.isEmpty else {
            throw FriendSocialTransportFailure.unavailable
        }
        return try passportResponses.removeFirst().get()
    }

    func socialEvents(
        after cursor: FriendSocialEventCursor
    ) async throws -> FriendSocialEventPage {
        if cursor == .bootstrap {
            return try FriendSocialEventPage(
                generation: 1,
                sequence: 0,
                requiresResynchronization: true,
                events: []
            )
        }
        return try FriendSocialEventPage(
            generation: cursor.generation,
            sequence: cursor.sequence,
            requiresResynchronization: false,
            events: []
        )
    }

    func passportRequestCount() -> Int {
        requestCount
    }
}

private actor DeferredFriendSocialTransport: FriendSocialTransport {
    private var responseContinuation: CheckedContinuation<FriendPassportAuthorizationEnvelope, Error>?
    private var requestContinuation: CheckedContinuation<Void, Never>?
    private var requested = false
    func friendCode() async throws -> HikerData.FriendCode {
        throw FriendSocialTransportFailure.unavailable
    }

    func regenerateFriendCode() async throws -> HikerData.FriendCode {
        throw FriendSocialTransportFailure.unavailable
    }

    func lookupFriendCode(_ code: HikerData.FriendCode) async throws -> FriendCodeLookupResult {
        throw FriendSocialTransportFailure.unavailable
    }

    func sendFriendRequest(using code: HikerData.FriendCode) async throws -> FriendRequestSendResult {
        throw FriendSocialTransportFailure.unavailable
    }

    func incomingFriendRequests() async throws -> [FriendRequestReference] {
        throw FriendSocialTransportFailure.unavailable
    }

    func respondToFriendRequest(
        _ request: FriendRequestReference,
        response: FriendRequestResponse
    ) async throws -> FriendRequestResponseResult {
        throw FriendSocialTransportFailure.unavailable
    }

    func cancelFriendRequest(
        _ request: FriendRequestReference
    ) async throws -> FriendRequestCancellationResult {
        throw FriendSocialTransportFailure.unavailable
    }

    func friends() async throws -> [FriendReference] {
        throw FriendSocialTransportFailure.unavailable
    }

    func unfriend(_ friend: FriendReference) async throws -> FriendUnfriendResult {
        throw FriendSocialTransportFailure.unavailable
    }

    func block(_ reference: FriendBlockReference) async throws -> FriendBlockResult {
        throw FriendSocialTransportFailure.unavailable
    }

    func friendPassport(
        for friend: FriendReference
    ) async throws -> FriendPassportAuthorizationEnvelope {
        requested = true
        requestContinuation?.resume()
        requestContinuation = nil
        return try await withCheckedThrowingContinuation { continuation in
            responseContinuation = continuation
        }
    }

    func socialEvents(
        after cursor: FriendSocialEventCursor
    ) async throws -> FriendSocialEventPage {
        if cursor == .bootstrap {
            return try FriendSocialEventPage(
                generation: 1,
                sequence: 0,
                requiresResynchronization: true,
                events: []
            )
        }
        return try FriendSocialEventPage(
            generation: cursor.generation,
            sequence: cursor.sequence,
            requiresResynchronization: false,
            events: []
        )
    }

    func waitForPassportRequest() async {
        guard !requested else {
            return
        }
        await withCheckedContinuation { continuation in
            requestContinuation = continuation
        }
    }

    func resolve(_ response: FriendPassportAuthorizationEnvelope) {
        responseContinuation?.resume(returning: response)
        responseContinuation = nil
    }
}
