import Foundation
import XCTest
@testable import HikerData
import HikerDomain

final class HikerDataTests: XCTestCase {
    func testTypedStoreContractRoundTripsAndRemovesValue() async throws {
        let store = InMemoryStore()
        let expected = StoredRoute(identifier: "bukhan-san")

        let roundTripped = try await roundTrip(expected, through: store)
        let removedValue = try await removeValue(from: store)

        XCTAssertEqual(roundTripped, expected)
        XCTAssertNil(removedValue)
    }

    func testJSONFileStorePersistsAndRemovesValue() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let store: JSONFileDataStore<StoredRoute> = try LocalDataStoreFactory(
            baseDirectory: directory
        ).makeJSONStore(named: "route.json")
        let expected = StoredRoute(identifier: "seorak-san")

        try await store.save(expected)
        let persisted = try await store.load()
        XCTAssertEqual(persisted, expected)

        try await store.remove()
        let removed = try await store.load()
        XCTAssertNil(removed)
    }

    func testJSONFileStoreRejectsEscapingNames() throws {
        let factory = LocalDataStoreFactory(baseDirectory: FileManager.default.temporaryDirectory)

        for invalidName in ["", ".", "..", "../outside.json", "nested/route.json", #"nested\route.json"#] {
            XCTAssertThrowsError(
                try factory.makeJSONStore(named: invalidName, as: StoredRoute.self)
            ) { error in
                XCTAssertEqual(error as? LocalDataStorePathError, .invalidFileName)
            }
        }
    }

    // OUT-001
    func testPreDispatchCreateDeleteCompacts() throws {
        let visit = try makeVisit(id: "00000000-0000-4000-8000-000000000001")
        let createMutationID = try mutationID("00000000-0000-4000-8000-000000000101")
        let deleteMutationID = try mutationID("00000000-0000-4000-8000-000000000102")
        var graph = try ManualVisitOutboxGraph()

        let create = try graph.enqueueCreate(
            visit,
            clientMutationID: createMutationID,
            at: referenceDate
        )
        let originalBytes = create.request.requestBytes

        let result = try graph.enqueueDelete(
            visitID: visit.id,
            mountainID: visit.mountainID,
            clientMutationID: deleteMutationID,
            at: referenceDate
        )

        guard case let .compacted(compactedMutationID) = result else {
            return XCTFail("Expected same-VisitID pre-dispatch compaction.")
        }
        XCTAssertEqual(compactedMutationID, createMutationID)
        XCTAssertTrue(graph.nodes.isEmpty)
        XCTAssertNil(graph.nextDispatchable(at: referenceDate))
        XCTAssertFalse(originalBytes.isEmpty)

        let gpsVisit = VisitRecord(
            id: try visitID("00000000-0000-4000-8000-000000000003"),
            mountainID: visit.mountainID,
            visitedAt: referenceDate,
            recordedAt: referenceDate,
            verificationMethod: .gpsVerified
        )
        XCTAssertThrowsError(
            try graph.enqueueCreate(
                gpsVisit,
                clientMutationID: try mutationID("00000000-0000-4000-8000-000000000103")
            )
        ) { error in
            XCTAssertEqual(
                error as? ManualVisitOutboxError,
                .gpsVerifiedVisitsAreNotQueueable
            )
        }
    }

    // OUT-002
    func testInFlightCreateThenDelete() throws {
        let visit = try makeVisit(id: "00000000-0000-4000-8000-000000000011")
        let createMutationID = try mutationID("00000000-0000-4000-8000-000000000111")
        let deleteMutationID = try mutationID("00000000-0000-4000-8000-000000000112")
        var graph = try ManualVisitOutboxGraph()

        let create = try graph.enqueueCreate(
            visit,
            clientMutationID: createMutationID,
            at: referenceDate
        )
        let dispatchedCreate = try XCTUnwrap(graph.nextDispatchable(at: referenceDate))
        XCTAssertEqual(dispatchedCreate.id, createMutationID)
        XCTAssertEqual(dispatchedCreate.request.requestBytes, create.request.requestBytes)

        let deleteResult = try graph.enqueueDelete(
            visitID: visit.id,
            mountainID: visit.mountainID,
            clientMutationID: deleteMutationID,
            at: referenceDate
        )
        guard case let .enqueued(delete) = deleteResult else {
            return XCTFail("An in-flight create must be retained.")
        }

        XCTAssertEqual(
            delete.dependency,
            ManualVisitOutboxDependency(
                clientMutationID: createMutationID,
                visitID: visit.id
            )
        )
        XCTAssertEqual(delete.request.visitID, visit.id)
        XCTAssertNil(graph.nextDispatchable(at: referenceDate))

        try graph.acknowledgeAccepted(mutationID: createMutationID)
        let dispatchedDelete = try XCTUnwrap(graph.nextDispatchable(at: referenceDate))
        XCTAssertEqual(dispatchedDelete.id, deleteMutationID)
        XCTAssertEqual(dispatchedDelete.request.requestBytes, delete.request.requestBytes)
        XCTAssertEqual(dispatchedDelete.dependency, delete.dependency)
    }

    // OUT-003
    func testRejectDropsDescendants() throws {
        let rejectedVisit = try makeVisit(id: "00000000-0000-4000-8000-000000000021")
        let independentVisit = try makeVisit(
            id: "00000000-0000-4000-8000-000000000022",
            mountain: "independent-mountain"
        )
        let createMutationID = try mutationID("00000000-0000-4000-8000-000000000121")
        let deleteMutationID = try mutationID("00000000-0000-4000-8000-000000000122")
        let independentMutationID = try mutationID("00000000-0000-4000-8000-000000000123")
        var graph = try ManualVisitOutboxGraph()

        _ = try graph.enqueueCreate(
            rejectedVisit,
            clientMutationID: createMutationID,
            at: referenceDate
        )
        let independent = try graph.enqueueCreate(
            independentVisit,
            clientMutationID: independentMutationID,
            at: referenceDate
        )
        _ = try XCTUnwrap(graph.nextDispatchable(at: referenceDate))
        let deleteResult = try graph.enqueueDelete(
            visitID: rejectedVisit.id,
            mountainID: rejectedVisit.mountainID,
            clientMutationID: deleteMutationID,
            at: referenceDate
        )
        guard case .enqueued = deleteResult else {
            return XCTFail("An in-flight create must retain its dependent delete.")
        }

        let removed = try graph.acknowledgeRejected(mutationID: createMutationID)
        XCTAssertEqual(Set(removed.map(\.id)), [createMutationID, deleteMutationID])
        XCTAssertEqual(graph.nodes.map(\.id), [independentMutationID])
        XCTAssertEqual(graph.nodes.first?.request.requestBytes, independent.request.requestBytes)
        XCTAssertEqual(graph.nodes.first?.localSequence, independent.localSequence)

        let rebasedIndependent = try XCTUnwrap(graph.nextDispatchable(at: referenceDate))
        XCTAssertEqual(rebasedIndependent.id, independentMutationID)
    }

    // OUT-004
    func testRestartCycleAndIsolation() async throws {
        let firstVisit = try makeVisit(id: "00000000-0000-4000-8000-000000000031")
        let secondVisit = try makeVisit(
            id: "00000000-0000-4000-8000-000000000032",
            mountain: "second-mountain"
        )
        let firstMutationID = try mutationID("00000000-0000-4000-8000-000000000131")
        let deleteMutationID = try mutationID("00000000-0000-4000-8000-000000000132")
        let secondMutationID = try mutationID("00000000-0000-4000-8000-000000000133")
        var graph = try ManualVisitOutboxGraph()

        _ = try graph.enqueueCreate(
            firstVisit,
            clientMutationID: firstMutationID,
            at: referenceDate
        )
        _ = try XCTUnwrap(graph.nextDispatchable(at: referenceDate))
        let firstDelete = try graph.enqueueDelete(
            visitID: firstVisit.id,
            mountainID: firstVisit.mountainID,
            clientMutationID: deleteMutationID,
            at: referenceDate
        )
        let secondCreate = try graph.enqueueCreate(
            secondVisit,
            clientMutationID: secondMutationID,
            at: referenceDate
        )

        guard case let .enqueued(deleteNode) = firstDelete else {
            return XCTFail("Expected dependent delete.")
        }
        XCTAssertEqual(deleteNode.dependency?.visitID, firstVisit.id)
        XCTAssertNil(secondCreate.dependency)
        XCTAssertNotEqual(deleteNode.request.visitID, secondCreate.request.visitID)

        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let outboxURL = directory.appendingPathComponent("manual-outbox.bin")
        let key = try ManualVisitOutboxEncryptionKey(data: Data(repeating: 0xA5, count: 32))
        let outboxStore = EncryptedManualVisitOutboxStore(fileURL: outboxURL, key: key)
        try await outboxStore.save(graph)

        let encryptedOutbox = try Data(contentsOf: outboxURL)
        XCTAssertNil(
            encryptedOutbox.range(
                of: Data(firstVisit.id.rawValue.utf8)
            )
        )

        let loadedGraph = try await outboxStore.load()
        let restoredGraph = try XCTUnwrap(loadedGraph)
        XCTAssertEqual(restoredGraph.nodes.map(\.id), graph.nodes.map(\.id))
        XCTAssertEqual(
            restoredGraph.nodes.map(\.request.requestBytes),
            graph.nodes.map(\.request.requestBytes)
        )
        XCTAssertEqual(restoredGraph.nodes.first?.state, .queued)

        var resumedGraph = restoredGraph
        let redispatchedCreate = try XCTUnwrap(resumedGraph.nextDispatchable(at: referenceDate))
        XCTAssertEqual(redispatchedCreate.id, firstMutationID)
        XCTAssertEqual(
            redispatchedCreate.request.requestBytes,
            graph.nodes.first?.request.requestBytes
        )
        try resumedGraph.acknowledgeAccepted(mutationID: firstMutationID)
        try resumedGraph.validate()

        let dispatchedDelete = try XCTUnwrap(resumedGraph.nextDispatchable(at: referenceDate))
        XCTAssertEqual(dispatchedDelete.id, deleteMutationID)
        XCTAssertEqual(dispatchedDelete.request.requestBytes, deleteNode.request.requestBytes)

        var passport = PassportStateMachine()
        try passport.recordVisit(secondVisit)
        let snapshot = try LocalPassportSnapshot(
            passportState: passport,
            manualVisitOutbox: graph
        )
        let passportURL = directory.appendingPathComponent("passport.bin")
        let passportStore = EncryptedLocalPassportStore(fileURL: passportURL, key: key)
        try await passportStore.save(snapshot)
        let loadedSnapshot = try await passportStore.load()
        let restoredSnapshot = try XCTUnwrap(loadedSnapshot)
        XCTAssertEqual(restoredSnapshot, snapshot)

        var tamperedPassport = try Data(contentsOf: passportURL)
        let lastIndex = try XCTUnwrap(tamperedPassport.indices.last)
        tamperedPassport[lastIndex] = tamperedPassport[lastIndex] ^ 0x01
        try tamperedPassport.write(to: passportURL, options: .atomic)

        do {
            _ = try await passportStore.load()
            XCTFail("Tampered encrypted passport storage must fail closed.")
        } catch {
            XCTAssertEqual(
                error as? EncryptedLocalPassportStoreError,
                .authenticationFailed
            )
        }

        let cycleFirst = try ManualVisitOutboxRequest(
            create: firstVisit,
            clientMutationID: firstMutationID
        )
        let cycleSecond = try ManualVisitOutboxRequest(
            create: secondVisit,
            clientMutationID: secondMutationID
        )
        let cycleNodes = [
            try ManualVisitOutboxNode(
                localSequence: 0,
                aggregateMountainID: firstVisit.mountainID,
                request: cycleFirst,
                dependency: ManualVisitOutboxDependency(
                    clientMutationID: secondMutationID,
                    visitID: secondVisit.id
                ),
                enqueuedAt: referenceDate
            ),
            try ManualVisitOutboxNode(
                localSequence: 1,
                aggregateMountainID: secondVisit.mountainID,
                request: cycleSecond,
                dependency: ManualVisitOutboxDependency(
                    clientMutationID: firstMutationID,
                    visitID: firstVisit.id
                ),
                enqueuedAt: referenceDate
            )
        ]
        XCTAssertThrowsError(try ManualVisitOutboxGraph(nodes: cycleNodes)) { error in
            XCTAssertEqual(error as? ManualVisitOutboxError, .dependencyCycle)
        }

        let unknownDelete = try ManualVisitOutboxRequest(
            deleteVisitID: firstVisit.id,
            mountainID: firstVisit.mountainID,
            clientMutationID: deleteMutationID
        )
        let unknownNode = try ManualVisitOutboxNode(
            localSequence: 0,
            aggregateMountainID: firstVisit.mountainID,
            request: unknownDelete,
            dependency: ManualVisitOutboxDependency(
                clientMutationID: try mutationID("00000000-0000-4000-8000-000000000199"),
                visitID: firstVisit.id
            ),
            enqueuedAt: referenceDate
        )
        XCTAssertThrowsError(try ManualVisitOutboxGraph(nodes: [unknownNode])) { error in
            XCTAssertEqual(error as? ManualVisitOutboxError, .unknownDependency)
        }
    }

    // OUT-005
    func testExpiryRequiresUserChoice() throws {
        let visit = try makeVisit(id: "00000000-0000-4000-8000-000000000041")
        let mutationID = try mutationID("00000000-0000-4000-8000-000000000141")
        let ninetyDays: TimeInterval = 90 * 24 * 60 * 60
        let enqueuedAt = referenceDate.addingTimeInterval(-ninetyDays)
        var graph = try ManualVisitOutboxGraph()

        let node = try graph.enqueueCreate(
            visit,
            clientMutationID: mutationID,
            at: enqueuedAt
        )
        XCTAssertEqual(graph.pauseExpired(at: referenceDate), [mutationID])
        XCTAssertEqual(graph.nodes.first?.state, .paused)
        XCTAssertNil(graph.nextDispatchable(at: referenceDate))

        let exported = graph.exportPaused()
        XCTAssertEqual(exported, [ManualVisitOutboxExport(node: node)])
        XCTAssertEqual(
            try graph.applyExpiryChoice(.export, for: [mutationID]),
            exported
        )
        XCTAssertEqual(graph.nodes.count, 1)

        XCTAssertEqual(
            try graph.applyExpiryChoice(.discard, for: [mutationID]),
            []
        )
        XCTAssertTrue(graph.nodes.isEmpty)
    }
    func testAcceptedCreateDependencyPersistsAfterReload() async throws {
        let visit = try makeVisit(id: "00000000-0000-4000-8000-000000000051")
        let createMutationID = try mutationID("00000000-0000-4000-8000-000000000151")
        let deleteMutationID = try mutationID("00000000-0000-4000-8000-000000000152")
        var graph = try ManualVisitOutboxGraph()

        let create = try graph.enqueueCreate(
            visit,
            clientMutationID: createMutationID,
            at: referenceDate
        )
        let dispatchedCreate = try XCTUnwrap(graph.nextDispatchable(at: referenceDate))
        XCTAssertEqual(dispatchedCreate.request.requestBytes, create.request.requestBytes)
        let deleteResult = try graph.enqueueDelete(
            visitID: visit.id,
            mountainID: visit.mountainID,
            clientMutationID: deleteMutationID,
            at: referenceDate
        )
        guard case let .enqueued(delete) = deleteResult else {
            return XCTFail("An in-flight create must retain its dependent delete.")
        }

        try graph.acknowledgeAccepted(mutationID: createMutationID)
        try graph.validate()

        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let key = try ManualVisitOutboxEncryptionKey(data: Data(repeating: 0xA5, count: 32))
        let store = EncryptedManualVisitOutboxStore(
            fileURL: directory.appendingPathComponent("manual-outbox.bin"),
            key: key
        )
        try await store.save(graph)
        let loadedGraph = try await store.load()
        var restoredGraph = try XCTUnwrap(loadedGraph)

        XCTAssertEqual(restoredGraph.acceptedCreates, [createMutationID: visit.id])

        let snapshot = try LocalPassportSnapshot(
            passportState: PassportStateMachine(),
            manualVisitOutbox: graph
        )
        let snapshotStore = EncryptedLocalPassportStore(
            fileURL: directory.appendingPathComponent("passport.bin"),
            key: key
        )
        try await snapshotStore.save(snapshot)
        let loadedSnapshot = try await snapshotStore.load()
        XCTAssertEqual(try XCTUnwrap(loadedSnapshot), snapshot)

        let dispatchedDelete = try XCTUnwrap(restoredGraph.nextDispatchable(at: referenceDate))
        XCTAssertEqual(dispatchedDelete.id, deleteMutationID)
        XCTAssertEqual(dispatchedDelete.request.requestBytes, delete.request.requestBytes)
    }

    func testOutboxRejectsCrossVisitAndCrossMountainDependencies() throws {
        let firstVisit = try makeVisit(
            id: "00000000-0000-4000-8000-000000000061",
            mountain: "first-mountain"
        )
        let secondVisit = try makeVisit(
            id: "00000000-0000-4000-8000-000000000062",
            mountain: "second-mountain"
        )
        let createMutationID = try mutationID("00000000-0000-4000-8000-000000000161")
        let crossVisitMutationID = try mutationID("00000000-0000-4000-8000-000000000162")
        let crossMountainMutationID = try mutationID("00000000-0000-4000-8000-000000000163")
        let createRequest = try ManualVisitOutboxRequest(
            create: firstVisit,
            clientMutationID: createMutationID
        )
        let createNode = try ManualVisitOutboxNode(
            localSequence: 0,
            aggregateMountainID: firstVisit.mountainID,
            request: createRequest,
            enqueuedAt: referenceDate
        )

        let crossVisitRequest = try ManualVisitOutboxRequest(
            deleteVisitID: secondVisit.id,
            mountainID: secondVisit.mountainID,
            clientMutationID: crossVisitMutationID
        )
        let crossVisitNode = try ManualVisitOutboxNode(
            localSequence: 1,
            aggregateMountainID: secondVisit.mountainID,
            request: crossVisitRequest,
            dependency: ManualVisitOutboxDependency(
                clientMutationID: createMutationID,
                visitID: firstVisit.id
            ),
            enqueuedAt: referenceDate
        )
        XCTAssertThrowsError(
            try ManualVisitOutboxGraph(nodes: [createNode, crossVisitNode])
        ) { error in
            XCTAssertEqual(error as? ManualVisitOutboxError, .invalidDependency)
        }

        let crossMountainRequest = try ManualVisitOutboxRequest(
            deleteVisitID: firstVisit.id,
            mountainID: secondVisit.mountainID,
            clientMutationID: crossMountainMutationID
        )
        let crossMountainNode = try ManualVisitOutboxNode(
            localSequence: 1,
            aggregateMountainID: secondVisit.mountainID,
            request: crossMountainRequest,
            dependency: ManualVisitOutboxDependency(
                clientMutationID: createMutationID,
                visitID: firstVisit.id
            ),
            enqueuedAt: referenceDate
        )
        XCTAssertThrowsError(
            try ManualVisitOutboxGraph(nodes: [createNode, crossMountainNode])
        ) { error in
            XCTAssertEqual(error as? ManualVisitOutboxError, .invalidDependency)
        }
    }

    func testLocalPassportSnapshotRequiresOutboxCoherence() throws {
        let manualVisit = try makeVisit(id: "00000000-0000-4000-8000-000000000071")
        let gpsVisit = VisitRecord(
            id: try visitID("00000000-0000-4000-8000-000000000072"),
            mountainID: try MountainID(rawValue: "gps-mountain"),
            visitedAt: referenceDate,
            recordedAt: referenceDate,
            verificationMethod: .gpsVerified
        )
        let createMutationID = try mutationID("00000000-0000-4000-8000-000000000171")
        let deleteMutationID = try mutationID("00000000-0000-4000-8000-000000000172")

        var presentPassport = PassportStateMachine()
        try presentPassport.recordVisit(manualVisit)
        try presentPassport.recordVisit(gpsVisit)
        var createGraph = try ManualVisitOutboxGraph()
        _ = try createGraph.enqueueCreate(
            manualVisit,
            clientMutationID: createMutationID,
            at: referenceDate
        )
        let createSnapshot = try LocalPassportSnapshot(
            passportState: presentPassport,
            manualVisitOutbox: createGraph
        )
        XCTAssertEqual(createSnapshot.passportState, presentPassport)

        var absentPassport = PassportStateMachine()
        try absentPassport.recordVisit(gpsVisit)
        var deleteGraph = try ManualVisitOutboxGraph()
        _ = try deleteGraph.enqueueCreate(
            manualVisit,
            clientMutationID: createMutationID,
            at: referenceDate
        )
        _ = try XCTUnwrap(deleteGraph.nextDispatchable(at: referenceDate))
        _ = try deleteGraph.enqueueDelete(
            visitID: manualVisit.id,
            mountainID: manualVisit.mountainID,
            clientMutationID: deleteMutationID,
            at: referenceDate
        )
        let deleteSnapshot = try LocalPassportSnapshot(
            passportState: absentPassport,
            manualVisitOutbox: deleteGraph
        )
        XCTAssertEqual(deleteSnapshot.passportState, absentPassport)

        XCTAssertThrowsError(
            try LocalPassportSnapshot(
                passportState: absentPassport,
                manualVisitOutbox: createGraph
            )
        ) { error in
            XCTAssertEqual(
                error as? LocalPassportSnapshotError,
                .inconsistentPassportAndOutbox
            )
        }
        XCTAssertThrowsError(
            try LocalPassportSnapshot(
                passportState: presentPassport,
                manualVisitOutbox: deleteGraph
            )
        ) { error in
            XCTAssertEqual(
                error as? LocalPassportSnapshotError,
                .inconsistentPassportAndOutbox
            )
        }
    }
    func testLocalPassportSnapshotRejectsCreatePayloadTimestampMismatches() throws {
        let queuedVisit = try makeVisit(id: "00000000-0000-4000-8000-000000000073")
        let createMutationID = try mutationID("00000000-0000-4000-8000-000000000173")
        var graph = try ManualVisitOutboxGraph()

        _ = try graph.enqueueCreate(
            queuedVisit,
            clientMutationID: createMutationID,
            at: referenceDate
        )

        let timestampMismatches = [
            VisitRecord(
                id: queuedVisit.id,
                mountainID: queuedVisit.mountainID,
                visitedAt: queuedVisit.visitedAt.addingTimeInterval(1),
                recordedAt: queuedVisit.recordedAt,
                verificationMethod: .manual
            ),
            VisitRecord(
                id: queuedVisit.id,
                mountainID: queuedVisit.mountainID,
                visitedAt: queuedVisit.visitedAt,
                recordedAt: queuedVisit.recordedAt.addingTimeInterval(1),
                verificationMethod: .manual
            ),
        ]

        for passportVisit in timestampMismatches {
            var passport = PassportStateMachine()
            try passport.recordVisit(passportVisit)

            XCTAssertThrowsError(
                try LocalPassportSnapshot(
                    passportState: passport,
                    manualVisitOutbox: graph
                )
            ) { error in
                XCTAssertEqual(
                    error as? LocalPassportSnapshotError,
                    .inconsistentPassportAndOutbox
                )
            }
        }
    }

    func testAcceptedCreateMetadataIsGarbageCollectedWithoutPendingDescendant() throws {
        let visit = try makeVisit(id: "00000000-0000-4000-8000-000000000074")
        let createMutationID = try mutationID("00000000-0000-4000-8000-000000000174")
        var graph = try ManualVisitOutboxGraph()

        _ = try graph.enqueueCreate(
            visit,
            clientMutationID: createMutationID,
            at: referenceDate
        )
        _ = try XCTUnwrap(graph.nextDispatchable(at: referenceDate))
        try graph.acknowledgeAccepted(mutationID: createMutationID)

        XCTAssertTrue(graph.nodes.isEmpty)
        XCTAssertTrue(graph.acceptedCreates.isEmpty)
        try graph.validate()
    }

    func testOutboxRejectsMissingAcceptedCreateMountainBinding() throws {
        let visit = try makeVisit(id: "00000000-0000-4000-8000-000000000075")
        let createMutationID = try mutationID("00000000-0000-4000-8000-000000000175")
        let deleteMutationID = try mutationID("00000000-0000-4000-8000-000000000176")
        var graph = try ManualVisitOutboxGraph()

        _ = try graph.enqueueCreate(
            visit,
            clientMutationID: createMutationID,
            at: referenceDate
        )
        _ = try XCTUnwrap(graph.nextDispatchable(at: referenceDate))
        _ = try graph.enqueueDelete(
            visitID: visit.id,
            mountainID: visit.mountainID,
            clientMutationID: deleteMutationID,
            at: referenceDate
        )
        try graph.acknowledgeAccepted(mutationID: createMutationID)

        let encodedData = try JSONEncoder().encode(graph)
        var encodedGraph = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encodedData) as? [String: Any]
        )
        encodedGraph.removeValue(forKey: "acceptedCreateMountains")
        let missingBinding = try JSONSerialization.data(withJSONObject: encodedGraph)

        XCTAssertThrowsError(
            try JSONDecoder().decode(ManualVisitOutboxGraph.self, from: missingBinding)
        ) { error in
            XCTAssertEqual(
                error as? ManualVisitOutboxError,
                .inconsistentRequestPayload
            )
        }
    }
    func testOutboxRejectsWrongAcceptedCreateVisitBinding() throws {
        let visit = try makeVisit(id: "00000000-0000-4000-8000-000000000076")
        let wrongVisitID = try visitID("00000000-0000-4000-8000-000000000077")
        let createMutationID = try mutationID("00000000-0000-4000-8000-000000000177")
        let deleteMutationID = try mutationID("00000000-0000-4000-8000-000000000178")
        let deleteRequest = try ManualVisitOutboxRequest(
            deleteVisitID: visit.id,
            mountainID: visit.mountainID,
            clientMutationID: deleteMutationID
        )
        let deleteNode = try ManualVisitOutboxNode(
            localSequence: 0,
            aggregateMountainID: visit.mountainID,
            request: deleteRequest,
            dependency: ManualVisitOutboxDependency(
                clientMutationID: createMutationID,
                visitID: visit.id
            ),
            enqueuedAt: referenceDate
        )

        XCTAssertThrowsError(
            try ManualVisitOutboxGraph(
                nodes: [deleteNode],
                acceptedCreates: [createMutationID: wrongVisitID]
            )
        ) { error in
            XCTAssertEqual(error as? ManualVisitOutboxError, .invalidDependency)
        }
    }


    func testEncryptedOutboxFailsClosedAndPreservesPersistenceIO() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let graph = try ManualVisitOutboxGraph()
        let key = try ManualVisitOutboxEncryptionKey(data: Data(repeating: 0xA5, count: 32))
        let fileURL = directory.appendingPathComponent("manual-outbox.bin")
        let store = EncryptedManualVisitOutboxStore(fileURL: fileURL, key: key)

        try await store.save(graph)
        var tampered = try Data(contentsOf: fileURL)
        let lastIndex = try XCTUnwrap(tampered.indices.last)
        tampered[lastIndex] = tampered[lastIndex] ^ 0x01
        try tampered.write(to: fileURL, options: .atomic)
        await assertOutboxLoadFails(store, expected: .authenticationFailed)

        try await store.save(graph)
        let wrongKeyStore = EncryptedManualVisitOutboxStore(
            fileURL: fileURL,
            key: try ManualVisitOutboxEncryptionKey(data: Data(repeating: 0xB6, count: 32))
        )
        await assertOutboxLoadFails(wrongKeyStore, expected: .authenticationFailed)

        try Data([0x48, 0x4B, 0x4F, 0x31]).write(to: fileURL, options: .atomic)
        await assertOutboxLoadFails(store, expected: .plaintextOrUnsupportedFormat)

        try Data("plaintext".utf8).write(to: fileURL, options: .atomic)
        await assertOutboxLoadFails(store, expected: .plaintextOrUnsupportedFormat)

        try Data([0x48, 0x4B, 0x50, 0x31, 0x00]).write(to: fileURL, options: .atomic)
        await assertOutboxLoadFails(store, expected: .plaintextOrUnsupportedFormat)

        let nonDirectory = directory.appendingPathComponent("not-a-directory")
        try Data("blocker".utf8).write(to: nonDirectory, options: .atomic)
        let unwritableOutboxStore = EncryptedManualVisitOutboxStore(
            fileURL: nonDirectory.appendingPathComponent("outbox.bin"),
            key: key
        )
        do {
            try await unwritableOutboxStore.save(graph)
            XCTFail("A non-directory parent must report persistence I/O.")
        } catch {
            assertOutboxPersistenceIO(error)
        }

        let readDirectory = directory.appendingPathComponent("read-directory", isDirectory: true)
        try FileManager.default.createDirectory(
            at: readDirectory,
            withIntermediateDirectories: true
        )
        let unreadableOutboxStore = EncryptedManualVisitOutboxStore(
            fileURL: readDirectory,
            key: key
        )
        do {
            _ = try await unreadableOutboxStore.load()
            XCTFail("A directory cannot be read as encrypted outbox data.")
        } catch {
            assertOutboxPersistenceIO(error)
        }

        let emptySnapshot = try LocalPassportSnapshot(
            passportState: PassportStateMachine(),
            manualVisitOutbox: graph
        )
        let unwritablePassportStore = EncryptedLocalPassportStore(
            fileURL: nonDirectory.appendingPathComponent("passport.bin"),
            key: key
        )
        do {
            try await unwritablePassportStore.save(emptySnapshot)
            XCTFail("A non-directory parent must report persistence I/O.")
        } catch {
            assertPassportPersistenceIO(error)
        }

        let unreadablePassportStore = EncryptedLocalPassportStore(
            fileURL: readDirectory,
            key: key
        )
        do {
            _ = try await unreadablePassportStore.load()
            XCTFail("A directory cannot be read as encrypted passport data.")
        } catch {
            assertPassportPersistenceIO(error)
        }
    }

    private func assertOutboxLoadFails(
        _ store: EncryptedManualVisitOutboxStore,
        expected: ManualVisitOutboxStoreError,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async {
        do {
            _ = try await store.load()
            XCTFail("Encrypted outbox load unexpectedly succeeded.", file: file, line: line)
        } catch {
            XCTAssertEqual(
                error as? ManualVisitOutboxStoreError,
                expected,
                file: file,
                line: line
            )
        }
    }

    private func assertOutboxPersistenceIO(
        _ error: Error,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        guard let storeError = error as? ManualVisitOutboxStoreError,
              case let .persistenceIO(domain, _) = storeError else {
            return XCTFail("Expected an outbox persistence I/O error.", file: file, line: line)
        }
        XCTAssertFalse(domain.isEmpty, file: file, line: line)
    }

    private func assertPassportPersistenceIO(
        _ error: Error,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        guard let storeError = error as? EncryptedLocalPassportStoreError,
              case let .persistenceIO(domain, _) = storeError else {
            return XCTFail("Expected a passport persistence I/O error.", file: file, line: line)
        }
        XCTAssertFalse(domain.isEmpty, file: file, line: line)
    }

    private var referenceDate: Date {
        Date(timeIntervalSince1970: 1_700_000_000)
    }

    private func visitID(_ rawValue: String) throws -> VisitID {
        try VisitID(rawValue: rawValue)
    }

    private func mutationID(_ rawValue: String) throws -> ClientMutationID {
        try ClientMutationID(rawValue: rawValue)
    }

    private func makeVisit(
        id: String,
        mountain: String = "test-mountain"
    ) throws -> VisitRecord {
        VisitRecord(
            id: try visitID(id),
            mountainID: try MountainID(rawValue: mountain),
            visitedAt: referenceDate.addingTimeInterval(-60),
            recordedAt: referenceDate,
            verificationMethod: .manual
        )
    }
    private func roundTrip<Store: HikerLocalDataStore>(
        _ value: Store.Value,
        through store: Store
    ) async throws -> Store.Value? {
        try await store.save(value)
        return try await store.load()
    }

    private func removeValue<Store: HikerLocalDataStore>(
        from store: Store
    ) async throws -> Store.Value? {
        try await store.remove()
        return try await store.load()
    }
}

private struct StoredRoute: Codable, Equatable, Sendable {
    let identifier: String
}

private actor InMemoryStore: HikerLocalDataStore {
    private var value: StoredRoute?

    func load() -> StoredRoute? {
        value
    }

    func save(_ value: StoredRoute) {
        self.value = value
    }

    func saveIfUnchanged(_ value: StoredRoute, expected: StoredRoute?) -> Bool {
        guard self.value == expected else {
            return false
        }
        self.value = value
        return true
    }

    func remove() {
        value = nil
    }
}

final class M3SelfPassportSyncTests: XCTestCase {
    func testCompleteBootstrapOnlyPublishesExact100Base() async throws {
        let mountainIDs = try m3MountainIDs()
        let initial = try m3Base(
            snapshotVersion: 7,
            mountainIDs: mountainIDs,
            visitCount: 0
        )
        let store = M3SnapshotStore(
            value: try LocalPassportSnapshot(
                passportState: PassportStateMachine(),
                manualVisitOutbox: ManualVisitOutboxGraph(),
                syncBase: initial
            )
        )
        let incomplete = SelfPassportBootstrapResponse(
            snapshotVersion: 8,
            datasetVersion: "dataset-v1",
            schemaVersion: 1,
            historyToken: try OpaqueHistoryToken(rawValue: "history-8"),
            aggregates: Array(initial.aggregates.dropLast())
        )
        let complete = SelfPassportBootstrapResponse(
            snapshotVersion: 9,
            datasetVersion: "dataset-v1",
            schemaVersion: 1,
            historyToken: try OpaqueHistoryToken(rawValue: "history-9"),
            aggregates: initial.aggregates
        )
        let transport = M3ScriptedTransport(
            bootstraps: [incomplete, complete]
        )
        let bootstrapper = SelfBootstrapper(
            store: store,
            transport: transport,
            expectedMountainIDs: Set(mountainIDs),
            expectedDatasetVersion: "dataset-v1"
        )

        do {
            _ = try await bootstrapper.bootstrap()
            XCTFail("A partial bootstrap must not publish a canonical base.")
        } catch let error as SelfPassportSyncError {
            XCTAssertEqual(error, .invalidBootstrap)
        } catch {
            throw error
        }

        let storedAfterIncomplete = await store.load()
        let unchanged = try XCTUnwrap(storedAfterIncomplete?.syncBase)
        XCTAssertEqual(unchanged.snapshotVersion, 7)
        XCTAssertEqual(unchanged.aggregates.count, 100)

        let published = try await bootstrapper.bootstrap()
        XCTAssertEqual(published.snapshotVersion, 9)
        XCTAssertEqual(published.aggregates.map(\.mountainID), mountainIDs)
        let storedAfterComplete = await store.load()
        XCTAssertEqual(storedAfterComplete?.syncBase, published)
    }

    func testMultiDeviceChangeRebasesDurableLocalOverlay() async throws {
        let mountainIDs = try m3MountainIDs()
        let base = try m3Base(
            snapshotVersion: 5,
            mountainIDs: mountainIDs,
            visitCount: 0
        )
        let firstMountain = try XCTUnwrap(mountainIDs.first)
        let remoteAggregate = try m3Aggregate(
            mountainID: firstMountain,
            aggregateVersion: 1,
            visitCount: 1
        )
        let change = SelfPassportChangePage(
            afterSnapshotVersion: 5,
            changes: [
                SelfPassportChange(
                    globalSnapshotVersion: 6,
                    aggregate: remoteAggregate
                )
            ],
            nextContinuationToken: nil,
            nextSnapshotVersion: 6,
            historyToken: try OpaqueHistoryToken(rawValue: "history-6")
        )
        let store = M3SnapshotStore()
        let transport = M3ScriptedTransport(
            bootstraps: [m3Bootstrap(base)],
            changePages: [change]
        )
        let engine = SelfPassportSyncEngine(
            store: store,
            transport: transport,
            expectedMountainIDs: Set(mountainIDs),
            expectedDatasetVersion: "dataset-v1"
        )
        _ = try await engine.bootstrap()

        let localVisit = try m3Visit(
            id: "00000000-0000-4000-8000-000000000201",
            mountainID: firstMountain
        )
        let mutationID = try ClientMutationID(
            rawValue: "00000000-0000-4000-8000-000000000301"
        )
        _ = try await engine.enqueueManualCreate(
            localVisit,
            clientMutationID: mutationID,
            at: m3Date
        )

        let refreshResult = try await engine.refreshChanges()
        XCTAssertEqual(refreshResult, .updated(snapshotVersion: 6))
        let effective = try await engine.effectiveAggregates()
        XCTAssertEqual(
            try XCTUnwrap(effective.first { $0.mountainID == firstMountain }).visitCount,
            2
        )
        let storedAfterChange = await store.load()
        let snapshot = try XCTUnwrap(storedAfterChange)
        XCTAssertEqual(snapshot.syncBase?.snapshotVersion, 6)
        XCTAssertEqual(snapshot.manualVisitOutbox.nodes.map(\.id), [mutationID])
    }

    func testHistoryThenContiguousChangesClearsStaleHistoryOnlyAfterCompletion() async throws {
        let mountainIDs = try m3MountainIDs()
        let firstMountain = try XCTUnwrap(mountainIDs.first)
        let firstVisit = try m3Visit(
            id: "00000000-0000-4000-8000-000000000211",
            mountainID: firstMountain,
            visitedOffset: -30
        )
        let secondVisit = try m3Visit(
            id: "00000000-0000-4000-8000-000000000212",
            mountainID: firstMountain,
            visitedOffset: -60
        )
        var aggregates = try m3Aggregates(mountainIDs: mountainIDs, visitCount: 0)
        aggregates[0] = try m3Aggregate(
            mountainID: firstMountain,
            aggregateVersion: 2,
            visitCount: 2
        )
        let base = try SelfPassportSyncBase(
            snapshotVersion: 10,
            datasetVersion: "dataset-v1",
            schemaVersion: 1,
            historyToken: try OpaqueHistoryToken(rawValue: "history-10"),
            aggregates: aggregates
        )
        let historyContinuation = try OpaqueHistoryToken(rawValue: "history-page-2")
        let changeAggregate = try m3Aggregate(
            mountainID: firstMountain,
            aggregateVersion: 3,
            visitCount: 1
        )
        let store = M3SnapshotStore()
        let transport = M3ScriptedTransport(
            bootstraps: [m3Bootstrap(base)],
            historyPages: [
                SelfPassportHistoryPage(
                    mountainID: firstMountain,
                    snapshotVersion: 10,
                    aggregateVersionAtSnapshot: 2,
                    visits: [firstVisit],
                    nextContinuationToken: historyContinuation
                ),
                SelfPassportHistoryPage(
                    mountainID: firstMountain,
                    snapshotVersion: 10,
                    aggregateVersionAtSnapshot: 2,
                    visits: [secondVisit],
                    nextContinuationToken: nil
                )
            ],
            changePages: [
                SelfPassportChangePage(
                    afterSnapshotVersion: 10,
                    changes: [
                        SelfPassportChange(
                            globalSnapshotVersion: 11,
                            aggregate: changeAggregate
                        )
                    ],
                    nextContinuationToken: nil,
                    nextSnapshotVersion: 11,
                    historyToken: try OpaqueHistoryToken(rawValue: "history-11")
                )
            ]
        )
        let engine = SelfPassportSyncEngine(
            store: store,
            transport: transport,
            expectedMountainIDs: Set(mountainIDs),
            expectedDatasetVersion: "dataset-v1"
        )
        _ = try await engine.bootstrap()

        let history = try await engine.loadCompleteHistory(for: firstMountain)
        XCTAssertEqual(history.visits.map(\.id), [firstVisit.id, secondVisit.id])
        let baseWithHistory = try await engine.canonicalBase()
        XCTAssertEqual(
            baseWithHistory?.completedHistory(for: firstMountain),
            history
        )

        let historyRefreshResult = try await engine.refreshChanges()
        XCTAssertEqual(historyRefreshResult, .updated(snapshotVersion: 11))
        let refreshedBase = try await engine.canonicalBase()
        let refreshed = try XCTUnwrap(refreshedBase)
        XCTAssertNil(refreshed.completedHistory(for: firstMountain))
        XCTAssertEqual(refreshed.aggregate(for: firstMountain), changeAggregate)
    }

    func testPartialHistoryCannotDelete() async throws {
        let mountainIDs = try m3MountainIDs()
        let firstMountain = try XCTUnwrap(mountainIDs.first)
        let base = try m3Base(
            snapshotVersion: 12,
            mountainIDs: mountainIDs,
            visitCount: 1
        )
        let store = M3SnapshotStore()
        let transport = M3ScriptedTransport(
            bootstraps: [m3Bootstrap(base)]
        )
        let engine = SelfPassportSyncEngine(
            store: store,
            transport: transport,
            expectedMountainIDs: Set(mountainIDs),
            expectedDatasetVersion: "dataset-v1"
        )
        _ = try await engine.bootstrap()

        let remoteVisitID = try VisitID(
            rawValue: "00000000-0000-4000-8000-000000000250"
        )
        let mutationID = try ClientMutationID(
            rawValue: "00000000-0000-4000-8000-000000000350"
        )

        do {
            _ = try await engine.enqueueManualDelete(
                visitID: remoteVisitID,
                mountainID: firstMountain,
                clientMutationID: mutationID,
                at: m3Date
            )
            XCTFail("A remote visit absent from completed local history must not become deletable.")
        } catch let error as SelfPassportSyncError {
            XCTAssertEqual(error, .remoteDeleteNotAuthorized)
            let stored = await store.load()
            let snapshot = try XCTUnwrap(stored)
            XCTAssertTrue(snapshot.manualVisitOutbox.nodes.isEmpty)
            XCTAssertNil(snapshot.syncBase?.completedHistory(for: firstMountain))
        } catch {
            throw error
        }
    }
    func testExactReceiptAcknowledgementRebasesCanonicalBase() async throws {
        let mountainIDs = try m3MountainIDs()
        let firstMountain = try XCTUnwrap(mountainIDs.first)
        let base = try m3Base(
            snapshotVersion: 1,
            mountainIDs: mountainIDs,
            visitCount: 0
        )
        let visit = try m3Visit(
            id: "00000000-0000-4000-8000-000000000221",
            mountainID: firstMountain
        )
        let mutationID = try ClientMutationID(
            rawValue: "00000000-0000-4000-8000-000000000321"
        )
        let receipt = SelfPassportMutationReceipt(
            clientMutationID: mutationID,
            operation: .create,
            visitID: visit.id,
            mountainID: firstMountain,
            aggregate: try m3Aggregate(
                mountainID: firstMountain,
                aggregateVersion: 1,
                visitCount: 1
            ),
            snapshotVersion: 2,
            historyToken: try OpaqueHistoryToken(rawValue: "history-2")
        )
        let store = M3SnapshotStore()
        let transport = M3ScriptedTransport(
            bootstraps: [m3Bootstrap(base)],
            uploadResults: [.receipt(receipt)]
        )
        let engine = SelfPassportSyncEngine(
            store: store,
            transport: transport,
            expectedMountainIDs: Set(mountainIDs),
            expectedDatasetVersion: "dataset-v1"
        )
        _ = try await engine.bootstrap()
        _ = try await engine.enqueueManualCreate(
            visit,
            clientMutationID: mutationID,
            at: m3Date
        )

        let acknowledgedReceipt = try await engine.uploadNextManualOutboxOperation(
            at: m3Date
        )
        XCTAssertEqual(acknowledgedReceipt, receipt)
        let storedAfterAcknowledgement = await store.load()
        let snapshot = try XCTUnwrap(storedAfterAcknowledgement)
        XCTAssertTrue(snapshot.manualVisitOutbox.nodes.isEmpty)
        XCTAssertEqual(snapshot.syncBase?.snapshotVersion, 2)
        XCTAssertEqual(
            snapshot.syncBase?.aggregate(for: firstMountain),
            receipt.aggregate
        )
        let effectiveAggregates = try await engine.effectiveAggregates()
        let effectiveAggregate = try XCTUnwrap(
            effectiveAggregates.first { $0.mountainID == firstMountain }
        )
        XCTAssertEqual(effectiveAggregate.visitCount, 1)
    }

    func testAuthenticationWritePausePreservesQueuedBytes() async throws {
        let mountainIDs = try m3MountainIDs()
        let firstMountain = try XCTUnwrap(mountainIDs.first)
        let base = try m3Base(
            snapshotVersion: 1,
            mountainIDs: mountainIDs,
            visitCount: 0
        )
        let visit = try m3Visit(
            id: "00000000-0000-4000-8000-000000000231",
            mountainID: firstMountain
        )
        let mutationID = try ClientMutationID(
            rawValue: "00000000-0000-4000-8000-000000000331"
        )
        let store = M3SnapshotStore()
        let transport = M3ScriptedTransport(
            bootstraps: [m3Bootstrap(base)],
            uploadResults: [.failure(.unauthenticated)]
        )
        let engine = SelfPassportSyncEngine(
            store: store,
            transport: transport,
            expectedMountainIDs: Set(mountainIDs),
            expectedDatasetVersion: "dataset-v1"
        )
        _ = try await engine.bootstrap()
        let node = try await engine.enqueueManualCreate(
            visit,
            clientMutationID: mutationID,
            at: m3Date
        )

        do {
            _ = try await engine.uploadNextManualOutboxOperation(at: m3Date)
            XCTFail("An authentication failure must pause writes.")
        } catch let error as SelfPassportTransportFailure {
            XCTAssertEqual(error, .unauthenticated)
        } catch {
            throw error
        }

        let writePauseReason = await engine.writePauseReason()
        XCTAssertEqual(writePauseReason, .unauthenticated)
        let storedAfterPause = await store.load()
        let persisted = try XCTUnwrap(storedAfterPause)
        XCTAssertEqual(persisted.manualVisitOutbox.nodes, [node])
        XCTAssertEqual(persisted.manualVisitOutbox.nodes.first?.state, .queued)
        XCTAssertEqual(
            persisted.manualVisitOutbox.nodes.first?.request.requestBytes,
            node.request.requestBytes
        )

        do {
            _ = try await engine.uploadNextManualOutboxOperation(at: m3Date)
            XCTFail("Paused writes must not consume the preserved queue.")
        } catch let error as SelfPassportSyncError {
            XCTAssertEqual(error, .writePaused(.unauthenticated))
        } catch {
            throw error
        }
    }
    func testTruncatedHistoryDoesNotReplaceCompletedHistory() async throws {
        let mountainIDs = try m3MountainIDs()
        let firstMountain = try XCTUnwrap(mountainIDs.first)
        let firstVisit = try m3Visit(
            id: "00000000-0000-4000-8000-000000000241",
            mountainID: firstMountain,
            visitedOffset: -30
        )
        let secondVisit = try m3Visit(
            id: "00000000-0000-4000-8000-000000000242",
            mountainID: firstMountain,
            visitedOffset: -60
        )
        var aggregates = try m3Aggregates(mountainIDs: mountainIDs, visitCount: 0)
        aggregates[0] = try m3Aggregate(
            mountainID: firstMountain,
            aggregateVersion: 2,
            visitCount: 2
        )
        let base = try SelfPassportSyncBase(
            snapshotVersion: 3,
            datasetVersion: "dataset-v1",
            schemaVersion: 1,
            historyToken: try OpaqueHistoryToken(rawValue: "history-3"),
            aggregates: aggregates
        )
        let store = M3SnapshotStore()
        let transport = M3ScriptedTransport(
            bootstraps: [m3Bootstrap(base)],
            historyPages: [
                SelfPassportHistoryPage(
                    mountainID: firstMountain,
                    snapshotVersion: 3,
                    aggregateVersionAtSnapshot: 2,
                    visits: [firstVisit, secondVisit],
                    nextContinuationToken: nil
                ),
                SelfPassportHistoryPage(
                    mountainID: firstMountain,
                    snapshotVersion: 3,
                    aggregateVersionAtSnapshot: 2,
                    visits: [firstVisit],
                    nextContinuationToken: nil
                ),
            ]
        )
        let engine = SelfPassportSyncEngine(
            store: store,
            transport: transport,
            expectedMountainIDs: Set(mountainIDs),
            expectedDatasetVersion: "dataset-v1"
        )
        _ = try await engine.bootstrap()

        let completed = try await engine.loadCompleteHistory(for: firstMountain)
        XCTAssertEqual(completed.visits.count, 2)

        do {
            _ = try await engine.loadCompleteHistory(for: firstMountain)
            XCTFail("A truncated history must not publish.")
        } catch let error as SelfPassportSyncError {
            XCTAssertEqual(error, .invalidHistoryPage)
        } catch {
            throw error
        }

        let storedSnapshot = await store.load()
        let stored = try XCTUnwrap(storedSnapshot)
        XCTAssertEqual(stored.syncBase?.completedHistory(for: firstMountain), completed)
    }

    func testCompletedHistoryAuthorizesOnlyExactRemoteDelete() async throws {
        let mountainIDs = try m3MountainIDs()
        let firstMountain = try XCTUnwrap(mountainIDs.first)
        let otherMountain = mountainIDs[1]
        let remoteVisit = try m3Visit(
            id: "00000000-0000-4000-8000-000000000251",
            mountainID: firstMountain
        )
        var aggregates = try m3Aggregates(mountainIDs: mountainIDs, visitCount: 0)
        aggregates[0] = try m3Aggregate(
            mountainID: firstMountain,
            aggregateVersion: 1,
            visitCount: 1
        )
        let history = try SelfPassportVisitHistory(
            mountainID: firstMountain,
            snapshotVersion: 4,
            aggregateVersionAtSnapshot: 1,
            visits: [remoteVisit]
        )
        let base = try SelfPassportSyncBase(
            snapshotVersion: 4,
            datasetVersion: "dataset-v1",
            schemaVersion: 1,
            historyToken: try OpaqueHistoryToken(rawValue: "history-4"),
            aggregates: aggregates,
            histories: [history]
        )
        let store = M3SnapshotStore(
            value: try LocalPassportSnapshot(
                passportState: PassportStateMachine(),
                manualVisitOutbox: ManualVisitOutboxGraph(),
                syncBase: base
            )
        )
        let engine = SelfPassportSyncEngine(
            store: store,
            transport: M3ScriptedTransport(),
            expectedMountainIDs: Set(mountainIDs),
            expectedDatasetVersion: "dataset-v1"
        )
        _ = try await engine.restore()

        let allowedMutationID = try ClientMutationID(
            rawValue: "00000000-0000-4000-8000-000000000351"
        )
        let allowed = try await engine.enqueueManualDelete(
            visitID: remoteVisit.id,
            mountainID: firstMountain,
            clientMutationID: allowedMutationID,
            at: m3Date
        )
        guard case let .enqueued(node) = allowed else {
            return XCTFail("A completed remote visit must enqueue a delete.")
        }
        XCTAssertEqual(node.request.visitID, remoteVisit.id)
        XCTAssertEqual(node.request.mountainID, firstMountain)

        do {
            _ = try await engine.enqueueManualDelete(
                visitID: remoteVisit.id,
                mountainID: otherMountain,
                clientMutationID: try ClientMutationID(
                    rawValue: "00000000-0000-4000-8000-000000000352"
                ),
                at: m3Date
            )
            XCTFail("A VisitID must not authorize deletion for another mountain.")
        } catch let error as SelfPassportSyncError {
            XCTAssertEqual(error, .remoteDeleteNotAuthorized)
        } catch {
            throw error
        }

        let storedSnapshot = await store.load()
        let stored = try XCTUnwrap(storedSnapshot)
        XCTAssertEqual(stored.manualVisitOutbox.nodes.map(\.id), [allowedMutationID])
    }

    func testPendingRemoteDeleteRecomputesStampFromCompletedHistory() async throws {
        let mountainIDs = try m3MountainIDs()
        let mountainID = try XCTUnwrap(mountainIDs.first)
        let firstVisit = try m3Visit(
            id: "00000000-0000-4000-8000-000000000261",
            mountainID: mountainID
        )
        let secondVisit = try m3Visit(
            id: "00000000-0000-4000-8000-000000000262",
            mountainID: mountainID
        )
        let firstStamp = Stamp(
            mountainID: mountainID,
            sourceVisitID: firstVisit.id,
            earnedAt: firstVisit.recordedAt,
            method: firstVisit.verificationMethod
        )
        var aggregates = try m3Aggregates(mountainIDs: mountainIDs, visitCount: 0)
        aggregates[0] = try SelfPassportAggregate(
            mountainID: mountainID,
            aggregateVersion: 2,
            visitCount: 2,
            planDisposition: nil,
            stamp: firstStamp
        )
        let history = try SelfPassportVisitHistory(
            mountainID: mountainID,
            snapshotVersion: 4,
            aggregateVersionAtSnapshot: 2,
            visits: [secondVisit, firstVisit]
        )
        let base = try SelfPassportSyncBase(
            snapshotVersion: 4,
            datasetVersion: "dataset-v1",
            schemaVersion: 1,
            historyToken: try OpaqueHistoryToken(rawValue: "history-4"),
            aggregates: aggregates,
            histories: [history]
        )
        let store = M3SnapshotStore(
            value: try LocalPassportSnapshot(
                passportState: PassportStateMachine(),
                manualVisitOutbox: ManualVisitOutboxGraph(),
                syncBase: base
            )
        )
        let engine = SelfPassportSyncEngine(
            store: store,
            transport: M3ScriptedTransport(),
            expectedMountainIDs: Set(mountainIDs),
            expectedDatasetVersion: "dataset-v1"
        )
        _ = try await engine.restore()
        _ = try await engine.enqueueManualDelete(
            visitID: firstVisit.id,
            mountainID: mountainID,
            clientMutationID: try ClientMutationID(
                rawValue: "00000000-0000-4000-8000-000000000361"
            ),
            at: m3Date
        )

        let effective = try await engine.effectiveAggregates()
        let aggregate = try XCTUnwrap(
            effective.first { $0.mountainID == mountainID }
        )
        XCTAssertEqual(aggregate.visitCount, 1)
        XCTAssertEqual(aggregate.stamp?.sourceVisitID, secondVisit.id)
        XCTAssertEqual(aggregate.stamp?.earnedAt, secondVisit.recordedAt)
    }

    func testRegressiveChangeAggregateDoesNotOverwriteBaseBeforeResync() async throws {
        let mountainIDs = try m3MountainIDs()
        let firstMountain = try XCTUnwrap(mountainIDs.first)
        let base = try m3Base(
            snapshotVersion: 1,
            mountainIDs: mountainIDs,
            visitCount: 0
        )
        let regressiveAggregate = try m3Aggregate(
            mountainID: firstMountain,
            aggregateVersion: 0,
            visitCount: 0
        )
        let store = M3SnapshotStore()
        let transport = M3ScriptedTransport(
            bootstraps: [m3Bootstrap(base)],
            changePages: [
                SelfPassportChangePage(
                    afterSnapshotVersion: 1,
                    changes: [
                        SelfPassportChange(
                            globalSnapshotVersion: 2,
                            aggregate: regressiveAggregate
                        ),
                    ],
                    nextContinuationToken: nil,
                    nextSnapshotVersion: 2,
                    historyToken: try OpaqueHistoryToken(rawValue: "history-2")
                ),
            ]
        )
        let engine = SelfPassportSyncEngine(
            store: store,
            transport: transport,
            expectedMountainIDs: Set(mountainIDs),
            expectedDatasetVersion: "dataset-v1"
        )
        _ = try await engine.bootstrap()

        do {
            _ = try await engine.refreshChanges()
            XCTFail("A regressive aggregate must force a full resync.")
        } catch let error as SelfPassportTransportFailure {
            XCTAssertEqual(error, .transient)
        } catch {
            throw error
        }

        let storedSnapshot = await store.load()
        let stored = try XCTUnwrap(storedSnapshot)
        XCTAssertEqual(stored.syncBase, base)
        XCTAssertEqual(stored.writePauseReason, .continuity)
    }
    func testChangeVersionGapDoesNotOverwriteBaseBeforeResync() async throws {
        let mountainIDs = try m3MountainIDs()
        let firstMountain = try XCTUnwrap(mountainIDs.first)
        let base = try m3Base(
            snapshotVersion: 1,
            mountainIDs: mountainIDs,
            visitCount: 0
        )
        let advancedAggregate = try m3Aggregate(
            mountainID: firstMountain,
            aggregateVersion: 1,
            visitCount: 1
        )
        let store = M3SnapshotStore()
        let transport = M3ScriptedTransport(
            bootstraps: [m3Bootstrap(base)],
            changePages: [
                SelfPassportChangePage(
                    afterSnapshotVersion: 1,
                    changes: [
                        SelfPassportChange(
                            globalSnapshotVersion: 3,
                            aggregate: advancedAggregate
                        ),
                    ],
                    nextContinuationToken: nil,
                    nextSnapshotVersion: 3,
                    historyToken: try OpaqueHistoryToken(rawValue: "history-3")
                ),
            ]
        )
        let engine = SelfPassportSyncEngine(
            store: store,
            transport: transport,
            expectedMountainIDs: Set(mountainIDs),
            expectedDatasetVersion: "dataset-v1"
        )
        _ = try await engine.bootstrap()

        do {
            _ = try await engine.refreshChanges()
            XCTFail("A change version gap must force a full resync.")
        } catch let error as SelfPassportTransportFailure {
            XCTAssertEqual(error, .transient)
        } catch {
            throw error
        }

        let storedSnapshot = await store.load()
        let stored = try XCTUnwrap(storedSnapshot)
        XCTAssertEqual(stored.syncBase, base)
        XCTAssertEqual(stored.writePauseReason, .continuity)
    }

    func testReceiptContinuityFailureRetainsImmutableRequest() async throws {
        let mountainIDs = try m3MountainIDs()
        let firstMountain = try XCTUnwrap(mountainIDs.first)
        let base = try m3Base(
            snapshotVersion: 1,
            mountainIDs: mountainIDs,
            visitCount: 0
        )
        let visit = try m3Visit(
            id: "00000000-0000-4000-8000-000000000261",
            mountainID: firstMountain
        )
        let mutationID = try ClientMutationID(
            rawValue: "00000000-0000-4000-8000-000000000361"
        )
        let receipt = SelfPassportMutationReceipt(
            clientMutationID: mutationID,
            operation: .create,
            visitID: visit.id,
            mountainID: firstMountain,
            aggregate: try m3Aggregate(
                mountainID: firstMountain,
                aggregateVersion: 0,
                visitCount: 1
            ),
            snapshotVersion: 2,
            historyToken: try OpaqueHistoryToken(rawValue: "history-2")
        )
        let store = M3SnapshotStore()
        let engine = SelfPassportSyncEngine(
            store: store,
            transport: M3ScriptedTransport(
                bootstraps: [m3Bootstrap(base)],
                uploadResults: [.receipt(receipt)]
            ),
            expectedMountainIDs: Set(mountainIDs),
            expectedDatasetVersion: "dataset-v1"
        )
        _ = try await engine.bootstrap()
        let node = try await engine.enqueueManualCreate(
            visit,
            clientMutationID: mutationID,
            at: m3Date
        )

        do {
            _ = try await engine.uploadNextManualOutboxOperation(at: m3Date)
            XCTFail("A non-increasing receipt aggregate must not be acknowledged.")
        } catch let error as SelfPassportTransportFailure {
            XCTAssertEqual(error, .fullRefreshRequired)
        } catch {
            throw error
        }

        let storedSnapshot = await store.load()
        let stored = try XCTUnwrap(storedSnapshot)
        XCTAssertEqual(stored.manualVisitOutbox.nodes.first?.id, mutationID)
        XCTAssertEqual(stored.manualVisitOutbox.nodes.first?.state, .queued)
        XCTAssertEqual(stored.manualVisitOutbox.nodes.first?.request.requestBytes, node.request.requestBytes)
        XCTAssertEqual(stored.syncBase, base)
        XCTAssertEqual(stored.writePauseReason, .continuity)
    }

    func testReceiptPersistenceFailureRetainsImmutableRequest() async throws {
        let mountainIDs = try m3MountainIDs()
        let firstMountain = try XCTUnwrap(mountainIDs.first)
        let base = try m3Base(
            snapshotVersion: 1,
            mountainIDs: mountainIDs,
            visitCount: 0
        )
        let visit = try m3Visit(
            id: "00000000-0000-4000-8000-000000000271",
            mountainID: firstMountain
        )
        let mutationID = try ClientMutationID(
            rawValue: "00000000-0000-4000-8000-000000000371"
        )
        let receipt = SelfPassportMutationReceipt(
            clientMutationID: mutationID,
            operation: .create,
            visitID: visit.id,
            mountainID: firstMountain,
            aggregate: try m3Aggregate(
                mountainID: firstMountain,
                aggregateVersion: 1,
                visitCount: 1
            ),
            snapshotVersion: 2,
            historyToken: try OpaqueHistoryToken(rawValue: "history-2")
        )
        let store = M3SnapshotStore(failingSaveCounts: [4])
        let engine = SelfPassportSyncEngine(
            store: store,
            transport: M3ScriptedTransport(
                bootstraps: [m3Bootstrap(base)],
                uploadResults: [.receipt(receipt)]
            ),
            expectedMountainIDs: Set(mountainIDs),
            expectedDatasetVersion: "dataset-v1"
        )
        _ = try await engine.bootstrap()
        let node = try await engine.enqueueManualCreate(
            visit,
            clientMutationID: mutationID,
            at: m3Date
        )

        do {
            _ = try await engine.uploadNextManualOutboxOperation(at: m3Date)
            XCTFail("A failed acknowledgement save must retain the immutable request.")
        } catch is M3SnapshotStoreError {
        } catch {
            throw error
        }

        let storedSnapshot = await store.load()
        let stored = try XCTUnwrap(storedSnapshot)
        XCTAssertEqual(stored.manualVisitOutbox.nodes.first?.id, mutationID)
        XCTAssertEqual(stored.manualVisitOutbox.nodes.first?.state, .queued)
        XCTAssertEqual(stored.manualVisitOutbox.nodes.first?.request.requestBytes, node.request.requestBytes)
        XCTAssertEqual(stored.syncBase, base)
    }

    func testWritePauseSurvivesEngineReconstructionUntilExplicitResume() async throws {
        let mountainIDs = try m3MountainIDs()
        let firstMountain = try XCTUnwrap(mountainIDs.first)
        let base = try m3Base(
            snapshotVersion: 1,
            mountainIDs: mountainIDs,
            visitCount: 0
        )
        let visit = try m3Visit(
            id: "00000000-0000-4000-8000-000000000281",
            mountainID: firstMountain
        )
        let mutationID = try ClientMutationID(
            rawValue: "00000000-0000-4000-8000-000000000381"
        )
        let store = M3SnapshotStore()
        let firstEngine = SelfPassportSyncEngine(
            store: store,
            transport: M3ScriptedTransport(
                bootstraps: [m3Bootstrap(base)],
                uploadResults: [.failure(.unauthenticated)]
            ),
            expectedMountainIDs: Set(mountainIDs),
            expectedDatasetVersion: "dataset-v1"
        )
        _ = try await firstEngine.bootstrap()
        _ = try await firstEngine.enqueueManualCreate(
            visit,
            clientMutationID: mutationID,
            at: m3Date
        )
        do {
            _ = try await firstEngine.uploadNextManualOutboxOperation(at: m3Date)
            XCTFail("An authentication failure must persist a write pause.")
        } catch let error as SelfPassportTransportFailure {
            XCTAssertEqual(error, .unauthenticated)
        } catch {
            throw error
        }

        let secondEngine = SelfPassportSyncEngine(
            store: store,
            transport: M3ScriptedTransport(bootstraps: [m3Bootstrap(base)]),
            expectedMountainIDs: Set(mountainIDs),
            expectedDatasetVersion: "dataset-v1"
        )
        _ = try await secondEngine.restore()
        let restoredPauseReason = await secondEngine.writePauseReason()
        XCTAssertEqual(restoredPauseReason, .unauthenticated)
        do {
            _ = try await secondEngine.uploadNextManualOutboxOperation(at: m3Date)
            XCTFail("A reconstructed write pause must block the retained request.")
        } catch let error as SelfPassportSyncError {
            XCTAssertEqual(error, .writePaused(.unauthenticated))
        } catch {
            throw error
        }

        _ = try await secondEngine.bootstrap()
        let pauseReasonAfterBootstrap = await secondEngine.writePauseReason()
        XCTAssertEqual(pauseReasonAfterBootstrap, .unauthenticated)

        try await secondEngine.resumeWrites()
        let pauseReasonAfterResume = await secondEngine.writePauseReason()
        XCTAssertNil(pauseReasonAfterResume)

        let thirdEngine = SelfPassportSyncEngine(
            store: store,
            transport: M3ScriptedTransport(),
            expectedMountainIDs: Set(mountainIDs),
            expectedDatasetVersion: "dataset-v1"
        )
        _ = try await thirdEngine.restore()
        let restoredClearedPauseReason = await thirdEngine.writePauseReason()
        XCTAssertNil(restoredClearedPauseReason)
    }
    func testOfflinePlanEnqueueSurvivesEncryptedReload() async throws {
        let mountainIDs = try m3MountainIDs()
        let mountainID = try XCTUnwrap(mountainIDs.first)
        let base = try m3Base(
            snapshotVersion: 1,
            mountainIDs: mountainIDs,
            visitCount: 0
        )
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let fileURL = directory.appendingPathComponent("passport.bin")
        let key = try LocalPassportEncryptionKey(data: Data(repeating: 0xA5, count: 32))
        let store = EncryptedLocalPassportStore(fileURL: fileURL, key: key)
        try await store.save(
            LocalPassportSnapshot(
                passportState: PassportStateMachine(),
                manualVisitOutbox: ManualVisitOutboxGraph(),
                syncBase: base
            )
        )
        let engine = SelfPassportSyncEngine(
            store: store,
            transport: M3ScriptedTransport(),
            expectedMountainIDs: Set(mountainIDs),
            expectedDatasetVersion: "dataset-v1"
        )
        _ = try await engine.restore()

        let addID = try ClientMutationID(
            rawValue: "00000000-0000-4000-8000-000000000401"
        )
        let removeID = try ClientMutationID(
            rawValue: "00000000-0000-4000-8000-000000000402"
        )
        let add = try await engine.enqueuePlanAdd(
            for: mountainID,
            clientMutationID: addID,
            at: m3Date
        )
        let remove = try await engine.enqueuePlanRemove(
            for: mountainID,
            clientMutationID: removeID,
            at: m3Date.addingTimeInterval(1)
        )

        let encrypted = try Data(contentsOf: fileURL)
        XCTAssertNil(encrypted.range(of: Data(addID.rawValue.utf8)))
        let loadedSnapshot = try await store.load()
        let reloaded = try XCTUnwrap(loadedSnapshot)
        XCTAssertEqual(reloaded.planMutationOutbox, [add, remove])
        XCTAssertTrue(reloaded.planMutationOutbox.allSatisfy { $0.state == .queued })
    }

    func testEffectiveReplayPreservesCrossOutboxEnqueueOrder() async throws {
        let mountainIDs = try m3MountainIDs()
        let mountainID = try XCTUnwrap(mountainIDs.first)
        let base = try m3Base(
            snapshotVersion: 1,
            mountainIDs: mountainIDs,
            visitCount: 0
        )
        let store = M3SnapshotStore(
            value: try LocalPassportSnapshot(
                passportState: PassportStateMachine(),
                manualVisitOutbox: ManualVisitOutboxGraph(),
                syncBase: base
            )
        )
        let engine = SelfPassportSyncEngine(
            store: store,
            transport: M3ScriptedTransport(),
            expectedMountainIDs: Set(mountainIDs),
            expectedDatasetVersion: "dataset-v1"
        )
        _ = try await engine.restore()
        _ = try await engine.enqueuePlanAdd(
            for: mountainID,
            clientMutationID: try ClientMutationID(
                rawValue: "00000000-0000-4000-8000-000000000413"
            ),
            at: m3Date
        )
        let visit = try m3Visit(
            id: "00000000-0000-4000-8000-000000000214",
            mountainID: mountainID
        )
        _ = try await engine.enqueueManualCreate(
            visit,
            clientMutationID: try ClientMutationID(
                rawValue: "00000000-0000-4000-8000-000000000414"
            ),
            at: m3Date.addingTimeInterval(1)
        )

        let effective = try await engine.effectiveAggregates()
        let aggregate = try XCTUnwrap(
            effective.first { $0.mountainID == mountainID }
        )
        XCTAssertEqual(aggregate.visitCount, 1)
        XCTAssertEqual(
            aggregate.planDisposition,
            .active(.autoCompleted(firstVisitID: visit.id))
        )
        XCTAssertEqual(aggregate.stamp?.sourceVisitID, visit.id)
    }
    func testPendingPlanMutationsReplayInSequenceOverCanonicalBase() async throws {
        let mountainIDs = try m3MountainIDs()
        let mountainID = try XCTUnwrap(mountainIDs.first)
        let base = try m3Base(
            snapshotVersion: 1,
            mountainIDs: mountainIDs,
            visitCount: 0
        )
        let store = M3SnapshotStore(
            value: try LocalPassportSnapshot(
                passportState: PassportStateMachine(),
                manualVisitOutbox: ManualVisitOutboxGraph(),
                syncBase: base
            )
        )
        let engine = SelfPassportSyncEngine(
            store: store,
            transport: M3ScriptedTransport(),
            expectedMountainIDs: Set(mountainIDs),
            expectedDatasetVersion: "dataset-v1"
        )
        _ = try await engine.restore()

        let add = try await engine.enqueuePlanAdd(
            for: mountainID,
            clientMutationID: try ClientMutationID(
                rawValue: "00000000-0000-4000-8000-000000000411"
            ),
            at: m3Date
        )
        let afterAdd = try await engine.effectiveAggregates()
        XCTAssertEqual(
            afterAdd.first { $0.mountainID == mountainID }?.planDisposition,
            .active(.manual)
        )

        let remove = try await engine.enqueuePlanRemove(
            for: mountainID,
            clientMutationID: try ClientMutationID(
                rawValue: "00000000-0000-4000-8000-000000000412"
            ),
            at: m3Date.addingTimeInterval(1)
        )
        let afterRemove = try await engine.effectiveAggregates()
        XCTAssertEqual(
            afterRemove.first { $0.mountainID == mountainID }?.planDisposition,
            .manuallyRemoved
        )
        let storedSnapshot = await store.load()
        let stored = try XCTUnwrap(storedSnapshot)
        XCTAssertEqual(stored.planMutationOutbox, [add, remove])
    }

    func testExactPlanReceiptAcknowledgesAndRebasesCanonicalBase() async throws {
        let mountainIDs = try m3MountainIDs()
        let mountainID = try XCTUnwrap(mountainIDs.first)
        let base = try m3Base(
            snapshotVersion: 1,
            mountainIDs: mountainIDs,
            visitCount: 0
        )
        let mutationID = try ClientMutationID(
            rawValue: "00000000-0000-4000-8000-000000000421"
        )
        let receipt = SelfPassportPlanMutationReceipt(
            clientMutationID: mutationID,
            operation: .add,
            mountainID: mountainID,
            aggregate: try SelfPassportAggregate(
                mountainID: mountainID,
                aggregateVersion: 1,
                visitCount: 0,
                planDisposition: .active(.manual),
                stamp: nil
            ),
            snapshotVersion: 2,
            historyToken: try OpaqueHistoryToken(rawValue: "history-2")
        )
        let store = M3SnapshotStore()
        let engine = SelfPassportSyncEngine(
            store: store,
            transport: M3ScriptedTransport(
                bootstraps: [m3Bootstrap(base)],
                planUploadResults: [.receipt(receipt)]
            ),
            expectedMountainIDs: Set(mountainIDs),
            expectedDatasetVersion: "dataset-v1"
        )
        _ = try await engine.bootstrap()
        _ = try await engine.enqueuePlanAdd(
            for: mountainID,
            clientMutationID: mutationID,
            at: m3Date
        )

        let acknowledged = try await engine.uploadNextPlanOutboxOperation()
        XCTAssertEqual(acknowledged, receipt)
        let storedSnapshot = await store.load()
        let stored = try XCTUnwrap(storedSnapshot)
        XCTAssertTrue(stored.planMutationOutbox.isEmpty)
        XCTAssertEqual(stored.syncBase?.snapshotVersion, 2)
        XCTAssertEqual(stored.syncBase?.aggregate(for: mountainID), receipt.aggregate)
    }

    func testFreshEngineHonorsPersistedWriteHoldBeforeEnqueue() async throws {
        let mountainIDs = try m3MountainIDs()
        let mountainID = try XCTUnwrap(mountainIDs.first)
        let heldSnapshot = try LocalPassportSnapshot(
            passportState: PassportStateMachine(),
            manualVisitOutbox: ManualVisitOutboxGraph(),
            syncBase: try m3Base(
                snapshotVersion: 1,
                mountainIDs: mountainIDs,
                visitCount: 0
            ),
            writePauseReason: .mutationRejected
        )
        let store = M3SnapshotStore(value: heldSnapshot)
        let engine = SelfPassportSyncEngine(
            store: store,
            transport: M3ScriptedTransport(),
            expectedMountainIDs: Set(mountainIDs),
            expectedDatasetVersion: "dataset-v1"
        )

        do {
            _ = try await engine.enqueuePlanAdd(
                for: mountainID,
                clientMutationID: try ClientMutationID(
                    rawValue: "00000000-0000-4000-8000-000000000415"
                )
            )
            XCTFail("A fresh engine must honor the durable write hold.")
        } catch let error as SelfPassportSyncError {
            XCTAssertEqual(error, .writePaused(.mutationRejected))
        }
        let storedSnapshot = await store.load()
        XCTAssertEqual(storedSnapshot, heldSnapshot)
    }
    func testPlanUploadFailuresPreserveQueuedWork() async throws {
        let mountainIDs = try m3MountainIDs()
        let mountainID = try XCTUnwrap(mountainIDs.first)
        let base = try m3Base(
            snapshotVersion: 1,
            mountainIDs: mountainIDs,
            visitCount: 0
        )
        let mutationID = try ClientMutationID(
            rawValue: "00000000-0000-4000-8000-000000000431"
        )
        let store = M3SnapshotStore()
        let engine = SelfPassportSyncEngine(
            store: store,
            transport: M3ScriptedTransport(
                bootstraps: [m3Bootstrap(base), m3Bootstrap(base)],
                planUploadResults: [
                    .failure(.transient),
                    .failure(.unauthenticated),
                    .failure(.mutationRejected),
                ]
            ),
            expectedMountainIDs: Set(mountainIDs),
            expectedDatasetVersion: "dataset-v1"
        )
        _ = try await engine.bootstrap()
        let node = try await engine.enqueuePlanAdd(
            for: mountainID,
            clientMutationID: mutationID,
            at: m3Date
        )

        do {
            _ = try await engine.uploadNextPlanOutboxOperation()
            XCTFail("A transient failure must retain the queued plan mutation.")
        } catch let error as SelfPassportTransportFailure {
            XCTAssertEqual(error, .transient)
        } catch {
            throw error
        }
        let transientSnapshot = await store.load()
        let afterTransient = try XCTUnwrap(transientSnapshot)
        XCTAssertEqual(afterTransient.planMutationOutbox, [node])
        XCTAssertNil(afterTransient.writePauseReason)

        do {
            _ = try await engine.uploadNextPlanOutboxOperation()
            XCTFail("An authentication failure must retain the queued plan mutation.")
        } catch let error as SelfPassportTransportFailure {
            XCTAssertEqual(error, .unauthenticated)
        } catch {
            throw error
        }
        let authenticationFailureSnapshot = await store.load()
        let afterAuthenticationFailure = try XCTUnwrap(authenticationFailureSnapshot)
        XCTAssertEqual(afterAuthenticationFailure.planMutationOutbox, [node])
        XCTAssertEqual(afterAuthenticationFailure.writePauseReason, .unauthenticated)

        try await engine.resumeWrites()
        do {
            _ = try await engine.uploadNextPlanOutboxOperation()
            XCTFail("A deterministic rejection must enter a durable continuity hold.")
        } catch let error as SelfPassportTransportFailure {
            XCTAssertEqual(error, .mutationRejected)
        }
        let storedAfterRejection = await store.load()
        let rejectionSnapshot = try XCTUnwrap(storedAfterRejection)
        XCTAssertEqual(rejectionSnapshot.planMutationOutbox, [node])
        XCTAssertEqual(rejectionSnapshot.writePauseReason, .mutationRejected)
        _ = try await engine.bootstrap()
        let pauseAfterBootstrap = await engine.writePauseReason()
        XCTAssertEqual(pauseAfterBootstrap, .mutationRejected)
    }
    func testUnifiedOutboxUploadsOlderPlanBeforeManualVisit() async throws {
        let mountainIDs = try m3MountainIDs()
        let mountainID = try XCTUnwrap(mountainIDs.first)
        let base = try m3Base(
            snapshotVersion: 1,
            mountainIDs: mountainIDs,
            visitCount: 0
        )
        let transport = M3ScriptedTransport(
            planUploadResults: [.failure(.transient)]
        )
        let store = M3SnapshotStore(
            value: try LocalPassportSnapshot(
                passportState: PassportStateMachine(),
                manualVisitOutbox: ManualVisitOutboxGraph(),
                syncBase: base
            )
        )
        let engine = SelfPassportSyncEngine(
            store: store,
            transport: transport,
            expectedMountainIDs: Set(mountainIDs),
            expectedDatasetVersion: "dataset-v1"
        )
        _ = try await engine.restore()
        _ = try await engine.enqueuePlanAdd(
            for: mountainID,
            clientMutationID: try ClientMutationID(
                rawValue: "00000000-0000-4000-8000-000000000441"
            ),
            at: m3Date
        )
        _ = try await engine.enqueueManualCreate(
            try m3Visit(
                id: "00000000-0000-4000-8000-000000000541",
                mountainID: mountainID
            ),
            clientMutationID: try ClientMutationID(
                rawValue: "00000000-0000-4000-8000-000000000442"
            ),
            at: m3Date.addingTimeInterval(1)
        )

        do {
            _ = try await engine.uploadNextOutboxOperation(
                at: m3Date.addingTimeInterval(2)
            )
            XCTFail("The scripted plan upload must fail after proving dispatch order.")
        } catch let error as SelfPassportTransportFailure {
            XCTAssertEqual(error, .transient)
        }
        let uploadOrder = await transport.recordedUploadOrder()
        XCTAssertEqual(uploadOrder, ["plan"])
    }

    func testUnifiedOutboxPreservesOlderManualVisitOrderAfterRestart() async throws {
        let mountainIDs = try m3MountainIDs()
        let mountainID = try XCTUnwrap(mountainIDs.first)
        let planMountainID = mountainIDs[1]
        let base = try m3Base(
            snapshotVersion: 1,
            mountainIDs: mountainIDs,
            visitCount: 0
        )
        let store = M3SnapshotStore(
            value: try LocalPassportSnapshot(
                passportState: PassportStateMachine(),
                manualVisitOutbox: ManualVisitOutboxGraph(),
                syncBase: base
            )
        )
        let enqueueEngine = SelfPassportSyncEngine(
            store: store,
            transport: M3ScriptedTransport(),
            expectedMountainIDs: Set(mountainIDs),
            expectedDatasetVersion: "dataset-v1"
        )
        _ = try await enqueueEngine.restore()
        _ = try await enqueueEngine.enqueueManualCreate(
            try m3Visit(
                id: "00000000-0000-4000-8000-000000000551",
                mountainID: mountainID
            ),
            clientMutationID: try ClientMutationID(
                rawValue: "00000000-0000-4000-8000-000000000451"
            ),
            at: m3Date
        )
        _ = try await enqueueEngine.enqueuePlanAdd(
            for: planMountainID,
            clientMutationID: try ClientMutationID(
                rawValue: "00000000-0000-4000-8000-000000000452"
            ),
            at: m3Date.addingTimeInterval(1)
        )

        let transport = M3ScriptedTransport(
            uploadResults: [.failure(.transient)]
        )
        let restartedEngine = SelfPassportSyncEngine(
            store: store,
            transport: transport,
            expectedMountainIDs: Set(mountainIDs),
            expectedDatasetVersion: "dataset-v1"
        )
        _ = try await restartedEngine.restore()

        do {
            _ = try await restartedEngine.uploadNextOutboxOperation(
                at: m3Date.addingTimeInterval(2)
            )
            XCTFail("The scripted manual upload must fail after proving dispatch order.")
        } catch let error as SelfPassportTransportFailure {
            XCTAssertEqual(error, .transient)
        }
        let uploadOrder = await transport.recordedUploadOrder()
        XCTAssertEqual(uploadOrder, ["manual"])
    }

    func testUnifiedPlanOnlyDispatchUsesDeterministicSelectedMutation() async throws {
        let mountainIDs = try m3MountainIDs()
        let base = try m3Base(
            snapshotVersion: 1,
            mountainIDs: mountainIDs,
            visitCount: 0
        )
        let lowerID = try ClientMutationID(
            rawValue: "00000000-0000-4000-8000-000000000461"
        )
        let higherID = try ClientMutationID(
            rawValue: "00000000-0000-4000-8000-000000000462"
        )
        let higher = PlanMutationOutboxNode(
            clientMutationID: higherID,
            mountainID: mountainIDs[1],
            operation: .add,
            enqueuedAt: m3Date
        )
        let lower = PlanMutationOutboxNode(
            clientMutationID: lowerID,
            mountainID: mountainIDs[0],
            operation: .add,
            enqueuedAt: m3Date
        )
        let store = M3SnapshotStore(
            value: try LocalPassportSnapshot(
                passportState: PassportStateMachine(),
                manualVisitOutbox: ManualVisitOutboxGraph(),
                planMutationOutbox: [higher, lower],
                syncBase: base
            )
        )
        let transport = M3ScriptedTransport(
            planUploadResults: [.failure(.transient)]
        )
        let engine = SelfPassportSyncEngine(
            store: store,
            transport: transport,
            expectedMountainIDs: Set(mountainIDs),
            expectedDatasetVersion: "dataset-v1"
        )
        _ = try await engine.restore()

        do {
            _ = try await engine.uploadNextOutboxOperation(
                at: m3Date.addingTimeInterval(1)
            )
            XCTFail("The scripted upload must fail after recording the selected mutation.")
        } catch let error as SelfPassportTransportFailure {
            XCTAssertEqual(error, .transient)
        }
        let planMutationIDs = await transport.recordedPlanMutationIDs()
        XCTAssertEqual(planMutationIDs, [lowerID])
    }

    func testEncryptedLocalPassportSnapshotRoundTripPreservesActorID() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let actorID = try XCTUnwrap(
            UUID(uuidString: "00000000-0000-4000-8000-000000000501")
        )
        let snapshot = try LocalPassportSnapshot(
            passportState: PassportStateMachine(),
            manualVisitOutbox: ManualVisitOutboxGraph(),
            actorID: actorID
        )
        let store = EncryptedLocalPassportStore(
            fileURL: directory.appendingPathComponent("passport.bin"),
            key: try LocalPassportEncryptionKey(data: Data(repeating: 0xA5, count: 32))
        )

        try await store.save(snapshot)

        let loaded = try await store.load()
        let restored = try XCTUnwrap(loaded)
        XCTAssertEqual(restored, snapshot)
        XCTAssertEqual(restored.actorID, actorID)
    }

    func testLocalPassportSnapshotDecodesLegacyPayloadWithoutPlanOutboxOrActorID() throws {
        let encoded = try JSONEncoder().encode(
            LegacyLocalPassportSnapshot(
                passportState: PassportStateMachine(),
                manualVisitOutbox: ManualVisitOutboxGraph()
            )
        )

        let snapshot = try JSONDecoder().decode(LocalPassportSnapshot.self, from: encoded)
        XCTAssertTrue(snapshot.planMutationOutbox.isEmpty)
        XCTAssertNil(snapshot.actorID)
    }

    func testCurrentSnapshotRejectsMissingDurableFields() throws {
        let snapshot = try LocalPassportSnapshot(
            passportState: PassportStateMachine(),
            manualVisitOutbox: ManualVisitOutboxGraph()
        )
        let encoded = try JSONEncoder().encode(snapshot)
        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
        object.removeValue(forKey: "planMutationOutbox")
        let damaged = try JSONSerialization.data(withJSONObject: object)

        XCTAssertThrowsError(
            try JSONDecoder().decode(LocalPassportSnapshot.self, from: damaged)
        ) { error in
            XCTAssertEqual(
                error as? LocalPassportSnapshotError,
                .invalidSchemaVersion
            )
        }

        var extraFieldObject = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
        extraFieldObject["unexpected"] = true
        let extraFieldData = try JSONSerialization.data(
            withJSONObject: extraFieldObject
        )
        XCTAssertThrowsError(
            try JSONDecoder().decode(
                LocalPassportSnapshot.self,
                from: extraFieldData
            )
        ) { error in
            XCTAssertEqual(
                error as? LocalPassportSnapshotError,
                .invalidSchemaVersion
            )
        }
    }
    // GPS-005
    func testGPSVerifiedVisitsNeverQueueOrPersistRawSampleFields() throws {
        let mountain = try MountainID(rawValue: "gps-mountain")
        let visit = VisitRecord(
            id: try VisitID(rawValue: "00000000-0000-4000-8000-000000000601"),
            mountainID: mountain,
            visitedAt: Date(timeIntervalSince1970: 1_700_000_000),
            recordedAt: Date(timeIntervalSince1970: 1_700_000_000),
            verificationMethod: .gpsVerified
        )
        var outbox = try ManualVisitOutboxGraph()

        XCTAssertThrowsError(
            try outbox.enqueueCreate(
                visit,
                clientMutationID: try ClientMutationID(
                    rawValue: "00000000-0000-4000-8000-000000000602"
                )
            )
        ) { error in
            XCTAssertEqual(
                error as? ManualVisitOutboxError,
                .gpsVerifiedVisitsAreNotQueueable
            )
        }

        var passport = PassportStateMachine()
        try passport.recordVisit(visit)
        let snapshot = try LocalPassportSnapshot(
            passportState: passport,
            manualVisitOutbox: outbox
        )
        let encoded = try JSONEncoder().encode(snapshot)
        let JSON = try XCTUnwrap(String(data: encoded, encoding: .utf8))

        XCTAssertTrue(snapshot.manualVisitOutbox.nodes.isEmpty)
        XCTAssertFalse(JSON.contains("latitude"))
        XCTAssertFalse(JSON.contains("longitude"))
        XCTAssertFalse(JSON.contains("horizontalAccuracy"))
        XCTAssertFalse(JSON.contains("sampledAt"))
    }

    func testGPSVerifiedVisitConvergesHistoryProjectionAndSyncBase() async throws {
        let mountainIDs = try m3MountainIDs()
        let mountain = try XCTUnwrap(mountainIDs.first)
        let visit = VisitRecord(
            id: try VisitID(rawValue: "00000000-0000-4000-8000-000000000611"),
            mountainID: mountain,
            visitedAt: m3Date.addingTimeInterval(-60),
            recordedAt: m3Date,
            verificationMethod: .gpsVerified
        )
        let aggregate = try SelfPassportAggregate(
            mountainID: mountain,
            aggregateVersion: 1,
            visitCount: 1,
            planDisposition: nil,
            stamp: Stamp(
                mountainID: mountain,
                sourceVisitID: visit.id,
                earnedAt: visit.recordedAt,
                method: .gpsVerified
            )
        )
        let initialBase = try m3Base(
            snapshotVersion: 0,
            mountainIDs: mountainIDs,
            visitCount: 0
        )
        let receipt = GPSVisitVerificationReceipt(
            clientMutationID: try ClientMutationID(
                rawValue: "00000000-0000-4000-8000-000000000612"
            ),
            visitID: visit.id,
            mountainID: mountain,
            aggregate: aggregate,
            snapshotVersion: 1,
            historyToken: try OpaqueHistoryToken(rawValue: "history-1")
        )
        let transport = M3ScriptedTransport(
            bootstraps: [m3Bootstrap(initialBase)],
            historyPages: [
                SelfPassportHistoryPage(
                    mountainID: mountain,
                    snapshotVersion: 1,
                    aggregateVersionAtSnapshot: 1,
                    visits: [visit],
                    nextContinuationToken: nil
                ),
            ],
            gpsResults: [.outcome(.gpsVerified(receipt))]
        )
        let store = M3SnapshotStore()
        let engine = SelfPassportSyncEngine(
            store: store,
            transport: transport,
            expectedMountainIDs: Set(mountainIDs),
            expectedDatasetVersion: "dataset-v1"
        )

        _ = try await engine.bootstrap()
        let outcome = try await engine.verifyGPSVisit(
            mountainID: mountain,
            visitID: visit.id,
            visitedAt: visit.visitedAt,
            clientMutationID: receipt.clientMutationID,
            latitude: 37,
            longitude: 127,
            horizontalAccuracyMeters: 100,
            sampledAt: visit.recordedAt
        )

        XCTAssertEqual(outcome, GPSVisitVerificationOutcome.gpsVerified(receipt))
        let stored = await store.load()
        let persisted = try XCTUnwrap(stored)
        XCTAssertTrue(persisted.manualVisitOutbox.nodes.isEmpty)
        XCTAssertEqual(
            persisted.syncBase?.completedHistory(for: mountain)?.visits,
            [visit]
        )
        XCTAssertEqual(
            persisted.passportState.projection(for: mountain)?.history,
            [visit]
        )
        XCTAssertEqual(
            persisted.syncBase?.aggregate(for: mountain)?.stamp?.method,
            .gpsVerified
        )
    }
    func testGPSConflictPreservesM3WriteHold() async throws {
        let mountainIDs = try m3MountainIDs()
        let mountain = try XCTUnwrap(mountainIDs.first)
        let base = try m3Base(
            snapshotVersion: 0,
            mountainIDs: mountainIDs,
            visitCount: 0
        )
        let transport = M3ScriptedTransport(
            bootstraps: [m3Bootstrap(base)],
            gpsResults: [.failure(.mutationConflict)]
        )
        let store = M3SnapshotStore()
        let engine = SelfPassportSyncEngine(
            store: store,
            transport: transport,
            expectedMountainIDs: Set(mountainIDs),
            expectedDatasetVersion: "dataset-v1"
        )

        _ = try await engine.bootstrap()
        do {
            _ = try await engine.verifyGPSVisit(
                mountainID: mountain,
                visitID: try VisitID(rawValue: "00000000-0000-4000-8000-000000000621"),
                visitedAt: m3Date,
                clientMutationID: try ClientMutationID(
                    rawValue: "00000000-0000-4000-8000-000000000622"
                ),
                latitude: 37,
                longitude: 127,
                horizontalAccuracyMeters: 1,
                sampledAt: m3Date
            )
            XCTFail("A GPS mutation conflict must fail closed.")
        } catch let error as SelfPassportTransportFailure {
            XCTAssertEqual(error, .mutationConflict)
        }
        let pauseReason = await engine.writePauseReason()
        XCTAssertEqual(pauseReason, .mutationConflict)
        let stored = await store.load()
        XCTAssertEqual(stored?.writePauseReason, .mutationConflict)
        XCTAssertTrue(stored?.manualVisitOutbox.nodes.isEmpty ?? false)
    }

    private func m3MountainIDs() throws -> [MountainID] {
        try (0..<100).map {
            try MountainID(rawValue: String(format: "m3-mountain-%03d", $0))
        }
    }

    private func m3Aggregates(
        mountainIDs: [MountainID],
        visitCount: Int
    ) throws -> [SelfPassportAggregate] {
        try mountainIDs.map {
            try m3Aggregate(
                mountainID: $0,
                aggregateVersion: 0,
                visitCount: visitCount
            )
        }
    }

    private func m3Aggregate(
        mountainID: MountainID,
        aggregateVersion: Int64,
        visitCount: Int
    ) throws -> SelfPassportAggregate {
        let stamp: Stamp?
        if visitCount > 0 {
            let sourceVisitID = try VisitID(
                rawValue: "00000000-0000-4000-8000-000000000099"
            )
            stamp = Stamp(
                mountainID: mountainID,
                sourceVisitID: sourceVisitID,
                earnedAt: m3Date,
                method: .manual
            )
        } else {
            stamp = nil
        }
        return try SelfPassportAggregate(
            mountainID: mountainID,
            aggregateVersion: aggregateVersion,
            visitCount: visitCount,
            planDisposition: nil,
            stamp: stamp
        )
    }

    private func m3Base(
        snapshotVersion: Int64,
        mountainIDs: [MountainID],
        visitCount: Int
    ) throws -> SelfPassportSyncBase {
        try SelfPassportSyncBase(
            snapshotVersion: snapshotVersion,
            datasetVersion: "dataset-v1",
            schemaVersion: 1,
            historyToken: try OpaqueHistoryToken(
                rawValue: "history-\(snapshotVersion)"
            ),
            aggregates: try m3Aggregates(
                mountainIDs: mountainIDs,
                visitCount: visitCount
            )
        )
    }

    private func m3Bootstrap(
        _ base: SelfPassportSyncBase
    ) -> SelfPassportBootstrapResponse {
        SelfPassportBootstrapResponse(
            snapshotVersion: base.snapshotVersion,
            datasetVersion: base.datasetVersion,
            schemaVersion: base.schemaVersion,
            historyToken: base.historyToken,
            aggregates: base.aggregates
        )
    }

    private func m3Visit(
        id: String,
        mountainID: MountainID,
        visitedOffset: TimeInterval = -60
    ) throws -> VisitRecord {
        VisitRecord(
            id: try VisitID(rawValue: id),
            mountainID: mountainID,
            visitedAt: m3Date.addingTimeInterval(visitedOffset),
            recordedAt: m3Date,
            verificationMethod: .manual
        )
    }

    private var m3Date: Date {
        Date(timeIntervalSince1970: 1_700_000_000)
    }
}
private struct LegacyLocalPassportSnapshot: Encodable {
    let passportState: PassportStateMachine
    let manualVisitOutbox: ManualVisitOutboxGraph
}

private enum M3SnapshotStoreError: Error, Sendable {
    case injectedSaveFailure
}

private actor M3SnapshotStore: HikerLocalDataStore {
    typealias Value = LocalPassportSnapshot

    private var value: LocalPassportSnapshot?
    private let failingSaveCounts: Set<Int>
    private var saveCount = 0

    init(
        value: LocalPassportSnapshot? = nil,
        failingSaveCounts: Set<Int> = []
    ) {
        self.value = value
        self.failingSaveCounts = failingSaveCounts
    }

    func load() -> LocalPassportSnapshot? {
        value
    }

    func save(_ value: LocalPassportSnapshot) throws {
        saveCount += 1
        guard !failingSaveCounts.contains(saveCount) else {
            throw M3SnapshotStoreError.injectedSaveFailure
        }
        self.value = value
    }

    func saveIfUnchanged(
        _ value: LocalPassportSnapshot,
        expected: LocalPassportSnapshot?
    ) throws -> Bool {
        guard self.value == expected else {
            return false
        }
        try save(value)
        return true
    }

    func remove() {
        value = nil
    }
}

private actor M3ScriptedTransport: SelfPassportSyncTransport, GPSVisitVerificationTransport {
    enum UploadResult: Sendable {
        case receipt(SelfPassportMutationReceipt)
        case failure(SelfPassportTransportFailure)
    }
    enum PlanUploadResult: Sendable {
        case receipt(SelfPassportPlanMutationReceipt)
        case failure(SelfPassportTransportFailure)
    }
    enum GPSResult: Sendable {
        case outcome(GPSVisitVerificationOutcome)
        case failure(SelfPassportTransportFailure)
    }



    private var bootstraps: [SelfPassportBootstrapResponse]
    private var historyPages: [SelfPassportHistoryPage]
    private var changePages: [SelfPassportChangePage]
    private var uploadResults: [UploadResult]
    private var planUploadResults: [PlanUploadResult]
    private var gpsResults: [GPSResult]
    private var uploadOrder: [String] = []
    private var planMutationIDs: [ClientMutationID] = []

    init(
        bootstraps: [SelfPassportBootstrapResponse] = [],
        historyPages: [SelfPassportHistoryPage] = [],
        changePages: [SelfPassportChangePage] = [],
        uploadResults: [UploadResult] = [],
        planUploadResults: [PlanUploadResult] = [],
        gpsResults: [GPSResult] = []
    ) {
        self.bootstraps = bootstraps
        self.historyPages = historyPages
        self.changePages = changePages
        self.uploadResults = uploadResults
        self.planUploadResults = planUploadResults
        self.gpsResults = gpsResults
        self.uploadOrder = []
        self.planMutationIDs = []
    }

    func bootstrap() throws -> SelfPassportBootstrapResponse {
        guard !bootstraps.isEmpty else {
            throw SelfPassportTransportFailure.transient
        }
        return bootstraps.removeFirst()
    }

    func historyPage(
        _: SelfPassportHistoryRequest
    ) throws -> SelfPassportHistoryPage {
        guard !historyPages.isEmpty else {
            throw SelfPassportTransportFailure.transient
        }
        return historyPages.removeFirst()
    }

    func changePage(
        _: SelfPassportChangeRequest
    ) throws -> SelfPassportChangePage {
        guard !changePages.isEmpty else {
            throw SelfPassportTransportFailure.transient
        }
        return changePages.removeFirst()
    }

    func upload(
        _: ManualVisitOutboxNode
    ) throws -> SelfPassportMutationReceipt {
        uploadOrder.append("manual")
        guard !uploadResults.isEmpty else {
            throw SelfPassportTransportFailure.transient
        }

        switch uploadResults.removeFirst() {
        case let .receipt(receipt):
            return receipt
        case let .failure(error):
            throw error
        }
    }
    func uploadPlan(
        _ node: PlanMutationOutboxNode
    ) throws -> SelfPassportPlanMutationReceipt {
        uploadOrder.append("plan")
        planMutationIDs.append(node.id)
        guard !planUploadResults.isEmpty else {
            throw SelfPassportTransportFailure.transient
        }

        switch planUploadResults.removeFirst() {
        case let .receipt(receipt):
            return receipt
        case let .failure(error):
            throw error
        }
    }
    func verifyGPSVisit(
        mountainID _: MountainID,
        visitID _: VisitID,
        visitedAt _: Date,
        clientMutationID _: ClientMutationID,
        latitude _: Double,
        longitude _: Double,
        horizontalAccuracyMeters _: Double,
        sampledAt _: Date
    ) throws -> GPSVisitVerificationOutcome {
        guard !gpsResults.isEmpty else {
            throw SelfPassportTransportFailure.transient
        }
        switch gpsResults.removeFirst() {
        case let .outcome(outcome):
            return outcome
        case let .failure(error):
            throw error
        }
    }

    func recordedUploadOrder() -> [String] {
        uploadOrder
    }

    func recordedPlanMutationIDs() -> [ClientMutationID] {
        planMutationIDs
    }
}
