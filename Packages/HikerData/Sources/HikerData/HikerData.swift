import Foundation
import CryptoKit
import HikerDomain

/// Defines the typed boundary for locally stored application data.
///
/// Concrete persistence mechanisms belong behind this contract so callers do not
/// depend on a specific local storage technology.
public protocol HikerLocalDataStore<Value>: Sendable {
    associatedtype Value: Equatable & Sendable

    func load() async throws -> Value?
    func save(_ value: Value) async throws
    func saveIfUnchanged(_ value: Value, expected: Value?) async throws -> Bool
    func remove() async throws
}

public enum LocalDataStorePathError: Error, Equatable, Sendable {
    case invalidFileName
}

public struct LocalDataStoreFactory: Sendable {
    private let baseDirectory: URL

    public init(baseDirectory: URL) {
        self.baseDirectory = baseDirectory
    }

    public func makeJSONStore<Value: Codable & Equatable & Sendable>(
        named name: String,
        as _: Value.Type = Value.self
    ) throws -> JSONFileDataStore<Value> {
        guard !name.isEmpty,
              name != ".",
              name != "..",
              !name.contains("/"),
              !name.contains("\\") else {
            throw LocalDataStorePathError.invalidFileName
        }
        return JSONFileDataStore(
            fileURL: baseDirectory.appendingPathComponent(name, isDirectory: false)
        )
    }
}

public actor JSONFileDataStore<Value: Codable & Equatable & Sendable>: HikerLocalDataStore {
    private let fileURL: URL
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    public init(fileURL: URL) {
        self.fileURL = fileURL
        encoder = JSONEncoder()
        decoder = JSONDecoder()
    }

    public func load() throws -> Value? {
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            return nil
        }
        return try decoder.decode(Value.self, from: Data(contentsOf: fileURL))
    }

    public func save(_ value: Value) throws {
        try FileManager.default.createDirectory(
            at: fileURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try encoder.encode(value).write(to: fileURL, options: .atomic)
    }

    public func saveIfUnchanged(_ value: Value, expected: Value?) throws -> Bool {
        guard try load() == expected else {
            return false
        }
        try save(value)
        return true
    }

    public func remove() throws {
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            return
        }
        try FileManager.default.removeItem(at: fileURL)
    }
}
public enum ManualVisitOutboxOperation: String, Codable, Equatable, Sendable {
    case create
    case delete
}

public enum ManualVisitOutboxNodeState: String, Codable, Equatable, Sendable {
    case queued
    case inFlight
    case paused
}

public struct ManualVisitOutboxDependency: Codable, Equatable, Sendable {
    public let clientMutationID: ClientMutationID
    public let visitID: VisitID

    public init(clientMutationID: ClientMutationID, visitID: VisitID) {
        self.clientMutationID = clientMutationID
        self.visitID = visitID
    }
}

/// An immutable wire request. `requestBytes` are the exact bytes retained for
/// replay, receipt binding, and user-directed export.
public struct ManualVisitOutboxRequest: Codable, Equatable, Sendable {
    public let operation: ManualVisitOutboxOperation
    public let visitID: VisitID
    public let mountainID: MountainID
    public let clientMutationID: ClientMutationID
    public let requestBytes: Data

    public init(
        create visit: VisitRecord,
        clientMutationID: ClientMutationID
    ) throws {
        guard visit.verificationMethod == .manual else {
            throw ManualVisitOutboxError.gpsVerifiedVisitsAreNotQueueable
        }

        let requestBytes = try Self.canonicalBytes(
            CreateWirePayload(visit: visit, clientMutationID: clientMutationID)
        )
        try self.init(
            operation: .create,
            visitID: visit.id,
            mountainID: visit.mountainID,
            clientMutationID: clientMutationID,
            requestBytes: requestBytes
        )
    }

    public init(
        deleteVisitID visitID: VisitID,
        mountainID: MountainID,
        clientMutationID: ClientMutationID
    ) throws {
        let requestBytes = try Self.canonicalBytes(
            DeleteWirePayload(
                visitID: visitID,
                mountainID: mountainID,
                clientMutationID: clientMutationID
            )
        )
        try self.init(
            operation: .delete,
            visitID: visitID,
            mountainID: mountainID,
            clientMutationID: clientMutationID,
            requestBytes: requestBytes
        )
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let rawContainer = try decoder.container(
            keyedBy: LocalPassportSnapshotCodingKey.self
        )
        guard Set(rawContainer.allKeys.map(\.stringValue)) == Set([
            "operation",
            "visitID",
            "mountainID",
            "clientMutationID",
            "requestBytes",
        ]) else {
            throw ManualVisitOutboxError.inconsistentRequestPayload
        }
        try self.init(
            operation: container.decode(ManualVisitOutboxOperation.self, forKey: .operation),
            visitID: container.decode(VisitID.self, forKey: .visitID),
            mountainID: container.decode(MountainID.self, forKey: .mountainID),
            clientMutationID: container.decode(ClientMutationID.self, forKey: .clientMutationID),
            requestBytes: container.decode(Data.self, forKey: .requestBytes)
        )
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(operation, forKey: .operation)
        try container.encode(visitID, forKey: .visitID)
        try container.encode(mountainID, forKey: .mountainID)
        try container.encode(clientMutationID, forKey: .clientMutationID)
        try container.encode(requestBytes, forKey: .requestBytes)
    }

    private init(
        operation: ManualVisitOutboxOperation,
        visitID: VisitID,
        mountainID: MountainID,
        clientMutationID: ClientMutationID,
        requestBytes: Data
    ) throws {
        guard !requestBytes.isEmpty else {
            throw ManualVisitOutboxError.inconsistentRequestPayload
        }

        self.operation = operation
        self.visitID = visitID
        self.mountainID = mountainID
        self.clientMutationID = clientMutationID
        self.requestBytes = requestBytes

        try validateWirePayload()
    }

    private func validateWirePayload() throws {
        switch operation {
        case .create:
            let payload = try JSONDecoder().decode(CreateWirePayload.self, from: requestBytes)
            let canonicalPayload = try Self.canonicalBytes(payload)
            guard payload.visit.id == visitID,
                  payload.visit.mountainID == mountainID,
                  payload.clientMutationID == clientMutationID,
                  payload.visit.verificationMethod == .manual,
                  requestBytes == canonicalPayload else {
                throw ManualVisitOutboxError.inconsistentRequestPayload
            }
        case .delete:
            let payload = try JSONDecoder().decode(DeleteWirePayload.self, from: requestBytes)
            let canonicalPayload = try Self.canonicalBytes(payload)
            guard payload.visitID == visitID,
                  payload.mountainID == mountainID,
                  payload.clientMutationID == clientMutationID,
                  requestBytes == canonicalPayload else {
                throw ManualVisitOutboxError.inconsistentRequestPayload
            }
        }
    }
    func validatedCreateVisit() throws -> VisitRecord? {
        guard operation == .create else {
            return nil
        }
        return try JSONDecoder().decode(CreateWirePayload.self, from: requestBytes).visit
    }


    private static func canonicalBytes<Payload: Encodable>(_ payload: Payload) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(payload)
    }

    private enum CodingKeys: String, CodingKey {
        case operation
        case visitID
        case mountainID
        case clientMutationID
        case requestBytes
    }
}

private struct CreateWirePayload: Codable {
    let visit: VisitRecord
    let clientMutationID: ClientMutationID
}

private struct DeleteWirePayload: Codable {
    let visitID: VisitID
    let mountainID: MountainID
    let clientMutationID: ClientMutationID
}

public struct ManualVisitOutboxNode: Codable, Equatable, Identifiable, Sendable {
    public let localSequence: Int64
    public let aggregateMountainID: MountainID
    public let request: ManualVisitOutboxRequest
    public let dependency: ManualVisitOutboxDependency?
    public var state: ManualVisitOutboxNodeState
    public let enqueuedAt: Date

    public var id: ClientMutationID {
        request.clientMutationID
    }

    public var dependencyMutationID: ClientMutationID? {
        dependency?.clientMutationID
    }

    public init(
        localSequence: Int64,
        aggregateMountainID: MountainID,
        request: ManualVisitOutboxRequest,
        dependency: ManualVisitOutboxDependency? = nil,
        state: ManualVisitOutboxNodeState = .queued,
        enqueuedAt: Date
    ) throws {
        guard aggregateMountainID == request.mountainID else {
            throw ManualVisitOutboxError.mountainMismatch
        }

        self.localSequence = localSequence
        self.aggregateMountainID = aggregateMountainID
        self.request = request
        self.dependency = dependency
        self.state = state
        self.enqueuedAt = enqueuedAt
    }
}

public struct ManualVisitOutboxExport: Codable, Equatable, Sendable {
    public let localSequence: Int64
    public let aggregateMountainID: MountainID
    public let operation: ManualVisitOutboxOperation
    public let visitID: VisitID
    public let clientMutationID: ClientMutationID
    public let dependency: ManualVisitOutboxDependency?
    public let enqueuedAt: Date
    public let requestBytes: Data

    public init(node: ManualVisitOutboxNode) {
        localSequence = node.localSequence
        aggregateMountainID = node.aggregateMountainID
        operation = node.request.operation
        visitID = node.request.visitID
        clientMutationID = node.request.clientMutationID
        dependency = node.dependency
        enqueuedAt = node.enqueuedAt
        requestBytes = node.request.requestBytes
    }
}

public enum ManualVisitOutboxEnqueueResult: Equatable, Sendable {
    case enqueued(ManualVisitOutboxNode)
    case compacted(createMutationID: ClientMutationID)
}

public enum ManualVisitOutboxExpiryChoice: Sendable {
    case export
    case discard
}

public enum ManualVisitOutboxError: Error, Equatable, Sendable {
    case gpsVerifiedVisitsAreNotQueueable
    case duplicateMutationID
    case duplicateVisitID
    case mountainMismatch
    case unknownMutationID
    case invalidNodeState
    case unknownDependency
    case dependencyCycle
    case invalidDependency
    case inconsistentRequestPayload
    case expiryChoiceRequiresPausedNode
}

/// Durable, per-mountain ordered manual visit operations and their dependency DAG.
///
/// The graph has no automatic deletion path. Expiry only transitions a queued
/// node to `paused`; bytes leave the graph only through an explicit discard.
public struct ManualVisitOutboxGraph: Codable, Equatable, Sendable {
    public private(set) var nodes: [ManualVisitOutboxNode]
    public private(set) var acceptedCreates: [ClientMutationID: VisitID]
    private var acceptedCreateMountains: [ClientMutationID: MountainID]
    private var nextLocalSequence: Int64

    public init(
        nodes: [ManualVisitOutboxNode] = [],
        acceptedCreates: [ClientMutationID: VisitID] = [:],
        nextLocalSequence: Int64 = 0
    ) throws {
        try self.init(
            nodes: nodes,
            acceptedCreates: acceptedCreates,
            nextLocalSequence: nextLocalSequence,
            acceptedCreateMountains: [:]
        )
    }

    private init(
        nodes: [ManualVisitOutboxNode],
        acceptedCreates: [ClientMutationID: VisitID],
        nextLocalSequence: Int64,
        acceptedCreateMountains: [ClientMutationID: MountainID]
    ) throws {
        self.nodes = nodes.sorted { $0.localSequence < $1.localSequence }
        self.acceptedCreates = acceptedCreates
        self.acceptedCreateMountains = acceptedCreateMountains
        self.nextLocalSequence = max(
            nextLocalSequence,
            (nodes.map(\.localSequence).max() ?? -1) + 1
        )
        garbageCollectAcceptedCreateMetadata()
        try validate()
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let rawContainer = try decoder.container(
            keyedBy: LocalPassportSnapshotCodingKey.self
        )
        guard Set(rawContainer.allKeys.map(\.stringValue)) == Set([
            "nodes",
            "acceptedCreates",
            "acceptedCreateMountains",
            "nextLocalSequence",
        ]) else {
            throw ManualVisitOutboxError.inconsistentRequestPayload
        }
        try self.init(
            nodes: container.decode([ManualVisitOutboxNode].self, forKey: .nodes),
            acceptedCreates: container.decode(
                [ClientMutationID: VisitID].self,
                forKey: .acceptedCreates
            ),
            nextLocalSequence: container.decode(Int64.self, forKey: .nextLocalSequence),
            acceptedCreateMountains: container.decode(
                [ClientMutationID: MountainID].self,
                forKey: .acceptedCreateMountains
            )
        )
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(nodes, forKey: .nodes)
        try container.encode(acceptedCreates, forKey: .acceptedCreates)
        try container.encode(nextLocalSequence, forKey: .nextLocalSequence)
        try container.encode(acceptedCreateMountains, forKey: .acceptedCreateMountains)
    }

    @discardableResult
    public mutating func enqueueCreate(
        _ visit: VisitRecord,
        clientMutationID: ClientMutationID,
        at enqueuedAt: Date = .now
    ) throws -> ManualVisitOutboxNode {
        guard !containsMutationID(clientMutationID) else {
            throw ManualVisitOutboxError.duplicateMutationID
        }
        guard !nodes.contains(where: {
            $0.request.operation == .create && $0.request.visitID == visit.id
        }),
        !acceptedCreates.values.contains(visit.id) else {
            throw ManualVisitOutboxError.duplicateVisitID
        }

        let request = try ManualVisitOutboxRequest(
            create: visit,
            clientMutationID: clientMutationID
        )
        let node = try makeNode(
            request: request,
            dependency: nil,
            state: .queued,
            enqueuedAt: enqueuedAt
        )
        nodes.append(node)
        return node
    }

    @discardableResult
    public mutating func enqueueDelete(
        visitID: VisitID,
        mountainID: MountainID,
        clientMutationID: ClientMutationID,
        at enqueuedAt: Date = .now
    ) throws -> ManualVisitOutboxEnqueueResult {
        guard !containsMutationID(clientMutationID) else {
            throw ManualVisitOutboxError.duplicateMutationID
        }

        if let create = nodes.first(where: {
            $0.request.operation == .create && $0.request.visitID == visitID
        }) {
            guard create.aggregateMountainID == mountainID else {
                throw ManualVisitOutboxError.mountainMismatch
            }

            if create.state == .queued {
                _ = removeNodeAndDescendants(startingAt: create.id)
                return .compacted(createMutationID: create.id)
            }

            let request = try ManualVisitOutboxRequest(
                deleteVisitID: visitID,
                mountainID: mountainID,
                clientMutationID: clientMutationID
            )
            let node = try makeNode(
                request: request,
                dependency: ManualVisitOutboxDependency(
                    clientMutationID: create.id,
                    visitID: visitID
                ),
                state: create.state == .paused ? .paused : .queued,
                enqueuedAt: enqueuedAt
            )
            nodes.append(node)
            return .enqueued(node)
        }

        let request = try ManualVisitOutboxRequest(
            deleteVisitID: visitID,
            mountainID: mountainID,
            clientMutationID: clientMutationID
        )
        let node = try makeNode(
            request: request,
            dependency: nil,
            state: .queued,
            enqueuedAt: enqueuedAt
        )
        nodes.append(node)
        return .enqueued(node)
    }

    /// Transitions queued nodes at least ninety days old to `paused`.
    /// This intentionally retains all bytes until the caller exports or discards.
    @discardableResult
    public mutating func pauseExpired(at now: Date) -> [ClientMutationID] {
        var paused: [ClientMutationID] = []

        for index in nodes.indices where nodes[index].state == .queued {
            guard now.timeIntervalSince(nodes[index].enqueuedAt) >= Self.expiryInterval else {
                continue
            }
            nodes[index].state = .paused
            paused.append(nodes[index].id)
        }

        return paused
    }

    /// Marks and returns one per-aggregate head that is ready to send.
    @discardableResult
    public mutating func nextDispatchable(at now: Date = .now) -> ManualVisitOutboxNode? {
        pauseExpired(at: now)

        for index in nodes.indices {
            let node = nodes[index]
            guard node.state == .queued,
                  isAggregateHead(at: index),
                  dependencyIsSatisfied(for: node) else {
                continue
            }

            nodes[index].state = .inFlight
            return nodes[index]
        }

        return nil
    }
    /// Requeues persisted attempts after a process restart. The immutable mutation
    /// IDs and request bytes are retained so transport retries remain idempotent.
    @discardableResult
    public mutating func recoverAfterRestart() -> [ClientMutationID] {
        var recovered: [ClientMutationID] = []

        for index in nodes.indices where nodes[index].state == .inFlight {
            nodes[index].state = .queued
            recovered.append(nodes[index].id)
        }

        return recovered
    }


    public mutating func acknowledgeAccepted(
        mutationID: ClientMutationID
    ) throws {
        guard let index = nodes.firstIndex(where: { $0.id == mutationID }) else {
            throw ManualVisitOutboxError.unknownMutationID
        }
        guard nodes[index].state == .inFlight else {
            throw ManualVisitOutboxError.invalidNodeState
        }

        let acknowledged = nodes.remove(at: index)
        if acknowledged.request.operation == .create {
            acceptedCreates[acknowledged.id] = acknowledged.request.visitID
            acceptedCreateMountains[acknowledged.id] = acknowledged.aggregateMountainID
        }
        garbageCollectAcceptedCreateMetadata()
    }

    @discardableResult
    public mutating func acknowledgeRejected(
        mutationID: ClientMutationID
    ) throws -> [ManualVisitOutboxNode] {
        guard let node = nodes.first(where: { $0.id == mutationID }) else {
            throw ManualVisitOutboxError.unknownMutationID
        }
        guard node.state == .inFlight else {
            throw ManualVisitOutboxError.invalidNodeState
        }

        return removeNodeAndDescendants(startingAt: mutationID)
    }

    public func exportPaused() -> [ManualVisitOutboxExport] {
        nodes
            .filter { $0.state == .paused }
            .map(ManualVisitOutboxExport.init(node:))
    }

    /// Resolves a paused node only through a caller-selected export or discard.
    /// Export is non-destructive; discard is the only removal operation here.
    @discardableResult
    public mutating func applyExpiryChoice(
        _ choice: ManualVisitOutboxExpiryChoice,
        for mutationIDs: Set<ClientMutationID>
    ) throws -> [ManualVisitOutboxExport] {
        let selected = try pausedNodes(for: mutationIDs)

        switch choice {
        case .export:
            return selected.map(ManualVisitOutboxExport.init(node:))
        case .discard:
            for mutationID in mutationIDs {
                _ = removeNodeAndDescendants(startingAt: mutationID)
            }
            return []
        }
    }

    public func validate() throws {
        let mutationIDs = nodes.map(\.id)
        guard Set(mutationIDs).count == mutationIDs.count,
              !mutationIDs.contains(where: { acceptedCreates[$0] != nil }) else {
            throw ManualVisitOutboxError.duplicateMutationID
        }
        guard acceptedCreateMountains.allSatisfy({
            acceptedCreates[$0.key] != nil
        }) else {
            throw ManualVisitOutboxError.invalidDependency
        }


        let sequences = nodes.map(\.localSequence)
        guard Set(sequences).count == sequences.count else {
            throw ManualVisitOutboxError.invalidDependency
        }

        let nodesByMutationID = Dictionary(uniqueKeysWithValues: nodes.map { ($0.id, $0) })
        for node in nodes {
            guard node.aggregateMountainID == node.request.mountainID else {
                throw ManualVisitOutboxError.mountainMismatch
            }

            guard let dependency = node.dependency else {
                continue
            }

            if let acceptedVisitID = acceptedCreates[dependency.clientMutationID] {
                guard acceptedVisitID == dependency.visitID else {
                    throw ManualVisitOutboxError.invalidDependency
                }
                continue
            }

            guard let dependencyNode = nodesByMutationID[dependency.clientMutationID] else {
                throw ManualVisitOutboxError.unknownDependency
            }
            guard dependencyNode.request.visitID == dependency.visitID else {
                throw ManualVisitOutboxError.invalidDependency
            }
        }

        try validateNoCycles(nodesByMutationID)

        for node in nodes where node.dependency != nil {
            guard node.request.operation == .delete,
                  let dependency = node.dependency,
                  node.request.visitID == dependency.visitID else {
                throw ManualVisitOutboxError.invalidDependency
            }

            if let acceptedVisitID = acceptedCreates[dependency.clientMutationID] {
                guard acceptedVisitID == dependency.visitID,
                      acceptedCreateMountains[dependency.clientMutationID]
                        == node.aggregateMountainID else {
                    throw ManualVisitOutboxError.invalidDependency
                }
                continue
            }

            guard let dependencyNode = nodesByMutationID[dependency.clientMutationID],
                  dependencyNode.request.operation == .create,
                  dependencyNode.request.visitID == dependency.visitID,
                  dependencyNode.aggregateMountainID == node.aggregateMountainID,
                  dependencyNode.localSequence < node.localSequence else {
                throw ManualVisitOutboxError.invalidDependency
            }
        }
    }

    private static let expiryInterval: TimeInterval = 90 * 24 * 60 * 60

    private enum CodingKeys: String, CodingKey {
        case nodes
        case acceptedCreates
        case nextLocalSequence
        case acceptedCreateMountains
    }

    private mutating func makeNode(
        request: ManualVisitOutboxRequest,
        dependency: ManualVisitOutboxDependency?,
        state: ManualVisitOutboxNodeState,
        enqueuedAt: Date
    ) throws -> ManualVisitOutboxNode {
        defer { nextLocalSequence += 1 }
        return try ManualVisitOutboxNode(
            localSequence: nextLocalSequence,
            aggregateMountainID: request.mountainID,
            request: request,
            dependency: dependency,
            state: state,
            enqueuedAt: enqueuedAt
        )
    }

    private func containsMutationID(_ mutationID: ClientMutationID) -> Bool {
        nodes.contains(where: { $0.id == mutationID }) || acceptedCreates[mutationID] != nil
    }
    private mutating func garbageCollectAcceptedCreateMetadata() {
        let referencedMutationIDs = Set(nodes.compactMap(\.dependencyMutationID))
        acceptedCreates = acceptedCreates.filter {
            referencedMutationIDs.contains($0.key)
        }
        acceptedCreateMountains = acceptedCreateMountains.filter {
            acceptedCreates[$0.key] != nil
        }
    }


    private func isAggregateHead(at index: Int) -> Bool {
        !nodes[..<index].contains {
            $0.aggregateMountainID == nodes[index].aggregateMountainID
        }
    }

    private func dependencyIsSatisfied(for node: ManualVisitOutboxNode) -> Bool {
        guard let dependency = node.dependency else {
            return true
        }
        return acceptedCreates[dependency.clientMutationID] == dependency.visitID
            && acceptedCreateMountains[dependency.clientMutationID] == node.aggregateMountainID
    }

    private func pausedNodes(
        for mutationIDs: Set<ClientMutationID>
    ) throws -> [ManualVisitOutboxNode] {
        let selected = nodes.filter { mutationIDs.contains($0.id) }
        guard selected.count == mutationIDs.count,
              selected.allSatisfy({ $0.state == .paused }) else {
            throw ManualVisitOutboxError.expiryChoiceRequiresPausedNode
        }
        return selected
    }

    private mutating func removeNodeAndDescendants(
        startingAt mutationID: ClientMutationID
    ) -> [ManualVisitOutboxNode] {
        var removedIDs: Set<ClientMutationID> = [mutationID]
        var foundNewDescendant = true

        while foundNewDescendant {
            foundNewDescendant = false
            for node in nodes {
                guard let dependency = node.dependency,
                      removedIDs.contains(dependency.clientMutationID),
                      !removedIDs.contains(node.id) else {
                    continue
                }
                removedIDs.insert(node.id)
                foundNewDescendant = true
            }
        }

        let removed = nodes.filter { removedIDs.contains($0.id) }
        nodes.removeAll { removedIDs.contains($0.id) }
        for mutationID in removedIDs {
            acceptedCreates.removeValue(forKey: mutationID)
            acceptedCreateMountains.removeValue(forKey: mutationID)
        }
        garbageCollectAcceptedCreateMetadata()
        return removed
    }

    private func validateNoCycles(
        _ nodesByMutationID: [ClientMutationID: ManualVisitOutboxNode]
    ) throws {
        enum VisitState: Equatable {
            case visiting
            case visited
        }

        var states: [ClientMutationID: VisitState] = [:]

        func visit(_ mutationID: ClientMutationID) throws {
            if states[mutationID] == .visiting {
                throw ManualVisitOutboxError.dependencyCycle
            }
            guard states[mutationID] == nil else {
                return
            }

            states[mutationID] = .visiting
            if let dependency = nodesByMutationID[mutationID]?.dependency,
               nodesByMutationID[dependency.clientMutationID] != nil {
                try visit(dependency.clientMutationID)
            }
            states[mutationID] = .visited
        }

        for mutationID in nodesByMutationID.keys {
            try visit(mutationID)
        }
    }
}

public enum PlanMutationOutboxOperation: String, Codable, Equatable, Sendable {
    case add
    case remove
}

public enum PlanMutationOutboxDispatchState: String, Codable, Equatable, Sendable {
    case queued
    case inFlight
}
public enum PlanMutationOutboxError: Error, Equatable, Sendable {
    case duplicateMutationID
}

/// An ordered, durable optimistic plan mutation. Its identity and target never
/// change; only dispatch state transitions around an upload attempt.
public struct PlanMutationOutboxNode: Codable, Equatable, Identifiable, Sendable {
    public let clientMutationID: ClientMutationID
    public let mountainID: MountainID
    public let operation: PlanMutationOutboxOperation
    public let enqueuedAt: Date
    public var state: PlanMutationOutboxDispatchState

    public var id: ClientMutationID {
        clientMutationID
    }

    public init(
        clientMutationID: ClientMutationID,
        mountainID: MountainID,
        operation: PlanMutationOutboxOperation,
        enqueuedAt: Date,
        state: PlanMutationOutboxDispatchState = .queued
    ) {
        self.clientMutationID = clientMutationID
        self.mountainID = mountainID
        self.operation = operation
        self.enqueuedAt = enqueuedAt
        self.state = state
    }
}

public struct ManualVisitOutboxEncryptionKey: Sendable {
    fileprivate let rawValue: Data

    public init(data: Data) throws {
        guard data.count == 32 else {
            throw ManualVisitOutboxStoreError.invalidKeyLength
        }
        rawValue = data
    }
}

public enum ManualVisitOutboxStoreError: Error, Equatable, Sendable {
    case invalidKeyLength
    case plaintextOrUnsupportedFormat
    case authenticationFailed
    case invalidGraph
    case persistenceIO(domain: String, code: Int)
}

/// AES-GCM durable storage for the self-only outbox. The key is injected by the
/// app composition root; this type neither creates nor persists keys.
/// A coherent encrypted persistence unit for the local passport projection and
/// its pending manual-visit and plan-mutation outboxes.
public enum LocalPassportSnapshotError: Error, Equatable, Sendable {
    case inconsistentPassportAndOutbox
    case duplicateMutationID
    case invalidPlanMutationOutbox
    case invalidSchemaVersion
}

private struct LocalPassportSnapshotCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int? = nil

    init?(stringValue: String) {
        self.stringValue = stringValue
    }

    init?(intValue: Int) {
        return nil
    }
}

public struct LocalPassportSnapshot: Codable, Equatable, Sendable {
    public let actorID: UUID?
    public let passportState: PassportStateMachine
    public let manualVisitOutbox: ManualVisitOutboxGraph
    public let planMutationOutbox: [PlanMutationOutboxNode]
    /// The accepted remote base. Pending local mutations remain solely in the
    /// outbox and are replayed over this base by `SelfPassportSyncEngine`.
    public let syncBase: SelfPassportSyncBase?
    /// A durable write hold that survives engine reconstruction until an
    /// explicitly verified resume clears it.
    public let writePauseReason: SelfPassportWritePauseReason?

    public var passport: PassportStateMachine {
        passportState
    }

    public var outbox: ManualVisitOutboxGraph {
        manualVisitOutbox
    }

    public init(
        passportState: PassportStateMachine,
        manualVisitOutbox: ManualVisitOutboxGraph,
        planMutationOutbox: [PlanMutationOutboxNode] = [],
        syncBase: SelfPassportSyncBase? = nil,
        writePauseReason: SelfPassportWritePauseReason? = nil,
        actorID: UUID? = nil
    ) throws {
        self.passportState = passportState
        self.manualVisitOutbox = manualVisitOutbox
        self.planMutationOutbox = planMutationOutbox
        self.syncBase = syncBase
        self.writePauseReason = writePauseReason
        self.actorID = actorID
        try validate()
    }

    public func validate() throws {
        try manualVisitOutbox.validate()

        let manualMutationIDs = manualVisitOutbox.nodes.map(\.id)
            + Array(manualVisitOutbox.acceptedCreates.keys)
        let planMutationIDs = planMutationOutbox.map(\.id)
        guard Set(manualMutationIDs + planMutationIDs).count
            == manualMutationIDs.count + planMutationIDs.count else {
            throw LocalPassportSnapshotError.duplicateMutationID
        }
        guard planMutationOutbox.filter({ $0.state == .inFlight }).count <= 1 else {
            throw LocalPassportSnapshotError.invalidPlanMutationOutbox
        }

        var passportVisitsByID: [VisitID: VisitRecord] = [:]
        for visit in passportState.allProjections().flatMap(\.history) {
            passportVisitsByID[visit.id] = visit
        }

        var latestPendingNodeByVisitID: [VisitID: ManualVisitOutboxNode] = [:]
        for node in manualVisitOutbox.nodes {
            latestPendingNodeByVisitID[node.request.visitID] = node
        }

        for (visitID, node) in latestPendingNodeByVisitID {
            switch node.request.operation {
            case .create:
                guard let passportVisit = passportVisitsByID[visitID],
                      let immutableRequestVisit = try node.request.validatedCreateVisit(),
                      passportVisit == immutableRequestVisit else {
                    throw LocalPassportSnapshotError.inconsistentPassportAndOutbox
                }
            case .delete:
                guard passportVisitsByID[visitID] == nil else {
                    throw LocalPassportSnapshotError.inconsistentPassportAndOutbox
                }
            }
        }
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let rawContainer = try decoder.container(
            keyedBy: LocalPassportSnapshotCodingKey.self
        )
        let rawKeys = Set(rawContainer.allKeys.map(\.stringValue))
        guard container.contains(.schemaVersion) else {
            guard rawKeys == Set([
                "passportState",
                "manualVisitOutbox",
            ]) else {
                throw LocalPassportSnapshotError.invalidSchemaVersion
            }
            guard !container.contains(.planMutationOutbox),
                  !container.contains(.syncBase),
                  !container.contains(.writePauseReason),
                  !container.contains(.actorID) else {
                throw LocalPassportSnapshotError.invalidSchemaVersion
            }
            try self.init(
                passportState: container.decode(
                    PassportStateMachine.self,
                    forKey: .passportState
                ),
                manualVisitOutbox: container.decode(
                    ManualVisitOutboxGraph.self,
                    forKey: .manualVisitOutbox
                )
            )
            return
        }

        guard rawKeys == Set([
            "schemaVersion",
            "passportState",
            "manualVisitOutbox",
            "planMutationOutbox",
            "syncBase",
            "writePauseReason",
            "actorID",
        ]) else {
            throw LocalPassportSnapshotError.invalidSchemaVersion
        }
        guard try container.decode(Int.self, forKey: .schemaVersion) == 1,
              container.contains(.planMutationOutbox),
              container.contains(.syncBase),
              container.contains(.writePauseReason),
              container.contains(.actorID) else {
            throw LocalPassportSnapshotError.invalidSchemaVersion
        }
        try self.init(
            passportState: container.decode(
                PassportStateMachine.self,
                forKey: .passportState
            ),
            manualVisitOutbox: container.decode(
                ManualVisitOutboxGraph.self,
                forKey: .manualVisitOutbox
            ),
            planMutationOutbox: container.decode(
                [PlanMutationOutboxNode].self,
                forKey: .planMutationOutbox
            ),
            syncBase: try container.decodeIfPresent(
                SelfPassportSyncBase.self,
                forKey: .syncBase
            ),
            writePauseReason: try container.decodeIfPresent(
                SelfPassportWritePauseReason.self,
                forKey: .writePauseReason
            ),
            actorID: try container.decodeIfPresent(UUID.self, forKey: .actorID)
        )
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(1, forKey: .schemaVersion)
        try container.encode(passportState, forKey: .passportState)
        try container.encode(manualVisitOutbox, forKey: .manualVisitOutbox)
        try container.encode(planMutationOutbox, forKey: .planMutationOutbox)
        try container.encode(syncBase, forKey: .syncBase)
        try container.encode(writePauseReason, forKey: .writePauseReason)
        try container.encode(actorID, forKey: .actorID)
    }

    private enum CodingKeys: String, CodingKey {
        case schemaVersion
        case passportState
        case manualVisitOutbox
        case planMutationOutbox
        case syncBase
        case writePauseReason
        case actorID
    }
}

public typealias LocalPassportEncryptionKey = ManualVisitOutboxEncryptionKey

public enum EncryptedLocalPassportStoreError: Error, Equatable, Sendable {
    case plaintextOrUnsupportedFormat
    case authenticationFailed
    case invalidSnapshot
    case persistenceIO(domain: String, code: Int)
}

/// AES-GCM durable storage for the self-only outbox. The key is injected by the
/// app composition root; this type neither creates nor persists keys.
public actor EncryptedManualVisitOutboxStore: HikerLocalDataStore {
    public typealias Value = ManualVisitOutboxGraph

    private let storage: AESGCMEncryptedFileStorage
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    public init(fileURL: URL, key: ManualVisitOutboxEncryptionKey) {
        storage = AESGCMEncryptedFileStorage(
            fileURL: fileURL,
            key: key,
            fileMagic: Data([0x48, 0x4B, 0x4F, 0x31])
        )
        encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        decoder = JSONDecoder()
    }

    public func load() throws -> ManualVisitOutboxGraph? {
        let plaintext: Data?
        do {
            plaintext = try storage.load()
        } catch {
            throw manualOutboxStoreError(for: error)
        }
        guard let plaintext else {
            return nil
        }

        do {
            var graph = try decoder.decode(ManualVisitOutboxGraph.self, from: plaintext)
            _ = graph.recoverAfterRestart()
            return graph
        } catch {
            throw ManualVisitOutboxStoreError.invalidGraph
        }
    }

    public func save(_ value: ManualVisitOutboxGraph) throws {
        do {
            try value.validate()
            try storage.save(encoder.encode(value))
        } catch let error as ManualVisitOutboxStoreError {
            throw error
        } catch is ManualVisitOutboxError {
            throw ManualVisitOutboxStoreError.invalidGraph
        } catch {
            throw manualOutboxStoreError(for: error)
        }
    }

    public func saveIfUnchanged(
        _ value: ManualVisitOutboxGraph,
        expected: ManualVisitOutboxGraph?
    ) throws -> Bool {
        guard try load() == expected else {
            return false
        }
        try save(value)
        return true
    }

    public func remove() throws {
        do {
            try storage.remove()
        } catch {
            throw manualOutboxStoreError(for: error)
        }
    }
}

/// Uses the same injected key type and AES-GCM/atomic-file machinery as the
/// outbox so passport state is never persisted separately in plaintext.
public actor EncryptedLocalPassportStore: HikerLocalDataStore {
    public typealias Value = LocalPassportSnapshot
    nonisolated private static let compareAndSaveLock = NSLock()

    private let storage: AESGCMEncryptedFileStorage
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    public init(fileURL: URL, key: LocalPassportEncryptionKey) {
        storage = AESGCMEncryptedFileStorage(
            fileURL: fileURL,
            key: key,
            fileMagic: Data([0x48, 0x4B, 0x50, 0x31])
        )
        encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        decoder = JSONDecoder()
    }

    public func load() throws -> LocalPassportSnapshot? {
        let plaintext: Data?
        do {
            plaintext = try storage.load()
        } catch {
            throw localPassportStoreError(for: error)
        }
        guard let plaintext else {
            return nil
        }

        do {
            return try decoder.decode(LocalPassportSnapshot.self, from: plaintext)
        } catch {
            throw EncryptedLocalPassportStoreError.invalidSnapshot
        }
    }

    public func save(_ value: LocalPassportSnapshot) throws {
        do {
            try value.validate()
            try storage.save(encoder.encode(value))
        } catch let error as EncryptedLocalPassportStoreError {
            throw error
        } catch is LocalPassportSnapshotError {
            throw EncryptedLocalPassportStoreError.invalidSnapshot
        } catch is ManualVisitOutboxError {
            throw EncryptedLocalPassportStoreError.invalidSnapshot
        } catch {
            throw localPassportStoreError(for: error)
        }
    }

    public func saveIfUnchanged(
        _ value: LocalPassportSnapshot,
        expected: LocalPassportSnapshot?
    ) throws -> Bool {
        Self.compareAndSaveLock.lock()
        defer { Self.compareAndSaveLock.unlock() }
        guard try load() == expected else {
            return false
        }
        try save(value)
        return true
    }

    public func remove() throws {
        do {
            try storage.remove()
        } catch {
            throw localPassportStoreError(for: error)
        }
    }
}

private enum AESGCMEncryptedFileStorageError: Error {
    case plaintextOrUnsupportedFormat
    case authenticationFailed
}

private func manualOutboxStoreError(for error: Error) -> ManualVisitOutboxStoreError {
    switch error as? AESGCMEncryptedFileStorageError {
    case .some(.plaintextOrUnsupportedFormat):
        return .plaintextOrUnsupportedFormat
    case .some(.authenticationFailed):
        return .authenticationFailed
    case .none:
        let error = error as NSError
        return .persistenceIO(domain: error.domain, code: error.code)
    }
}

private func localPassportStoreError(for error: Error) -> EncryptedLocalPassportStoreError {
    switch error as? AESGCMEncryptedFileStorageError {
    case .some(.plaintextOrUnsupportedFormat):
        return .plaintextOrUnsupportedFormat
    case .some(.authenticationFailed):
        return .authenticationFailed
    case .none:
        let error = error as NSError
        return .persistenceIO(domain: error.domain, code: error.code)
    }
}

private struct AESGCMEncryptedFileStorage: Sendable {
    private let fileURL: URL
    private let encryptionKey: SymmetricKey
    private let fileMagic: Data

    init(
        fileURL: URL,
        key: ManualVisitOutboxEncryptionKey,
        fileMagic: Data
    ) {
        self.fileURL = fileURL
        encryptionKey = SymmetricKey(data: key.rawValue)
        self.fileMagic = fileMagic
    }

    func load() throws -> Data? {
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            return nil
        }

        let encrypted = try Data(contentsOf: fileURL)
        guard encrypted.count > fileMagic.count,
              encrypted.starts(with: fileMagic) else {
            throw AESGCMEncryptedFileStorageError.plaintextOrUnsupportedFormat
        }

        let combined = Data(encrypted.dropFirst(fileMagic.count))
        do {
            let sealedBox = try AES.GCM.SealedBox(combined: combined)
            return try AES.GCM.open(sealedBox, using: encryptionKey)
        } catch {
            throw AESGCMEncryptedFileStorageError.authenticationFailed
        }
    }

    func save(_ plaintext: Data) throws {
        let sealedBox = try AES.GCM.seal(plaintext, using: encryptionKey)
        guard let combined = sealedBox.combined else {
            throw AESGCMEncryptedFileStorageError.authenticationFailed
        }

        var encrypted = fileMagic
        encrypted.append(combined)
        try atomicallyReplaceFile(with: encrypted)
    }

    func remove() throws {
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            return
        }
        try FileManager.default.removeItem(at: fileURL)
    }

    private func atomicallyReplaceFile(with data: Data) throws {
        let fileManager = FileManager.default
        let directory = fileURL.deletingLastPathComponent()
        try fileManager.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )

        let temporaryURL = directory.appendingPathComponent(
            ".\(fileURL.lastPathComponent).\(UUID().uuidString).tmp",
            isDirectory: false
        )

        do {
            try data.write(to: temporaryURL, options: .atomic)
            if fileManager.fileExists(atPath: fileURL.path) {
                _ = try fileManager.replaceItemAt(
                    fileURL,
                    withItemAt: temporaryURL,
                    backupItemName: nil,
                    options: []
                )
            } else {
                try fileManager.moveItem(at: temporaryURL, to: fileURL)
            }
        } catch {
            try? fileManager.removeItem(at: temporaryURL)
            throw error
        }
    }
}
public enum SelfPassportSyncError: Error, Equatable, Sendable {
    case invalidExpectedMountainSet
    case invalidBootstrap
    case invalidAggregate
    case invalidHistoryPage
    case invalidChangePage
    case missingCanonicalBase
    case receiptMismatch
    case remoteDeleteNotAuthorized
    case writePaused(SelfPassportWritePauseReason)
    case emptyOpaqueToken
}

public struct OpaqueHistoryToken: Codable, Equatable, Hashable, Sendable {
    public let rawValue: String

public init(rawValue: String) throws {
        guard !rawValue.isEmpty else {
            throw SelfPassportSyncError.emptyOpaqueToken
        }
        self.rawValue = rawValue
    }

    public init(from decoder: any Decoder) throws {
        try self.init(rawValue: decoder.singleValueContainer().decode(String.self))
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

public struct OpaqueChangeToken: Codable, Equatable, Hashable, Sendable {
    public let rawValue: String

public init(rawValue: String) throws {
        guard !rawValue.isEmpty else {
            throw SelfPassportSyncError.emptyOpaqueToken
        }
        self.rawValue = rawValue
    }

    public init(from decoder: any Decoder) throws {
        try self.init(rawValue: decoder.singleValueContainer().decode(String.self))
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

/// The server-authoritative aggregate facts used for the local map and
/// passport summary. This deliberately contains no catalog labels or remote
/// credentials; labels continue to come from the bundled dataset.
public struct SelfPassportAggregate: Codable, Equatable, Sendable {
    public let mountainID: MountainID
    public let aggregateVersion: Int64
    public let visitCount: Int
    public let planDisposition: PlanDisposition?
    public let stamp: Stamp?

    public init(
        mountainID: MountainID,
        aggregateVersion: Int64,
        visitCount: Int,
        planDisposition: PlanDisposition?,
        stamp: Stamp?
    ) throws {
guard aggregateVersion >= 0, visitCount >= 0 else {
            throw SelfPassportSyncError.invalidAggregate
        }
        guard stamp?.mountainID == nil || stamp?.mountainID == mountainID else {
            throw SelfPassportSyncError.invalidAggregate
        }
        guard (visitCount > 0) == (stamp != nil) else {
            throw SelfPassportSyncError.invalidAggregate
        }

        self.mountainID = mountainID
        self.aggregateVersion = aggregateVersion
        self.visitCount = visitCount
        self.planDisposition = planDisposition
        self.stamp = stamp
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            mountainID: container.decode(MountainID.self, forKey: .mountainID),
            aggregateVersion: container.decode(Int64.self, forKey: .aggregateVersion),
            visitCount: container.decode(Int.self, forKey: .visitCount),
            planDisposition: container.decodeIfPresent(
                PlanDisposition.self,
                forKey: .planDisposition
            ),
            stamp: container.decodeIfPresent(Stamp.self, forKey: .stamp)
        )
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(mountainID, forKey: .mountainID)
        try container.encode(aggregateVersion, forKey: .aggregateVersion)
        try container.encode(visitCount, forKey: .visitCount)
        try container.encodeIfPresent(planDisposition, forKey: .planDisposition)
        try container.encodeIfPresent(stamp, forKey: .stamp)
    }

    private enum CodingKeys: String, CodingKey {
        case mountainID
        case aggregateVersion
        case visitCount
        case planDisposition
        case stamp
    }
}

/// A completed, snapshot-bound history. Its contents are never exposed as a
/// delete target until the corresponding history pagination is complete.
public struct SelfPassportVisitHistory: Codable, Equatable, Sendable {
    public let mountainID: MountainID
    public let snapshotVersion: Int64
    public let aggregateVersionAtSnapshot: Int64
    public let visits: [VisitRecord]

    public init(
        mountainID: MountainID,
        snapshotVersion: Int64,
        aggregateVersionAtSnapshot: Int64,
        visits: [VisitRecord]
    ) throws {
guard snapshotVersion >= 0,
              aggregateVersionAtSnapshot >= 0,
              visits.allSatisfy({ $0.mountainID == mountainID }),
              Set(visits.map(\.id)).count == visits.count,
              Self.isStrictlyDescending(visits) else {
            throw SelfPassportSyncError.invalidHistoryPage
        }

        self.mountainID = mountainID
        self.snapshotVersion = snapshotVersion
        self.aggregateVersionAtSnapshot = aggregateVersionAtSnapshot
        self.visits = visits
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            mountainID: container.decode(MountainID.self, forKey: .mountainID),
            snapshotVersion: container.decode(Int64.self, forKey: .snapshotVersion),
            aggregateVersionAtSnapshot: container.decode(
                Int64.self,
                forKey: .aggregateVersionAtSnapshot
            ),
            visits: container.decode([VisitRecord].self, forKey: .visits)
        )
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(mountainID, forKey: .mountainID)
        try container.encode(snapshotVersion, forKey: .snapshotVersion)
        try container.encode(
            aggregateVersionAtSnapshot,
            forKey: .aggregateVersionAtSnapshot
        )
        try container.encode(visits, forKey: .visits)
    }

    private enum CodingKeys: String, CodingKey {
        case mountainID
        case snapshotVersion
        case aggregateVersionAtSnapshot
        case visits
    }

    private static func isStrictlyDescending(_ visits: [VisitRecord]) -> Bool {
        zip(visits, visits.dropFirst()).allSatisfy { earlier, later in
            if earlier.visitedAt != later.visitedAt {
                return earlier.visitedAt > later.visitedAt
            }
            return earlier.id.rawValue > later.id.rawValue
        }
    }
}

/// The only durable canonical remote base. Pending writes are deliberately
/// excluded and continue to live in the local mutation outboxes.
public struct SelfPassportSyncBase: Codable, Equatable, Sendable {
    public let snapshotVersion: Int64
    public let datasetVersion: String
    public let schemaVersion: Int
    public let historyToken: OpaqueHistoryToken
    public let aggregates: [SelfPassportAggregate]
    public let histories: [SelfPassportVisitHistory]

    public init(
        snapshotVersion: Int64,
        datasetVersion: String,
        schemaVersion: Int,
        historyToken: OpaqueHistoryToken,
        aggregates: [SelfPassportAggregate],
        histories: [SelfPassportVisitHistory] = []
    ) throws {
        guard snapshotVersion >= 0,
              !datasetVersion.isEmpty,
              schemaVersion == 1,
              Self.isStrictlyAscending(aggregates),
              Set(aggregates.map(\.mountainID)).count == aggregates.count,
              Set(histories.map(\.mountainID)).count == histories.count,
              histories.allSatisfy({ history in
                  history.snapshotVersion == snapshotVersion
                      && aggregates.first {
                          $0.mountainID == history.mountainID
                      }?.aggregateVersion == history.aggregateVersionAtSnapshot
                      && aggregates.first {
                          $0.mountainID == history.mountainID
                      }?.visitCount == history.visits.count
              }) else {
            throw SelfPassportSyncError.invalidBootstrap
        }

        self.snapshotVersion = snapshotVersion
        self.datasetVersion = datasetVersion
        self.schemaVersion = schemaVersion
        self.historyToken = historyToken
        self.aggregates = aggregates
        self.histories = histories
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let rawContainer = try decoder.container(
            keyedBy: LocalPassportSnapshotCodingKey.self
        )
        guard Set(rawContainer.allKeys.map(\.stringValue)) == Set([
            "snapshotVersion",
            "datasetVersion",
            "schemaVersion",
            "historyToken",
            "aggregates",
            "histories",
        ]) else {
            throw SelfPassportSyncError.invalidBootstrap
        }
        try self.init(
            snapshotVersion: container.decode(Int64.self, forKey: .snapshotVersion),
            datasetVersion: container.decode(String.self, forKey: .datasetVersion),
            schemaVersion: container.decode(Int.self, forKey: .schemaVersion),
            historyToken: container.decode(OpaqueHistoryToken.self, forKey: .historyToken),
            aggregates: container.decode(
                [SelfPassportAggregate].self,
                forKey: .aggregates
            ),
            histories: container.decode(
                [SelfPassportVisitHistory].self,
                forKey: .histories
            )
        )
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(snapshotVersion, forKey: .snapshotVersion)
        try container.encode(datasetVersion, forKey: .datasetVersion)
        try container.encode(schemaVersion, forKey: .schemaVersion)
        try container.encode(historyToken, forKey: .historyToken)
        try container.encode(aggregates, forKey: .aggregates)
        try container.encode(histories, forKey: .histories)
    }

    private enum CodingKeys: String, CodingKey {
        case snapshotVersion
        case datasetVersion
        case schemaVersion
        case historyToken
        case aggregates
        case histories
    }

    public func aggregate(for mountainID: MountainID) -> SelfPassportAggregate? {
        aggregates.first { $0.mountainID == mountainID }
    }

    public func completedHistory(
        for mountainID: MountainID
    ) -> SelfPassportVisitHistory? {
        histories.first { $0.mountainID == mountainID }
    }

    fileprivate func replacing(
        snapshotVersion: Int64? = nil,
        historyToken: OpaqueHistoryToken? = nil,
        aggregates: [SelfPassportAggregate]? = nil,
        histories: [SelfPassportVisitHistory]? = nil
    ) throws -> SelfPassportSyncBase {
        try SelfPassportSyncBase(
            snapshotVersion: snapshotVersion ?? self.snapshotVersion,
            datasetVersion: datasetVersion,
            schemaVersion: schemaVersion,
            historyToken: historyToken ?? self.historyToken,
            aggregates: aggregates ?? self.aggregates,
            histories: histories ?? self.histories
        )
    }

    private static func isStrictlyAscending(
        _ aggregates: [SelfPassportAggregate]
    ) -> Bool {
        zip(aggregates, aggregates.dropFirst()).allSatisfy {
            $0.mountainID.rawValue < $1.mountainID.rawValue
        }
    }
}

public struct SelfPassportBootstrapResponse: Codable, Equatable, Sendable {
    public let snapshotVersion: Int64
    public let datasetVersion: String
    public let schemaVersion: Int
    public let historyToken: OpaqueHistoryToken
    public let aggregates: [SelfPassportAggregate]

    public init(
        snapshotVersion: Int64,
        datasetVersion: String,
        schemaVersion: Int,
        historyToken: OpaqueHistoryToken,
        aggregates: [SelfPassportAggregate]
    ) {
        self.snapshotVersion = snapshotVersion
        self.datasetVersion = datasetVersion
        self.schemaVersion = schemaVersion
        self.historyToken = historyToken
        self.aggregates = aggregates
    }
}

public struct SelfPassportHistoryRequest: Equatable, Sendable {
    public let mountainID: MountainID
    public let snapshotVersion: Int64
    public let historyToken: OpaqueHistoryToken
    public let continuationToken: OpaqueHistoryToken?

    public init(
        mountainID: MountainID,
        snapshotVersion: Int64,
        historyToken: OpaqueHistoryToken,
        continuationToken: OpaqueHistoryToken?
    ) {
        self.mountainID = mountainID
        self.snapshotVersion = snapshotVersion
        self.historyToken = historyToken
        self.continuationToken = continuationToken
    }
}

public struct SelfPassportHistoryPage: Codable, Equatable, Sendable {
    public let mountainID: MountainID
    public let snapshotVersion: Int64
    public let aggregateVersionAtSnapshot: Int64
    public let visits: [VisitRecord]
    public let nextContinuationToken: OpaqueHistoryToken?

    public init(
        mountainID: MountainID,
        snapshotVersion: Int64,
        aggregateVersionAtSnapshot: Int64,
        visits: [VisitRecord],
        nextContinuationToken: OpaqueHistoryToken?
    ) {
        self.mountainID = mountainID
        self.snapshotVersion = snapshotVersion
        self.aggregateVersionAtSnapshot = aggregateVersionAtSnapshot
        self.visits = visits
        self.nextContinuationToken = nextContinuationToken
    }
}

public struct SelfPassportChangeRequest: Equatable, Sendable {
    public let afterSnapshotVersion: Int64
    public let continuationToken: OpaqueChangeToken?

    public init(
        afterSnapshotVersion: Int64,
        continuationToken: OpaqueChangeToken?
    ) {
        self.afterSnapshotVersion = afterSnapshotVersion
        self.continuationToken = continuationToken
    }
}

public struct SelfPassportChange: Codable, Equatable, Sendable {
    public let globalSnapshotVersion: Int64
    public let aggregate: SelfPassportAggregate

    public init(globalSnapshotVersion: Int64, aggregate: SelfPassportAggregate) {
        self.globalSnapshotVersion = globalSnapshotVersion
        self.aggregate = aggregate
    }
}

public struct SelfPassportChangePage: Codable, Equatable, Sendable {
    public let afterSnapshotVersion: Int64
    public let changes: [SelfPassportChange]
    public let nextContinuationToken: OpaqueChangeToken?
    public let nextSnapshotVersion: Int64
    public let historyToken: OpaqueHistoryToken

    public init(
        afterSnapshotVersion: Int64,
        changes: [SelfPassportChange],
        nextContinuationToken: OpaqueChangeToken?,
        nextSnapshotVersion: Int64,
        historyToken: OpaqueHistoryToken
    ) {
        self.afterSnapshotVersion = afterSnapshotVersion
        self.changes = changes
        self.nextContinuationToken = nextContinuationToken
        self.nextSnapshotVersion = nextSnapshotVersion
        self.historyToken = historyToken
    }
}

public struct SelfPassportMutationReceipt: Codable, Equatable, Sendable {
    public let clientMutationID: ClientMutationID
    public let operation: ManualVisitOutboxOperation
    public let visitID: VisitID
    public let mountainID: MountainID
    public let aggregate: SelfPassportAggregate
    public let snapshotVersion: Int64
    public let historyToken: OpaqueHistoryToken

    public init(
        clientMutationID: ClientMutationID,
        operation: ManualVisitOutboxOperation,
        visitID: VisitID,
        mountainID: MountainID,
        aggregate: SelfPassportAggregate,
        snapshotVersion: Int64,
        historyToken: OpaqueHistoryToken
    ) {
        self.clientMutationID = clientMutationID
        self.operation = operation
        self.visitID = visitID
        self.mountainID = mountainID
        self.aggregate = aggregate
        self.snapshotVersion = snapshotVersion
        self.historyToken = historyToken
    }
}
public struct SelfPassportPlanMutationReceipt: Codable, Equatable, Sendable {
    public let clientMutationID: ClientMutationID
    public let operation: PlanMutationOutboxOperation
    public let mountainID: MountainID
    public let aggregate: SelfPassportAggregate
    public let snapshotVersion: Int64
    public let historyToken: OpaqueHistoryToken

    public init(
        clientMutationID: ClientMutationID,
        operation: PlanMutationOutboxOperation,
        mountainID: MountainID,
        aggregate: SelfPassportAggregate,
        snapshotVersion: Int64,
        historyToken: OpaqueHistoryToken
    ) {
        self.clientMutationID = clientMutationID
        self.operation = operation
        self.mountainID = mountainID
        self.aggregate = aggregate
        self.snapshotVersion = snapshotVersion
        self.historyToken = historyToken
    }
}


public enum SelfPassportTransportFailure: Error, Equatable, Sendable {
    case unauthenticated
    case forbidden
    case refreshRequired
    case fullRefreshRequired
    case upgradeRequired
    case mutationConflict
    case mutationRejected
    case transient
}

public enum SelfPassportWritePauseReason: String, Codable, Equatable, Sendable {
    case unauthenticated
    case authorization
    case continuity
    case compatibility
    case mutationConflict
    case mutationRejected
}
/// Privacy-safe classifications returned by the M4 server after it discards a
/// one-shot GPS sample. They deliberately contain no coordinate, accuracy, or
/// timestamp data.
public enum GPSVisitManualFallbackReason: String, Codable, Equatable, Sendable {
    case sampleInvalid = "gps_sample_invalid"
    case sampleAgeRejected = "gps_sample_age_rejected"
    case accuracyRejected = "gps_accuracy_rejected"
    case distanceRejected = "gps_distance_rejected"
}

/// A definitive M4 rejection for which no GPS visit was committed. The UI may
/// keep manual recording available for these cases.
public enum GPSVisitVerificationRejection: Equatable, Sendable {
    case authorization
    case policy
    case server
    case precondition
}

/// The acknowledged, server-authoritative GPS mutation. The corresponding
/// `VisitRecord` is loaded from the refreshed, actor-bound history capability;
/// the RPC response intentionally does not expose a server-recorded timestamp.
public struct GPSVisitVerificationReceipt: Equatable, Sendable {
    public let clientMutationID: ClientMutationID
    public let visitID: VisitID
    public let mountainID: MountainID
    public let aggregate: SelfPassportAggregate
    public let snapshotVersion: Int64
    public let historyToken: OpaqueHistoryToken

    public init(
        clientMutationID: ClientMutationID,
        visitID: VisitID,
        mountainID: MountainID,
        aggregate: SelfPassportAggregate,
        snapshotVersion: Int64,
        historyToken: OpaqueHistoryToken
    ) {
        self.clientMutationID = clientMutationID
        self.visitID = visitID
        self.mountainID = mountainID
        self.aggregate = aggregate
        self.snapshotVersion = snapshotVersion
        self.historyToken = historyToken
    }
}

/// An online GPS attempt never joins the manual outbox. A definitive rejection
/// permits manual recording; an indeterminate result requires a refresh before
/// another visit action so a potentially committed visit is not duplicated.
public enum GPSVisitVerificationOutcome: Equatable, Sendable {
    case gpsVerified(GPSVisitVerificationReceipt)
    case manualFallback(GPSVisitManualFallbackReason)
    case rejected(GPSVisitVerificationRejection)
    case indeterminate
}

/// The GPS surface is deliberately separate from `SelfPassportSyncTransport`:
/// it consumes a current actor-bound sync capability and is never replayed from
/// durable local state. Sample arguments are ephemeral values, not a Codable
/// request model, so they cannot enter `LocalPassportSnapshot`.
public protocol GPSVisitVerificationTransport: Sendable {
    func verifyGPSVisit(
        mountainID: MountainID,
        visitID: VisitID,
        visitedAt: Date,
        clientMutationID: ClientMutationID,
        latitude: Double,
        longitude: Double,
        horizontalAccuracyMeters: Double,
        sampledAt: Date
    ) async throws -> GPSVisitVerificationOutcome
}

/// Transport is intentionally protocol-injected. Implementations are expected
/// to authenticate as the current user and must not contain service-role
/// credentials.
public protocol SelfPassportSyncTransport: Sendable {
    func bootstrap() async throws -> SelfPassportBootstrapResponse
    func historyPage(_ request: SelfPassportHistoryRequest) async throws
        -> SelfPassportHistoryPage
    func changePage(_ request: SelfPassportChangeRequest) async throws
        -> SelfPassportChangePage
    func upload(_ node: ManualVisitOutboxNode) async throws
        -> SelfPassportMutationReceipt
    func uploadPlan(_ node: PlanMutationOutboxNode) async throws
        -> SelfPassportPlanMutationReceipt
}

public enum SelfBootstrapPublication: Equatable, Sendable {
    case unavailable
    case published(SelfPassportSyncBase)
}

/// Fetches and atomically publishes only a complete exact-100 self base. A
/// failed or incomplete response does not overwrite a previously verified
/// base, so cache loss stays unavailable until a complete bootstrap succeeds.
public actor SelfBootstrapper<Store: HikerLocalDataStore> where Store.Value == LocalPassportSnapshot {
    private let store: Store
    private let transport: any SelfPassportSyncTransport
    private let expectedMountainIDs: Set<MountainID>
    private let expectedDatasetVersion: String

    public private(set) var publication: SelfBootstrapPublication = .unavailable

    public init(
        store: Store,
        transport: any SelfPassportSyncTransport,
        expectedMountainIDs: Set<MountainID>,
        expectedDatasetVersion: String
    ) {
        self.store = store
        self.transport = transport
        self.expectedMountainIDs = expectedMountainIDs
        self.expectedDatasetVersion = expectedDatasetVersion
    }

    @discardableResult
    public func restore() async throws -> SelfBootstrapPublication {
        guard expectedMountainIDs.count == 100,
              !expectedDatasetVersion.isEmpty,
              let snapshot = try await store.load(),
              let base = snapshot.syncBase,
              isComplete(base) else {
            publication = .unavailable
            return publication
        }

        publication = .published(base)
        return publication
    }

    @discardableResult
    public func bootstrap() async throws -> SelfPassportSyncBase {
        guard expectedMountainIDs.count == 100, !expectedDatasetVersion.isEmpty else {
            throw SelfPassportSyncError.invalidExpectedMountainSet
        }

        let startingStoredSnapshot = try await store.load()
        let startingSnapshot = try startingStoredSnapshot ?? LocalPassportSnapshot(
            passportState: PassportStateMachine(),
            manualVisitOutbox: ManualVisitOutboxGraph()
        )
        let response = try await transport.bootstrap()
        let base = try SelfPassportSyncBase(
            snapshotVersion: response.snapshotVersion,
            datasetVersion: response.datasetVersion,
            schemaVersion: response.schemaVersion,
            historyToken: response.historyToken,
            aggregates: response.aggregates
        )
        guard isComplete(base) else {
            throw SelfPassportSyncError.invalidBootstrap
        }

        let currentStoredSnapshot = try await store.load()
        let current = try currentStoredSnapshot ?? LocalPassportSnapshot(
            passportState: PassportStateMachine(),
            manualVisitOutbox: ManualVisitOutboxGraph()
        )
        guard current.actorID == startingSnapshot.actorID else {
            throw SelfPassportTransportFailure.unauthenticated
        }
        let recoveredPauseReason: SelfPassportWritePauseReason? =
            current.writePauseReason == .continuity ? nil : current.writePauseReason
        let updated = try LocalPassportSnapshot(
            passportState: current.passportState,
            manualVisitOutbox: current.manualVisitOutbox,
            planMutationOutbox: current.planMutationOutbox,
            syncBase: base,
            writePauseReason: recoveredPauseReason,
            actorID: current.actorID
        )
        guard try await store.saveIfUnchanged(
            updated,
            expected: currentStoredSnapshot
        ) else {
            throw SelfPassportTransportFailure.fullRefreshRequired
        }
        publication = .published(base)
        return base
    }

    private func isComplete(_ base: SelfPassportSyncBase) -> Bool {
        base.datasetVersion == expectedDatasetVersion
            && base.schemaVersion == 1
            && base.aggregates.count == 100
            && Set(base.aggregates.map(\.mountainID)) == expectedMountainIDs
    }

    private func currentSnapshot() async throws -> LocalPassportSnapshot {
        if let snapshot = try await store.load() {
            return snapshot
        }
        return try LocalPassportSnapshot(
            passportState: PassportStateMachine(),
            manualVisitOutbox: ManualVisitOutboxGraph()
        )
    }
}

public enum SelfPassportChangeRefreshResult: Equatable, Sendable {
    case unchanged(snapshotVersion: Int64)
    case updated(snapshotVersion: Int64)
    case fullResync(snapshotVersion: Int64)
}

/// Sync orchestration keeps the encrypted local snapshot and immutable outbox
/// as the persistence boundary. Canonical server bases replace only
/// `syncBase`; durable local operations are then reapplied in sequence when
/// callers request the effective aggregate view.
private enum PendingPassportMutation {
    case manual(ManualVisitOutboxNode)
    case plan(PlanMutationOutboxNode)

    var enqueuedAt: Date {
        switch self {
        case let .manual(node):
            node.enqueuedAt
        case let .plan(node):
            node.enqueuedAt
        }
    }

    var mutationID: String {
        switch self {
        case let .manual(node):
            node.id.rawValue
        case let .plan(node):
            node.clientMutationID.rawValue
        }
    }
}

public actor SelfPassportSyncEngine<Store: HikerLocalDataStore> where Store.Value == LocalPassportSnapshot {
    private let store: Store
    private let transport: any SelfPassportSyncTransport
    private let bootstrapper: SelfBootstrapper<Store>
    private var cachedSnapshot: LocalPassportSnapshot?
    private var pauseReason: SelfPassportWritePauseReason?

    public init(
        store: Store,
        transport: any SelfPassportSyncTransport,
        expectedMountainIDs: Set<MountainID>,
        expectedDatasetVersion: String
    ) {
        self.store = store
        self.transport = transport
        bootstrapper = SelfBootstrapper(
            store: store,
            transport: transport,
            expectedMountainIDs: expectedMountainIDs,
            expectedDatasetVersion: expectedDatasetVersion
        )
    }

    public func restore() async throws -> SelfBootstrapPublication {
        let publication = try await bootstrapper.restore()
        if let stored = try await store.load() {
            var manualOutbox = stored.manualVisitOutbox
            _ = manualOutbox.recoverAfterRestart()
            var planOutbox = stored.planMutationOutbox
            for index in planOutbox.indices where planOutbox[index].state == .inFlight {
                planOutbox[index].state = .queued
            }
            let recovered = try LocalPassportSnapshot(
                passportState: stored.passportState,
                manualVisitOutbox: manualOutbox,
                planMutationOutbox: planOutbox,
                syncBase: stored.syncBase,
                writePauseReason: stored.writePauseReason,
                actorID: stored.actorID
            )
            if recovered != stored {
                guard try await store.saveIfUnchanged(recovered, expected: stored) else {
                    throw SelfPassportTransportFailure.fullRefreshRequired
                }
            }
            cachedSnapshot = recovered
            pauseReason = recovered.writePauseReason
        } else {
            cachedSnapshot = nil
            pauseReason = nil
        }
        return publication
    }

    @discardableResult
    public func bootstrap() async throws -> SelfPassportSyncBase {
        do {
            let base = try await bootstrapper.bootstrap()
            cachedSnapshot = try await store.load()
            pauseReason = cachedSnapshot?.writePauseReason
            return base
        } catch {
            try await persistPause(for: error)
            throw error
        }
    }

    public func canonicalBase() async throws -> SelfPassportSyncBase? {
        let snapshot = try await currentSnapshot()
        return snapshot.syncBase
    }

    public func writePauseReason() -> SelfPassportWritePauseReason? {
        pauseReason
    }

    public func effectiveAggregates() async throws -> [SelfPassportAggregate] {
        try replayEffectiveAggregates(try await currentSnapshot())
    }
    /// Sends one user-initiated GPS sample directly to the authenticated M4
    /// boundary. The sample never enters a local outbox or snapshot; only a
    /// server-confirmed visit and refreshed canonical base are persisted.
    @discardableResult
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
        let snapshot: LocalPassportSnapshot
        let base: SelfPassportSyncBase
        let gpsTransport: any GPSVisitVerificationTransport
        do {
            snapshot = try await requireWritesEnabled()
            guard let acceptedBase = snapshot.syncBase,
                  let acceptedTransport = transport as? any GPSVisitVerificationTransport else {
                return .rejected(.precondition)
            }
            base = acceptedBase
            gpsTransport = acceptedTransport
            try validatePlanMutationID(clientMutationID, in: snapshot)
        } catch {
            return .rejected(.precondition)
        }

        let outcome: GPSVisitVerificationOutcome
        do {
            outcome = try await gpsTransport.verifyGPSVisit(
                mountainID: mountainID,
                visitID: visitID,
                visitedAt: visitedAt,
                clientMutationID: clientMutationID,
                latitude: latitude,
                longitude: longitude,
                horizontalAccuracyMeters: horizontalAccuracyMeters,
                sampledAt: sampledAt
            )
        } catch let error as SelfPassportTransportFailure where error == .mutationConflict {
            try await persistRecoveredState(pauseReason: pauseReason(for: error))
            throw error
        } catch {
            try await persistRecoveredState(pauseReason: pauseReason(for: error))
            return .indeterminate
        }

        guard case let .gpsVerified(receipt) = outcome else {
            return outcome
        }

        do {
            guard receipt.clientMutationID == clientMutationID,
                  receipt.visitID == visitID,
                  receipt.mountainID == mountainID,
                  receipt.aggregate.mountainID == mountainID else {
                throw SelfPassportSyncError.receiptMismatch
            }

            let rebasedBase = try await resolvedBase(base: base, with: receipt)
            let current = try await currentSnapshot()
            guard current.actorID == snapshot.actorID,
                  current.syncBase == base || current.syncBase == rebasedBase else {
                throw SelfPassportTransportFailure.fullRefreshRequired
            }
            try await persist(
                try LocalPassportSnapshot(
                    passportState: current.passportState,
                    manualVisitOutbox: current.manualVisitOutbox,
                    planMutationOutbox: current.planMutationOutbox,
                    syncBase: rebasedBase,
                    writePauseReason: current.writePauseReason,
                    actorID: current.actorID
                )
            )

            let history = try await loadCompleteHistory(for: mountainID)
            guard let verifiedVisit = history.visits.first(where: {
                $0.id == visitID && $0.verificationMethod == .gpsVerified
            }) else {
                throw SelfPassportSyncError.receiptMismatch
            }

            let historySnapshot = try await currentSnapshot()
            var passport = historySnapshot.passportState
            if let existing = passport.allProjections()
                .flatMap(\.history)
                .first(where: { $0.id == visitID }) {
                guard existing == verifiedVisit else {
                    throw SelfPassportSyncError.receiptMismatch
                }
            } else {
                try passport.recordVisit(verifiedVisit)
            }
            try await persist(
                try LocalPassportSnapshot(
                    passportState: passport,
                    manualVisitOutbox: historySnapshot.manualVisitOutbox,
                    planMutationOutbox: historySnapshot.planMutationOutbox,
                    syncBase: historySnapshot.syncBase,
                    writePauseReason: historySnapshot.writePauseReason,
                    actorID: historySnapshot.actorID
                )
            )
            return .gpsVerified(receipt)
        } catch let error as SelfPassportTransportFailure where error == .mutationConflict {
            try await persistRecoveredState(pauseReason: pauseReason(for: error))
            throw error
        } catch {
            try await persistRecoveredState(pauseReason: pauseReason(for: error))
            return .indeterminate
        }
    }

    private func replayEffectiveAggregates(
        _ snapshot: LocalPassportSnapshot
    ) throws -> [SelfPassportAggregate] {
        guard let base = snapshot.syncBase else {
            throw SelfPassportSyncError.missingCanonicalBase
        }

        var aggregates = Dictionary(
            uniqueKeysWithValues: base.aggregates.map { ($0.mountainID, $0) }
        )
        var effectiveHistories = Dictionary(
            uniqueKeysWithValues: base.histories.map { ($0.mountainID, $0.visits) }
        )

        func stamp(
            for mountainID: MountainID,
            visits: [VisitRecord]
        ) -> Stamp? {
            guard let source = visits.min(by: { lhs, rhs in
                if lhs.recordedAt != rhs.recordedAt {
                    return lhs.recordedAt < rhs.recordedAt
                }
                return lhs.id.rawValue < rhs.id.rawValue
            }) else {
                return nil
            }
            return Stamp(
                mountainID: mountainID,
                sourceVisitID: source.id,
                earnedAt: source.recordedAt,
                method: source.verificationMethod
            )
        }
        let pendingMutations =
            snapshot.manualVisitOutbox.nodes.map(PendingPassportMutation.manual)
                + snapshot.planMutationOutbox.map(PendingPassportMutation.plan)
        for pendingMutation in pendingMutations.sorted(by: { lhs, rhs in
            if lhs.enqueuedAt != rhs.enqueuedAt {
                return lhs.enqueuedAt < rhs.enqueuedAt
            }
            return lhs.mutationID < rhs.mutationID
        }) {
            switch pendingMutation {
            case let .manual(node):
                guard var aggregate = aggregates[node.aggregateMountainID] else {
                    throw SelfPassportSyncError.invalidAggregate
                }

                switch node.request.operation {
                case .create:
                    guard let visit = try node.request.validatedCreateVisit() else {
                        throw SelfPassportSyncError.invalidAggregate
                    }
                    let plan: PlanDisposition?
                    if case .some(.active(.manual)) = aggregate.planDisposition {
                        plan = .active(.autoCompleted(firstVisitID: visit.id))
                    } else {
                        plan = aggregate.planDisposition
                    }
                    let visitHistory: [VisitRecord]?
                    if var history = effectiveHistories[node.aggregateMountainID] {
                        history.append(visit)
                        effectiveHistories[node.aggregateMountainID] = history
                        visitHistory = history
                    } else {
                        visitHistory = nil
                    }
                    let effectiveStamp = visitHistory.map {
                        stamp(for: aggregate.mountainID, visits: $0)
                    } ?? aggregate.stamp ?? Stamp(
                        mountainID: visit.mountainID,
                        sourceVisitID: visit.id,
                        earnedAt: visit.recordedAt,
                        method: visit.verificationMethod
                    )
                    aggregate = try SelfPassportAggregate(
                        mountainID: aggregate.mountainID,
                        aggregateVersion: aggregate.aggregateVersion,
                        visitCount: visitHistory?.count ?? aggregate.visitCount + 1,
                        planDisposition: plan,
                        stamp: effectiveStamp
                    )
                case .delete:
                    let visitHistory: [VisitRecord]?
                    if var history = effectiveHistories[node.aggregateMountainID] {
                        guard history.contains(where: { $0.id == node.request.visitID }) else {
                            throw SelfPassportSyncError.invalidAggregate
                        }
                        history.removeAll { $0.id == node.request.visitID }
                        effectiveHistories[node.aggregateMountainID] = history
                        visitHistory = history
                    } else {
                        visitHistory = nil
                    }
                    let count = visitHistory?.count ?? max(0, aggregate.visitCount - 1)
                    let plan: PlanDisposition?
                    if count == 0,
                       case .some(.active(.autoCompleted(firstVisitID: _))) =
                           aggregate.planDisposition {
                        plan = .active(.manual)
                    } else {
                        plan = aggregate.planDisposition
                    }
                    aggregate = try SelfPassportAggregate(
                        mountainID: aggregate.mountainID,
                        aggregateVersion: aggregate.aggregateVersion,
                        visitCount: count,
                        planDisposition: plan,
                        stamp: visitHistory.map {
                            stamp(for: aggregate.mountainID, visits: $0)
                        } ?? (count == 0 ? nil : aggregate.stamp)
                    )
                }
                aggregates[node.aggregateMountainID] = aggregate

            case let .plan(node):
                guard let aggregate = aggregates[node.mountainID] else {
                    throw SelfPassportSyncError.invalidAggregate
                }
                let plan: PlanDisposition = switch node.operation {
                case .add:
                    .active(.manual)
                case .remove:
                    .manuallyRemoved
                }
                aggregates[node.mountainID] = try SelfPassportAggregate(
                    mountainID: aggregate.mountainID,
                    aggregateVersion: aggregate.aggregateVersion,
                    visitCount: aggregate.visitCount,
                    planDisposition: plan,
                    stamp: aggregate.stamp
                )
            }
        }

        return aggregates.values.sorted { $0.mountainID.rawValue < $1.mountainID.rawValue }
    }

    /// Stores history only after every page completes at the currently
    /// published snapshot. Any token, page, or continuity failure leaves the
    /// prior completed history intact.
    @discardableResult
    public func loadCompleteHistory(
        for mountainID: MountainID
    ) async throws -> SelfPassportVisitHistory {
        let snapshot = try await currentSnapshot()
        guard let base = snapshot.syncBase,
              let aggregate = base.aggregate(for: mountainID) else {
            throw SelfPassportSyncError.missingCanonicalBase
        }

        var continuationToken: OpaqueHistoryToken?
        var visitedTokens = Set<String>()
        var visits: [VisitRecord] = []
        var pageCount = 0
        var lastVisit: VisitRecord?

        while true {
            pageCount += 1
            guard pageCount <= max(1, aggregate.visitCount + 1) else {
                throw SelfPassportSyncError.invalidHistoryPage
            }
            let page = try await transport.historyPage(
                SelfPassportHistoryRequest(
                    mountainID: mountainID,
                    snapshotVersion: base.snapshotVersion,
                    historyToken: base.historyToken,
                    continuationToken: continuationToken
                )
            )
            guard page.mountainID == mountainID,
                  page.snapshotVersion == base.snapshotVersion,
                  page.aggregateVersionAtSnapshot == aggregate.aggregateVersion,
                  page.visits.allSatisfy({ $0.mountainID == mountainID }),
                  page.visits.count <= 100,
                  page.visits.allSatisfy({ !visits.contains($0) }),
                  Self.isStrictlyDescending(page.visits),
                  lastVisit == nil || page.visits.first.map({
                      Self.precedes(lastVisit!, $0)
                  }) ?? true else {
                throw SelfPassportSyncError.invalidHistoryPage
            }

            visits.append(contentsOf: page.visits)
            guard visits.count <= aggregate.visitCount else {
                throw SelfPassportSyncError.invalidHistoryPage
            }
            lastVisit = visits.last

            guard let nextToken = page.nextContinuationToken else {
                break
            }
            guard !page.visits.isEmpty else {
                throw SelfPassportSyncError.invalidHistoryPage
            }
            guard visitedTokens.insert(nextToken.rawValue).inserted else {
                throw SelfPassportSyncError.invalidHistoryPage
            }
            continuationToken = nextToken
        }
        guard visits.count == aggregate.visitCount else {
            throw SelfPassportSyncError.invalidHistoryPage
        }


        let history = try SelfPassportVisitHistory(
            mountainID: mountainID,
            snapshotVersion: base.snapshotVersion,
            aggregateVersionAtSnapshot: aggregate.aggregateVersion,
            visits: visits
        )
        let histories = base.histories.filter { $0.mountainID != mountainID } + [history]
        let updatedBase = try base.replacing(
            histories: histories.sorted { $0.mountainID.rawValue < $1.mountainID.rawValue }
        )
        try await persist(
            try LocalPassportSnapshot(
                passportState: snapshot.passportState,
                manualVisitOutbox: snapshot.manualVisitOutbox,
                planMutationOutbox: snapshot.planMutationOutbox,
                syncBase: updatedBase,
                writePauseReason: snapshot.writePauseReason,
                actorID: snapshot.actorID
            ),
            expected: snapshot
        )
        return history
    }

    /// Advances the global baseline only after every change page is validated.
    /// A retention/gap failure performs a complete bootstrap before returning.
    @discardableResult
    public func refreshChanges() async throws -> SelfPassportChangeRefreshResult {
        let snapshot = try await currentSnapshot()
        guard let base = snapshot.syncBase else {
            throw SelfPassportSyncError.missingCanonicalBase
        }

        do {
            var continuationToken: OpaqueChangeToken?
            var seenTokens = Set<String>()
            var expectedVersion = base.snapshotVersion
            var aggregates = Dictionary(
                uniqueKeysWithValues: base.aggregates.map { ($0.mountainID, $0) }
            )
            var historyToken = base.historyToken
            var pageCount = 0
            var totalChangeCount = 0

            while true {
                pageCount += 1
                guard pageCount <= 1_000 else {
                    throw SelfPassportSyncError.invalidChangePage
                }
                let page = try await transport.changePage(
                    SelfPassportChangeRequest(
                        afterSnapshotVersion: base.snapshotVersion,
                        continuationToken: continuationToken
                    )
                )
                totalChangeCount += page.changes.count
                guard page.afterSnapshotVersion == base.snapshotVersion,
                      page.nextSnapshotVersion >= expectedVersion,
                      page.changes.count <= 500,
                      totalChangeCount <= 100_000 else {
                    throw SelfPassportSyncError.invalidChangePage
                }

                for change in page.changes {
                    guard change.globalSnapshotVersion == expectedVersion + 1,
                          let currentAggregate = aggregates[change.aggregate.mountainID],
                          change.aggregate.aggregateVersion > currentAggregate.aggregateVersion else {
                        throw SelfPassportTransportFailure.fullRefreshRequired
                    }
                    aggregates[change.aggregate.mountainID] = change.aggregate
                    expectedVersion = change.globalSnapshotVersion
                }
                historyToken = page.historyToken

                guard let nextToken = page.nextContinuationToken else {
                    guard page.nextSnapshotVersion == expectedVersion else {
                        throw SelfPassportSyncError.invalidChangePage
                    }
                    break
                }
                guard !page.changes.isEmpty,
                      seenTokens.insert(nextToken.rawValue).inserted else {
                    throw SelfPassportSyncError.invalidChangePage
                }
                continuationToken = nextToken
            }

            guard expectedVersion >= base.snapshotVersion else {
                throw SelfPassportSyncError.invalidChangePage
            }
            let updatedBase = try base.replacing(
                snapshotVersion: expectedVersion,
                historyToken: historyToken,
                aggregates: aggregates.values.sorted {
                    $0.mountainID.rawValue < $1.mountainID.rawValue
                },
                histories: []
            )
            try await persist(
                try LocalPassportSnapshot(
                    passportState: snapshot.passportState,
                    manualVisitOutbox: snapshot.manualVisitOutbox,
                    planMutationOutbox: snapshot.planMutationOutbox,
                    syncBase: updatedBase,
                    writePauseReason: snapshot.writePauseReason,
                    actorID: snapshot.actorID
                ),
                expected: snapshot
            )
            return expectedVersion == base.snapshotVersion
                ? .unchanged(snapshotVersion: expectedVersion)
                : .updated(snapshotVersion: expectedVersion)
        } catch SelfPassportTransportFailure.fullRefreshRequired {
            try await persistPause(.continuity)
            let base = try await bootstrap()
            return .fullResync(snapshotVersion: base.snapshotVersion)
        } catch SelfPassportTransportFailure.refreshRequired {
            try await persistPause(.continuity)
            let base = try await bootstrap()
            return .fullResync(snapshotVersion: base.snapshotVersion)
        } catch SelfPassportSyncError.invalidChangePage {
            try await persistPause(.continuity)
            let base = try await bootstrap()
            return .fullResync(snapshotVersion: base.snapshotVersion)
        } catch {
            try await persistPause(for: error)
            throw error
        }
    }

    /// Dispatches at most one per-aggregate head. The exact immutable request
    /// bytes are supplied to the transport and the graph is acknowledged only
    /// after its matching receipt has been persisted with the rebased base.
    @discardableResult
    public func uploadNextManualOutboxOperation(
        at now: Date = .now
    ) async throws -> SelfPassportMutationReceipt? {
        var snapshot = try await requireWritesEnabled()
        guard let base = snapshot.syncBase else {
            throw SelfPassportSyncError.missingCanonicalBase
        }

        var outbox = snapshot.manualVisitOutbox
        guard let node = outbox.nextDispatchable(at: now) else {
            if outbox != snapshot.manualVisitOutbox {
                try await persist(
                    try LocalPassportSnapshot(
                        passportState: snapshot.passportState,
                        manualVisitOutbox: outbox,
                        planMutationOutbox: snapshot.planMutationOutbox,
                        syncBase: snapshot.syncBase,
                        writePauseReason: snapshot.writePauseReason,
                        actorID: snapshot.actorID
                    )
                )
            }
            return nil
        }

        snapshot = try LocalPassportSnapshot(
            passportState: snapshot.passportState,
            manualVisitOutbox: outbox,
            planMutationOutbox: snapshot.planMutationOutbox,
            syncBase: snapshot.syncBase,
            writePauseReason: snapshot.writePauseReason,
            actorID: snapshot.actorID
        )
        try await persist(snapshot)

        do {
            let receipt = try await transport.upload(node)
            guard receipt.clientMutationID == node.id,
                  receipt.operation == node.request.operation,
                  receipt.visitID == node.request.visitID,
                  receipt.mountainID == node.aggregateMountainID,
                  receipt.aggregate.mountainID == node.aggregateMountainID else {
                throw SelfPassportSyncError.receiptMismatch
            }

            let rebasedBase = try await resolvedBase(base: base, with: receipt)
            let current = try await currentSnapshot()
            guard current.actorID == snapshot.actorID,
                  current.syncBase == base || current.syncBase == rebasedBase else {
                throw SelfPassportTransportFailure.fullRefreshRequired
            }
            var acknowledgedOutbox = current.manualVisitOutbox
            try acknowledgedOutbox.acknowledgeAccepted(mutationID: node.id)
            try await persist(
                try LocalPassportSnapshot(
                    passportState: current.passportState,
                    manualVisitOutbox: acknowledgedOutbox,
                    planMutationOutbox: current.planMutationOutbox,
                    syncBase: rebasedBase,
                    writePauseReason: current.writePauseReason,
                    actorID: current.actorID
                )
            )
            return receipt
        } catch {
            try await persistRecoveredState(
                pauseReason: pauseReason(for: error)
            )
            throw error
        }
    }
    @discardableResult
    public func uploadNextOutboxOperation(at now: Date = .now) async throws -> Bool {
        let snapshot = try await currentSnapshot()
        var manualOutbox = snapshot.manualVisitOutbox
        let manualNode = manualOutbox.nextDispatchable(at: now)
        let planNode = snapshot.planMutationOutbox
            .filter { $0.state == .queued }
            .min {
                if $0.enqueuedAt != $1.enqueuedAt {
                    return $0.enqueuedAt < $1.enqueuedAt
                }
                return $0.clientMutationID.rawValue < $1.clientMutationID.rawValue
            }

        switch (manualNode, planNode) {
        case (nil, nil):
            if manualOutbox != snapshot.manualVisitOutbox {
                try await persistManualOutbox(manualOutbox, over: snapshot)
            }
            return false
        case (.some, nil):
            _ = try await uploadNextManualOutboxOperation(at: now)
        case let (nil, .some(plan)):
            if manualOutbox != snapshot.manualVisitOutbox {
                try await persistManualOutbox(manualOutbox, over: snapshot)
            }
            _ = try await uploadNextPlanOutboxOperation(
                clientMutationID: plan.clientMutationID
            )
        case let (.some(manual), .some(plan)):
            if manual.enqueuedAt < plan.enqueuedAt
                || (manual.enqueuedAt == plan.enqueuedAt
                    && manual.id.rawValue < plan.clientMutationID.rawValue) {
                _ = try await uploadNextManualOutboxOperation(at: now)
            } else {
                _ = manualOutbox.recoverAfterRestart()
                if manualOutbox != snapshot.manualVisitOutbox {
                    try await persistManualOutbox(manualOutbox, over: snapshot)
                }
                _ = try await uploadNextPlanOutboxOperation(
                    clientMutationID: plan.clientMutationID
                )
            }
        }
        return true
    }
    /// Dispatches one durable plan mutation at a time. Acknowledgement and the
    /// corresponding canonical-base rebase are persisted as one snapshot.
    @discardableResult
    public func uploadNextPlanOutboxOperation(
        clientMutationID: ClientMutationID? = nil
    ) async throws -> SelfPassportPlanMutationReceipt? {
        let snapshot = try await requireWritesEnabled()
        guard let base = snapshot.syncBase else {
            throw SelfPassportSyncError.missingCanonicalBase
        }

        var planMutationOutbox = snapshot.planMutationOutbox
        guard !planMutationOutbox.contains(where: { $0.state == .inFlight }),
              let index = planMutationOutbox.firstIndex(where: {
                  $0.state == .queued
                      && (clientMutationID == nil || $0.clientMutationID == clientMutationID)
              }) else {
            return nil
        }

        planMutationOutbox[index].state = .inFlight
        let node = planMutationOutbox[index]
        let dispatchSnapshot = try LocalPassportSnapshot(
            passportState: snapshot.passportState,
            manualVisitOutbox: snapshot.manualVisitOutbox,
            planMutationOutbox: planMutationOutbox,
            syncBase: snapshot.syncBase,
            writePauseReason: snapshot.writePauseReason,
            actorID: snapshot.actorID
        )
        try await persist(dispatchSnapshot)

        do {
            let receipt = try await transport.uploadPlan(node)
            guard receipt.clientMutationID == node.id,
                  receipt.operation == node.operation,
                  receipt.mountainID == node.mountainID,
                  receipt.aggregate.mountainID == node.mountainID else {
                throw SelfPassportSyncError.receiptMismatch
            }

            let rebasedBase = try await resolvedBase(base: base, with: receipt)
            let current = try await currentSnapshot()
            guard current.actorID == snapshot.actorID,
                  current.syncBase == base || current.syncBase == rebasedBase else {
                throw SelfPassportTransportFailure.fullRefreshRequired
            }
            var acknowledgedOutbox = current.planMutationOutbox
            guard let acknowledgedIndex = acknowledgedOutbox.firstIndex(
                where: { $0.id == node.id && $0.state == .inFlight }
            ) else {
                throw SelfPassportSyncError.receiptMismatch
            }
            acknowledgedOutbox.remove(at: acknowledgedIndex)
            try await persist(
                try LocalPassportSnapshot(
                    passportState: current.passportState,
                    manualVisitOutbox: current.manualVisitOutbox,
                    planMutationOutbox: acknowledgedOutbox,
                    syncBase: rebasedBase,
                    writePauseReason: current.writePauseReason,
                    actorID: current.actorID
                )
            )
            return receipt
        } catch {
            try await persistRecoveredState(
                pauseReason: pauseReason(for: error)
            )
            throw error
        }
    }

    public func enqueuePlanAdd(
        for mountainID: MountainID,
        clientMutationID: ClientMutationID,
        at enqueuedAt: Date = .now
    ) async throws -> PlanMutationOutboxNode {
        let snapshot = try await requireWritesEnabled()
        try validatePlanAdd(for: mountainID, in: snapshot)
        try validatePlanMutationID(clientMutationID, in: snapshot)

        let node = PlanMutationOutboxNode(
            clientMutationID: clientMutationID,
            mountainID: mountainID,
            operation: .add,
            enqueuedAt: enqueuedAt
        )
        try await persist(
            try LocalPassportSnapshot(
                passportState: snapshot.passportState,
                manualVisitOutbox: snapshot.manualVisitOutbox,
                planMutationOutbox: snapshot.planMutationOutbox + [node],
                syncBase: snapshot.syncBase,
                writePauseReason: snapshot.writePauseReason,
                actorID: snapshot.actorID
            )
        )
        return node
    }

    public func enqueuePlanRemove(
        for mountainID: MountainID,
        clientMutationID: ClientMutationID,
        at enqueuedAt: Date = .now
    ) async throws -> PlanMutationOutboxNode {
        let snapshot = try await requireWritesEnabled()
        try validatePlanRemove(for: mountainID, in: snapshot)
        try validatePlanMutationID(clientMutationID, in: snapshot)

        let node = PlanMutationOutboxNode(
            clientMutationID: clientMutationID,
            mountainID: mountainID,
            operation: .remove,
            enqueuedAt: enqueuedAt
        )
        try await persist(
            try LocalPassportSnapshot(
                passportState: snapshot.passportState,
                manualVisitOutbox: snapshot.manualVisitOutbox,
                planMutationOutbox: snapshot.planMutationOutbox + [node],
                syncBase: snapshot.syncBase,
                writePauseReason: snapshot.writePauseReason,
                actorID: snapshot.actorID
            )
        )
        return node
    }

    public func enqueueManualCreate(
        _ visit: VisitRecord,
        clientMutationID: ClientMutationID,
        at enqueuedAt: Date = .now
    ) async throws -> ManualVisitOutboxNode {
        let snapshot = try await requireWritesEnabled()
        var passport = snapshot.passportState
        var outbox = snapshot.manualVisitOutbox
        try passport.recordVisit(visit)
        let node = try outbox.enqueueCreate(
            visit,
            clientMutationID: clientMutationID,
            at: enqueuedAt
        )
        try await persist(
            try LocalPassportSnapshot(
                passportState: passport,
                manualVisitOutbox: outbox,
                planMutationOutbox: snapshot.planMutationOutbox,
                syncBase: snapshot.syncBase,
                writePauseReason: snapshot.writePauseReason,
                actorID: snapshot.actorID
            )
        )
        return node
    }

    public func enqueueManualDelete(
        visitID: VisitID,
        mountainID: MountainID,
        clientMutationID: ClientMutationID,
        at enqueuedAt: Date = .now
    ) async throws -> ManualVisitOutboxEnqueueResult {
        let snapshot = try await requireWritesEnabled()
        var passport = snapshot.passportState
        var outbox = snapshot.manualVisitOutbox
        let hasPendingLocalCreate = outbox.nodes.contains {
            $0.request.operation == .create
                && $0.request.visitID == visitID
                && $0.aggregateMountainID == mountainID
        }
        let hasCompletedRemoteVisit = snapshot.syncBase?
            .completedHistory(for: mountainID)?
            .visits
            .contains { $0.id == visitID && $0.mountainID == mountainID } ?? false
        guard hasPendingLocalCreate || hasCompletedRemoteVisit else {
            throw SelfPassportSyncError.remoteDeleteNotAuthorized
        }

        if let localVisit = passport.allProjections()
            .flatMap(\.history)
            .first(where: { $0.id == visitID }) {
            guard localVisit.mountainID == mountainID else {
                throw SelfPassportSyncError.remoteDeleteNotAuthorized
            }
            try passport.deleteVisit(id: visitID)
        }

        let result = try outbox.enqueueDelete(
            visitID: visitID,
            mountainID: mountainID,
            clientMutationID: clientMutationID,
            at: enqueuedAt
        )
        try await persist(
            try LocalPassportSnapshot(
                passportState: passport,
                manualVisitOutbox: outbox,
                planMutationOutbox: snapshot.planMutationOutbox,
                syncBase: snapshot.syncBase,
                writePauseReason: snapshot.writePauseReason,
                actorID: snapshot.actorID
            )
        )
        return result
    }

    @discardableResult
    public func pauseExpiredOutbox(at now: Date = .now) async throws
        -> [ClientMutationID] {
        let snapshot = try await currentSnapshot()
        var outbox = snapshot.manualVisitOutbox
        let paused = outbox.pauseExpired(at: now)
        guard !paused.isEmpty else {
            return []
        }
        try await persist(
            try LocalPassportSnapshot(
                passportState: snapshot.passportState,
                manualVisitOutbox: outbox,
                planMutationOutbox: snapshot.planMutationOutbox,
                syncBase: snapshot.syncBase,
                writePauseReason: snapshot.writePauseReason,
                actorID: snapshot.actorID
            )
        )
        return paused
    }

    public func exportPausedOutbox() async throws -> [ManualVisitOutboxExport] {
        let snapshot = try await currentSnapshot()
        return snapshot.manualVisitOutbox.exportPaused()
    }

    @discardableResult
    public func applyOutboxExpiryChoice(
        _ choice: ManualVisitOutboxExpiryChoice,
        for mutationIDs: Set<ClientMutationID>
    ) async throws -> [ManualVisitOutboxExport] {
        let snapshot = try await currentSnapshot()
        var outbox = snapshot.manualVisitOutbox
        let exported = try outbox.applyExpiryChoice(choice, for: mutationIDs)
        switch choice {
        case .export:
            break
        case .discard:
            try await persist(
                try LocalPassportSnapshot(
                    passportState: snapshot.passportState,
                    manualVisitOutbox: outbox,
                    planMutationOutbox: snapshot.planMutationOutbox,
                    syncBase: snapshot.syncBase,
                    writePauseReason: snapshot.writePauseReason,
                    actorID: snapshot.actorID
                )
            )
        }
        return exported
    }

    /// Clears the durable write hold only after the caller has explicitly
    /// verified refreshed authentication or completed continuity recovery.
    public func resumeWrites() async throws {
        let snapshot = try await currentSnapshot()
        guard pauseReason != nil || snapshot.writePauseReason != nil else {
            return
        }
        try await persist(
            try LocalPassportSnapshot(
                passportState: snapshot.passportState,
                manualVisitOutbox: snapshot.manualVisitOutbox,
                planMutationOutbox: snapshot.planMutationOutbox,
                syncBase: snapshot.syncBase,
                writePauseReason: nil,
                actorID: snapshot.actorID
            )
        )
    }

    private func currentSnapshot() async throws -> LocalPassportSnapshot {
        if let loaded = try await store.load() {
            cachedSnapshot = loaded
            pauseReason = loaded.writePauseReason
            return loaded
        }
        let empty = try LocalPassportSnapshot(
            passportState: PassportStateMachine(),
            manualVisitOutbox: ManualVisitOutboxGraph()
        )
        cachedSnapshot = empty
        pauseReason = nil
        return empty
    }

    private func persist(
        _ snapshot: LocalPassportSnapshot,
        expected explicitExpected: LocalPassportSnapshot? = nil
    ) async throws {
        let expected = explicitExpected ?? cachedSnapshot
        guard try await store.saveIfUnchanged(snapshot, expected: expected) else {
            cachedSnapshot = try await store.load()
            pauseReason = cachedSnapshot?.writePauseReason
            throw SelfPassportTransportFailure.fullRefreshRequired
        }
        cachedSnapshot = snapshot
        pauseReason = snapshot.writePauseReason
    }

    private func requireWritesEnabled() async throws -> LocalPassportSnapshot {
        let snapshot = try await currentSnapshot()
        if let reason = snapshot.writePauseReason ?? pauseReason {
            pauseReason = reason
            throw SelfPassportSyncError.writePaused(reason)
        }
        return snapshot
    }
    private func validatePlanAdd(
        for mountainID: MountainID,
        in snapshot: LocalPassportSnapshot
    ) throws {
        guard let aggregate = try replayEffectiveAggregates(snapshot)
            .first(where: { $0.mountainID == mountainID }) else {
            throw SelfPassportSyncError.invalidAggregate
        }
        guard aggregate.visitCount == 0 else {
            throw PassportValidationError.cannotAddPlanForVisitedMountain(mountainID)
        }
        if case .some(.active(_)) = aggregate.planDisposition {
            throw PassportValidationError.planAlreadyExists(mountainID)
        }
    }

    private func validatePlanRemove(
        for mountainID: MountainID,
        in snapshot: LocalPassportSnapshot
    ) throws {
        guard let aggregate = try replayEffectiveAggregates(snapshot)
            .first(where: { $0.mountainID == mountainID }) else {
            throw SelfPassportSyncError.invalidAggregate
        }
        guard let disposition = aggregate.planDisposition else {
            throw PassportValidationError.planNotFound(mountainID)
        }

        switch disposition {
        case .active(.manual):
            return
        case .active(.autoCompleted(firstVisitID: _)):
            throw PassportValidationError.cannotRemoveAutoCompletedPlan(mountainID)
        case .manuallyRemoved:
            throw PassportValidationError.planAlreadyRemoved(mountainID)
        }
    }

    private func validatePlanMutationID(
        _ mutationID: ClientMutationID,
        in snapshot: LocalPassportSnapshot
    ) throws {
        guard !snapshot.planMutationOutbox.contains(where: { $0.id == mutationID }),
              !snapshot.manualVisitOutbox.nodes.contains(where: { $0.id == mutationID }),
              snapshot.manualVisitOutbox.acceptedCreates[mutationID] == nil else {
            throw PlanMutationOutboxError.duplicateMutationID
        }
    }


    private func resolvedBase(
        base: SelfPassportSyncBase,
        with receipt: SelfPassportMutationReceipt
    ) async throws -> SelfPassportSyncBase {
        if receipt.snapshotVersion == base.snapshotVersion,
           let aggregate = base.aggregate(for: receipt.mountainID),
           aggregate.aggregateVersion >= receipt.aggregate.aggregateVersion {
            return base
        }
        if base.snapshotVersion < Int64.max,
           receipt.snapshotVersion == base.snapshotVersion + 1 {
            return try rebase(base: base, with: receipt)
        }
        let refreshed = try await bootstrapper.bootstrap()
        guard refreshed.snapshotVersion >= receipt.snapshotVersion,
              let aggregate = refreshed.aggregate(for: receipt.mountainID),
              aggregate.aggregateVersion >= receipt.aggregate.aggregateVersion else {
            throw SelfPassportTransportFailure.fullRefreshRequired
        }
        return refreshed
    }
    private func resolvedBase(
        base: SelfPassportSyncBase,
        with receipt: GPSVisitVerificationReceipt
    ) async throws -> SelfPassportSyncBase {
        try await resolvedBase(
            base: base,
            with: SelfPassportMutationReceipt(
                clientMutationID: receipt.clientMutationID,
                operation: .create,
                visitID: receipt.visitID,
                mountainID: receipt.mountainID,
                aggregate: receipt.aggregate,
                snapshotVersion: receipt.snapshotVersion,
                historyToken: receipt.historyToken
            )
        )
    }

    private func resolvedBase(
        base: SelfPassportSyncBase,
        with receipt: SelfPassportPlanMutationReceipt
    ) async throws -> SelfPassportSyncBase {
        if receipt.snapshotVersion == base.snapshotVersion,
           let aggregate = base.aggregate(for: receipt.mountainID),
           aggregate.aggregateVersion >= receipt.aggregate.aggregateVersion {
            return base
        }
        if base.snapshotVersion < Int64.max,
           receipt.snapshotVersion == base.snapshotVersion + 1 {
            return try rebase(base: base, with: receipt)
        }
        let refreshed = try await bootstrapper.bootstrap()
        guard refreshed.snapshotVersion >= receipt.snapshotVersion,
              let aggregate = refreshed.aggregate(for: receipt.mountainID),
              aggregate.aggregateVersion >= receipt.aggregate.aggregateVersion else {
            throw SelfPassportTransportFailure.fullRefreshRequired
        }
        return refreshed
    }
    private func rebase(
        base: SelfPassportSyncBase,
        with receipt: SelfPassportMutationReceipt
    ) throws -> SelfPassportSyncBase {
        guard base.snapshotVersion < Int64.max,
              receipt.snapshotVersion == base.snapshotVersion + 1 else {
            throw SelfPassportTransportFailure.fullRefreshRequired
        }

        var aggregates = Dictionary(
            uniqueKeysWithValues: base.aggregates.map { ($0.mountainID, $0) }
        )
        guard let currentAggregate = aggregates[receipt.mountainID],
              receipt.aggregate.aggregateVersion > currentAggregate.aggregateVersion else {
            throw SelfPassportTransportFailure.fullRefreshRequired
        }
        aggregates[receipt.mountainID] = receipt.aggregate
        return try base.replacing(
            snapshotVersion: receipt.snapshotVersion,
            historyToken: receipt.historyToken,
            aggregates: aggregates.values.sorted {
                $0.mountainID.rawValue < $1.mountainID.rawValue
            },
            histories: []
        )
    }
    private func rebase(
        base: SelfPassportSyncBase,
        with receipt: SelfPassportPlanMutationReceipt
    ) throws -> SelfPassportSyncBase {
        guard base.snapshotVersion < Int64.max,
              receipt.snapshotVersion == base.snapshotVersion + 1 else {
            throw SelfPassportTransportFailure.fullRefreshRequired
        }

        var aggregates = Dictionary(
            uniqueKeysWithValues: base.aggregates.map { ($0.mountainID, $0) }
        )
        guard let currentAggregate = aggregates[receipt.mountainID],
              receipt.aggregate.aggregateVersion > currentAggregate.aggregateVersion else {
            throw SelfPassportTransportFailure.fullRefreshRequired
        }
        aggregates[receipt.mountainID] = receipt.aggregate
        return try base.replacing(
            snapshotVersion: receipt.snapshotVersion,
            historyToken: receipt.historyToken,
            aggregates: aggregates.values.sorted {
                $0.mountainID.rawValue < $1.mountainID.rawValue
            },
            histories: []
        )
    }

    private func persistManualOutbox(
        _ manualOutbox: ManualVisitOutboxGraph,
        over snapshot: LocalPassportSnapshot
    ) async throws {
        try await persist(
            try LocalPassportSnapshot(
                passportState: snapshot.passportState,
                manualVisitOutbox: manualOutbox,
                planMutationOutbox: snapshot.planMutationOutbox,
                syncBase: snapshot.syncBase,
                writePauseReason: snapshot.writePauseReason,
                actorID: snapshot.actorID
            ),
            expected: snapshot
        )
    }
    private func persistRecoveredState(
        pauseReason requestedPauseReason: SelfPassportWritePauseReason?
    ) async throws {
        for _ in 0..<3 {
            let stored = try await store.load()
            let current = try stored ?? LocalPassportSnapshot(
                passportState: PassportStateMachine(),
                manualVisitOutbox: ManualVisitOutboxGraph()
            )
            var manualOutbox = current.manualVisitOutbox
            _ = manualOutbox.recoverAfterRestart()
            var planOutbox = current.planMutationOutbox
            for index in planOutbox.indices where planOutbox[index].state == .inFlight {
                planOutbox[index].state = .queued
            }
            let recovered = try LocalPassportSnapshot(
                passportState: current.passportState,
                manualVisitOutbox: manualOutbox,
                planMutationOutbox: planOutbox,
                syncBase: current.syncBase,
                writePauseReason: strongerPauseReason(
                    current.writePauseReason,
                    requestedPauseReason
                ),
                actorID: current.actorID
            )
            if try await store.saveIfUnchanged(recovered, expected: stored) {
                cachedSnapshot = recovered
                pauseReason = recovered.writePauseReason
                return
            }
        }
        throw SelfPassportTransportFailure.fullRefreshRequired
    }

    private func persistPause(
        _ reason: SelfPassportWritePauseReason
    ) async throws {
        for _ in 0..<3 {
            let stored = try await store.load()
            let current = try stored ?? LocalPassportSnapshot(
                passportState: PassportStateMachine(),
                manualVisitOutbox: ManualVisitOutboxGraph()
            )
            let paused = try LocalPassportSnapshot(
                passportState: current.passportState,
                manualVisitOutbox: current.manualVisitOutbox,
                planMutationOutbox: current.planMutationOutbox,
                syncBase: current.syncBase,
                writePauseReason: strongerPauseReason(
                    current.writePauseReason,
                    reason
                ),
                actorID: current.actorID
            )
            if try await store.saveIfUnchanged(paused, expected: stored) {
                cachedSnapshot = paused
                pauseReason = paused.writePauseReason
                return
            }
        }
        throw SelfPassportTransportFailure.fullRefreshRequired
    }

    private func strongerPauseReason(
        _ lhs: SelfPassportWritePauseReason?,
        _ rhs: SelfPassportWritePauseReason?
    ) -> SelfPassportWritePauseReason? {
        [lhs, rhs]
            .compactMap { $0 }
            .max { pausePriority($0) < pausePriority($1) }
    }

    private func pausePriority(_ reason: SelfPassportWritePauseReason) -> Int {
        switch reason {
        case .continuity:
            1
        case .unauthenticated:
            2
        case .authorization:
            3
        case .compatibility:
            4
        case .mutationConflict, .mutationRejected:
            5
        }
    }
    private func persistPause(for error: Error) async throws {
        guard let reason = pauseReason(for: error) else {
            return
        }
        try await persistPause(reason)
    }

    private func pauseReason(for error: Error) -> SelfPassportWritePauseReason? {
        switch error as? SelfPassportTransportFailure {
        case .some(.unauthenticated):
            return .unauthenticated
        case .some(.forbidden):
            return .authorization
        case .some(.fullRefreshRequired):
            return .continuity
        case .some(.mutationConflict):
            return .mutationConflict
        case .some(.mutationRejected):
            return .mutationRejected
        case .some(.upgradeRequired):
            return .compatibility
        case .some(.refreshRequired), .some(.transient), .none:
            break
        }

        if case .some(.receiptMismatch) = error as? SelfPassportSyncError {
            return .continuity
        }
        return nil
    }

    private static func precedes(_ lhs: VisitRecord, _ rhs: VisitRecord) -> Bool {
        if lhs.visitedAt != rhs.visitedAt {
            return lhs.visitedAt > rhs.visitedAt
        }
        return lhs.id.rawValue > rhs.id.rawValue
    }

    private static func isStrictlyDescending(_ visits: [VisitRecord]) -> Bool {
        zip(visits, visits.dropFirst()).allSatisfy { lhs, rhs in
            precedes(lhs, rhs)
        }
    }
}
/// Aggregate-only, in-memory facts for one accepted friend. This type deliberately
/// does not conform to `Codable`, so friend data cannot enter a local passport
/// snapshot, encrypted store, or outbox.
public struct FriendPassportDTO: Equatable, Sendable {
    public let friendReference: FriendReference
    public let mountains: [FriendPassportMountainAggregate]

    public init(
        friendReference: FriendReference,
        mountains: [FriendPassportMountainAggregate]
    ) throws {
        guard Set(mountains.map(\.mountainID)).count == mountains.count else {
            throw FriendPassportDTOError.duplicateMountainID
        }
        self.friendReference = friendReference
        self.mountains = mountains.sorted { $0.mountainID.rawValue < $1.mountainID.rawValue }
    }
}

/// A per-mountain aggregate. It intentionally contains no visit record, visit
/// time, history, or planned-time data.
public struct FriendPassportMountainAggregate: Equatable, Identifiable, Sendable {
    public let mountainID: MountainID
    public let visitCount: Int
    public let isPlanned: Bool
    public let hasStamp: Bool
    public let stampVerificationMethod: FriendPassportStampVerificationMethod?

    public var id: MountainID {
        mountainID
    }

    public init(
        mountainID: MountainID,
        visitCount: Int,
        isPlanned: Bool,
        hasStamp: Bool,
        stampVerificationMethod: FriendPassportStampVerificationMethod?
    ) throws {
        guard visitCount >= 0 else {
            throw FriendPassportDTOError.negativeVisitCount
        }
        guard hasStamp == (stampVerificationMethod != nil) else {
            throw FriendPassportDTOError.inconsistentStamp
        }
        self.mountainID = mountainID
        self.visitCount = visitCount
        self.isPlanned = isPlanned
        self.hasStamp = hasStamp
        self.stampVerificationMethod = stampVerificationMethod
    }
}

public enum FriendPassportStampVerificationMethod: Equatable, Sendable {
    case manual
    case gpsVerified
}


public enum FriendPassportDTOError: Error, Equatable, Sendable {
    case duplicateMountainID
    case negativeVisitCount
    case inconsistentStamp
}

/// An opaque, friend-code-only discovery value. It is passed only to the
/// designated friend-code RPCs and never used to derive an actor identity.
public struct FriendCode: Equatable, Hashable, Sendable {
    public let rawValue: String

    public init(rawValue: String) throws {
        guard !rawValue.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              rawValue.count <= 128 else {
            throw FriendSocialContractError.invalidFriendCode
        }
        self.rawValue = rawValue
    }
}

/// A recipient-local opaque reference. It is not an actor ID and cannot be used
/// to discover a person outside the authenticated social RPC surface.
public struct FriendReference: Equatable, Hashable, Sendable {
    public let rawValue: UUID

    public init(rawValue: UUID) {
        self.rawValue = rawValue
    }
}

/// An opaque pending-request reference. It identifies neither requester nor
/// recipient and is valid only for the authenticated actor's lifecycle RPCs.
public struct FriendRequestReference: Equatable, Hashable, Sendable {
    public let rawValue: UUID

    public init(rawValue: UUID) {
        self.rawValue = rawValue
    }
}

public enum FriendCodeLookupResult: Equatable, Sendable {
    case available
    case unavailable
}

public enum FriendRequestSendResult: Equatable, Sendable {
    case pending(FriendRequestReference)
    case incomingRequest(FriendRequestReference)
    case friends(FriendReference)
    case unavailable
}

public enum FriendRequestResponse: String, Equatable, Sendable {
    case accept
    case decline
}

public enum FriendRequestResponseResult: Equatable, Sendable {
    case accepted(FriendReference)
    case declined(FriendRequestReference)
    case unavailable
}

public enum FriendRequestCancellationResult: Equatable, Sendable {
    case cancelled(FriendRequestReference)
    case unavailable
}

public enum FriendUnfriendResult: Equatable, Sendable {
    case unfriended(FriendReference)
    case unavailable
}

public enum FriendBlockReference: Equatable, Sendable {
    case friend(FriendReference)
    case request(FriendRequestReference)

    var rawValue: UUID {
        switch self {
        case let .friend(reference):
            reference.rawValue
        case let .request(reference):
            reference.rawValue
        }
    }
}

public enum FriendBlockResult: Equatable, Sendable {
    case blocked(FriendReference?)
    case unavailable
}

/// The server-issued ordering cursor for a recipient-private social event
/// channel. Generation zero is the one-shot bootstrap request and must not be
/// retained as an active cursor.
public struct FriendSocialEventCursor: Equatable, Sendable {
    public let generation: Int64
    public let sequence: Int64

    public init(generation: Int64, sequence: Int64) throws {
        guard generation >= 0, sequence >= 0,
              generation != 0 || sequence == 0 else {
            throw FriendSocialContractError.invalidSequence
        }
        self.generation = generation
        self.sequence = sequence
    }

    public static let bootstrap = FriendSocialEventCursor(
        uncheckedGeneration: 0,
        sequence: 0
    )

    fileprivate init(uncheckedGeneration: Int64, sequence: Int64) {
        generation = uncheckedGeneration
        self.sequence = sequence
    }
}

/// An opaque authorization invalidation for one already-known friend. It does
/// not disclose whether the other party revoked, unfriended, or blocked.
public struct FriendSocialEvent: Equatable, Sendable {
    public let friendReference: FriendReference
    public let generation: Int64
    public let sequence: Int64

    public init(
        friendReference: FriendReference,
        generation: Int64,
        sequence: Int64
    ) throws {
        guard generation > 0, sequence > 0 else {
            throw FriendSocialContractError.invalidSequence
        }
        self.friendReference = friendReference
        self.generation = generation
        self.sequence = sequence
    }
}

/// A recipient-private response to polling the social event channel. A gap is
/// a fail-closed authorization boundary, not a retryable continuation.
public struct FriendSocialEventPage: Equatable, Sendable {
    public let generation: Int64
    public let sequence: Int64
    public let requiresResynchronization: Bool
    public let events: [FriendSocialEvent]

    public init(
        generation: Int64,
        sequence: Int64,
        requiresResynchronization: Bool,
        events: [FriendSocialEvent]
    ) throws {
        guard generation > 0, sequence >= 0 else {
            throw FriendSocialContractError.invalidSequence
        }
        self.generation = generation
        self.sequence = sequence
        self.requiresResynchronization = requiresResynchronization
        self.events = events
    }

    public var cursor: FriendSocialEventCursor {
        FriendSocialEventCursor(
            uncheckedGeneration: generation,
            sequence: sequence
        )
    }
}

/// An aggregate response which the session may publish only while its
/// authorization lease remains valid.
public struct FriendPassportAuthorizationEnvelope: Equatable, Sendable {
    public let passport: FriendPassportDTO
    public let authorizationGeneration: Int64
    public let leaseExpiresAt: Date

    public init(
        passport: FriendPassportDTO,
        authorizationGeneration: Int64,
        leaseExpiresAt: Date
    ) throws {
        guard authorizationGeneration > 0 else {
            throw FriendSocialContractError.invalidAuthorizationGeneration
        }
        self.passport = passport
        self.authorizationGeneration = authorizationGeneration
        self.leaseExpiresAt = leaseExpiresAt
    }
}

public enum FriendSocialContractError: Error, Equatable, Sendable {
    case invalidFriendCode
    case invalidSequence
    case invalidAuthorizationGeneration
}

public enum FriendSocialTransportFailure: Error, Equatable, Sendable {
    case unauthenticated
    case forbidden
    case rejected
    case unavailable
    case malformedResponse
}

/// An online-only boundary for friend-code discovery, explicit friendship
/// lifecycle RPCs, accepted-friend aggregates, and recipient-private
/// revocations. It has no persistence or outbox API.
public protocol FriendSocialTransport: Sendable {
    func friendCode() async throws -> FriendCode
    func regenerateFriendCode() async throws -> FriendCode
    func lookupFriendCode(_ code: FriendCode) async throws -> FriendCodeLookupResult
    func sendFriendRequest(using code: FriendCode) async throws -> FriendRequestSendResult
    func incomingFriendRequests() async throws -> [FriendRequestReference]
    func respondToFriendRequest(
        _ request: FriendRequestReference,
        response: FriendRequestResponse
    ) async throws -> FriendRequestResponseResult
    func cancelFriendRequest(
        _ request: FriendRequestReference
    ) async throws -> FriendRequestCancellationResult
    func friends() async throws -> [FriendReference]
    func unfriend(_ friend: FriendReference) async throws -> FriendUnfriendResult
    func block(_ reference: FriendBlockReference) async throws -> FriendBlockResult
    /// Returns aggregate-only facts and only for an accepted friendship.
    func friendPassport(
        for friend: FriendReference
    ) async throws -> FriendPassportAuthorizationEnvelope
    /// Polls recipient-private opaque authorization invalidations. The cursor
    /// must be retained only in memory alongside its active passport session.
    func socialEvents(
        after cursor: FriendSocialEventCursor
    ) async throws -> FriendSocialEventPage
}

public enum FriendPassportSessionLifecycle: Equatable, Sendable {
    case appWillResignActive
    case signedOut
}

public enum FriendPassportSessionError: Error, Equatable, Sendable {
    case invalidAuthorizationEnvelope
}
/// An in-memory authorization-bound passport publication. The lease deadline
/// accompanies the aggregate through the presentation boundary and is never
/// persisted.
public struct FriendPassportSessionPublication: Equatable, Sendable {
    public let passport: FriendPassportDTO
    public let authorizationGeneration: Int64
    public let leaseExpiresAt: Date

    fileprivate init(
        passport: FriendPassportDTO,
        authorizationGeneration: Int64,
        leaseExpiresAt: Date
    ) {
        self.passport = passport
        self.authorizationGeneration = authorizationGeneration
        self.leaseExpiresAt = leaseExpiresAt
    }
}
/// An in-memory, single-friend authorization lease. This actor never writes
/// friend data to a store. Invalidating events are deliberately opaque: every
/// matching event clears the aggregate without exposing revocation provenance.
public actor FriendPassportSession {
    public static let maximumLease: TimeInterval = 30

    private struct ActivePassport: Sendable {
        let passport: FriendPassportDTO
        let authorizationGeneration: Int64
        let leaseExpiresAt: Date
    }

    private var friendReference: FriendReference?
    private let now: @Sendable () -> Date
    private var cursor: FriendSocialEventCursor?
    private var activePassport: ActivePassport?
    private var invalidated = false
    private var authorizationEpoch: UInt64 = 0

    public init(
        friendReference: FriendReference,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.friendReference = friendReference
        self.now = now
    }


    /// Returns the aggregate and the exact server lease deadline as one in-memory
    /// publication for presentation-layer authorization checks.
    public func publication() -> FriendPassportSessionPublication? {
        expireIfNeeded()
        guard let activePassport, !invalidated else {
            return nil
        }

        return FriendPassportSessionPublication(
            passport: activePassport.passport,
            authorizationGeneration: activePassport.authorizationGeneration,
            leaseExpiresAt: activePassport.leaseExpiresAt
        )
    }

    public func currentCursor() -> FriendSocialEventCursor? {
        expireIfNeeded()
        guard activePassport != nil, !invalidated else {
            return nil
        }
        return cursor
    }

    /// Establishes or advances the opaque event stream before an aggregate
    /// read. A lost event stream invalidates the existing aggregate.
    @discardableResult
    public func pollEvents(
        using transport: any FriendSocialTransport
    ) async throws -> FriendSocialEventCursor? {
        expireIfNeeded()
        guard !invalidated else {
            return nil
        }
        do {
            let page = try await transport.socialEvents(
                after: cursor ?? .bootstrap
            )
            consume(page)
        } catch {
            invalidate()
            throw error
        }
        return currentCursor()
    }

    /// Fetches an accepted-friend aggregate with its exact server lease deadline.
    /// A response that races an event, generation change, lifecycle transition,
    /// or lease expiry is discarded.
    @discardableResult
    public func refresh(
        using transport: any FriendSocialTransport
    ) async throws -> FriendPassportSessionPublication? {
        _ = try await pollEvents(using: transport)
        expireIfNeeded()
        guard !invalidated else {
            return nil
        }

        guard let friendReference else {
            return nil
        }
        let requestEpoch = authorizationEpoch
        let response: FriendPassportAuthorizationEnvelope
        do {
            response = try await transport.friendPassport(for: friendReference)
        } catch let failure as FriendSocialTransportFailure {
            if failure == .forbidden || failure == .unauthenticated || failure == .unavailable {
                invalidate()
            }
            throw failure
        } catch {
            throw error
        }

        expireIfNeeded()
        guard requestEpoch == authorizationEpoch, !invalidated else {
            return nil
        }
        guard response.passport.friendReference == friendReference,
              isValidLease(response.leaseExpiresAt),
              isValidAuthorizationGeneration(response.authorizationGeneration) else {
            invalidate()
            throw FriendPassportSessionError.invalidAuthorizationEnvelope
        }

        activePassport = ActivePassport(
            passport: response.passport,
            authorizationGeneration: response.authorizationGeneration,
            leaseExpiresAt: response.leaseExpiresAt
        )
        return publication()
    }

    /// Delivers one ordered opaque revocation event from a poll or stream.
    public func consume(_ event: FriendSocialEvent) {
        guard !invalidated,
              let friendReference,
              advanceCursor(generation: event.generation, sequence: event.sequence) else {
            return
        }
        if event.friendReference == friendReference {
            invalidate()
        }
    }

    /// Delivers an ordered poll page. Missing, duplicate, or malformed event
    /// sequences invalidate the active aggregate rather than guessing.
    public func consume(_ page: FriendSocialEventPage) {
        expireIfNeeded()
        guard !invalidated, let friendReference else {
            return
        }

        guard let cursor else {
            guard page.requiresResynchronization,
                  page.events.isEmpty else {
                invalidate()
                return
            }
            self.cursor = page.cursor
            return
        }

        guard !page.requiresResynchronization,
              page.generation == cursor.generation else {
            invalidate()
            return
        }

        var expectedSequence = cursor.sequence
        for event in page.events {
            guard event.generation == page.generation,
                  event.sequence == expectedSequence + 1,
                  advanceCursor(generation: event.generation, sequence: event.sequence) else {
                invalidate()
                return
            }
            expectedSequence = event.sequence
            if event.friendReference == friendReference {
                invalidate()
                return
            }
        }

        guard page.sequence == expectedSequence else {
            invalidate()
            return
        }
        self.cursor = page.cursor
    }

    /// A disconnected, terminated, or otherwise untrustworthy stream is an
    /// authorization boundary, not a retryable cache condition.
    public func streamLost() {
        invalidate()
    }

    public func handleLifecycle(_ event: FriendPassportSessionLifecycle) {
        switch event {
        case .appWillResignActive, .signedOut:
            invalidate()
        }
    }

    private func isValidAuthorizationGeneration(_ generation: Int64) -> Bool {
        guard generation > 0 else {
            return false
        }
        guard let activePassport else {
            return true
        }
        return activePassport.authorizationGeneration == generation
    }

    private func advanceCursor(generation: Int64, sequence: Int64) -> Bool {
        guard generation > 0, sequence > 0 else {
            invalidate()
            return false
        }
        guard let cursor else {
            do {
                self.cursor = try FriendSocialEventCursor(
                    generation: generation,
                    sequence: sequence
                )
                return true
            } catch {
                invalidate()
                return false
            }
        }
        guard cursor.generation == generation,
              sequence > cursor.sequence else {
            if cursor.generation != generation {
                invalidate()
            }
            return false
        }
        guard sequence == cursor.sequence + 1 else {
            invalidate()
            return false
        }
        do {
            self.cursor = try FriendSocialEventCursor(
                generation: generation,
                sequence: sequence
            )
            return true
        } catch {
            invalidate()
            return false
        }
    }

    private func isValidLease(_ leaseExpiresAt: Date) -> Bool {
        let current = now()
        return leaseExpiresAt > current
            && leaseExpiresAt.timeIntervalSince(current) <= Self.maximumLease
    }

    private func expireIfNeeded() {
        guard let activePassport,
              activePassport.leaseExpiresAt <= now() else {
            return
        }
        invalidate()
    }

    private func invalidate() {
        activePassport = nil
        cursor = nil
        friendReference = nil
        invalidated = true
        authorizationEpoch &+= 1
    }
}
