import Foundation

public enum HikerDomain {}

public enum MountainValidationError: Error, Equatable, Sendable {
    case emptyMountainID
    case emptyKoreanName
    case emptyRegion
    case nonFiniteLatitude
    case nonFiniteLongitude
    case latitudeOutOfRange
    case longitudeOutOfRange
    case negativeVisitCount
}

public struct MountainID: Codable, Equatable, Hashable, Sendable {
    public let rawValue: String

    public init(rawValue: String) throws {
        guard !rawValue.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw MountainValidationError.emptyMountainID
        }

        self.rawValue = rawValue
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        try self.init(rawValue: container.decode(String.self))
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

public struct SummitCoordinate: Codable, Equatable, Sendable {
    public let latitude: Double
    public let longitude: Double

    public init(latitude: Double, longitude: Double) throws {
        guard latitude.isFinite else {
            throw MountainValidationError.nonFiniteLatitude
        }
        guard longitude.isFinite else {
            throw MountainValidationError.nonFiniteLongitude
        }
        guard (-90...90).contains(latitude) else {
            throw MountainValidationError.latitudeOutOfRange
        }
        guard (-180...180).contains(longitude) else {
            throw MountainValidationError.longitudeOutOfRange
        }

        self.latitude = latitude
        self.longitude = longitude
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            latitude: container.decode(Double.self, forKey: .latitude),
            longitude: container.decode(Double.self, forKey: .longitude)
        )
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(latitude, forKey: .latitude)
        try container.encode(longitude, forKey: .longitude)
    }

    private enum CodingKeys: String, CodingKey {
        case latitude
        case longitude
    }
}

public struct Mountain: Codable, Equatable, Sendable {
    public let id: MountainID
    public let koreanName: String
    public let region: String
    public let summitCoordinate: SummitCoordinate

    public init(
        id: MountainID,
        koreanName: String,
        region: String,
        summitCoordinate: SummitCoordinate
    ) throws {
        guard !koreanName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw MountainValidationError.emptyKoreanName
        }
        guard !region.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw MountainValidationError.emptyRegion
        }

        self.id = id
        self.koreanName = koreanName
        self.region = region
        self.summitCoordinate = summitCoordinate
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            id: container.decode(MountainID.self, forKey: .id),
            koreanName: container.decode(String.self, forKey: .koreanName),
            region: container.decode(String.self, forKey: .region),
            summitCoordinate: container.decode(SummitCoordinate.self, forKey: .summitCoordinate)
        )
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(koreanName, forKey: .koreanName)
        try container.encode(region, forKey: .region)
        try container.encode(summitCoordinate, forKey: .summitCoordinate)
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case koreanName
        case region
        case summitCoordinate
    }
}

public struct MountainProgress: Codable, Equatable, Sendable {
    public let visitCount: Int
    public let planned: Bool

    public var isVisited: Bool {
        visitCount > 0
    }

    public init(visitCount: Int, planned: Bool) throws {
        guard visitCount >= 0 else {
            throw MountainValidationError.negativeVisitCount
        }

        self.visitCount = visitCount
        self.planned = planned
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            visitCount: container.decode(Int.self, forKey: .visitCount),
            planned: container.decode(Bool.self, forKey: .planned)
        )
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(visitCount, forKey: .visitCount)
        try container.encode(planned, forKey: .planned)
    }

    private enum CodingKeys: String, CodingKey {
        case visitCount
        case planned
    }
}
public struct VisitID: Codable, Comparable, Hashable, Sendable {
    public let rawValue: String

    public init() {
        rawValue = UUID().uuidString.lowercased()
    }

    public init(rawValue: String) throws {
        guard let canonicalValue = canonicalUUIDString(rawValue) else {
            throw PassportValidationError.invalidVisitID
        }

        self.rawValue = canonicalValue
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        try self.init(rawValue: container.decode(String.self))
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }

    public static func < (lhs: VisitID, rhs: VisitID) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

public struct ClientMutationID: Codable, Comparable, Hashable, Sendable {
    public let rawValue: String

    public init() {
        rawValue = UUID().uuidString.lowercased()
    }

    public init(rawValue: String) throws {
        guard let canonicalValue = canonicalUUIDString(rawValue) else {
            throw PassportValidationError.invalidClientMutationID
        }

        self.rawValue = canonicalValue
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        try self.init(rawValue: container.decode(String.self))
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }

    public static func < (lhs: ClientMutationID, rhs: ClientMutationID) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

public enum VisitVerificationMethod: Codable, Equatable, Sendable {
    case manual
    case gpsVerified
}

public struct VisitRecord: Codable, Equatable, Sendable {
    public let id: VisitID
    public let mountainID: MountainID
    public let visitedAt: Date
    public let recordedAt: Date
    public let verificationMethod: VisitVerificationMethod

    public var method: VisitVerificationMethod {
        verificationMethod
    }

    public init(
        id: VisitID,
        mountainID: MountainID,
        visitedAt: Date,
        recordedAt: Date,
        verificationMethod: VisitVerificationMethod
    ) {
        self.id = id
        self.mountainID = mountainID
        self.visitedAt = visitedAt
        self.recordedAt = recordedAt
        self.verificationMethod = verificationMethod
    }

    public init(
        id: VisitID,
        mountainID: MountainID,
        visitedAt: Date,
        recordedAt: Date,
        method: VisitVerificationMethod
    ) {
        self.init(
            id: id,
            mountainID: mountainID,
            visitedAt: visitedAt,
            recordedAt: recordedAt,
            verificationMethod: method
        )
    }
}

public enum PlanProvenance: Codable, Equatable, Sendable {
    case manual
    case autoCompleted(firstVisitID: VisitID)
}

public enum PlanDisposition: Codable, Equatable, Sendable {
    case active(PlanProvenance)
    case manuallyRemoved

    public var provenance: PlanProvenance? {
        guard case let .active(provenance) = self else {
            return nil
        }

        return provenance
    }

    public var isPlanned: Bool {
        if case .active(.manual) = self {
            return true
        }

        return false
    }
}

public struct Stamp: Codable, Equatable, Sendable {
    public let mountainID: MountainID
    public let sourceVisitID: VisitID
    public let earnedAt: Date
    public let method: VisitVerificationMethod

    public var verificationMethod: VisitVerificationMethod {
        method
    }

    public init(
        mountainID: MountainID,
        sourceVisitID: VisitID,
        earnedAt: Date,
        method: VisitVerificationMethod
    ) {
        self.mountainID = mountainID
        self.sourceVisitID = sourceVisitID
        self.earnedAt = earnedAt
        self.method = method
    }
}

public struct MountainPassportProjection: Codable, Equatable, Sendable {
    public let mountainID: MountainID
    public let visitCount: Int
    public let history: [VisitRecord]
    public let stamp: Stamp?
    public let planDisposition: PlanDisposition?

    public var visits: [VisitRecord] {
        history
    }

    public var visitHistory: [VisitRecord] {
        history
    }

    public var isVisited: Bool {
        visitCount > 0
    }

    public var planned: Bool {
        planDisposition?.isPlanned ?? false
    }

    public var planProvenance: PlanProvenance? {
        planDisposition?.provenance
    }

    public init(
        mountainID: MountainID,
        visitCount: Int,
        history: [VisitRecord],
        stamp: Stamp?,
        planDisposition: PlanDisposition?
    ) {
        self.mountainID = mountainID
        self.visitCount = visitCount
        self.history = history
        self.stamp = stamp
        self.planDisposition = planDisposition
    }
}

public typealias PassportProjection = MountainPassportProjection

public enum PassportValidationError: Error, Equatable, Sendable {
    case invalidVisitID
    case invalidClientMutationID
    case duplicateVisitID(VisitID)
    case visitNotFound(VisitID)
    case cannotAddPlanForVisitedMountain(MountainID)
    case planAlreadyExists(MountainID)
    case planNotFound(MountainID)
    case planAlreadyRemoved(MountainID)
    case cannotRemoveAutoCompletedPlan(MountainID)
}

public struct PassportStateMachine: Codable, Equatable, Sendable {
    private var visitRecords: [VisitID: VisitRecord]
    private var planDispositions: [MountainID: PlanDisposition]

    public init() {
        visitRecords = [:]
        planDispositions = [:]
    }

    public mutating func addPlan(for mountainID: MountainID) throws {
        guard visits(for: mountainID).isEmpty else {
            throw PassportValidationError.cannotAddPlanForVisitedMountain(mountainID)
        }

        switch planDispositions[mountainID] {
        case .none, .some(.manuallyRemoved):
            planDispositions[mountainID] = .active(.manual)
        case .some(.active(_)):
            throw PassportValidationError.planAlreadyExists(mountainID)
        }
    }

    public mutating func removePlan(for mountainID: MountainID) throws {
        guard let disposition = planDispositions[mountainID] else {
            throw PassportValidationError.planNotFound(mountainID)
        }

        switch disposition {
        case .active(.manual):
            planDispositions[mountainID] = .manuallyRemoved
        case .active(.autoCompleted(firstVisitID: _)):
            throw PassportValidationError.cannotRemoveAutoCompletedPlan(mountainID)
        case .manuallyRemoved:
            throw PassportValidationError.planAlreadyRemoved(mountainID)
        }
    }

    public mutating func recordVisit(_ visit: VisitRecord) throws {
        guard visitRecords[visit.id] == nil else {
            throw PassportValidationError.duplicateVisitID(visit.id)
        }

        if case .some(.active(.manual)) = planDispositions[visit.mountainID] {
            planDispositions[visit.mountainID] = .active(
                .autoCompleted(firstVisitID: visit.id)
            )
        }

        visitRecords[visit.id] = visit
    }

    public mutating func deleteVisit(id: VisitID) throws {
        guard let deletedVisit = visitRecords.removeValue(forKey: id) else {
            throw PassportValidationError.visitNotFound(id)
        }

        guard visits(for: deletedVisit.mountainID).isEmpty else {
            return
        }

        if case .some(.active(.autoCompleted(firstVisitID: _))) = planDispositions[
            deletedVisit.mountainID
        ] {
            planDispositions[deletedVisit.mountainID] = .active(.manual)
        }
    }

    public func projection(for mountainID: MountainID) -> MountainPassportProjection? {
        let history = visits(for: mountainID)
        let disposition = planDispositions[mountainID]

        guard !history.isEmpty || disposition != nil else {
            return nil
        }

        let stamp = stamp(for: mountainID, from: history)
        return MountainPassportProjection(
            mountainID: mountainID,
            visitCount: history.count,
            history: history,
            stamp: stamp,
            planDisposition: disposition
        )
    }

    public func allProjections() -> [MountainPassportProjection] {
        var mountainIDs = Set(planDispositions.keys)
        mountainIDs.formUnion(visitRecords.values.map(\.mountainID))

        return mountainIDs
            .sorted { $0.rawValue < $1.rawValue }
            .compactMap { projection(for: $0) }
    }

    public func visits(for mountainID: MountainID) -> [VisitRecord] {
        visitRecords.values
            .filter { $0.mountainID == mountainID }
            .sorted(by: visitHistoryOrdering)
    }

    private func stamp(
        for mountainID: MountainID,
        from history: [VisitRecord]
    ) -> Stamp? {
        guard let source = history.min(by: stampSourceOrdering) else {
            return nil
        }

        return Stamp(
            mountainID: mountainID,
            sourceVisitID: source.id,
            earnedAt: source.recordedAt,
            method: source.verificationMethod
        )
    }

    private func visitHistoryOrdering(
        _ lhs: VisitRecord,
        _ rhs: VisitRecord
    ) -> Bool {
        if lhs.visitedAt != rhs.visitedAt {
            return lhs.visitedAt < rhs.visitedAt
        }

        if lhs.recordedAt != rhs.recordedAt {
            return lhs.recordedAt < rhs.recordedAt
        }

        return lhs.id.rawValue < rhs.id.rawValue
    }

    private func stampSourceOrdering(
        _ lhs: VisitRecord,
        _ rhs: VisitRecord
    ) -> Bool {
        if lhs.recordedAt != rhs.recordedAt {
            return lhs.recordedAt < rhs.recordedAt
        }

        return lhs.id.rawValue < rhs.id.rawValue
    }
}
// MARK: - Test-only pure friendship policy (SOC-004)

internal enum FriendIdentityValidationError: Error, Equatable, Sendable {
    case emptyFriendActorID
    case emptyFriendCode
}

internal struct FriendActorID: Comparable, Hashable, Sendable {
    let rawValue: String

    init(rawValue: String) throws {
        let normalizedValue = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalizedValue.isEmpty else {
            throw FriendIdentityValidationError.emptyFriendActorID
        }

        self.rawValue = normalizedValue
    }

    static func < (lhs: FriendActorID, rhs: FriendActorID) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

internal struct FriendshipPolicyFriendCode: Equatable, Hashable, Sendable {
    let displayValue: String

    init(displayValue: String) throws {
        let normalizedValue = displayValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalizedValue.isEmpty else {
            throw FriendIdentityValidationError.emptyFriendCode
        }

        self.displayValue = normalizedValue
    }
}

internal struct FriendshipPolicyCodeIdentity: Equatable, Sendable {
    let actorID: FriendActorID
    let friendCode: FriendshipPolicyFriendCode

    init(actorID: FriendActorID, friendCode: FriendshipPolicyFriendCode) {
        self.actorID = actorID
        self.friendCode = friendCode
    }
}

internal enum FriendshipPairValidationError: Error, Equatable, Sendable {
    case identicalActors
}

internal struct FriendshipPair: Equatable, Hashable, Sendable {
    let firstActorID: FriendActorID
    let secondActorID: FriendActorID

    init(actorID: FriendActorID, friendActorID: FriendActorID) throws {
        guard actorID != friendActorID else {
            throw FriendshipPairValidationError.identicalActors
        }

        if actorID < friendActorID {
            firstActorID = actorID
            secondActorID = friendActorID
        } else {
            firstActorID = friendActorID
            secondActorID = actorID
        }
    }

    func contains(_ actorID: FriendActorID) -> Bool {
        actorID == firstActorID || actorID == secondActorID
    }
}

internal enum FriendshipStatus: Equatable, Sendable {
    case none
    case pending(requestedBy: FriendActorID)
    case accepted
    case blocked(blockedBy: FriendActorID)
}

internal enum FriendshipPolicyError: Error, Equatable, Sendable {
    case actorNotInPair(FriendActorID)
    case invalidPendingActor(FriendActorID)
    case invalidBlockedActor(FriendActorID)
    case transitionNotAllowed(FriendshipStatus)
    case onlyRequestingActorMayCancel
    case onlyRecipientMayRespond
    case friendPassportNotAuthorized
}

internal struct FriendshipPolicy: Equatable, Sendable {
    let pair: FriendshipPair
    private(set) var status: FriendshipStatus

    init(pair: FriendshipPair) {
        self.pair = pair
        status = .none
    }

    init(pair: FriendshipPair, status: FriendshipStatus) throws {
        try Self.validate(status: status, for: pair)
        self.pair = pair
        self.status = status
    }

    var isAccepted: Bool {
        status == .accepted
    }

    var isBlocked: Bool {
        if case .blocked = status {
            return true
        }

        return false
    }

    mutating func request(by actorID: FriendActorID) throws {
        try requirePairMember(actorID)

        guard case .none = status else {
            throw FriendshipPolicyError.transitionNotAllowed(status)
        }

        status = .pending(requestedBy: actorID)
    }

    mutating func cancelRequest(by actorID: FriendActorID) throws {
        try requirePairMember(actorID)

        guard case let .pending(requestedBy) = status else {
            throw FriendshipPolicyError.transitionNotAllowed(status)
        }
        guard requestedBy == actorID else {
            throw FriendshipPolicyError.onlyRequestingActorMayCancel
        }

        status = .none
    }

    mutating func declineRequest(by actorID: FriendActorID) throws {
        try requirePairMember(actorID)

        guard case let .pending(requestedBy) = status else {
            throw FriendshipPolicyError.transitionNotAllowed(status)
        }
        guard requestedBy != actorID else {
            throw FriendshipPolicyError.onlyRecipientMayRespond
        }

        status = .none
    }

    mutating func acceptRequest(by actorID: FriendActorID) throws {
        try requirePairMember(actorID)

        guard case let .pending(requestedBy) = status else {
            throw FriendshipPolicyError.transitionNotAllowed(status)
        }
        guard requestedBy != actorID else {
            throw FriendshipPolicyError.onlyRecipientMayRespond
        }

        status = .accepted
    }

    mutating func unfriend(by actorID: FriendActorID) throws {
        try requirePairMember(actorID)

        guard case .accepted = status else {
            throw FriendshipPolicyError.transitionNotAllowed(status)
        }

        status = .none
    }

    mutating func block(by actorID: FriendActorID) throws {
        try requirePairMember(actorID)

        guard !isBlocked else {
            throw FriendshipPolicyError.transitionNotAllowed(status)
        }

        status = .blocked(blockedBy: actorID)
    }

    func authorizesFriendPassport(
        viewerActorID: FriendActorID,
        friendActorID: FriendActorID
    ) -> Bool {
        guard viewerActorID != friendActorID else {
            return false
        }

        return status == .accepted
            && pair.contains(viewerActorID)
            && pair.contains(friendActorID)
    }

    func friendPassportAggregate(
        for viewerActorID: FriendActorID,
        friendActorID: FriendActorID,
        projection: MountainPassportProjection
    ) throws -> FriendPassportAggregate {
        guard authorizesFriendPassport(
            viewerActorID: viewerActorID,
            friendActorID: friendActorID
        ) else {
            throw FriendshipPolicyError.friendPassportNotAuthorized
        }

        return try FriendPassportAggregate(
            friendActorID: friendActorID,
            projection: projection
        )
    }

    private func requirePairMember(_ actorID: FriendActorID) throws {
        guard pair.contains(actorID) else {
            throw FriendshipPolicyError.actorNotInPair(actorID)
        }
    }

    private static func validate(
        status: FriendshipStatus,
        for pair: FriendshipPair
    ) throws {
        switch status {
        case .none, .accepted:
            return
        case let .pending(requestedBy):
            guard pair.contains(requestedBy) else {
                throw FriendshipPolicyError.invalidPendingActor(requestedBy)
            }
        case let .blocked(blockedBy):
            guard pair.contains(blockedBy) else {
                throw FriendshipPolicyError.invalidBlockedActor(blockedBy)
            }
        }
    }
}

internal enum FriendPassportPlanState: String, Equatable, Sendable {
    case notPlanned
    case planned
    case completed
    case removed

    var planned: Bool {
        self == .planned
    }
}

internal enum FriendStampProvenance: String, Equatable, Sendable {
    case manual
    case gpsVerified
}

internal enum FriendPassportAggregateValidationError: Error, Equatable, Sendable {
    case negativeVisitCount
    case stampProvenanceWithoutVisit
}

internal struct FriendPassportAggregate: Equatable, Sendable {
    let friendActorID: FriendActorID
    let mountainID: MountainID
    let visitCount: Int
    let planState: FriendPassportPlanState
    let stampProvenance: FriendStampProvenance?

    var planned: Bool {
        planState.planned
    }

    var hasStamp: Bool {
        stampProvenance != nil
    }

    init(
        friendActorID: FriendActorID,
        mountainID: MountainID,
        visitCount: Int,
        planState: FriendPassportPlanState,
        stampProvenance: FriendStampProvenance?
    ) throws {
        guard visitCount >= 0 else {
            throw FriendPassportAggregateValidationError.negativeVisitCount
        }
        guard visitCount > 0 || stampProvenance == nil else {
            throw FriendPassportAggregateValidationError.stampProvenanceWithoutVisit
        }

        self.friendActorID = friendActorID
        self.mountainID = mountainID
        self.visitCount = visitCount
        self.planState = planState
        self.stampProvenance = stampProvenance
    }

    init(
        friendActorID: FriendActorID,
        projection: MountainPassportProjection
    ) throws {
        try self.init(
            friendActorID: friendActorID,
            mountainID: projection.mountainID,
            visitCount: projection.visitCount,
            planState: friendPassportPlanState(for: projection.planDisposition),
            stampProvenance: projection.stamp.map {
                friendStampProvenance(for: $0)
            }
        )
    }
}

private func friendPassportPlanState(
    for disposition: PlanDisposition?
) -> FriendPassportPlanState {
    guard let disposition else {
        return .notPlanned
    }

    switch disposition {
    case .active(.manual):
        return .planned
    case .active(.autoCompleted(firstVisitID: _)):
        return .completed
    case .manuallyRemoved:
        return .removed
    }
}

private func friendStampProvenance(
    for stamp: Stamp
) -> FriendStampProvenance {
    switch stamp.method {
    case .manual:
        return .manual
    case .gpsVerified:
        return .gpsVerified
    }
}

private func canonicalUUIDString(_ rawValue: String) -> String? {
    guard let uuid = UUID(uuidString: rawValue) else {
        return nil
    }

    let canonicalValue = uuid.uuidString.lowercased()
    guard rawValue.lowercased() == canonicalValue else {
        return nil
    }

    return canonicalValue
}
