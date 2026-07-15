import XCTest
@testable import HikerDomain

final class PassportStateMachineTests: XCTestCase {
    func testDomainNamespaceCrossesActorBoundary() async {
        let store = DomainNamespaceStore(namespace: HikerDomain.self)

        let namespace = await store.namespace()

        XCTAssertEqual(ObjectIdentifier(namespace), ObjectIdentifier(HikerDomain.self))
    }

    func testMountainConstructionPreservesImmutableValues() throws {
        let id = try MountainID(rawValue: "F100-001")
        let summitCoordinate = try SummitCoordinate(latitude: 37.801, longitude: 128.516)
        let mountain = try Mountain(
            id: id,
            koreanName: "설악산",
            region: "강원특별자치도",
            summitCoordinate: summitCoordinate
        )

        XCTAssertEqual(mountain.id, id)
        XCTAssertEqual(mountain.koreanName, "설악산")
        XCTAssertEqual(mountain.region, "강원특별자치도")
        XCTAssertEqual(mountain.summitCoordinate, summitCoordinate)
    }

    func testSummitCoordinateAcceptsWGS84Boundaries() throws {
        let southwest = try SummitCoordinate(latitude: -90, longitude: -180)
        let northeast = try SummitCoordinate(latitude: 90, longitude: 180)

        XCTAssertEqual(southwest.latitude, -90)
        XCTAssertEqual(southwest.longitude, -180)
        XCTAssertEqual(northeast.latitude, 90)
        XCTAssertEqual(northeast.longitude, 180)
    }

    func testValidationRejectsInvalidValues() throws {
        let id = try MountainID(rawValue: "F100-001")
        let summitCoordinate = try SummitCoordinate(latitude: 37.801, longitude: 128.516)

        assertValidationError(.emptyMountainID) {
            _ = try MountainID(rawValue: " \n")
        }
        assertValidationError(.emptyKoreanName) {
            _ = try Mountain(
                id: id,
                koreanName: "",
                region: "강원특별자치도",
                summitCoordinate: summitCoordinate
            )
        }
        assertValidationError(.emptyRegion) {
            _ = try Mountain(
                id: id,
                koreanName: "설악산",
                region: "  ",
                summitCoordinate: summitCoordinate
            )
        }
        assertValidationError(.nonFiniteLatitude) {
            _ = try SummitCoordinate(latitude: .infinity, longitude: 0)
        }
        assertValidationError(.nonFiniteLongitude) {
            _ = try SummitCoordinate(latitude: 0, longitude: .nan)
        }
        assertValidationError(.latitudeOutOfRange) {
            _ = try SummitCoordinate(latitude: -90.000_001, longitude: 0)
        }
        assertValidationError(.longitudeOutOfRange) {
            _ = try SummitCoordinate(latitude: 0, longitude: 180.000_001)
        }
        assertValidationError(.negativeVisitCount) {
            _ = try MountainProgress(visitCount: -1, planned: false)
        }
    }

    func testVisitedStateIsDerivedFromVisitCount() throws {
        let unvisited = try MountainProgress(visitCount: 0, planned: true)
        let visited = try MountainProgress(visitCount: 1, planned: false)

        XCTAssertFalse(unvisited.isVisited)
        XCTAssertTrue(visited.isVisited)
        XCTAssertTrue(unvisited.planned)
        XCTAssertFalse(visited.planned)
    }

    // PASS-001
    func testFirstVisitAutoCompletesPlan() throws {
        let mountainID = try mountainID("F100-101")
        let visit = try makeVisit(
            id: "00000000-0000-0000-0000-000000000101",
            mountainID: mountainID,
            visitedAt: 100,
            recordedAt: 200
        )
        var passport = PassportStateMachine()

        try passport.addPlan(for: mountainID)
        try passport.recordVisit(visit)

        let projection = try requireProjection(passport, for: mountainID)
        XCTAssertEqual(projection.visitCount, 1)
        XCTAssertEqual(
            projection.planDisposition,
            .active(.autoCompleted(firstVisitID: visit.id))
        )
        XCTAssertFalse(projection.planned)
        XCTAssertEqual(projection.stamp?.sourceVisitID, visit.id)
    }

    // PASS-002
    func testNoPlanVisitDoesNotCreatePlan() throws {
        let mountainID = try mountainID("F100-102")
        let visit = try makeVisit(
            id: "00000000-0000-0000-0000-000000000102",
            mountainID: mountainID,
            visitedAt: 100,
            recordedAt: 200
        )
        var passport = PassportStateMachine()

        try passport.recordVisit(visit)

        let projection = try requireProjection(passport, for: mountainID)
        XCTAssertNil(projection.planDisposition)
        XCTAssertNil(projection.planProvenance)
        XCTAssertFalse(projection.planned)
    }

    // PASS-003
    func testRevisitKeepsOneStamp() throws {
        let mountainID = try mountainID("F100-103")
        let firstVisit = try makeVisit(
            id: "00000000-0000-0000-0000-000000000103",
            mountainID: mountainID,
            visitedAt: 100,
            recordedAt: 200
        )
        let secondVisit = try makeVisit(
            id: "00000000-0000-0000-0000-000000000104",
            mountainID: mountainID,
            visitedAt: 300,
            recordedAt: 400,
            method: .gpsVerified
        )
        var passport = PassportStateMachine()

        try passport.recordVisit(firstVisit)
        try passport.recordVisit(secondVisit)
        XCTAssertThrowsError(try passport.recordVisit(firstVisit)) { error in
            XCTAssertEqual(
                error as? PassportValidationError,
                .duplicateVisitID(firstVisit.id)
            )
        }

        let projection = try requireProjection(passport, for: mountainID)
        XCTAssertEqual(projection.visitCount, 2)
        XCTAssertEqual(projection.history.map(\.id), [firstVisit.id, secondVisit.id])
        XCTAssertEqual(projection.stamp?.sourceVisitID, firstVisit.id)
        XCTAssertEqual(projection.stamp?.method, .manual)
    }

    // PASS-004
    func testFirstRemainingStampSource() throws {
        let mountainID = try mountainID("F100-104")
        let firstByID = try makeVisit(
            id: "00000000-0000-0000-0000-000000000105",
            mountainID: mountainID,
            visitedAt: 200,
            recordedAt: 500
        )
        let secondByID = try makeVisit(
            id: "00000000-0000-0000-0000-000000000106",
            mountainID: mountainID,
            visitedAt: 100,
            recordedAt: 500,
            method: .gpsVerified
        )
        var passport = PassportStateMachine()

        try passport.recordVisit(secondByID)
        try passport.recordVisit(firstByID)

        XCTAssertEqual(
            try requireProjection(passport, for: mountainID).stamp?.sourceVisitID,
            firstByID.id
        )

        try passport.deleteVisit(id: firstByID.id)

        let projection = try requireProjection(passport, for: mountainID)
        XCTAssertEqual(projection.visitCount, 1)
        XCTAssertEqual(projection.stamp?.sourceVisitID, secondByID.id)
        XCTAssertEqual(projection.stamp?.earnedAt, Date(timeIntervalSince1970: 500))
        XCTAssertEqual(projection.stamp?.method, .gpsVerified)
    }

    // PASS-005
    func testNonfinalDeleteRetainsStamp() throws {
        let mountainID = try mountainID("F100-105")
        let firstVisit = try makeVisit(
            id: "00000000-0000-0000-0000-000000000107",
            mountainID: mountainID,
            visitedAt: 100,
            recordedAt: 100
        )
        let secondVisit = try makeVisit(
            id: "00000000-0000-0000-0000-000000000108",
            mountainID: mountainID,
            visitedAt: 200,
            recordedAt: 200
        )
        var passport = PassportStateMachine()

        try passport.recordVisit(firstVisit)
        try passport.recordVisit(secondVisit)
        try passport.deleteVisit(id: secondVisit.id)

        let projection = try requireProjection(passport, for: mountainID)
        XCTAssertTrue(projection.isVisited)
        XCTAssertEqual(projection.visitCount, 1)
        XCTAssertEqual(projection.history, [firstVisit])
        XCTAssertEqual(projection.stamp?.sourceVisitID, firstVisit.id)
    }

    // PASS-006
    func testFinalDeleteRemovesStamp() throws {
        let mountainID = try mountainID("F100-106")
        let visit = try makeVisit(
            id: "00000000-0000-0000-0000-000000000109",
            mountainID: mountainID,
            visitedAt: 100,
            recordedAt: 200
        )
        var passport = PassportStateMachine()

        try passport.recordVisit(visit)
        try passport.deleteVisit(id: visit.id)

        XCTAssertTrue(passport.visits(for: mountainID).isEmpty)
        XCTAssertNil(passport.projection(for: mountainID))
        XCTAssertTrue(passport.allProjections().isEmpty)
    }

    // PASS-007
    func testFinalDeleteRestoresEligiblePlan() throws {
        let mountainID = try mountainID("F100-107")
        let visit = try makeVisit(
            id: "00000000-0000-0000-0000-000000000110",
            mountainID: mountainID,
            visitedAt: 100,
            recordedAt: 200
        )
        var passport = PassportStateMachine()

        try passport.addPlan(for: mountainID)
        try passport.recordVisit(visit)
        try passport.deleteVisit(id: visit.id)

        let projection = try requireProjection(passport, for: mountainID)
        XCTAssertFalse(projection.isVisited)
        XCTAssertEqual(projection.visitCount, 0)
        XCTAssertTrue(projection.history.isEmpty)
        XCTAssertNil(projection.stamp)
        XCTAssertEqual(projection.planDisposition, .active(.manual))
        XCTAssertTrue(projection.planned)
    }

    // PASS-008
    func testIneligiblePlanIsNotRestoredOrRemoved() throws {
        let absentMountainID = try mountainID("F100-108")
        let absentVisit = try makeVisit(
            id: "00000000-0000-0000-0000-000000000111",
            mountainID: absentMountainID,
            visitedAt: 100,
            recordedAt: 200
        )
        let manuallyRemovedMountainID = try mountainID("F100-109")
        let removedPlanVisit = try makeVisit(
            id: "00000000-0000-0000-0000-000000000112",
            mountainID: manuallyRemovedMountainID,
            visitedAt: 100,
            recordedAt: 200
        )
        let completedMountainID = try mountainID("F100-110")
        let completedPlanVisit = try makeVisit(
            id: "00000000-0000-0000-0000-000000000113",
            mountainID: completedMountainID,
            visitedAt: 100,
            recordedAt: 200
        )
        var passport = PassportStateMachine()

        try passport.recordVisit(absentVisit)
        XCTAssertThrowsError(try passport.addPlan(for: absentMountainID)) { error in
            XCTAssertEqual(
                error as? PassportValidationError,
                .cannotAddPlanForVisitedMountain(absentMountainID)
            )
        }
        try passport.deleteVisit(id: absentVisit.id)
        XCTAssertNil(passport.projection(for: absentMountainID))

        try passport.addPlan(for: manuallyRemovedMountainID)
        try passport.removePlan(for: manuallyRemovedMountainID)
        try passport.recordVisit(removedPlanVisit)
        try passport.deleteVisit(id: removedPlanVisit.id)

        let manuallyRemovedProjection = try requireProjection(
            passport,
            for: manuallyRemovedMountainID
        )
        XCTAssertEqual(
            manuallyRemovedProjection.planDisposition,
            .manuallyRemoved
        )
        XCTAssertFalse(manuallyRemovedProjection.planned)
        XCTAssertNil(manuallyRemovedProjection.stamp)
        XCTAssertFalse(manuallyRemovedProjection.isVisited)

        try passport.addPlan(for: completedMountainID)
        try passport.recordVisit(completedPlanVisit)
        XCTAssertThrowsError(try passport.removePlan(for: completedMountainID)) { error in
            XCTAssertEqual(
                error as? PassportValidationError,
                .cannotRemoveAutoCompletedPlan(completedMountainID)
            )
        }
        XCTAssertEqual(
            try requireProjection(passport, for: completedMountainID).planDisposition,
            .active(.autoCompleted(firstVisitID: completedPlanVisit.id))
        )
    }

    private func mountainID(_ rawValue: String) throws -> MountainID {
        try MountainID(rawValue: rawValue)
    }

    private func makeVisit(
        id rawID: String,
        mountainID: MountainID,
        visitedAt: TimeInterval,
        recordedAt: TimeInterval,
        method: VisitVerificationMethod = .manual
    ) throws -> VisitRecord {
        try VisitRecord(
            id: VisitID(rawValue: rawID),
            mountainID: mountainID,
            visitedAt: Date(timeIntervalSince1970: visitedAt),
            recordedAt: Date(timeIntervalSince1970: recordedAt),
            method: method
        )
    }

    private func requireProjection(
        _ passport: PassportStateMachine,
        for mountainID: MountainID
    ) throws -> MountainPassportProjection {
        guard let projection = passport.projection(for: mountainID) else {
            throw ProjectionError.missing
        }

        return projection
    }

    private enum ProjectionError: Error {
        case missing
    }
    private func assertValidationError(
        _ expectedError: MountainValidationError,
        operation: () throws -> Void
    ) {
        XCTAssertThrowsError(try operation()) { error in
            XCTAssertEqual(error as? MountainValidationError, expectedError)
        }
    }
}
final class FriendshipPolicyTests: XCTestCase {
    func testLifecycle() throws {
        let alice = try FriendActorID(rawValue: "actor-alice")
        let bob = try FriendActorID(rawValue: "actor-bob")
        let pair = try FriendshipPair(actorID: alice, friendActorID: bob)
        let reversePair = try FriendshipPair(actorID: bob, friendActorID: alice)
        let projection = try friendProjection()
        var policy = FriendshipPolicy(pair: pair)
        let outsider = try FriendActorID(rawValue: "actor-outsider")
        XCTAssertThrowsError(try policy.request(by: outsider)) { error in
            XCTAssertEqual(
                error as? FriendshipPolicyError,
                .actorNotInPair(outsider)
            )
        }

        XCTAssertEqual(pair, reversePair)
        XCTAssertFalse(
            policy.authorizesFriendPassport(
                viewerActorID: alice,
                friendActorID: bob
            )
        )
        XCTAssertThrowsError(
            try policy.friendPassportAggregate(
                for: alice,
                friendActorID: bob,
                projection: projection
            )
        ) { error in
            XCTAssertEqual(
                error as? FriendshipPolicyError,
                .friendPassportNotAuthorized
            )
        }

        try policy.request(by: alice)
        XCTAssertEqual(policy.status, .pending(requestedBy: alice))
        XCTAssertThrowsError(try policy.acceptRequest(by: alice)) { error in
            XCTAssertEqual(
                error as? FriendshipPolicyError,
                .onlyRecipientMayRespond
            )
        }
        try policy.cancelRequest(by: alice)
        XCTAssertEqual(policy.status, .none)

        try policy.request(by: alice)
        try policy.declineRequest(by: bob)
        XCTAssertEqual(policy.status, .none)

        try policy.request(by: alice)
        try policy.acceptRequest(by: bob)
        XCTAssertEqual(policy.status, .accepted)
        XCTAssertTrue(
            policy.authorizesFriendPassport(
                viewerActorID: bob,
                friendActorID: alice
            )
        )

        let aggregate = try policy.friendPassportAggregate(
            for: bob,
            friendActorID: alice,
            projection: projection
        )
        XCTAssertEqual(aggregate.friendActorID, alice)
        XCTAssertEqual(aggregate.mountainID, projection.mountainID)
        XCTAssertEqual(aggregate.visitCount, 2)
        XCTAssertEqual(aggregate.planState, .planned)
        XCTAssertTrue(aggregate.planned)
        XCTAssertTrue(aggregate.hasStamp)
        XCTAssertEqual(aggregate.stampProvenance, .gpsVerified)

        try policy.unfriend(by: bob)
        XCTAssertEqual(policy.status, .none)

        try policy.request(by: bob)
        try policy.block(by: alice)
        XCTAssertEqual(policy.status, .blocked(blockedBy: alice))
        XCTAssertFalse(
            policy.authorizesFriendPassport(
                viewerActorID: bob,
                friendActorID: alice
            )
        )
        XCTAssertThrowsError(try policy.request(by: bob)) { error in
            XCTAssertEqual(
                error as? FriendshipPolicyError,
                .transitionNotAllowed(.blocked(blockedBy: alice))
            )
        }
        XCTAssertThrowsError(try policy.acceptRequest(by: alice)) { error in
            XCTAssertEqual(
                error as? FriendshipPolicyError,
                .transitionNotAllowed(.blocked(blockedBy: alice))
            )
        }
        XCTAssertThrowsError(
            try policy.friendPassportAggregate(
                for: bob,
                friendActorID: alice,
                projection: projection
            )
        ) { error in
            XCTAssertEqual(
                error as? FriendshipPolicyError,
                .friendPassportNotAuthorized
            )
        }
    }

    func testFriendCodeIdentityAndAggregateModelShape() throws {
        let actorID = try FriendActorID(rawValue: "actor-alice")
        let friendCode = try FriendshipPolicyFriendCode(displayValue: " HIKER-7Q9P ")
        let mountainID = try MountainID(rawValue: "F100-201")
        let aggregate = try FriendPassportAggregate(
            friendActorID: actorID,
            mountainID: mountainID,
            visitCount: 2,
            planState: .completed,
            stampProvenance: .manual
        )

        XCTAssertEqual(friendCode.displayValue, "HIKER-7Q9P")
        XCTAssertEqual(
            storedPropertyNames(of: friendCode),
            Set(["displayValue"])
        )
        XCTAssertThrowsError(try FriendshipPolicyFriendCode(displayValue: " \n")) { error in
            XCTAssertEqual(
                error as? FriendIdentityValidationError,
                .emptyFriendCode
            )
        }
        XCTAssertEqual(
            FriendshipPolicyCodeIdentity(actorID: actorID, friendCode: friendCode).actorID,
            actorID
        )
        XCTAssertEqual(aggregate.planState, .completed)
        XCTAssertFalse(aggregate.planned)
        XCTAssertTrue(aggregate.hasStamp)
        XCTAssertEqual(
            storedPropertyNames(of: aggregate),
            Set([
                "friendActorID",
                "mountainID",
                "visitCount",
                "planState",
                "stampProvenance",
            ])
        )
        XCTAssertEqual(
            storedPropertyNames(
                of: FriendshipPolicyCodeIdentity(actorID: actorID, friendCode: friendCode)
            ),
            Set(["actorID", "friendCode"])
        )

        XCTAssertThrowsError(
            try FriendPassportAggregate(
                friendActorID: actorID,
                mountainID: mountainID,
                visitCount: -1,
                planState: .notPlanned,
                stampProvenance: nil
            )
        ) { error in
            XCTAssertEqual(
                error as? FriendPassportAggregateValidationError,
                .negativeVisitCount
            )
        }
        XCTAssertThrowsError(
            try FriendPassportAggregate(
                friendActorID: actorID,
                mountainID: mountainID,
                visitCount: 0,
                planState: .notPlanned,
                stampProvenance: .manual
            )
        ) { error in
            XCTAssertEqual(
                error as? FriendPassportAggregateValidationError,
                .stampProvenanceWithoutVisit
            )
        }
    }

    private func friendProjection() throws -> MountainPassportProjection {
        let mountainID = try MountainID(rawValue: "F100-200")
        let sourceVisitID = try VisitID(
            rawValue: "00000000-0000-0000-0000-000000000200"
        )
        return MountainPassportProjection(
            mountainID: mountainID,
            visitCount: 2,
            history: [],
            stamp: Stamp(
                mountainID: mountainID,
                sourceVisitID: sourceVisitID,
                earnedAt: Date(timeIntervalSince1970: 200),
                method: .gpsVerified
            ),
            planDisposition: .active(.manual)
        )
    }

    private func storedPropertyNames<T>(of value: T) -> Set<String> {
        Set(Mirror(reflecting: value).children.compactMap(\.label))
    }
}

private actor DomainNamespaceStore {
    private let storedNamespace: HikerDomain.Type

    init(namespace: HikerDomain.Type) {
        storedNamespace = namespace
    }

    func namespace() -> HikerDomain.Type {
        storedNamespace
    }
}
