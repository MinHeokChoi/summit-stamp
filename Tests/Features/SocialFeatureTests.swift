import XCTest
import HikerSocialFeature

@MainActor
final class SocialFeatureTests: XCTestCase {
    func testUnavailableStateZeroizesSocialFactsAndActions() {
        let state = SocialFeatureState(
            availability: .unavailable,
            currentFriendCode: "CODE-ONLY",
            friendCodeInput: "opaque-input",
            friendCodeLookupStatus: .available,
            incomingRequests: [SocialIncomingRequest(id: "request-0")],
            friends: [SocialFriend(id: "friend-0", displayLabel: "Friend 1")],
            selectedFriendID: "friend-0",
            selectedPassport: SocialFriendPassport(
                mountains: [
                    SocialFriendPassportMountain(
                        id: "mountain-0",
                        localMountainLabel: "Bundled mountain",
                        visitCount: 1,
                        isPlanned: true,
                        stampLabel: "Manual"
                    ),
                ]
            ),
            isPerformingAction: true
        )

        XCTAssertNil(state.currentFriendCode)
        XCTAssertEqual(state.friendCodeInput, "")
        XCTAssertEqual(state.friendCodeLookupStatus, .idle)
        XCTAssertTrue(state.incomingRequests.isEmpty)
        XCTAssertTrue(state.friends.isEmpty)
        XCTAssertNil(state.selectedFriendID)
        XCTAssertNil(state.selectedPassport)
        XCTAssertFalse(state.isPerformingAction)
        XCTAssertFalse(state.canRegenerateFriendCode)
        XCTAssertFalse(state.canLookupFriendCode)
        XCTAssertFalse(state.canSendFriendRequest)
        XCTAssertFalse(state.canRespondToRequests)
        XCTAssertFalse(state.canManageFriends)
    }

    func testReadyStateMakesOnlyExpectedSocialActionsAvailable() {
        let state = SocialFeatureState(
            availability: .ready,
            currentFriendCode: "CODE-ONLY",
            friendCodeInput: "opaque-input",
            friendCodeLookupStatus: .available,
            incomingRequests: [SocialIncomingRequest(id: "request-0")],
            friends: [SocialFriend(id: "friend-0", displayLabel: "Friend 1")]
        )

        XCTAssertTrue(state.canRegenerateFriendCode)
        XCTAssertEqual(state.friendCodeInput, "opaque-input")
        XCTAssertTrue(state.canLookupFriendCode)
        XCTAssertTrue(state.canSendFriendRequest)
        XCTAssertTrue(state.canRespondToRequests)
        XCTAssertTrue(state.canManageFriends)
        XCTAssertNil(state.selectedPassport)
    }

    func testPassportPresentationIsAggregateOnlyAndLocallyLabeled() {
        let mountain = SocialFriendPassportMountain(
            id: "mountain-0",
            localMountainLabel: "Bundled mountain",
            visitCount: 2,
            isPlanned: true,
            stampLabel: "GPS confirmed"
        )
        let passport = SocialFriendPassport(mountains: [mountain])

        XCTAssertEqual(passport.mountains.map(\.localMountainLabel), ["Bundled mountain"])
        XCTAssertEqual(passport.mountains.map(\.visitCount), [2])
        XCTAssertEqual(passport.mountains.map(\.isPlanned), [true])
        XCTAssertEqual(passport.mountains.map(\.stampLabel), ["GPS confirmed"])
    }
}
