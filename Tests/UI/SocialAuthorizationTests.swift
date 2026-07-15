import XCTest

@MainActor
final class SocialAuthorizationTests: XCTestCase {
    private let launchTimeout: TimeInterval = 5

    func testFailClosed() {
        let app = XCUIApplication()
        app.launch()
        defer { app.terminate() }

        openFriends(in: app)

        XCTAssertTrue(
            app.descendants(matching: .any)["social.unavailable"].waitForExistence(timeout: launchTimeout),
            "The unsigned local shell must expose only the generic social unavailable state."
        )
        XCTAssertFalse(app.staticTexts["social.current-code"].exists)
        XCTAssertFalse(app.textFields["social.friend-code.input"].exists)
        XCTAssertFalse(app.buttons["social.friend-code.lookup"].exists)
        XCTAssertFalse(app.buttons["social.friend-code.request"].exists)
        XCTAssertFalse(app.staticTexts["social.friend.passport"].exists)
    }

    func testNoPersistedFriendBytes() {
        let app = XCUIApplication()
        app.launch()
        openFriends(in: app)
        XCTAssertTrue(app.descendants(matching: .any)["social.unavailable"].waitForExistence(timeout: launchTimeout))
        XCTAssertFalse(app.staticTexts["social.friend.passport"].exists)
        app.terminate()

        app.launch()
        defer { app.terminate() }
        openFriends(in: app)

        XCTAssertTrue(app.descendants(matching: .any)["social.unavailable"].waitForExistence(timeout: launchTimeout))
        XCTAssertFalse(
            app.descendants(matching: .any)["social.friend.passport"].exists,
            "Relaunching without an authenticated transport must not restore friend presentation bytes."
        )
        XCTAssertFalse(app.staticTexts["social.current-code"].exists)
    }

    func testSocialE2E() {
        let app = XCUIApplication()
        app.launch()
        defer { app.terminate() }

        openFriends(in: app)
        XCTAssertTrue(app.descendants(matching: .any)["social.unavailable"].waitForExistence(timeout: launchTimeout))

        for identifier in [
            "social.friend-code.input",
            "social.friend-code.lookup",
            "social.friend-code.request",
            "social.current-code",
            "social.friend.passport",
            "social.search.email",
            "social.search.phone",
            "social.search.contacts",
            "social.search.username",
        ] {
            XCTAssertFalse(
                app.descendants(matching: .any)[identifier].exists,
                "The local unsigned shell must not expose \(identifier)."
            )
        }
    }

    private func openFriends(in app: XCUIApplication) {
        let friendsTab = app.tabBars.buttons["Friends"]
        XCTAssertTrue(
            friendsTab.waitForExistence(timeout: launchTimeout),
            "The Friends tab must be discoverable."
        )
        friendsTab.tap()
    }
}
