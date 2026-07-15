import Foundation
import XCTest

@MainActor
final class AuthenticationShellTests: XCTestCase {
    private let launchTimeout: TimeInterval = 5

    func testUnconfiguredAuthenticationFailsClosedWhileLocalTabsRemainAvailable() {
        let app = XCUIApplication()
        app.launch()
        defer { app.terminate() }

        let state = app.staticTexts["auth.state"]
        XCTAssertTrue(
            state.waitForExistence(timeout: launchTimeout),
            "The authentication shell must expose its state."
        )
        XCTAssertEqual(state.label, "Sign-in unavailable")

        let error = app.staticTexts["auth.error"]
        XCTAssertTrue(
            error.waitForExistence(timeout: launchTimeout),
            "Unconfigured authentication must explain the unavailable state."
        )
        XCTAssertEqual(error.label, "Sign in with Apple is unavailable in this build.")

        let signIn = app.buttons["auth.sign-in"]
        XCTAssertTrue(signIn.exists, "The Apple sign-in control must remain discoverable.")
        XCTAssertFalse(signIn.isEnabled, "Unconfigured authentication must fail closed.")
        XCTAssertFalse(app.buttons["auth.sign-out"].exists)

        for identifier in [
            "test-login",
            "auth.test-login",
            "auth.bypass",
            "auth.test-identity",
        ] {
            XCTAssertFalse(
                app.descendants(matching: .any)[identifier].exists,
                "Production authentication must not expose \(identifier)."
            )
        }

        let mapTab = app.tabBars.buttons["Map"]
        let passportTab = app.tabBars.buttons["Passport"]
        XCTAssertTrue(mapTab.waitForExistence(timeout: launchTimeout))
        XCTAssertTrue(passportTab.waitForExistence(timeout: launchTimeout))
        XCTAssertTrue(mapTab.isHittable)
        XCTAssertTrue(passportTab.isHittable)

        mapTab.tap()
        XCTAssertTrue(
            app.staticTexts["map.ready"].waitForExistence(timeout: launchTimeout),
            "Map loading must continue when authentication is unavailable."
        )

        passportTab.tap()
        XCTAssertTrue(
            app.navigationBars["Passport"].waitForExistence(timeout: launchTimeout),
            "Passport navigation must remain available when authentication is unavailable."
        )
        let attachment = XCTAttachment(screenshot: app.screenshot())
        attachment.name = "M2A auth shell unavailable without protected configuration"
        attachment.lifetime = .keepAlways
        add(attachment)
    }
}
