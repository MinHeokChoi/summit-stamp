import Foundation
import XCTest

@MainActor
final class PassportFlowTests: XCTestCase {
    private let launchTimeout: TimeInterval = 5

    // E2E-001 local fail-closed contract. This test does not exercise or claim
    // protected two-device staging; an unsigned shell must not fabricate it.
    func testTwoDeviceSync() {
        let app = XCUIApplication()
        app.launch()
        defer { app.terminate() }

        let initialSnapshot = assertLocalPassportLaunchState(in: app)

        app.terminate()
        app.launch()

        let relaunchedSnapshot = assertLocalPassportLaunchState(in: app)
        XCTAssertEqual(
            relaunchedSnapshot,
            initialSnapshot,
            "Relaunching an unsigned shell must preserve only the canonical local passport state."
        )
    }

    private func assertLocalPassportLaunchState(in app: XCUIApplication) -> [String: String] {
        let authenticationState = app.staticTexts["auth.state"]
        XCTAssertTrue(authenticationState.waitForExistence(timeout: launchTimeout))
        XCTAssertEqual(
            authenticationState.label,
            "Sign-in unavailable",
            "The local test shell must remain unsigned rather than fabricating a remote device."
        )
        XCTAssertFalse(
            app.buttons["auth.sign-out"].exists,
            "An unsigned shell must not fabricate a remote actor session."
        )

        let passportTab = app.tabBars.buttons["Passport"]
        XCTAssertTrue(passportTab.waitForExistence(timeout: launchTimeout))
        passportTab.tap()

        let passportReady = app.staticTexts["passport.ready"]
        XCTAssertTrue(
            passportReady.waitForExistence(timeout: launchTimeout),
            "The local passport must load before its persisted launch state is inspected."
        )
        XCTAssertEqual(passportReady.label, "Local passport ready")

        let mountainCount = app.staticTexts.matching(
            NSPredicate(format: "identifier BEGINSWITH %@", "passport.mountain.")
        ).count
        XCTAssertEqual(
            mountainCount,
            100,
            "The self passport must retain the canonical local 100-mountain catalog."
        )

        let pendingCount = app.staticTexts["passport.pending.count"]
        XCTAssertTrue(pendingCount.exists)
        XCTAssertEqual(
            app.descendants(matching: .any).matching(
                NSPredicate(format: "identifier BEGINSWITH %@", "passport.friend.")
            ).count,
            0,
            "Self-passport state must not contain persisted friend fields."
        )
        XCTAssertEqual(
            app.descendants(matching: .any).matching(
                NSPredicate(format: "identifier BEGINSWITH %@", "passport.social.")
            ).count,
            0,
            "Self-passport state must not contain persisted social fields."
        )

        return [
            "ready": passportReady.label,
            "mountainCount": String(mountainCount),
            "pendingCount": pendingCount.label,
        ]
    }
}
