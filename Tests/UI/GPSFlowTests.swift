import Foundation
import XCTest

@MainActor
final class GPSFlowTests: XCTestCase {
    private let launchTimeout: TimeInterval = 15

    // GPS-004
    func testFreshGPSFallbackStateMachineContract() {
        let app = XCUIApplication()
        app.launch()
        defer { app.terminate() }

        let passportTab = app.tabBars.buttons["Passport"]
        XCTAssertTrue(passportTab.waitForExistence(timeout: launchTimeout))
        passportTab.tap()
        XCTAssertTrue(app.staticTexts["passport.ready"].waitForExistence(timeout: launchTimeout))

        let mountainCount = app.staticTexts.matching(
            NSPredicate(format: "identifier BEGINSWITH %@", "passport.mountain.")
        )
        XCTAssertEqual(mountainCount.count, 100, "The exact official catalog must be visible.")

        let mountainID = "hkr_mtn_03f343fae9427a772cc169f1fb3c0dd2"
        let firstGPSAction = app.buttons["passport.gps.verify.\(mountainID)"]
        let manualFallback = app.buttons["passport.visit.add.\(mountainID)"]
        XCTAssertTrue(firstGPSAction.waitForExistence(timeout: launchTimeout))
        XCTAssertTrue(
            manualFallback.waitForExistence(timeout: launchTimeout),
            "The sampled GPS control must retain its matching manual fallback."
        )
        XCTAssertEqual(
            app.staticTexts.matching(
                NSPredicate(format: "identifier BEGINSWITH %@", "passport.gps.status.")
            ).count,
            0,
            "A fresh passport must not retain stale GPS permission or failure feedback."
        )

        firstGPSAction.tap()
        let fallbackStatus = app.staticTexts["passport.gps.status.\(mountainID)"]
        XCTAssertTrue(fallbackStatus.waitForExistence(timeout: launchTimeout))
        XCTAssertEqual(
            fallbackStatus.label,
            "GPS confirmation was not accepted. You can record this visit manually."
        )
        XCTAssertTrue(manualFallback.exists && manualFallback.isEnabled)
    }

    // GPS-007
    func testAdvisoryCopy() {
        let app = XCUIApplication()
        app.launch()
        defer { app.terminate() }

        let passportTab = app.tabBars.buttons["Passport"]
        XCTAssertTrue(passportTab.waitForExistence(timeout: launchTimeout))
        passportTab.tap()
        XCTAssertTrue(app.staticTexts["passport.ready"].waitForExistence(timeout: launchTimeout))

        let advisoryCopy = app.staticTexts.matching(
            NSPredicate(format: "identifier BEGINSWITH %@", "passport.gps.advisory.")
        )
        XCTAssertEqual(advisoryCopy.count, 100, "Every GPS action must include advisory, online-only copy.")

        let prohibitedTerms = [
            "anti-spoof",
            "anti spoof",
            "anti-spoofing",
            "anti spoofing",
            "spoof",
            "anti-cheat",
            "anti cheat",
            "anti-cheating",
            "anti cheating",
            "cheat",
        ]
        let expectedLabel = "GPS confirmation is advisory and available only while online"
        XCTAssertEqual(
            advisoryCopy.matching(NSPredicate(format: "label != %@", expectedLabel)).count,
            0,
            "Every advisory label must use the approved online-only wording."
        )
        for prohibitedTerm in prohibitedTerms {
            XCTAssertEqual(
                advisoryCopy.matching(
                    NSPredicate(format: "label CONTAINS[c] %@", prohibitedTerm)
                ).count,
                0,
                "GPS advisory copy must not claim \(prohibitedTerm) capabilities."
            )
        }
    }

    // E2E-002 contract: GPS remains user-triggered and manual recording remains available.
    func testGPSE2E() {
        let app = XCUIApplication()
        app.launch()
        defer { app.terminate() }

        XCTAssertEqual(
            app.alerts.count,
            0,
            "Launching the app must not request location permission."
        )

        let passportTab = app.tabBars.buttons["Passport"]
        XCTAssertTrue(passportTab.waitForExistence(timeout: launchTimeout))
        passportTab.tap()
        XCTAssertTrue(app.staticTexts["passport.ready"].waitForExistence(timeout: launchTimeout))

        let gpsAction = app.buttons.matching(
            NSPredicate(format: "identifier BEGINSWITH %@", "passport.gps.verify.")
        ).firstMatch
        XCTAssertTrue(gpsAction.waitForExistence(timeout: launchTimeout))

        let mountainID = String(gpsAction.identifier.dropFirst("passport.gps.verify.".count))
        let manualAction = app.buttons["passport.visit.add.\(mountainID)"]
        XCTAssertTrue(
            manualAction.exists && manualAction.isEnabled,
            "The online-only GPS path must leave the manual recording action available."
        )
    }
}
