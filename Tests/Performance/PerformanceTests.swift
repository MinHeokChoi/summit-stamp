import Foundation
import XCTest

final class PerformanceTests: XCTestCase {
    private let launchBudget: TimeInterval = 3
    private let readinessTimeout: TimeInterval = 5

    @MainActor
    func testBudgets() {
        let app = XCUIApplication()
        let bootStartedAt = Date()
        app.launch()
        defer { app.terminate() }

        let navigationIsReady = waitForExistence(app.tabBars.firstMatch, timeout: readinessTimeout)
        let navigationDuration = Date().timeIntervalSince(bootStartedAt)
        XCTAssertTrue(
            navigationIsReady,
            "The app must expose primary navigation before launch performance can be accepted."
        )
        guard navigationIsReady else { return }
        XCTAssertLessThanOrEqual(
            navigationDuration,
            launchBudget,
            "Primary navigation took \(navigationDuration)s; budget is \(launchBudget)s."
        )

        let mapIsReady = waitForExistence(app.staticTexts["map.ready"], timeout: readinessTimeout)
        let mapDuration = Date().timeIntervalSince(bootStartedAt)
        XCTAssertTrue(
            mapIsReady,
            "The map bootstrap surface map.ready must be exposed before its budget can be accepted."
        )
        guard mapIsReady else { return }
        XCTAssertLessThanOrEqual(
            mapDuration,
            launchBudget,
            "Map bootstrap took \(mapDuration)s; budget is \(launchBudget)s."
        )

        let passportTab = app.tabBars.buttons["Passport"]
        let passportReady = app.staticTexts["passport.ready"]
        XCTAssertTrue(
            waitForExistence(passportTab, timeout: readinessTimeout),
            "The Passport tab must remain reachable after the launch budget is verified."
        )
        guard passportTab.exists else { return }
        passportTab.tap()

        let passportIsReady = waitForExistence(passportReady, timeout: readinessTimeout)
        XCTAssertTrue(
            passportIsReady,
            "The passport surface must become ready during the bounded smoke check."
        )
    }

    @MainActor
    private func waitForExistence(_ element: XCUIElement, timeout: TimeInterval) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        repeat {
            if element.exists {
                return true
            }
            RunLoop.current.run(until: Date().addingTimeInterval(0.05))
        } while Date() < deadline
        return element.exists
    }
}