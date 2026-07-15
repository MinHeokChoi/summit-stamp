import Foundation
import XCTest

@MainActor
final class MapFlowTests: XCTestCase {
    private let launchTimeout: TimeInterval = 60

    func testManualPendingAddDeleteUpdatesPinImmediately() throws {
        let app = XCUIApplication()
        app.launch()
        defer { app.terminate() }

        let passportTab = app.tabBars.buttons["Passport"]
        XCTAssertTrue(passportTab.waitForExistence(timeout: launchTimeout))
        passportTab.tap()

        XCTAssertTrue(
            app.staticTexts["passport.ready"].waitForExistence(timeout: launchTimeout),
            "The locally persisted passport must load before mutations are available."
        )

        let addPlanButtons = app.buttons.matching(
            NSPredicate(format: "identifier BEGINSWITH %@", "passport.plan.add.")
        )
        let addPlanButton = addPlanButtons.firstMatch
        XCTAssertTrue(
            addPlanButton.waitForExistence(timeout: launchTimeout),
            "The first available unvisited mountain must offer a plan control."
        )

        let mountainID = try XCTUnwrap(
            addPlanButton.identifier.removingPrefix("passport.plan.add."),
            "The selected plan control must expose its mountain ID."
        )
        addPlanButton.tap()
        let removePlanButton = app.buttons["passport.plan.remove.\(mountainID)"]
        XCTAssertTrue(
            removePlanButton.waitForExistence(timeout: launchTimeout),
            "Adding a plan must persist before recording its manual visit."
        )

        let pendingCount = app.staticTexts["passport.pending.count"]
        XCTAssertTrue(pendingCount.waitForExistence(timeout: launchTimeout))
        let baselinePendingCount = try pendingMutationCount(from: pendingCount.label)

        let existingManualVisitIDs = Set(
            app.staticTexts.matching(
                NSPredicate(format: "identifier BEGINSWITH %@", "passport.visit.badge.")
            ).allElementsBoundByIndex.map(\.identifier)
        )

        let addVisitButton = app.buttons["passport.visit.add.\(mountainID)"]
        XCTAssertTrue(addVisitButton.waitForExistence(timeout: launchTimeout))
        addVisitButton.tap()

        let manualBadges = app.staticTexts.matching(
            NSPredicate(format: "identifier BEGINSWITH %@", "passport.visit.badge.")
        )
        XCTAssertTrue(
            manualBadges.firstMatch.waitForExistence(timeout: launchTimeout),
            "Recording a manual visit must expose its manual badge."
        )
        let addedManualVisitIDs = Set(
            manualBadges.allElementsBoundByIndex.map(\.identifier)
        ).subtracting(existingManualVisitIDs)
        XCTAssertEqual(
            addedManualVisitIDs.count,
            1,
            "Recording one manual visit must add exactly one visit badge."
        )
        let visitIdentifier = try XCTUnwrap(addedManualVisitIDs.first)
        let visitID = try XCTUnwrap(
            visitIdentifier.removingPrefix("passport.visit.badge."),
            "The manual badge must expose the exact visit ID."
        )

        XCTAssertEqual(
            try pendingMutationCount(from: pendingCount.label),
            baselinePendingCount + 1
        )

        let mapTab = app.tabBars.buttons["Map"]
        mapTab.tap()
        XCTAssertTrue(app.staticTexts["map.ready"].waitForExistence(timeout: launchTimeout))
        XCTAssertEqual(
            app.staticTexts["map.annotation.count"].label,
            "100 official mountains shown"
        )

        let marker = app.buttons["map.annotation.\(mountainID)"]
        XCTAssertTrue(marker.waitForExistence(timeout: launchTimeout))
        XCTAssertTrue(marker.isHittable, "The selected mountain marker must be tappable.")
        marker.tap()
        XCTAssertTrue(
            app.staticTexts["map.summary"].waitForExistence(timeout: launchTimeout),
            "Selecting the updated marker must expose its summary."
        )
        XCTAssertTrue(marker.label.hasSuffix("Visited"))
        assertSelectedSummary(
            in: app,
            visitedStatus: "Visited",
            visitCount: "1",
            plannedStatus: "Not planned"
        )

        let selectedStateScreenshot = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        selectedStateScreenshot.name = "MAP-003-manual-visit-selected"
        selectedStateScreenshot.lifetime = .keepAlways
        add(selectedStateScreenshot)

        passportTab.tap()
        let deleteVisitButton = app.buttons["passport.visit.delete.\(visitID)"]
        XCTAssertTrue(
            deleteVisitButton.waitForExistence(timeout: launchTimeout),
            "The exact pending manual visit must remain deletable before dispatch."
        )
        deleteVisitButton.tap()

        let deletedBadgeExpectation = expectation(
            for: NSPredicate(format: "exists == false"),
            evaluatedWith: app.staticTexts["passport.visit.badge.\(visitID)"],
            handler: nil
        )
        wait(for: [deletedBadgeExpectation], timeout: launchTimeout)
        XCTAssertEqual(
            try pendingMutationCount(from: pendingCount.label),
            baselinePendingCount
        )

        mapTab.tap()
        XCTAssertTrue(app.staticTexts["map.ready"].waitForExistence(timeout: launchTimeout))
        XCTAssertEqual(
            app.staticTexts["map.annotation.count"].label,
            "100 official mountains shown"
        )
        XCTAssertTrue(marker.waitForExistence(timeout: launchTimeout))
        XCTAssertTrue(marker.label.hasSuffix("Not visited"))
        XCTAssertTrue(app.staticTexts["map.summary"].waitForExistence(timeout: launchTimeout))
        assertSelectedSummary(
            in: app,
            visitedStatus: "Not visited",
            visitCount: "0",
            plannedStatus: "Planned"
        )

        passportTab.tap()
        XCTAssertTrue(
            removePlanButton.waitForExistence(timeout: launchTimeout),
            "Deleting the final pending visit must restore the original manual plan."
        )
        removePlanButton.tap()
        XCTAssertTrue(
            app.buttons["passport.plan.add.\(mountainID)"].waitForExistence(timeout: launchTimeout),
            "Removing the restored plan must leave the mountain repeatable for the next run."
        )
    }

    private func assertSelectedSummary(
        in app: XCUIApplication,
        visitedStatus: String,
        visitCount: String,
        plannedStatus: String
    ) {
        let fields = [
            app.staticTexts["map.summary.name"],
            app.staticTexts["map.summary.region"],
            app.staticTexts["map.summary.visited-status"],
            app.staticTexts["map.summary.visit-count"],
            app.staticTexts["map.summary.planned-status"],
        ]

        for field in fields {
            XCTAssertTrue(field.waitForExistence(timeout: launchTimeout))
            XCTAssertFalse(field.label.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        }

        XCTAssertEqual(
            app.staticTexts.matching(
                NSPredicate(format: "identifier BEGINSWITH %@", "map.summary.")
            ).count,
            5
        )
        assertLabel(
            "Visited status: \(visitedStatus)",
            for: app.staticTexts["map.summary.visited-status"]
        )
        assertLabel(
            "Visit count: \(visitCount)",
            for: app.staticTexts["map.summary.visit-count"]
        )
        assertLabel(
            "Planned status: \(plannedStatus)",
            for: app.staticTexts["map.summary.planned-status"]
        )
    }

    private func assertLabel(_ expectedLabel: String, for element: XCUIElement) {
        let labelExpectation = expectation(
            for: NSPredicate(format: "label == %@", expectedLabel),
            evaluatedWith: element,
            handler: nil
        )
        wait(for: [labelExpectation], timeout: launchTimeout)
    }
    private func pendingMutationCount(from label: String) throws -> Int {
        let value = label.split(separator: " ", maxSplits: 1).first
        return try XCTUnwrap(value.flatMap { Int($0) })
    }
}

private extension String {
    func removingPrefix(_ prefix: String) -> String? {
        guard hasPrefix(prefix) else {
            return nil
        }
        return String(dropFirst(prefix.count))
    }
}
