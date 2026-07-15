import Foundation
import XCTest

@MainActor
final class AccessibilitySmokeTests: XCTestCase {
    private let launchTimeout: TimeInterval = 5
    private let primaryTabIdentifiers = ["Map", "Passport", "Friends"]

    func testLaunchExposesAccessiblePrimaryNavigation() {
        let app = XCUIApplication()
        app.launch()
        defer { app.terminate() }

        let tabBar = app.tabBars.firstMatch
        XCTAssertTrue(
            tabBar.waitForExistence(timeout: launchTimeout),
            "The app must expose its primary tab bar after launch."
        )

        for identifier in primaryTabIdentifiers {
            let tab = tabBar.buttons[identifier]
            XCTAssertTrue(
                tab.waitForExistence(timeout: launchTimeout),
                "Missing primary tab accessibility identifier: \(identifier)"
            )
            XCTAssertTrue(tab.isHittable, "Primary tab is not hittable: \(identifier)")
            XCTAssertFalse(
                tab.label.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                "Primary tab must have an accessibility label: \(identifier)"
            )
        }
    }

    func testPrimaryTabsExposeTheirAccessibleContent() {
        let app = XCUIApplication()
        app.launch()
        defer { app.terminate() }

        let contentIdentifiers = [
            (tab: "Map", content: "Map"),
            (tab: "Passport", content: "Passport"),
            (tab: "Friends", content: "Social"),
        ]

        for item in contentIdentifiers {
            let tab = app.tabBars.buttons[item.tab]
            XCTAssertTrue(
                tab.waitForExistence(timeout: launchTimeout),
                "Missing primary tab accessibility identifier: \(item.tab)"
            )
            tab.tap()

            let content = app.staticTexts[item.content].firstMatch
            XCTAssertTrue(
                content.waitForExistence(timeout: launchTimeout),
                "Tab \(item.tab) did not expose content accessibility identifier: \(item.content)"
            )
        }
    }
    func testMapAccessibility() throws {
        let app = XCUIApplication()
        app.launch()
        defer { app.terminate() }

        let mapTab = app.tabBars.buttons["Map"]
        XCTAssertTrue(
            mapTab.waitForExistence(timeout: launchTimeout),
            "The map tab must be available in the real app."
        )
        mapTab.tap()

        let ready = app.staticTexts["map.ready"]
        XCTAssertTrue(
            ready.waitForExistence(timeout: launchTimeout),
            "The official map must report readiness after launch."
        )
        XCTAssertEqual(
            ready.label,
            "Official mountain map ready",
            "The map readiness signal must identify the official map."
        )

        let annotationCount = app.staticTexts["map.annotation.count"]
        XCTAssertTrue(
            annotationCount.waitForExistence(timeout: launchTimeout),
            "The map must expose its official annotation count."
        )
        XCTAssertEqual(
            annotationCount.label,
            "100 official mountains shown",
            "The map must report exactly the fixed official 100-mountain catalog."
        )

        let markers = app.buttons.matching(
            NSPredicate(format: "identifier BEGINSWITH %@", "map.annotation.")
        )
        let allMarkersVisible = expectation(
            for: NSPredicate { object, _ in
                (object as? XCUIElementQuery)?.count == 100
            },
            evaluatedWith: markers
        )
        wait(for: [allMarkersVisible], timeout: launchTimeout)

        XCTAssertEqual(markers.count, 100, "Every official mountain must be accessible.")

        let markerIdentifiers = markers.allElementsBoundByIndex.map(\.identifier)
        XCTAssertEqual(
            markerIdentifiers.count,
            100,
            "Every accessible mountain marker must expose an identifier."
        )
        XCTAssertEqual(
            Set(markerIdentifiers).count,
            100,
            "Accessible mountain identifiers must be unique."
        )

        let marker = markers.firstMatch
        XCTAssertTrue(marker.isHittable, "The accessible mountain marker must be usable.")
        XCTAssertTrue(
            marker.label.hasSuffix("Not visited"),
            "The initial fixed catalog marker must expose its unvisited status."
        )
        marker.tap()

        let summary = app.staticTexts["map.summary"]
        XCTAssertTrue(
            summary.waitForExistence(timeout: launchTimeout),
            "Selecting a marker must expose its mountain summary."
        )

        let name = app.staticTexts["map.summary.name"]
        let region = app.staticTexts["map.summary.region"]
        let visitedStatus = app.staticTexts["map.summary.visited-status"]
        let visitCount = app.staticTexts["map.summary.visit-count"]
        let plannedStatus = app.staticTexts["map.summary.planned-status"]
        let fields = [name, region, visitedStatus, visitCount, plannedStatus]

        for field in fields {
            XCTAssertTrue(
                field.waitForExistence(timeout: launchTimeout),
                "Missing selected-mountain summary field: \(field.identifier)"
            )
            XCTAssertFalse(
                field.label.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                "Selected-mountain summary field must have an accessibility label: \(field.identifier)"
            )
        }

        let summaryFields = app.staticTexts.matching(
            NSPredicate(format: "identifier BEGINSWITH %@", "map.summary.")
        )
        XCTAssertEqual(
            summaryFields.count,
            5,
            "A selected mountain must expose exactly the five required summary fields."
        )
        XCTAssertEqual(visitedStatus.label, "Visited status: Not visited")
        XCTAssertEqual(visitCount.label, "Visit count: 0")
        XCTAssertEqual(plannedStatus.label, "Planned status: Not planned")
        let selectedStateScreenshot = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        selectedStateScreenshot.name = "M1-map-selected-summary"
        selectedStateScreenshot.lifetime = .keepAlways
        add(selectedStateScreenshot)
    }
}
