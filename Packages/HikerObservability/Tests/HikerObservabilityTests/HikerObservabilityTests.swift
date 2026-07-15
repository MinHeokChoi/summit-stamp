import XCTest
@testable import HikerObservability

final class HikerObservabilityTests: XCTestCase {
    func testSinkRecordsOnlyTheClosedPrivacySafeEventSet() async {
        let sink = EventRecorder()
        let expectedEvents = HikerObservabilityEvent.allCases

        for event in expectedEvents {
            await sink.record(event)
        }

        let recordedEvents = await sink.events
        XCTAssertEqual(recordedEvents, expectedEvents)
        XCTAssertEqual(
            recordedEvents.map(\.rawValue),
            [
                "route_planning_started",
                "route_planning_completed",
                "route_planning_unavailable"
            ]
        )
    }
}

private actor EventRecorder: HikerEventSink {
    private(set) var events: [HikerObservabilityEvent] = []

    func record(_ event: HikerObservabilityEvent) {
        events.append(event)
    }
}
