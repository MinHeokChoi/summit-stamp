import Foundation
import HikerLocation
import XCTest

final class HikerLocationTests: XCTestCase {
    // GPS-001
    func testGPS001SummitDistanceThresholdIsInclusive() {
        let now = Date(timeIntervalSinceReferenceDate: 1_000)
        let summit = GPSSummitCoordinate(latitude: 0, longitude: 0)

        XCTAssertEqual(
            GPSVerificationPolicy.evaluate(
                sample: sample(
                    latitude: 0,
                    longitude: 0,
                    horizontalAccuracy: 0,
                    timestamp: now
                ),
                summit: summit,
                now: now
            ),
            .eligible
        )
        XCTAssertEqual(
            GPSVerificationPolicy.evaluate(
                sample: sampleAtDistance(299.9, timestamp: now),
                summit: summit,
                now: now
            ),
            .eligible
        )
        XCTAssertEqual(
            GPSVerificationPolicy.evaluate(
                sample: sampleAtDistance(
                    GPSVerificationPolicy.maximumSummitDistanceMeters,
                    timestamp: now
                ),
                summit: summit,
                now: now
            ),
            .eligible
        )
        XCTAssertEqual(
            GPSVerificationPolicy.evaluate(
                sample: sampleAtDistance(
                    GPSVerificationPolicy.maximumSummitDistanceMeters + 0.1,
                    timestamp: now
                ),
                summit: summit,
                now: now
            ),
            .outsideSummitRadius
        )
    }

    // GPS-002
    func testGPS002HorizontalAccuracyThresholdIsInclusive() {
        let now = Date(timeIntervalSinceReferenceDate: 1_000)
        let summit = GPSSummitCoordinate(latitude: 0, longitude: 0)

        XCTAssertEqual(
            GPSVerificationPolicy.evaluate(
                sample: sample(horizontalAccuracy: 0, timestamp: now),
                summit: summit,
                now: now
            ),
            .eligible
        )
        XCTAssertEqual(
            GPSVerificationPolicy.evaluate(
                sample: sample(
                    horizontalAccuracy: GPSVerificationPolicy.maximumHorizontalAccuracyMeters,
                    timestamp: now
                ),
                summit: summit,
                now: now
            ),
            .eligible
        )
        XCTAssertEqual(
            GPSVerificationPolicy.evaluate(
                sample: sample(horizontalAccuracy: 99.9, timestamp: now),
                summit: summit,
                now: now
            ),
            .eligible
        )
        XCTAssertEqual(
            GPSVerificationPolicy.evaluate(
                sample: sample(horizontalAccuracy: -0.1, timestamp: now),
                summit: summit,
                now: now
            ),
            .inaccurateSample
        )
        XCTAssertEqual(
            GPSVerificationPolicy.evaluate(
                sample: sample(
                    horizontalAccuracy: GPSVerificationPolicy.maximumHorizontalAccuracyMeters + 0.1,
                    timestamp: now
                ),
                summit: summit,
                now: now
            ),
            .inaccurateSample
        )
    }

    // GPS-003
    func testGPS003SampleAgeThresholdRejectsStaleAndFutureSamples() {
        let now = Date(timeIntervalSinceReferenceDate: 1_000)
        let summit = GPSSummitCoordinate(latitude: 0, longitude: 0)

        XCTAssertEqual(
            GPSVerificationPolicy.evaluate(
                sample: sample(timestamp: now),
                summit: summit,
                now: now
            ),
            .eligible
        )
        XCTAssertEqual(
            GPSVerificationPolicy.evaluate(
                sample: sample(
                    timestamp: now.addingTimeInterval(
                        -GPSVerificationPolicy.maximumSampleAge
                    )
                ),
                summit: summit,
                now: now
            ),
            .eligible
        )
        XCTAssertEqual(
            GPSVerificationPolicy.evaluate(
                sample: sample(timestamp: now.addingTimeInterval(-119.9)),
                summit: summit,
                now: now
            ),
            .eligible
        )
        XCTAssertEqual(
            GPSVerificationPolicy.evaluate(
                sample: sample(
                    timestamp: now.addingTimeInterval(
                        -GPSVerificationPolicy.maximumSampleAge - 0.1
                    )
                ),
                summit: summit,
                now: now
            ),
            .staleSample
        )
        XCTAssertEqual(
            GPSVerificationPolicy.evaluate(
                sample: sample(timestamp: now.addingTimeInterval(0.1)),
                summit: summit,
                now: now
            ),
            .futureSample
        )
    }

    func testInvalidCoordinatesAndRequestErrorsRequireManualFallback() {
        let now = Date(timeIntervalSinceReferenceDate: 1_000)

        let invalidSample = GPSVerificationPolicy.evaluate(
            sample: sample(latitude: .infinity, timestamp: now),
            summit: GPSSummitCoordinate(latitude: 0, longitude: 0),
            now: now
        )
        XCTAssertEqual(invalidSample, .invalidSample)
        XCTAssertTrue(invalidSample.manualFallbackRequired)

        XCTAssertEqual(
            OneShotLocationRequestError.permissionDenied.eligibility,
            .permissionDenied
        )
        XCTAssertEqual(
            OneShotLocationRequestError.permissionRestricted.eligibility,
            .permissionRestricted
        )
        XCTAssertEqual(
            OneShotLocationRequestError.unavailable.eligibility,
            .unavailable
        )
        XCTAssertTrue(
            OneShotLocationRequestError.requestInProgress.eligibility.manualFallbackRequired
        )
    }

    func testOneShotPreflightRequiresAuthorizationBeforeLocationRequest() {
        XCTAssertEqual(
            LocationPermission.notDetermined.oneShotRequestPreflight,
            .requiresWhenInUseAuthorization
        )
        XCTAssertEqual(
            LocationPermission.denied.oneShotRequestPreflight,
            .denied
        )
        XCTAssertEqual(
            LocationPermission.restricted.oneShotRequestPreflight,
            .restricted
        )
        XCTAssertEqual(
            LocationPermission.authorizedWhenInUse.oneShotRequestPreflight,
            .ready
        )
        XCTAssertEqual(
            LocationPermission.authorizedAlways.oneShotRequestPreflight,
            .ready
        )
    }

    private func sample(
        latitude: Double = 0,
        longitude: Double = 0,
        horizontalAccuracy: Double = 10,
        timestamp: Date
    ) -> GPSLocationSample {
        GPSLocationSample(
            latitude: latitude,
            longitude: longitude,
            horizontalAccuracy: horizontalAccuracy,
            timestamp: timestamp
        )
    }

    private func sampleAtDistance(
        _ distance: Double,
        timestamp: Date
    ) -> GPSLocationSample {
        let latitude = distance / 6_371_008.8 * 180 / .pi
        return sample(latitude: latitude, timestamp: timestamp)
    }
}