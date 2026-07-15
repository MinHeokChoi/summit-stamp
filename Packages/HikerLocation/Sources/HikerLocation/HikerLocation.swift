import CoreLocation
import Foundation

/// An immutable, transient location reading used only for advisory verification.
public struct GPSLocationSample: Sendable, Equatable {
    public let latitude: Double
    public let longitude: Double
    public let horizontalAccuracy: Double
    public let timestamp: Date

    public init(
        latitude: Double,
        longitude: Double,
        horizontalAccuracy: Double,
        timestamp: Date
    ) {
        self.latitude = latitude
        self.longitude = longitude
        self.horizontalAccuracy = horizontalAccuracy
        self.timestamp = timestamp
    }
}

/// The known summit coordinate against which a transient GPS sample is evaluated.
public struct GPSSummitCoordinate: Sendable, Equatable {
    public let latitude: Double
    public let longitude: Double

    public init(latitude: Double, longitude: Double) {
        self.latitude = latitude
        self.longitude = longitude
    }
}

/// The outcome of an advisory GPS verification attempt.
///
/// Every outcome other than `eligible` requires the caller to offer manual fallback.
public enum GPSVerificationEligibility: Sendable, Equatable {
    case eligible
    case requiresWhenInUseAuthorization
    case permissionDenied
    case permissionRestricted
    case requestInProgress
    case unavailable
    case invalidSample
    case invalidSummitCoordinate
    case futureSample
    case staleSample
    case inaccurateSample
    case outsideSummitRadius

    public var manualFallbackRequired: Bool {
        self != .eligible
    }
}

/// A pure policy for deciding whether a transient location sample is eligible for
/// advisory GPS verification. It has no persistence behavior.
public enum GPSVerificationPolicy {
    public static let maximumSummitDistanceMeters = 300.0
    public static let minimumHorizontalAccuracyMeters = 0.0
    public static let maximumHorizontalAccuracyMeters = 100.0
    public static let maximumSampleAge: TimeInterval = 120.0

    public static func evaluate(
        sample: GPSLocationSample,
        summit: GPSSummitCoordinate,
        now: Date
    ) -> GPSVerificationEligibility {
        guard isValidCoordinate(latitude: summit.latitude, longitude: summit.longitude) else {
            return .invalidSummitCoordinate
        }

        guard isValidCoordinate(latitude: sample.latitude, longitude: sample.longitude) else {
            return .invalidSample
        }

        guard sample.horizontalAccuracy.isFinite,
              (minimumHorizontalAccuracyMeters...maximumHorizontalAccuracyMeters)
                .contains(sample.horizontalAccuracy) else {
            return .inaccurateSample
        }

        let sampleAge = now.timeIntervalSince(sample.timestamp)
        guard sampleAge.isFinite else {
            return .invalidSample
        }

        guard sampleAge >= 0 else {
            return .futureSample
        }

        guard sampleAge <= maximumSampleAge else {
            return .staleSample
        }

        let distance = distanceMeters(
            latitude: sample.latitude,
            longitude: sample.longitude,
            from: summit
        )
        guard distance.isFinite else {
            return .unavailable
        }

        return distance <= maximumSummitDistanceMeters ? .eligible : .outsideSummitRadius
    }

    private static func isValidCoordinate(latitude: Double, longitude: Double) -> Bool {
        latitude.isFinite
            && longitude.isFinite
            && (-90.0...90.0).contains(latitude)
            && (-180.0...180.0).contains(longitude)
    }

    private static func distanceMeters(
        latitude: Double,
        longitude: Double,
        from summit: GPSSummitCoordinate
    ) -> Double {
        let latitudeRadians = latitude * .pi / 180
        let summitLatitudeRadians = summit.latitude * .pi / 180
        let deltaLatitude = summitLatitudeRadians - latitudeRadians
        let deltaLongitude = (summit.longitude - longitude) * .pi / 180

        let haversine = pow(sin(deltaLatitude / 2), 2)
            + cos(latitudeRadians) * cos(summitLatitudeRadians)
            * pow(sin(deltaLongitude / 2), 2)
        let boundedHaversine = min(1, max(0, haversine))
        let centralAngle = 2 * atan2(
            sqrt(boundedHaversine),
            sqrt(1 - boundedHaversine)
        )

        return 6_371_008.8 * centralAngle
    }
}

public enum LocationPermission: Sendable, Equatable {
    case notDetermined
    case denied
    case restricted
    case authorizedWhenInUse
    case authorizedAlways

    public var oneShotRequestPreflight: OneShotLocationRequestPreflight {
        switch self {
        case .notDetermined:
            .requiresWhenInUseAuthorization
        case .denied:
            .denied
        case .restricted:
            .restricted
        case .authorizedWhenInUse, .authorizedAlways:
            .ready
        }
    }
}

public enum OneShotLocationRequestPreflight: Sendable, Equatable {
    case ready
    case requiresWhenInUseAuthorization
    case denied
    case restricted
}

public enum OneShotLocationRequestError: Error, Sendable, Equatable {
    case requiresWhenInUseAuthorization
    case permissionDenied
    case permissionRestricted
    case requestInProgress
    case unavailable
    case cancelled

    public var eligibility: GPSVerificationEligibility {
        switch self {
        case .requiresWhenInUseAuthorization:
            .requiresWhenInUseAuthorization
        case .permissionDenied:
            .permissionDenied
        case .permissionRestricted:
            .permissionRestricted
        case .requestInProgress:
            .requestInProgress
        case .unavailable, .cancelled:
            .unavailable
        }
    }
}

@MainActor
public final class OneShotLocationRequester: NSObject, CLLocationManagerDelegate {
    private let manager: CLLocationManager
    private var continuation: CheckedContinuation<GPSLocationSample, Error>?

    public override init() {
        manager = CLLocationManager()
        super.init()
        manager.delegate = self
    }

    public var permission: LocationPermission {
        LocationPermission(manager.authorizationStatus)
    }

    public func requestWhenInUseAuthorization() {
        guard permission == .notDetermined else { return }
        manager.requestWhenInUseAuthorization()
    }

    public func requestOneShotLocation() async throws -> GPSLocationSample {
        switch permission.oneShotRequestPreflight {
        case .ready:
            break
        case .requiresWhenInUseAuthorization:
            throw OneShotLocationRequestError.requiresWhenInUseAuthorization
        case .denied:
            throw OneShotLocationRequestError.permissionDenied
        case .restricted:
            throw OneShotLocationRequestError.permissionRestricted
        }

        guard continuation == nil else {
            throw OneShotLocationRequestError.requestInProgress
        }

        return try await withTaskCancellationHandler(
            operation: {
                try await withCheckedThrowingContinuation { continuation in
                    guard self.continuation == nil else {
                        continuation.resume(
                            throwing: OneShotLocationRequestError.requestInProgress
                        )
                        return
                    }

                    guard !Task.isCancelled else {
                        continuation.resume(throwing: OneShotLocationRequestError.cancelled)
                        return
                    }

                    self.continuation = continuation
                    self.manager.requestLocation()
                }
            },
            onCancel: {
                Task { @MainActor [weak self] in
                    self?.complete(.failure(.cancelled))
                }
            }
        )
    }

    nonisolated public func locationManager(
        _: CLLocationManager,
        didUpdateLocations locations: [CLLocation]
    ) {
        let sample = locations.last.map {
            GPSLocationSample(
                latitude: $0.coordinate.latitude,
                longitude: $0.coordinate.longitude,
                horizontalAccuracy: $0.horizontalAccuracy,
                timestamp: $0.timestamp
            )
        }

        Task { @MainActor [weak self] in
            guard let sample else {
                self?.complete(.failure(.unavailable))
                return
            }
            self?.complete(.success(sample))
        }
    }

    nonisolated public func locationManager(
        _ manager: CLLocationManager,
        didFailWithError _: Error
    ) {
        let requestError: OneShotLocationRequestError
        switch LocationPermission(manager.authorizationStatus).oneShotRequestPreflight {
        case .ready:
            requestError = .unavailable
        case .requiresWhenInUseAuthorization:
            requestError = .requiresWhenInUseAuthorization
        case .denied:
            requestError = .permissionDenied
        case .restricted:
            requestError = .permissionRestricted
        }

        Task { @MainActor [weak self] in
            self?.complete(.failure(requestError))
        }
    }

    nonisolated public func locationManagerDidChangeAuthorization(
        _ manager: CLLocationManager
    ) {
        let preflight = LocationPermission(
            manager.authorizationStatus
        ).oneShotRequestPreflight

        Task { @MainActor [weak self] in
            self?.handleAuthorizationTransition(preflight)
        }
    }

    private func handleAuthorizationTransition(
        _ preflight: OneShotLocationRequestPreflight
    ) {
        switch preflight {
        case .ready:
            break
        case .requiresWhenInUseAuthorization:
            complete(.failure(.requiresWhenInUseAuthorization))
        case .denied:
            complete(.failure(.permissionDenied))
        case .restricted:
            complete(.failure(.permissionRestricted))
        }
    }

    private func complete(
        _ result: Result<GPSLocationSample, OneShotLocationRequestError>
    ) {
        guard let continuation else { return }
        self.continuation = nil
        manager.stopUpdatingLocation()

        switch result {
        case let .success(sample):
            continuation.resume(returning: sample)
        case let .failure(error):
            continuation.resume(throwing: error)
        }
    }
}

private extension LocationPermission {
    init(_ status: CLAuthorizationStatus) {
        switch status {
        case .notDetermined:
            self = .notDetermined
        case .restricted:
            self = .restricted
        case .denied:
            self = .denied
        case .authorizedWhenInUse:
            self = .authorizedWhenInUse
        case .authorizedAlways:
            self = .authorizedAlways
        @unknown default:
            self = .restricted
        }
    }
}