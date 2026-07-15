import OSLog

/// A closed set of operational events that may be sent to observability systems.
///
/// Events intentionally carry no associated values or caller-provided metadata, so
/// coordinates, secrets, and other user data cannot cross this boundary.
public enum HikerObservabilityEvent: String, CaseIterable, Sendable {
    case routePlanningStarted = "route_planning_started"
    case routePlanningCompleted = "route_planning_completed"
    case routePlanningUnavailable = "route_planning_unavailable"
}

/// Receives privacy-safe operational events.
public protocol HikerEventSink: Sendable {
    func record(_ event: HikerObservabilityEvent) async
}

public actor OSLogEventSink: HikerEventSink {
    private let logger: Logger

    public init(subsystem: String, category: String = "operations") {
        logger = Logger(subsystem: subsystem, category: category)
    }

    public func record(_ event: HikerObservabilityEvent) {
        logger.info("event=\(event.rawValue, privacy: .public)")
    }
}
