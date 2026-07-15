import SwiftUI
import MapKit
import HikerDomain

public enum MapPinPresentation: Equatable, Sendable {
    case visited
    case unvisited

    public var accessibilityLabel: String {
        switch self {
        case .visited:
            "Visited"
        case .unvisited:
            "Not visited"
        }
    }

    var symbolName: String {
        switch self {
        case .visited:
            "checkmark.circle.fill"
        case .unvisited:
            "mappin.circle.fill"
        }
    }

    var tint: Color {
        switch self {
        case .visited:
            .green
        case .unvisited:
            .secondary
        }
    }
}

public struct MapPin: Identifiable, Equatable, Sendable {
    public let id: MountainID
    public let name: String
    public let region: String
    public let coordinate: SummitCoordinate
    public let presentation: MapPinPresentation
    public let visitCount: Int
    public let isPlanned: Bool

    init(
        id: MountainID,
        name: String,
        region: String,
        coordinate: SummitCoordinate,
        presentation: MapPinPresentation,
        visitCount: Int,
        isPlanned: Bool
    ) {
        self.id = id
        self.name = name
        self.region = region
        self.coordinate = coordinate
        self.presentation = presentation
        self.visitCount = visitCount
        self.isPlanned = isPlanned
    }
}

public enum MapSummaryFieldID: String, CaseIterable, Equatable, Hashable, Sendable {
    case name
    case region
    case visitedStatus = "visited-status"
    case visitCount = "visit-count"
    case plannedStatus = "planned-status"
}

public struct MapSummaryField: Identifiable, Equatable, Sendable {
    public let id: MapSummaryFieldID
    public let label: String
    public let value: String

    public init(id: MapSummaryFieldID, label: String, value: String) {
        self.id = id
        self.label = label
        self.value = value
    }
}

public struct MapMountainSummary: Equatable, Sendable {
    public let name: String
    public let region: String
    public let isVisited: Bool
    public let visitCount: Int
    public let isPlanned: Bool

    public init(
        name: String,
        region: String,
        isVisited: Bool,
        visitCount: Int,
        isPlanned: Bool
    ) {
        self.name = name
        self.region = region
        self.isVisited = isVisited
        self.visitCount = visitCount
        self.isPlanned = isPlanned
    }

    public var fields: [MapSummaryField] {
        [
            MapSummaryField(id: .name, label: "Name", value: name),
            MapSummaryField(id: .region, label: "Region", value: region),
            MapSummaryField(
                id: .visitedStatus,
                label: "Visited status",
                value: isVisited ? "Visited" : "Not visited"
            ),
            MapSummaryField(
                id: .visitCount,
                label: "Visit count",
                value: String(visitCount)
            ),
            MapSummaryField(
                id: .plannedStatus,
                label: "Planned status",
                value: isPlanned ? "Planned" : "Not planned"
            ),
        ]
    }
}

public enum MapCatalogValidationError: Error, Equatable, Sendable {
    case expectedExactly100Mountains(actual: Int)
    case duplicateMountainID(MountainID)
    case missingProgress(MountainID)
    case unknownProgress(MountainID)
    case datasetUnavailable(String)

    public var message: String {
        switch self {
        case let .expectedExactly100Mountains(actual):
            "The mountain catalog must contain exactly 100 mountains. Found \(actual)."
        case let .duplicateMountainID(id):
            "The mountain catalog contains duplicate ID \(id.rawValue)."
        case let .missingProgress(id):
            "The mountain catalog is missing progress for ID \(id.rawValue)."
        case let .unknownProgress(id):
            "The mountain catalog has progress for unknown ID \(id.rawValue)."
        case let .datasetUnavailable(message):
            "The official mountain dataset is unavailable. \(message)"
        }
    }
}

public enum MapViewModelState: Equatable, Sendable {
    case loading
    case ready
    case empty
    case localStateUnavailable(String)
    case invalidCatalog(MapCatalogValidationError)
}

public struct MapViewModel: Sendable {
    public private(set) var state: MapViewModelState
    public private(set) var pins: [MapPin]
    public private(set) var selectedMountainID: MountainID?

    public static let loading = MapViewModel(state: .loading)
    public static let empty = MapViewModel(state: .empty)
    public static func invalidCatalog(message: String) -> MapViewModel {
        MapViewModel(state: .invalidCatalog(.datasetUnavailable(message)))
    }
    public static func localStateUnavailable(message: String) -> MapViewModel {
        MapViewModel(state: .localStateUnavailable(message))
    }

    public init(mountains: [Mountain], progress: [MountainID: MountainProgress]) {
        guard mountains.count == 100 else {
            self.init(state: .invalidCatalog(.expectedExactly100Mountains(actual: mountains.count)))
            return
        }

        var mountainIDs = Set<MountainID>()
        for mountain in mountains {
            guard mountainIDs.insert(mountain.id).inserted else {
                self.init(state: .invalidCatalog(.duplicateMountainID(mountain.id)))
                return
            }
        }

        let progressIDs = Set(progress.keys)
        if let missingID = mountainIDs.subtracting(progressIDs).min(by: {
            $0.rawValue < $1.rawValue
        }) {
            self.init(state: .invalidCatalog(.missingProgress(missingID)))
            return
        }

        if let unknownID = progressIDs.subtracting(mountainIDs).min(by: {
            $0.rawValue < $1.rawValue
        }) {
            self.init(state: .invalidCatalog(.unknownProgress(unknownID)))
            return
        }

        var mappedPins: [MapPin] = []
        for mountain in mountains.sorted(by: { $0.id.rawValue < $1.id.rawValue }) {
            guard let mountainProgress = progress[mountain.id] else {
                self.init(state: .invalidCatalog(.missingProgress(mountain.id)))
                return
            }

            mappedPins.append(
                MapPin(
                    id: mountain.id,
                    name: mountain.koreanName,
                    region: mountain.region,
                    coordinate: mountain.summitCoordinate,
                    presentation: mountainProgress.isVisited ? .visited : .unvisited,
                    visitCount: mountainProgress.visitCount,
                    isPlanned: mountainProgress.planned
                )
            )
        }

        self.init(state: .ready, pins: mappedPins)
    }

    public var selectedSummary: MapMountainSummary? {
        guard
            state == .ready,
            let selectedMountainID,
            let pin = pins.first(where: { $0.id == selectedMountainID })
        else {
            return nil
        }

        return MapMountainSummary(
            name: pin.name,
            region: pin.region,
            isVisited: pin.presentation == .visited,
            visitCount: pin.visitCount,
            isPlanned: pin.isPlanned
        )
    }

    @discardableResult
    public mutating func select(mountainID: MountainID?) -> Bool {
        guard state == .ready else {
            selectedMountainID = nil
            return false
        }

        guard let mountainID else {
            selectedMountainID = nil
            return true
        }

        guard pins.contains(where: { $0.id == mountainID }) else {
            selectedMountainID = nil
            return false
        }

        selectedMountainID = mountainID
        return true
    }

    private init(state: MapViewModelState, pins: [MapPin] = []) {
        self.state = state
        self.pins = pins
        selectedMountainID = nil
    }
}

public struct MapFeatureView: View {
    private let viewModelProvider: @MainActor () -> MapViewModel
    private let revision: UInt64
    @State private var selectedMountainID: MountainID?
    @State private var mapPosition: MapCameraPosition

    public init(viewModel: MapViewModel, revision: UInt64 = 0) {
        viewModelProvider = { viewModel }
        self.revision = revision
        _selectedMountainID = State(initialValue: nil)
        _mapPosition = State(initialValue: .automatic)
    }

    public init(
        viewModelProvider: @escaping @MainActor () -> MapViewModel,
        revision: UInt64
    ) {
        self.viewModelProvider = viewModelProvider
        self.revision = revision
        _selectedMountainID = State(initialValue: nil)
        _mapPosition = State(initialValue: .automatic)
    }

    public var body: some View {
        Group {
            switch viewModel.state {
            case .loading:
                ContentUnavailableView("Loading mountain map", systemImage: "map")
                    .accessibilityIdentifier("map.loading")
                    .accessibilityLabel("Loading official mountain map")

            case .empty:
                ContentUnavailableView("No mountains available", systemImage: "map")
                    .accessibilityIdentifier("map.empty")
                    .accessibilityLabel("No official mountains available")

            case let .localStateUnavailable(message):
                ContentUnavailableView(
                    "Local passport state unavailable",
                    systemImage: "exclamationmark.triangle",
                    description: Text(message)
                )
                .accessibilityIdentifier("map.error")
                .accessibilityLabel("Local passport state unavailable. \(message)")

            case let .invalidCatalog(error):
                ContentUnavailableView(
                    "Invalid mountain catalog",
                    systemImage: "exclamationmark.triangle",
                    description: Text(error.message)
                )
                .accessibilityIdentifier("map.invalid-catalog")
                .accessibilityLabel("Invalid mountain catalog. \(error.message)")

            case .ready:
                readyMap
            }
        }
        .onChange(of: revision) { _, _ in
            selectedMountainID = nil
        }
    }

    private var viewModel: MapViewModel {
        viewModelProvider()
    }

    @ViewBuilder
    private var readyMap: some View {
        VStack(spacing: 12) {
            Map(position: $mapPosition) {
                ForEach(viewModel.pins) { pin in
                    Annotation(
                        pin.name,
                        coordinate: CLLocationCoordinate2D(
                            latitude: pin.coordinate.latitude,
                            longitude: pin.coordinate.longitude
                        )
                    ) {
                        Button {
                            selectedMountainID = pin.id
                        } label: {
                            Image(systemName: pin.presentation.symbolName)
                                .font(.title2)
                                .foregroundStyle(pin.presentation.tint)
                                .padding(6)
                                .background(.thinMaterial, in: Circle())
                        }
                        .accessibilityIdentifier("map.annotation.\(pin.id.rawValue)")
                        .accessibilityLabel(
                            "\(pin.name), \(pin.region), \(pin.presentation.accessibilityLabel)"
                        )
                    }
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .accessibilityIdentifier("map.canvas")
            .accessibilityLabel("Official 100 mountain map")

            Text("Map ready")
                .accessibilityIdentifier("map.ready")
                .accessibilityLabel("Official mountain map ready")

            Text("\(viewModel.pins.count) official mountains shown")
                .accessibilityIdentifier("map.annotation.count")
                .accessibilityLabel("\(viewModel.pins.count) official mountains shown")


            if let summary = selectedSummary {
                summaryView(summary)
            }
        }
    }

    private var selectedSummary: MapMountainSummary? {
        guard
            let selectedMountainID,
            let pin = viewModel.pins.first(where: { $0.id == selectedMountainID })
        else {
            return nil
        }

        return MapMountainSummary(
            name: pin.name,
            region: pin.region,
            isVisited: pin.presentation == .visited,
            visitCount: pin.visitCount,
            isPlanned: pin.isPlanned
        )
    }

    private func summaryView(_ summary: MapMountainSummary) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Selected mountain")
                .font(.headline)
                .accessibilityIdentifier("map.summary")
                .accessibilityLabel("Selected mountain summary")

            ForEach(summary.fields) { field in
                Text("\(field.label): \(field.value)")
                    .accessibilityIdentifier("map.summary.\(field.id.rawValue)")
                    .accessibilityLabel("\(field.label): \(field.value)")
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
        .padding(.horizontal)
    }
}