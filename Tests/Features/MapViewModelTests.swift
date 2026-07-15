import Foundation
import XCTest
@testable import HikerDataset
import HikerDomain
import HikerMapFeature

final class MapViewModelTests: XCTestCase {
    func testBundleMapsAll100AndSummaryHasFiveFields() throws {
        let manifest = try HikerDataset.loadManifest()
        let mountains = try HikerDataset.loadMountains()
        let progress = try makeProgress(for: mountains)
        var viewModel = MapViewModel(mountains: mountains, progress: progress)

        XCTAssertEqual(manifest.status, "release_candidate_public_official_source")
        XCTAssertEqual(manifest.review.status, "not_human_reviewed")
        XCTAssertTrue(manifest.review.reviewers.isEmpty)
        XCTAssertNil(manifest.review.reviewedAt)
        XCTAssertEqual(mountains.count, 100)
        XCTAssertEqual(Set(mountains.map(\.id)).count, 100)
        XCTAssertEqual(viewModel.state, .ready)
        XCTAssertEqual(viewModel.pins.count, 100)
        XCTAssertEqual(
            viewModel.pins.map(\.id),
            mountains.map(\.id).sorted { $0.rawValue < $1.rawValue }
        )
        XCTAssertTrue(viewModel.pins.allSatisfy {
            $0.id.rawValue.range(
                of: "^hkr_mtn_[0-9a-f]{32}$",
                options: .regularExpression
            ) != nil
        })

        let visitedMountain = try XCTUnwrap(mountains.first)
        let unvisitedMountain = try XCTUnwrap(mountains.dropFirst().first)
        XCTAssertEqual(
            visitedMountain.id.rawValue,
            "hkr_mtn_4d9852ed3a4678b1dab6400733c8fa77"
        )

        let visitedPin = try XCTUnwrap(
            viewModel.pins.first { $0.id == visitedMountain.id }
        )
        XCTAssertEqual(visitedPin.presentation, .visited)
        XCTAssertEqual(visitedPin.visitCount, 3)
        XCTAssertTrue(visitedPin.isPlanned)

        let unvisitedPin = try XCTUnwrap(
            viewModel.pins.first { $0.id == unvisitedMountain.id }
        )
        XCTAssertEqual(unvisitedPin.presentation, .unvisited)
        XCTAssertEqual(unvisitedPin.visitCount, 0)
        XCTAssertFalse(unvisitedPin.isPlanned)
        XCTAssertEqual(
            viewModel.pins.filter { $0.presentation == .visited }.count,
            1
        )
        XCTAssertEqual(
            viewModel.pins.filter { $0.presentation == .unvisited }.count,
            99
        )

        XCTAssertTrue(viewModel.select(mountainID: visitedMountain.id))
        XCTAssertEqual(viewModel.selectedMountainID, visitedMountain.id)

        let summary = try XCTUnwrap(viewModel.selectedSummary)
        XCTAssertEqual(summary.name, visitedMountain.koreanName)
        XCTAssertEqual(summary.region, visitedMountain.region)
        XCTAssertTrue(summary.isVisited)
        XCTAssertEqual(summary.visitCount, 3)
        XCTAssertTrue(summary.isPlanned)
        XCTAssertEqual(
            summary.fields,
            [
                MapSummaryField(
                    id: .name,
                    label: "Name",
                    value: visitedMountain.koreanName
                ),
                MapSummaryField(
                    id: .region,
                    label: "Region",
                    value: visitedMountain.region
                ),
                MapSummaryField(
                    id: .visitedStatus,
                    label: "Visited status",
                    value: "Visited"
                ),
                MapSummaryField(
                    id: .visitCount,
                    label: "Visit count",
                    value: "3"
                ),
                MapSummaryField(
                    id: .plannedStatus,
                    label: "Planned status",
                    value: "Planned"
                ),
            ]
        )

        XCTAssertTrue(viewModel.select(mountainID: unvisitedMountain.id))
        XCTAssertEqual(viewModel.selectedMountainID, unvisitedMountain.id)
        XCTAssertEqual(viewModel.selectedSummary?.isVisited, false)
    }

    func testInvalidManifestFailsClosed() throws {
        let manifestData = try invalidReviewManifestData()
        let catalogData = try HikerDataset.bundledResourceData(
            named: "official-100-mountains-v1"
        )
        let legacyMetadataData = try HikerDataset.bundledResourceData(
            named: "legacy-mountain-metadata-v1"
        )

        let datasetError: HikerDataset.MountainDatasetError
        do {
            _ = try HikerDataset.validateCatalog(
                manifestData: manifestData,
                catalogData: catalogData,
                legacyMetadataData: legacyMetadataData
            )
            return XCTFail("Expected invalid review provenance to fail validation.")
        } catch let error as HikerDataset.MountainDatasetError {
            datasetError = error
        } catch {
            return XCTFail("Expected manifest validation error, got \(error).")
        }

        XCTAssertEqual(
            datasetError,
            .invalidManifest("review provenance must not claim approval")
        )

        let integrityMessage = "The bundled mountain catalog failed integrity validation."
        let viewModel = MapViewModel.invalidCatalog(message: integrityMessage)

        XCTAssertEqual(
            viewModel.state,
            .invalidCatalog(.datasetUnavailable(integrityMessage))
        )
        XCTAssertEqual(
            MapCatalogValidationError.datasetUnavailable(integrityMessage).message,
            "The official mountain dataset is unavailable. \(integrityMessage)"
        )
        XCTAssertTrue(viewModel.pins.isEmpty)
        XCTAssertNil(viewModel.selectedMountainID)
        XCTAssertNil(viewModel.selectedSummary)
    }

    func testDatasetUnavailableFactoryFailsClosed() {
        let viewModel = MapViewModel.invalidCatalog(
            message: "The bundled official manifest could not be read."
        )

        XCTAssertEqual(
            viewModel.state,
            .invalidCatalog(
                .datasetUnavailable("The bundled official manifest could not be read.")
            )
        )
        XCTAssertTrue(viewModel.pins.isEmpty)
        XCTAssertNil(viewModel.selectedMountainID)
        XCTAssertNil(viewModel.selectedSummary)
    }

    func testCatalogCountBoundariesFailClosed() throws {
        let mountains = try makeMountains()
        let progress = try makeProgress(for: mountains)

        let ninetyNine = MapViewModel(
            mountains: Array(mountains.dropLast()),
            progress: progress
        )
        let oneHundredOne = MapViewModel(
            mountains: mountains + [try makeMountain(index: 101)],
            progress: progress
        )

        XCTAssertEqual(
            ninetyNine.state,
            .invalidCatalog(.expectedExactly100Mountains(actual: 99))
        )
        XCTAssertTrue(ninetyNine.pins.isEmpty)
        XCTAssertEqual(
            oneHundredOne.state,
            .invalidCatalog(.expectedExactly100Mountains(actual: 101))
        )
        XCTAssertTrue(oneHundredOne.pins.isEmpty)
    }

    func testProgressCatalogMismatchFailsClosedAndUnknownSelectionClears() throws {
        let mountains = try makeMountains()
        var missingProgress = try makeProgress(for: mountains)
        let selectedMountain = try XCTUnwrap(mountains.first)
        missingProgress[selectedMountain.id] = nil

        var missingProgressViewModel = MapViewModel(
            mountains: mountains,
            progress: missingProgress
        )
        XCTAssertEqual(
            missingProgressViewModel.state,
            .invalidCatalog(.missingProgress(selectedMountain.id))
        )
        XCTAssertTrue(missingProgressViewModel.pins.isEmpty)
        XCTAssertFalse(missingProgressViewModel.select(mountainID: selectedMountain.id))
        XCTAssertNil(missingProgressViewModel.selectedMountainID)

        var validViewModel = MapViewModel(
            mountains: mountains,
            progress: try makeProgress(for: mountains)
        )
        let unknownID = try MountainID(rawValue: "official-unknown")
        XCTAssertFalse(validViewModel.select(mountainID: unknownID))
        XCTAssertNil(validViewModel.selectedMountainID)
        XCTAssertTrue(validViewModel.select(mountainID: selectedMountain.id))
        XCTAssertTrue(validViewModel.select(mountainID: nil))
        XCTAssertNil(validViewModel.selectedMountainID)
    }

    func testDuplicateAndUnknownProgressFailClosedWithClearErrors() throws {
        let mountains = try makeMountains()
        let firstMountain = try XCTUnwrap(mountains.first)
        var duplicateMountains = mountains
        duplicateMountains[1] = firstMountain

        let duplicateViewModel = MapViewModel(
            mountains: duplicateMountains,
            progress: try makeProgress(for: mountains)
        )
        XCTAssertEqual(
            duplicateViewModel.state,
            .invalidCatalog(.duplicateMountainID(firstMountain.id))
        )
        XCTAssertTrue(duplicateViewModel.pins.isEmpty)

        let unknownID = try MountainID(rawValue: "official-unknown")
        var progress = try makeProgress(for: mountains)
        progress[unknownID] = try MountainProgress(visitCount: 0, planned: false)
        let unknownProgressViewModel = MapViewModel(mountains: mountains, progress: progress)
        XCTAssertEqual(
            unknownProgressViewModel.state,
            .invalidCatalog(.unknownProgress(unknownID))
        )
        XCTAssertEqual(
            MapCatalogValidationError.unknownProgress(unknownID).message,
            "The mountain catalog has progress for unknown ID official-unknown."
        )
    }

    private func invalidReviewManifestData() throws -> Data {
        let manifestData = try HikerDataset.bundledResourceData(
            named: "dataset-manifest"
        )
        var manifest = try XCTUnwrap(
            JSONSerialization.jsonObject(with: manifestData) as? [String: Any]
        )
        var review = try XCTUnwrap(manifest["review"] as? [String: Any])
        review["status"] = "human_reviewed"
        manifest["review"] = review

        return try JSONSerialization.data(withJSONObject: manifest, options: [.sortedKeys])
    }

    private func makeMountains() throws -> [Mountain] {
        try (1...100).map(makeMountain(index:))
    }

    private func makeMountain(index: Int) throws -> Mountain {
        try Mountain(
            id: MountainID(rawValue: "official-\(index)"),
            koreanName: "Mountain \(index)",
            region: "Region \(index)",
            summitCoordinate: SummitCoordinate(
                latitude: 33 + Double(index) / 1_000,
                longitude: 126 + Double(index) / 1_000
            )
        )
    }

    private func makeProgress(
        for mountains: [Mountain]
    ) throws -> [MountainID: MountainProgress] {
        var progress: [MountainID: MountainProgress] = [:]
        for (index, mountain) in mountains.enumerated() {
            progress[mountain.id] = try MountainProgress(
                visitCount: index == 0 ? 3 : 0,
                planned: index == 0
            )
        }
        return progress
    }
}
