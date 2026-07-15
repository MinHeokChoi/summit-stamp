import XCTest
@testable import HikerDataset

final class MountainDatasetValidatorTests: XCTestCase {
    func testExactly100UniqueStableSummitRecords() throws {
        let mountains = try HikerDataset.loadMountains()
        let manifest = try HikerDataset.loadManifest()

        XCTAssertEqual(mountains.count, 100)
        XCTAssertTrue(mountains.allSatisfy {
            $0.id.rawValue.range(
                of: "^hkr_mtn_[0-9a-f]{32}$",
                options: .regularExpression
            ) != nil
        })
        XCTAssertEqual(Set(mountains.map(\.id)).count, 100)
        XCTAssertTrue(mountains.allSatisfy { !$0.koreanName.isEmpty && !$0.region.isEmpty })
        XCTAssertTrue(mountains.allSatisfy {
            $0.summitCoordinate.latitude.isFinite
                && $0.summitCoordinate.longitude.isFinite
                && (-90...90).contains($0.summitCoordinate.latitude)
                && (-180...180).contains($0.summitCoordinate.longitude)
        })
        XCTAssertEqual(manifest.entryCount, 100)
        XCTAssertEqual(manifest.status, "release_candidate_public_official_source")
        XCTAssertEqual(manifest.source.dataset, "FDMS_BASE:TB_FGDI_FS_F100")
        XCTAssertEqual(manifest.content.sha256, try HikerDataset.checksum(for: officialCatalogData()))
        XCTAssertEqual(mountains[24].id.rawValue, "hkr_mtn_61b836d0d388e1cab93898d9b90d0da6")
    }

    func testAllLegacyIDsResolveToTheirCurrentIDs() throws {
        let mountains = try HikerDataset.loadMountains()
        let legacyMetadata = try HikerDataset.loadLegacyMountainMetadata()
        guard let stableID = mountains.first?.id else {
            return XCTFail("Expected a nonempty catalog")
        }

        XCTAssertEqual(legacyMetadata.entryCount, 100)
        for mapping in legacyMetadata.entries {
            let legacyID = try type(of: stableID).init(rawValue: mapping.legacyID)
            let currentID = try type(of: stableID).init(rawValue: mapping.currentID)

            XCTAssertEqual(try HikerDataset.resolveStableID(legacyID), currentID)
        }
    }

    func testCatalogTamperingReportsChecksumBeforeDecoding() throws {
        XCTAssertThrowsError(
            try HikerDataset.validateCatalog(
                manifestData: manifestData(),
                catalogData: Data("{".utf8),
                legacyMetadataData: legacyMetadataData()
            )
        ) { error in
            self.assertChecksumMismatch(error, resource: "official-100-mountains-v1")
        }
    }

    func testLegacyChecksumFailureFailsClosed() throws {
        var alteredLegacyMetadataData = try legacyMetadataData()
        alteredLegacyMetadataData.append(0x20)

        XCTAssertThrowsError(
            try HikerDataset.validateCatalog(
                manifestData: manifestData(),
                catalogData: officialCatalogData(),
                legacyMetadataData: alteredLegacyMetadataData
            )
        ) { error in
            self.assertChecksumMismatch(error, resource: "legacy-mountain-metadata-v1")
        }
    }

    func testMalformedPinnedManifestFailsClosed() throws {
        XCTAssertThrowsError(
            try HikerDataset.validateCatalog(
                manifestData: Data("{".utf8),
                catalogData: officialCatalogData(),
                legacyMetadataData: legacyMetadataData()
            )
        ) { error in
            guard case .some(.invalid("dataset-manifest", _)) = error as? HikerDataset.ResourceError else {
                return XCTFail("Expected invalid manifest resource error, got \(error)")
            }
        }
    }

    func testFalseReviewProvenanceFailsClosed() throws {
        var manifest = try object(from: manifestData())
        var review = try dictionary(manifest["review"])
        review["status"] = "human_reviewed"
        review["reviewers"] = ["reviewer"]
        review["reviewedAt"] = "2026-07-14T00:03:32.659Z"
        manifest["review"] = review

        XCTAssertThrowsError(
            try HikerDataset.validateCatalog(
                manifestData: encoded(manifest),
                catalogData: officialCatalogData(),
                legacyMetadataData: legacyMetadataData()
            )
        ) { error in
            guard case .some(.invalidManifest) = error as? HikerDataset.MountainDatasetError else {
                return XCTFail("Expected manifest validation failure, got \(error)")
            }
        }
    }
    func testMissingSourceEvidencePathsFailClosed() throws {
        for field in ["rawResource", "normalizedSnapshotPath"] {
            var manifest = try object(from: manifestData())
            var source = try dictionary(manifest["source"])
            source.removeValue(forKey: field)
            manifest["source"] = source

            XCTAssertThrowsError(
                try HikerDataset.validateCatalog(
                    manifestData: encoded(manifest),
                    catalogData: officialCatalogData(),
                    legacyMetadataData: legacyMetadataData()
                )
            ) { error in
                guard case .some(.invalid("dataset-manifest", _)) = error as? HikerDataset.ResourceError else {
                    return XCTFail("Expected invalid manifest resource error, got \(error)")
                }
            }
        }
    }

    func testAlteredSourceEvidencePathsFailClosed() throws {
        for field in ["rawResource", "normalizedSnapshotPath"] {
            var manifest = try object(from: manifestData())
            var source = try dictionary(manifest["source"])
            source[field] = "Evidence/dataset/altered-\(field).json"
            manifest["source"] = source

            XCTAssertThrowsError(
                try HikerDataset.validateCatalog(
                    manifestData: encoded(manifest),
                    catalogData: officialCatalogData(),
                    legacyMetadataData: legacyMetadataData()
                )
            ) { error in
                guard case .some(.invalidManifest) = error as? HikerDataset.MountainDatasetError else {
                    return XCTFail("Expected manifest validation failure, got \(error)")
                }
            }
        }
    }

    func testProductionTamperingReportsChecksumBeforeSemanticValidation() throws {
        var catalog = try object(from: officialCatalogData())
        var entries = try array(catalog["entries"])
        var duplicate = try dictionary(entries[1])
        duplicate["id"] = try dictionary(entries[0])["id"]
        entries[1] = duplicate
        catalog["entries"] = entries

        XCTAssertThrowsError(
            try HikerDataset.validateCatalog(
                manifestData: manifestData(),
                catalogData: encoded(catalog),
                legacyMetadataData: legacyMetadataData()
            )
        ) { error in
            self.assertChecksumMismatch(error, resource: "official-100-mountains-v1")
        }
    }

    func testDuplicateStableIDFailsSemanticValidation() throws {
        var catalog = try object(from: officialCatalogData())
        var entries = try array(catalog["entries"])
        var duplicate = try dictionary(entries[1])
        duplicate["id"] = try dictionary(entries[0])["id"]
        entries[1] = duplicate
        catalog["entries"] = entries

        XCTAssertThrowsError(
            try HikerDataset.validateCatalogSemantics(
                manifestData: manifestData(),
                catalogData: encoded(catalog),
                legacyMetadataData: legacyMetadataData()
            )
        ) { error in
            guard case .some(.duplicateStableID) = error as? HikerDataset.MountainDatasetError else {
                return XCTFail("Expected duplicate stable-ID failure, got \(error)")
            }
        }
    }

    func testCoordinateFailureFailsSemanticValidation() throws {
        var catalog = try object(from: officialCatalogData())
        var entries = try array(catalog["entries"])
        var firstEntry = try dictionary(entries[0])
        firstEntry["latitude"] = 91.0
        entries[0] = firstEntry
        catalog["entries"] = entries

        XCTAssertThrowsError(
            try HikerDataset.validateCatalogSemantics(
                manifestData: manifestData(),
                catalogData: encoded(catalog),
                legacyMetadataData: legacyMetadataData()
            )
        ) { error in
            guard case .some(.invalidCoordinate) = error as? HikerDataset.MountainDatasetError else {
                return XCTFail("Expected coordinate validation failure, got \(error)")
            }
        }
    }

    func testWrongOpaqueIDAndOrderFailSemanticValidation() throws {
        var wrongIDCatalog = try object(from: officialCatalogData())
        var wrongIDEntries = try array(wrongIDCatalog["entries"])
        var firstEntry = try dictionary(wrongIDEntries[0])
        firstEntry["id"] = "hkr_mtn_00000000000000000000000000000000"
        wrongIDEntries[0] = firstEntry
        wrongIDCatalog["entries"] = wrongIDEntries

        assertInvalidCatalog(
            try HikerDataset.validateCatalogSemantics(
                manifestData: manifestData(),
                catalogData: encoded(wrongIDCatalog),
                legacyMetadataData: legacyMetadataData()
            )
        )

        var reorderedCatalog = try object(from: officialCatalogData())
        var reorderedEntries = try array(reorderedCatalog["entries"])
        reorderedEntries.swapAt(0, 1)
        reorderedCatalog["entries"] = reorderedEntries

        assertInvalidCatalog(
            try HikerDataset.validateCatalogSemantics(
                manifestData: manifestData(),
                catalogData: encoded(reorderedCatalog),
                legacyMetadataData: legacyMetadataData()
            )
        )
    }

    func testDuplicateLegacyAndCurrentMappingsFailSemanticValidation() throws {
        var duplicateLegacyMetadata = try object(from: legacyMetadataData())
        var duplicateLegacyEntries = try array(duplicateLegacyMetadata["entries"])
        var duplicateLegacyMapping = try dictionary(duplicateLegacyEntries[1])
        duplicateLegacyMapping["legacyID"] = try dictionary(duplicateLegacyEntries[0])["legacyID"]
        duplicateLegacyEntries[1] = duplicateLegacyMapping
        duplicateLegacyMetadata["entries"] = duplicateLegacyEntries

        assertInvalidLegacyMetadata(
            try HikerDataset.validateCatalogSemantics(
                manifestData: manifestData(),
                catalogData: officialCatalogData(),
                legacyMetadataData: encoded(duplicateLegacyMetadata)
            ),
            containing: "duplicate legacy ID"
        )

        var duplicateCurrentMetadata = try object(from: legacyMetadataData())
        var duplicateCurrentEntries = try array(duplicateCurrentMetadata["entries"])
        var duplicateCurrentMapping = try dictionary(duplicateCurrentEntries[1])
        duplicateCurrentMapping["currentID"] = try dictionary(duplicateCurrentEntries[0])["currentID"]
        duplicateCurrentEntries[1] = duplicateCurrentMapping
        duplicateCurrentMetadata["entries"] = duplicateCurrentEntries

        assertInvalidLegacyMetadata(
            try HikerDataset.validateCatalogSemantics(
                manifestData: manifestData(),
                catalogData: officialCatalogData(),
                legacyMetadataData: encoded(duplicateCurrentMetadata)
            ),
            containing: "duplicate current ID"
        )
    }

    func testUnknownStableIDFailsClosed() throws {
        let mountains = try HikerDataset.loadMountains()
        guard let stableID = mountains.first?.id else {
            return XCTFail("Expected a nonempty catalog")
        }
        let unknownID = try type(of: stableID).init(
            rawValue: "hkr_mtn_00000000000000000000000000000000"
        )

        XCTAssertThrowsError(try HikerDataset.resolveStableID(unknownID)) { error in
            guard case let .some(.unknownStableID(rawID)) = error as? HikerDataset.MountainDatasetError else {
                return XCTFail("Expected unknown stable-ID failure, got \(error)")
            }
            XCTAssertEqual(rawID, unknownID.rawValue)
        }
    }

    private func manifestData() throws -> Data {
        try HikerDataset.bundledResourceData(named: "dataset-manifest")
    }

    private func officialCatalogData() throws -> Data {
        try HikerDataset.bundledResourceData(named: "official-100-mountains-v1")
    }

    private func legacyMetadataData() throws -> Data {
        try HikerDataset.bundledResourceData(named: "legacy-mountain-metadata-v1")
    }

    private func assertChecksumMismatch(_ error: any Error, resource: String) {
        guard case let .some(
            .checksumMismatch(resource: actualResource, expected: _, actual: _)
        ) = error as? HikerDataset.MountainDatasetError else {
            return XCTFail("Expected checksum mismatch, got \(error)")
        }
        XCTAssertEqual(actualResource, resource)
    }

    private func assertInvalidCatalog<T>(_ expression: @autoclosure () throws -> T) {
        XCTAssertThrowsError(try expression()) { error in
            guard case .some(.invalidCatalog) = error as? HikerDataset.MountainDatasetError else {
                return XCTFail("Expected catalog validation failure, got \(error)")
            }
        }
    }

    private func assertInvalidLegacyMetadata<T>(
        _ expression: @autoclosure () throws -> T,
        containing expectedReason: String
    ) {
        XCTAssertThrowsError(try expression()) { error in
            guard case let .some(.invalidLegacyMetadata(reason)) = error as? HikerDataset.MountainDatasetError else {
                return XCTFail("Expected legacy metadata validation failure, got \(error)")
            }
            XCTAssertTrue(reason.contains(expectedReason))
        }
    }

    private func object(from data: Data) throws -> [String: Any] {
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw FixtureError.invalidJSON
        }
        return object
    }

    private func dictionary(_ value: Any?) throws -> [String: Any] {
        guard let dictionary = value as? [String: Any] else {
            throw FixtureError.invalidJSON
        }
        return dictionary
    }

    private func array(_ value: Any?) throws -> [Any] {
        guard let array = value as? [Any] else {
            throw FixtureError.invalidJSON
        }
        return array
    }

    private func encoded(_ object: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }

    private enum FixtureError: Error {
        case invalidJSON
    }
}
