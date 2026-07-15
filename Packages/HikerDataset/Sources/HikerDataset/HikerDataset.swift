import Foundation
import CryptoKit
import HikerDomain

public enum HikerDataset {
    private static let schemaVersion = "1.0.0"
    private static let datasetVersion = "1.0.0-rc.1"
    private static let officialStatus = "release_candidate_public_official_source"
    private static let legacyStatus = "release_candidate_legacy_mapping"
    private static let expectedEntryCount = 100
    private static let officialSourceURL = "https://map.forest.go.kr/forest/?systype=appdata"
    private static let officialServiceURL = "https://map.forest.go.kr/gis1/iserver/services/data-fdms/rest/data"
    private static let officialDataset = "FDMS_BASE:TB_FGDI_FS_F100"
    private static let officialSourceCRS = "EPSG:5179"
    private static let sourceSnapshotSHA256 = "c82eab718f45afc58bbe45d7f6a4904187fb7f0d0cd6aadd0a287ae78d13128d"
    private static let rawSnapshotResource = "Evidence/dataset/official-100-mountains-v1.raw.json"
    private static let normalizedSnapshotPath = "Evidence/dataset/official-100-mountains-v1.normalized.json"
    private static let catalogContentSHA256 = "1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae"
    private static let legacyMetadataSHA256 = "04028d8e4895eff00cdcd96267460eebb0ccaed3450c643ef06b30e1c87ffc73"

    public static func loadManifest() throws -> Manifest {
        try loadValidatedManifest()
    }

    public static func loadLegacyMountainMetadata() throws -> LegacyMountainMetadata {
        try loadValidatedCatalog().legacyMetadata
    }

    public static func loadMountains() throws -> [Mountain] {
        try loadValidatedCatalog().mountains
    }

    public static func resolveStableID(_ stableID: MountainID) throws -> MountainID {
        let catalog = try loadValidatedCatalog()
        return try catalog.resolve(stableID)
    }

    public static func mountain(for stableID: MountainID) throws -> Mountain {
        let catalog = try loadValidatedCatalog()
        let resolvedID = try catalog.resolve(stableID)

        guard let mountain = catalog.mountainsByID[resolvedID] else {
            throw MountainDatasetError.unknownStableID(stableID.rawValue)
        }

        return mountain
    }

    public struct Manifest: Decodable, Equatable, Sendable {
        public let schemaVersion: String
        public let datasetVersion: String
        public let status: String
        public let source: SourceProvenance
        public let content: ContentProvenance
        public let legacy: LegacyProvenance
        public let review: ReviewProvenance
        public let entryCount: Int
    }

    public struct SourceProvenance: Decodable, Equatable, Sendable {
        public let status: String
        public let url: String
        public let service: String
        public let dataset: String
        public let crs: String
        public let retrievedAt: String
        public let sha256: String
        public let rawResource: String
        public let normalizedSnapshotPath: String
    }

    public struct ContentProvenance: Decodable, Equatable, Sendable {
        public let status: String
        public let resource: String
        public let coordinateReferenceSystem: String
        public let sha256: String
    }
    public struct LegacyProvenance: Decodable, Equatable, Sendable {
        public let status: String
        public let resource: String
        public let sha256: String
    }


    public struct ReviewProvenance: Decodable, Equatable, Sendable {
        public let status: String
        public let reviewers: [String]
        public let reviewedAt: String?
    }

    public struct LegacyMountainMetadata: Decodable, Equatable, Sendable {
        public let schemaVersion: String
        public let datasetVersion: String
        public let status: String
        public let entries: [LegacyMountainMapping]

        public var entryCount: Int {
            entries.count
        }
    }

    public struct LegacyMountainMapping: Decodable, Equatable, Sendable {
        public let legacyID: String
        public let currentID: String
    }

    public enum ResourceError: Error, Equatable, LocalizedError, Sendable {
        case missing(String)
        case unreadable(String, String)
        case invalid(String, String)

        public var errorDescription: String? {
            switch self {
            case let .missing(name):
                return "The HikerDataset resource '\(name).json' is missing from the package bundle."
            case let .unreadable(name, description):
                return "The HikerDataset resource '\(name).json' could not be read: \(description)"
            case let .invalid(name, description):
                return "The HikerDataset resource '\(name).json' is invalid: \(description)"
            }
        }
    }

    public enum MountainDatasetError: Error, Equatable, LocalizedError, Sendable {
        case invalidManifest(String)
        case checksumMismatch(resource: String, expected: String, actual: String)
        case invalidCatalog(String)
        case invalidLegacyMetadata(String)
        case duplicateStableID(String)
        case invalidStableID(String)
        case emptyName(String)
        case invalidAdministrativeCode(String)
        case unsupportedAdministrativeRegion(String)
        case invalidCoordinate(String)
        case unknownStableID(String)

        public var errorDescription: String? {
            switch self {
            case let .invalidManifest(reason):
                return "The mountain dataset manifest is invalid: \(reason)"
            case let .checksumMismatch(resource, expected, actual):
                return "The SHA-256 checksum for '\(resource)' does not match (expected \(expected), got \(actual))."
            case let .invalidCatalog(reason):
                return "The official mountain catalog is invalid: \(reason)"
            case let .invalidLegacyMetadata(reason):
                return "The legacy mountain metadata is invalid: \(reason)"
            case let .duplicateStableID(id):
                return "The official mountain catalog contains duplicate stable ID '\(id)'."
            case let .invalidStableID(id):
                return "The official mountain catalog contains invalid stable ID '\(id)'."
            case let .emptyName(id):
                return "The official mountain catalog has an empty name for stable ID '\(id)'."
            case let .invalidAdministrativeCode(code):
                return "The official mountain catalog contains invalid administrative code '\(code)'."
            case let .unsupportedAdministrativeRegion(code):
                return "The official mountain catalog contains unsupported administrative code '\(code)'."
            case let .invalidCoordinate(id):
                return "The official mountain catalog contains an invalid WGS84 coordinate for stable ID '\(id)'."
            case let .unknownStableID(id):
                return "The stable mountain ID '\(id)' is not present in the official catalog or legacy metadata."
            }
        }
    }

    static func bundledResourceData(named name: String) throws -> Data {
        guard let url = Bundle.module.url(forResource: name, withExtension: "json") else {
            throw ResourceError.missing(name)
        }

        do {
            return try Data(contentsOf: url)
        } catch {
            throw ResourceError.unreadable(name, error.localizedDescription)
        }
    }

    static func validateCatalog(
        manifestData: Data,
        catalogData: Data,
        legacyMetadataData: Data
    ) throws -> [Mountain] {
        let manifest = try loadValidatedManifest(from: manifestData)
        return try validateTrustedCatalogResources(
            manifest: manifest,
            catalogData: catalogData,
            legacyMetadataData: legacyMetadataData
        ).mountains
    }

    static func validateCatalogSemantics(
        manifestData: Data,
        catalogData: Data,
        legacyMetadataData: Data
    ) throws -> [Mountain] {
        let manifest = try loadValidatedManifest(from: manifestData)
        let catalog = try decode(
            OfficialMountainCatalog.self,
            from: catalogData,
            resource: manifest.content.resource
        )
        let legacyMetadata = try decode(
            LegacyMountainMetadata.self,
            from: legacyMetadataData,
            resource: manifest.legacy.resource
        )
        return try validateCatalogSemantics(
            manifest: manifest,
            catalog: catalog,
            legacyMetadata: legacyMetadata
        ).mountains
    }

    static func checksum(for data: Data) -> String {
        SHA256.hexDigest(of: data)
    }

    private static func loadValidatedCatalog() throws -> ValidatedCatalog {
        let manifest = try loadValidatedManifest()
        let catalogData = try bundledResourceData(named: manifest.content.resource)
        let legacyMetadataData = try bundledResourceData(named: manifest.legacy.resource)

        return try validateTrustedCatalogResources(
            manifest: manifest,
            catalogData: catalogData,
            legacyMetadataData: legacyMetadataData
        )
    }

    private static func loadValidatedManifest() throws -> Manifest {
        try loadValidatedManifest(from: bundledResourceData(named: "dataset-manifest"))
    }

    private static func loadValidatedManifest(from data: Data) throws -> Manifest {
        let manifest = try decode(Manifest.self, from: data, resource: "dataset-manifest")
        try validate(manifest: manifest)
        return manifest
    }

    private static func validateTrustedCatalogResources(
        manifest: Manifest,
        catalogData: Data,
        legacyMetadataData: Data
    ) throws -> ValidatedCatalog {
        try validateChecksum(
            for: catalogData,
            resource: manifest.content.resource,
            expected: manifest.content.sha256
        )
        try validateChecksum(
            for: legacyMetadataData,
            resource: manifest.legacy.resource,
            expected: manifest.legacy.sha256
        )

        let catalog = try decode(
            OfficialMountainCatalog.self,
            from: catalogData,
            resource: manifest.content.resource
        )
        let legacyMetadata = try decode(
            LegacyMountainMetadata.self,
            from: legacyMetadataData,
            resource: manifest.legacy.resource
        )
        return try validateCatalogSemantics(
            manifest: manifest,
            catalog: catalog,
            legacyMetadata: legacyMetadata
        )
    }

    private static func validateChecksum(
        for data: Data,
        resource: String,
        expected: String
    ) throws {
        let actual = checksum(for: data)
        guard actual == expected else {
            throw MountainDatasetError.checksumMismatch(
                resource: resource,
                expected: expected,
                actual: actual
            )
        }
    }

    private static func validateCatalogSemantics(
        manifest: Manifest,
        catalog: OfficialMountainCatalog,
        legacyMetadata: LegacyMountainMetadata
    ) throws -> ValidatedCatalog {
        try validate(catalog: catalog)

        var mountains = [Mountain]()
        mountains.reserveCapacity(catalog.entries.count)
        var mountainsByID = [MountainID: Mountain]()
        mountainsByID.reserveCapacity(catalog.entries.count)
        var stableIDs = Set<MountainID>()
        stableIDs.reserveCapacity(catalog.entries.count)

        for (offset, entry) in catalog.entries.enumerated() {
            let stableID = try validatedCurrentStableID(entry.id)
            guard stableIDs.insert(stableID).inserted else {
                throw MountainDatasetError.duplicateStableID(stableID.rawValue)
            }

            let sourceReference = try validatedLegacyStableID(entry.sourceReference)
            let expectedSourceReference = String(offset + 1)
            guard sourceReference.rawValue == expectedSourceReference,
                  stableID.rawValue == opaqueStableID(for: expectedSourceReference) else {
                throw MountainDatasetError.invalidCatalog(
                    "entries must be in ascending official MNTN_ID order with derived opaque IDs"
                )
            }

            guard !entry.name.isEmpty else {
                throw MountainDatasetError.emptyName(stableID.rawValue)
            }
            guard entry.name == entry.name.trimmingCharacters(in: .whitespacesAndNewlines) else {
                throw MountainDatasetError.invalidCatalog(
                    "name for stable ID '\(stableID.rawValue)' contains noncanonical whitespace"
                )
            }
            let name = entry.name

            let region = try regionName(for: entry.administrativeCode)
            guard entry.latitude.isFinite,
                  entry.longitude.isFinite,
                  (-90...90).contains(entry.latitude),
                  (-180...180).contains(entry.longitude) else {
                throw MountainDatasetError.invalidCoordinate(stableID.rawValue)
            }

            let coordinate = try SummitCoordinate(latitude: entry.latitude, longitude: entry.longitude)
            let mountain = try Mountain(
                id: stableID,
                koreanName: name,
                region: region,
                summitCoordinate: coordinate
            )
            mountains.append(mountain)
            mountainsByID[stableID] = mountain
        }

        guard mountains.count == expectedEntryCount,
              stableIDs.count == expectedEntryCount else {
            throw MountainDatasetError.invalidCatalog("expected exactly \(expectedEntryCount) unique stable summit records")
        }

        let legacyIDs = try validate(legacyMetadata: legacyMetadata, catalog: catalog)

        return ValidatedCatalog(
            legacyMetadata: legacyMetadata,
            mountains: mountains,
            mountainsByID: mountainsByID,
            legacyIDs: legacyIDs
        )
    }

    private static func decode<Value: Decodable>(
        _ type: Value.Type,
        from data: Data,
        resource: String
    ) throws -> Value {
        do {
            return try JSONDecoder().decode(type, from: data)
        } catch {
            throw ResourceError.invalid(resource, error.localizedDescription)
        }
    }

    private static func validate(manifest: Manifest) throws {
        guard manifest.schemaVersion == schemaVersion else {
            throw MountainDatasetError.invalidManifest("unsupported schema version '\(manifest.schemaVersion)'")
        }
        guard manifest.datasetVersion == datasetVersion else {
            throw MountainDatasetError.invalidManifest("unsupported dataset version '\(manifest.datasetVersion)'")
        }
        guard manifest.status == officialStatus else {
            throw MountainDatasetError.invalidManifest("unapproved dataset status '\(manifest.status)'")
        }
        guard manifest.entryCount == expectedEntryCount else {
            throw MountainDatasetError.invalidManifest("entryCount must be \(expectedEntryCount)")
        }

        let source = manifest.source
        guard source.status == officialStatus,
              source.url == officialSourceURL,
              source.service == officialServiceURL,
              source.dataset == officialDataset,
              source.crs == officialSourceCRS,
              source.retrievedAt == "2026-07-14T00:03:32.659Z",
              source.sha256 == sourceSnapshotSHA256,
              source.rawResource == rawSnapshotResource,
              source.normalizedSnapshotPath == normalizedSnapshotPath else {
            throw MountainDatasetError.invalidManifest("official source provenance does not match the release snapshot")
        }

        let content = manifest.content
        guard content.status == officialStatus,
              content.resource == "official-100-mountains-v1",
              content.coordinateReferenceSystem == "WGS84",
              content.sha256 == catalogContentSHA256 else {
            throw MountainDatasetError.invalidManifest("content provenance is incomplete or malformed")
        }
        let legacy = manifest.legacy
        guard legacy.status == legacyStatus,
              legacy.resource == "legacy-mountain-metadata-v1",
              legacy.sha256 == legacyMetadataSHA256 else {
            throw MountainDatasetError.invalidManifest("legacy metadata provenance is incomplete or malformed")
        }

        let review = manifest.review
        guard review.status == "not_human_reviewed",
              review.reviewers.isEmpty,
              review.reviewedAt == nil else {
            throw MountainDatasetError.invalidManifest("review provenance must not claim approval")
        }
    }

    private static func validate(catalog: OfficialMountainCatalog) throws {
        guard catalog.schemaVersion == schemaVersion else {
            throw MountainDatasetError.invalidCatalog("unsupported schema version '\(catalog.schemaVersion)'")
        }
        guard catalog.datasetVersion == datasetVersion else {
            throw MountainDatasetError.invalidCatalog("unsupported dataset version '\(catalog.datasetVersion)'")
        }
        guard catalog.status == officialStatus else {
            throw MountainDatasetError.invalidCatalog("unapproved catalog status '\(catalog.status)'")
        }
        guard catalog.coordinateReferenceSystem == "WGS84" else {
            throw MountainDatasetError.invalidCatalog("representative coordinates must use WGS84")
        }
        guard catalog.entries.count == expectedEntryCount else {
            throw MountainDatasetError.invalidCatalog("expected \(expectedEntryCount) entries, got \(catalog.entries.count)")
        }
    }

    private static func validate(
        legacyMetadata: LegacyMountainMetadata,
        catalog: OfficialMountainCatalog
    ) throws -> [MountainID: MountainID] {
        guard legacyMetadata.schemaVersion == schemaVersion else {
            throw MountainDatasetError.invalidLegacyMetadata(
                "unsupported schema version '\(legacyMetadata.schemaVersion)'"
            )
        }
        guard legacyMetadata.datasetVersion == datasetVersion else {
            throw MountainDatasetError.invalidLegacyMetadata(
                "unsupported dataset version '\(legacyMetadata.datasetVersion)'"
            )
        }
        guard legacyMetadata.status == legacyStatus else {
            throw MountainDatasetError.invalidLegacyMetadata(
                "unapproved legacy metadata status '\(legacyMetadata.status)'"
            )
        }
        guard legacyMetadata.entries.count == expectedEntryCount else {
            throw MountainDatasetError.invalidLegacyMetadata(
                "expected \(expectedEntryCount) legacy mappings, got \(legacyMetadata.entries.count)"
            )
        }

        let catalogIDs = Set(catalog.entries.map(\.id))
        var legacyIDs = [MountainID: MountainID]()
        legacyIDs.reserveCapacity(legacyMetadata.entries.count)
        var currentIDs = Set<MountainID>()
        currentIDs.reserveCapacity(legacyMetadata.entries.count)

        for (offset, mapping) in legacyMetadata.entries.enumerated() {
            let legacyID: MountainID
            let currentID: MountainID
            do {
                legacyID = try validatedLegacyStableID(mapping.legacyID)
                currentID = try validatedCurrentStableID(mapping.currentID)
            } catch {
                throw MountainDatasetError.invalidLegacyMetadata(
                    "mapping contains a noncanonical stable ID"
                )
            }
            guard legacyIDs[legacyID] == nil else {
                throw MountainDatasetError.invalidLegacyMetadata(
                    "duplicate legacy ID '\(legacyID.rawValue)'"
                )
            }
            guard currentIDs.insert(currentID).inserted else {
                throw MountainDatasetError.invalidLegacyMetadata(
                    "duplicate current ID '\(currentID.rawValue)'"
                )
            }
            let expectedLegacyID = String(offset + 1)
            guard legacyID.rawValue == expectedLegacyID,
                  currentID.rawValue == opaqueStableID(for: expectedLegacyID) else {
                throw MountainDatasetError.invalidLegacyMetadata(
                    "legacy mappings must be in ascending official MNTN_ID order"
                )
            }
            guard catalogIDs.contains(currentID.rawValue) else {
                throw MountainDatasetError.invalidLegacyMetadata(
                    "legacy ID '\(legacyID.rawValue)' resolves to absent current ID '\(currentID.rawValue)'"
                )
            }
            legacyIDs[legacyID] = currentID
        }

        guard legacyIDs.count == expectedEntryCount,
              currentIDs.count == expectedEntryCount else {
            throw MountainDatasetError.invalidLegacyMetadata("legacy mappings are incomplete")
        }

        return legacyIDs
    }

    private static func validatedLegacyStableID(_ rawID: String) throws -> MountainID {
        let bytes = Array(rawID.utf8)
        guard !bytes.isEmpty,
              bytes.allSatisfy({ (48...57).contains($0) }),
              let value = Int(rawID),
              (1...expectedEntryCount).contains(value),
              rawID == String(value) else {
            throw MountainDatasetError.invalidStableID(rawID)
        }

        return try MountainID(rawValue: rawID)
    }

    private static func validatedCurrentStableID(_ rawID: String) throws -> MountainID {
        let prefix = "hkr_mtn_"
        let suffix = rawID.dropFirst(prefix.count)
        guard rawID.hasPrefix(prefix),
              suffix.count == 32,
              suffix.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
            throw MountainDatasetError.invalidStableID(rawID)
        }

        return try MountainID(rawValue: rawID)
    }

    private static func opaqueStableID(for sourceReference: String) -> String {
        let seed = "kfs:\(officialDataset):\(sourceReference)"
        return "hkr_mtn_\(checksum(for: Data(seed.utf8)).prefix(32))"
    }

    private static func regionName(for administrativeCode: String) throws -> String {
        let bytes = Array(administrativeCode.utf8)
        guard bytes.count == 8,
              bytes.allSatisfy({ (48...57).contains($0) }) else {
            throw MountainDatasetError.invalidAdministrativeCode(administrativeCode)
        }

        switch String(administrativeCode.prefix(2)) {
        case "11": return "Seoul"
        case "26": return "Busan"
        case "27": return "Daegu"
        case "28": return "Incheon"
        case "29": return "Gwangju"
        case "30": return "Daejeon"
        case "31": return "Ulsan"
        case "36": return "Sejong"
        case "41": return "Gyeonggi"
        case "43": return "Chungcheongbuk-do"
        case "44": return "Chungcheongnam-do"
        case "46": return "Jeollanam-do"
        case "47": return "Gyeongsangbuk-do"
        case "48": return "Gyeongsangnam-do"
        case "50": return "Jeju"
        case "51": return "Gangwon"
        case "52": return "Jeonbuk"
        default:
            throw MountainDatasetError.unsupportedAdministrativeRegion(administrativeCode)
        }
    }

    private struct ValidatedCatalog {
        let legacyMetadata: LegacyMountainMetadata
        let mountains: [Mountain]
        let mountainsByID: [MountainID: Mountain]
        let legacyIDs: [MountainID: MountainID]

        func resolve(_ stableID: MountainID) throws -> MountainID {
            if mountainsByID[stableID] != nil {
                return stableID
            }
            if let resolvedID = legacyIDs[stableID] {
                return resolvedID
            }
            throw MountainDatasetError.unknownStableID(stableID.rawValue)
        }
    }

    private struct OfficialMountainCatalog: Decodable {
        let schemaVersion: String
        let datasetVersion: String
        let status: String
        let coordinateReferenceSystem: String
        let entries: [OfficialMountainEntry]
    }

    private struct OfficialMountainEntry: Decodable {
        let id: String
        let sourceReference: String
        let name: String
        let administrativeCode: String
        let longitude: Double
        let latitude: Double
    }
}

private enum SHA256 {
    static func hexDigest(of data: Data) -> String {
        CryptoKit.SHA256.hash(data: data)
            .map { String(format: "%02x", $0) }
            .joined()
    }
}
