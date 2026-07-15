import Foundation
import XCTest
import HikerDomain
import HikerDataset

final class M3DatasetIdentityTests: XCTestCase {
    func testProductionDatasetSatisfiesM3BootstrapIdentityContract() throws {
        let mountains = try HikerDataset.loadMountains()
        let manifest = try HikerDataset.loadManifest()
        let opaqueID = try NSRegularExpression(
            pattern: "^hkr_mtn_[0-9a-f]{32}$"
        )

        XCTAssertEqual(mountains.count, 100)
        XCTAssertEqual(Set(mountains.map(\.id)).count, 100)
        XCTAssertTrue(mountains.allSatisfy { mountain in
            let rawValue = mountain.id.rawValue
            return opaqueID.firstMatch(
                in: rawValue,
                range: NSRange(rawValue.startIndex..., in: rawValue)
            ) != nil
        })
        XCTAssertEqual(
            manifest.content.sha256,
            "1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae"
        )
    }
}
