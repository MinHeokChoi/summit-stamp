// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "HikerDataset",
    platforms: [
        .iOS(.v17),
        .macOS(.v14)
    ],
    products: [
        .library(name: "HikerDataset", targets: ["HikerDataset"])
    ],
    dependencies: [
        .package(path: "../HikerDomain")
    ],
    targets: [
        .target(
            name: "HikerDataset",
            dependencies: [
                .product(name: "HikerDomain", package: "HikerDomain")
            ],
            resources: [.process("Resources")]
        ),
        .testTarget(
            name: "HikerDatasetTests",
            dependencies: ["HikerDataset"]
        )
    ],
    swiftLanguageModes: [.v6]
)
