// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "HikerObservability",
    platforms: [
        .iOS(.v17),
        .macOS(.v14)
    ],
    products: [
        .library(name: "HikerObservability", targets: ["HikerObservability"])
    ],
    dependencies: [
        .package(path: "../HikerDomain")
    ],
    targets: [
        .target(
            name: "HikerObservability",
            dependencies: [
                .product(name: "HikerDomain", package: "HikerDomain")
            ]
        ),
        .testTarget(
            name: "HikerObservabilityTests",
            dependencies: ["HikerObservability"]
        )
    ],
    swiftLanguageModes: [.v6]
)
