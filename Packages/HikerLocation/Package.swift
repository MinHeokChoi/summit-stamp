// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "HikerLocation",
    platforms: [
        .iOS(.v17),
        .macOS(.v14)
    ],
    products: [
        .library(name: "HikerLocation", targets: ["HikerLocation"])
    ],
    dependencies: [
        .package(path: "../HikerDomain")
    ],
    targets: [
        .target(
            name: "HikerLocation",
            dependencies: [
                .product(name: "HikerDomain", package: "HikerDomain")
            ]
        ),
        .testTarget(
            name: "HikerLocationTests",
            dependencies: ["HikerLocation"]
        )
    ],
    swiftLanguageModes: [.v6]
)
