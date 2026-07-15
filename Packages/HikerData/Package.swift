// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "HikerData",
    platforms: [
        .iOS(.v17),
        .macOS(.v14)
    ],
    products: [
        .library(name: "HikerData", targets: ["HikerData"])
    ],
    dependencies: [
        .package(path: "../HikerDomain")
    ],
    targets: [
        .target(
            name: "HikerData",
            dependencies: [
                .product(name: "HikerDomain", package: "HikerDomain")
            ]
        ),
        .testTarget(
            name: "HikerDataTests",
            dependencies: [
                "HikerData",
                .product(name: "HikerDomain", package: "HikerDomain")
            ]
        )
    ],
    swiftLanguageModes: [.v6]
)
