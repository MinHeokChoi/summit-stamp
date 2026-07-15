// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "HikerDomain",
    platforms: [
        .iOS(.v17)
    ],
    products: [
        .library(name: "HikerDomain", targets: ["HikerDomain"])
    ],
    targets: [
        .target(
            name: "HikerDomain"
        ),
        .testTarget(
            name: "HikerDomainTests",
            dependencies: ["HikerDomain"]
        )
    ],
    swiftLanguageModes: [.v6]
)
