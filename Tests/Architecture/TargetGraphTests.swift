import Foundation
import XCTest

final class TargetGraphTests: XCTestCase {
    private let featureModules: Set<String> = [
        "HikerMapFeature",
        "HikerPassportFeature",
        "HikerSocialFeature",
    ]

    private let adapterModules: Set<String> = [
        "HikerData",
        "HikerDataset",
        "HikerLocation",
        "HikerObservability",
    ]

    func testOnlyAppComposesConcreteAdapters() throws {
        let root = try repositoryRoot()
        let project = try contents(of: root.appendingPathComponent("project.yml"))
        let appDependencies = try dependencyNames(
            in: targetSection(named: "HikerApp", in: project)
        )
        let requiredAppDependencies = featureModules.union(adapterModules)
        let missingAppDependencies = requiredAppDependencies.subtracting(appDependencies)

        XCTAssertTrue(
            missingAppDependencies.isEmpty,
            "HikerApp must reference every feature and adapter: \(missingAppDependencies.sorted())"
        )

        let compositionRoot = root.appendingPathComponent("App/AppContainer.swift")
        let compositionImports = try importedModules(in: compositionRoot)
        let composedAdapters: Set<String> = [
            "HikerData",
            "HikerDataset",
            "HikerObservability",
        ]
        XCTAssertTrue(
            composedAdapters.isSubset(of: compositionImports),
            "AppContainer must import each adapter used by the active local milestone"
        )

        let compositionSource = try contents(of: compositionRoot)
        for concreteType in [
            "EncryptedLocalPassportStore",
            "HikerDataset.self",
            "OSLogEventSink",
        ] {
            XCTAssertTrue(
                compositionSource.contains(concreteType),
                "AppContainer must construct or retain \(concreteType)"
            )
        }

        for feature in featureModules.sorted() {
            let dependencies = try dependencyNames(
                in: targetSection(named: feature, in: project)
            )
            let adapterDependencies = dependencies.intersection(adapterModules)

            XCTAssertTrue(
                adapterDependencies.isEmpty,
                "\(feature) must not reference adapters: \(adapterDependencies.sorted())"
            )
            XCTAssertEqual(
                dependencies,
                ["HikerDomain"],
                "\(feature) must reference only HikerDomain"
            )
        }
    }
    func testAuthenticationCompositionAndConfigurationStayInApp() throws {
        let root = try repositoryRoot()
        let appDirectory = root.appendingPathComponent("App")
        let authenticationCoordinator = appDirectory
            .appendingPathComponent("AuthenticationCoordinator.swift")
        let selfPassportTransport = root.appendingPathComponent(
            "Packages/HikerData/Sources/HikerData/SupabaseSelfPassportSyncTransport.swift"
        )
        let appFiles = try swiftFiles(in: appDirectory)
        let featureFiles = try swiftFiles(in: root.appendingPathComponent("Features"))
        let packageFiles = try swiftFiles(in: root.appendingPathComponent("Packages"))
        let nonAppFiles = featureFiles + packageFiles
        let allSourceFiles = appFiles + nonAppFiles
        let project = try contents(of: root.appendingPathComponent("project.yml"))
        let appTarget = try targetSection(named: "HikerApp", in: project)
        XCTAssertTrue(
            appTarget.contains("Config/HikerApp.entitlements"),
            "HikerApp must apply the Sign in with Apple entitlement configuration."
        )

        let authenticationServicesFiles = try allSourceFiles.filter {
            try importedModules(in: $0).contains("AuthenticationServices")
        }
        XCTAssertEqual(
            Set(authenticationServicesFiles),
            Set([authenticationCoordinator]),
            "AuthenticationServices must be imported only by AuthenticationCoordinator in App."
        )

        let transportSymbols = ["URLSession", "NWConnection", "NWPathMonitor"]
        let transportFiles = try allSourceFiles.filter { file in
            guard !file.path.contains("/Tests/") else {
                return false
            }
            let source = try contents(of: file)
            return transportSymbols.contains { source.contains($0) }
        }
        XCTAssertEqual(
            Set(transportFiles),
            Set([authenticationCoordinator, selfPassportTransport]),
            "Concrete network transport must stay in App authentication or the HikerData sync adapter."
        )

        let authenticationSource = try contents(of: authenticationCoordinator)
        XCTAssertTrue(
            authenticationSource.contains("static func production"),
            "AuthenticationCoordinator must own production authentication composition."
        )
        XCTAssertTrue(
            authenticationSource.contains("URLSession"),
            "AuthenticationCoordinator must own the concrete exchange transport."
        )

        let appContainer = try contents(of: appDirectory.appendingPathComponent("AppContainer.swift"))
        XCTAssertTrue(
            appContainer.contains("AuthenticationCoordinator.production()"),
            "AppContainer must retain the coordinator rather than compose auth dependencies."
        )

        let concreteAuthSymbols = [
            "ASWebAuthenticationSession",
            "URLSessionAppleSupabaseCodeExchanger",
            "KeychainAuthenticationSessionStore",
            "SystemOAuthWebAuthenticationSessionFactory",
        ]
        var compositionViolations: [String] = []
        for file in appFiles where file != authenticationCoordinator {
            let source = try contents(of: file)
            let symbols = concreteAuthSymbols.filter { source.contains($0) }
            guard !symbols.isEmpty else { continue }
            compositionViolations.append(
                "\(file.lastPathComponent): \(symbols.sorted().joined(separator: ", "))"
            )
        }
        XCTAssertTrue(
            compositionViolations.isEmpty,
            "AuthenticationCoordinator must be the sole concrete auth composition:\n"
                + compositionViolations.joined(separator: "\n")
        )

        let entitlementData = try Data(
            contentsOf: root.appendingPathComponent("Config/HikerApp.entitlements")
        )
        let entitlements = try XCTUnwrap(
            try PropertyListSerialization.propertyList(from: entitlementData, format: nil)
                as? [String: Any]
        )
        XCTAssertTrue(
            (entitlements["com.apple.developer.applesignin"] as? [String])?.contains("Default") == true,
            "The app must retain the Sign in with Apple entitlement."
        )

        let infoData = try Data(contentsOf: root.appendingPathComponent("Config/Info.plist"))
        let info = try XCTUnwrap(
            try PropertyListSerialization.propertyList(from: infoData, format: nil)
                as? [String: Any]
        )
        let callbackKeys = [
            "HikerAppleSupabaseAuthorizationURL",
            "HikerAppleSupabaseSessionExchangeURL",
            "HikerAppleSupabasePublishableKey",
            "HikerAppleSupabaseCallbackScheme",
            "HikerAppleSupabaseCallbackHost",
            "HikerAppleSupabaseCallbackPath",
        ]
        for key in callbackKeys {
            XCTAssertFalse(
                (info[key] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ?? true,
                "Info.plist must declare \(key)."
            )
        }

        let callbackSchemes = (info["CFBundleURLTypes"] as? [[String: Any]] ?? [])
            .flatMap { $0["CFBundleURLSchemes"] as? [String] ?? [] }
        XCTAssertTrue(
            callbackSchemes.contains("$(HIKER_APPLE_SUPABASE_CALLBACK_SCHEME)"),
            "Info.plist must register the configured OAuth callback scheme."
        )

        let prohibitedProductionSymbols = [
            "test-login",
            "test identity",
            "testidentity",
            "bypass",
            "service-role",
            "service_role",
            "servicerole",
            "private-key",
            "private_key",
            "privatekey",
        ]
        var prohibitedSymbolViolations: [String] = []
        for file in appFiles {
            let source = try contents(of: file).lowercased()
            let symbols = prohibitedProductionSymbols.filter { source.contains($0) }
            guard !symbols.isEmpty else { continue }
            prohibitedSymbolViolations.append(
                "\(file.lastPathComponent): \(symbols.sorted().joined(separator: ", "))"
            )
        }
        XCTAssertTrue(
            prohibitedSymbolViolations.isEmpty,
            "Production App sources must not include bypass, test identity, or privileged-key paths:\n"
                + prohibitedSymbolViolations.joined(separator: "\n")
        )
    }

    func testIndependentPackageDependenciesRespectLayers() throws {
        let root = try repositoryRoot()
        let domainManifest = try contents(
            of: root.appendingPathComponent("Packages/HikerDomain/Package.swift")
        )

        XCTAssertEqual(
            try packageDependencies(for: "HikerDomain", in: domainManifest),
            [],
            "HikerDomain must not have dependencies"
        )

        for adapter in adapterModules.sorted() {
            let manifest = try contents(
                of: root.appendingPathComponent("Packages/\(adapter)/Package.swift")
            )
            XCTAssertEqual(
                try packageDependencies(for: adapter, in: manifest),
                ["HikerDomain"],
                "\(adapter) must depend only on HikerDomain"
            )
        }
    }

    func testFeatureSourcesDoNotImportAdapters() throws {
        let root = try repositoryRoot()
        let files = try swiftFiles(in: root.appendingPathComponent("Features"))
        let violations = try importViolations(
            in: files,
            forbiddenModules: adapterModules,
            root: root
        )

        XCTAssertTrue(
            violations.isEmpty,
            "Feature sources must not import adapters:\n\(violations.joined(separator: "\n"))"
        )
    }

    func testAdapterSourcesDoNotImportFeatures() throws {
        let root = try repositoryRoot()
        var files: [URL] = []
        for adapter in adapterModules {
            files += try swiftFiles(
                in: root.appendingPathComponent("Packages/\(adapter)/Sources/\(adapter)")
            )
        }
        let violations = try importViolations(
            in: files,
            forbiddenModules: featureModules,
            root: root
        )

        XCTAssertTrue(
            violations.isEmpty,
            "Adapter sources must not import features:\n\(violations.joined(separator: "\n"))"
        )
    }

    func testOnlyAppSourcesImportFeatures() throws {
        let root = try repositoryRoot()
        let appDirectory = root.appendingPathComponent("App")
        var files = try swiftFiles(in: appDirectory)
        files += try swiftFiles(in: root.appendingPathComponent("Features"))
        files += try swiftFiles(in: root.appendingPathComponent("Packages"))
        let violations = try importViolations(
            in: files,
            forbiddenModules: featureModules,
            root: root,
            allowedDirectory: appDirectory
        )

        XCTAssertTrue(
            violations.isEmpty,
            "Only App sources may import features:\n\(violations.joined(separator: "\n"))"
        )
    }

    func testAppUsesBundledMountainCatalogCompositionPath() throws {
        let root = try repositoryRoot()
        let appContainer = try contents(
            of: root.appendingPathComponent("App/AppContainer.swift")
        )
        let rootView = try contents(
            of: root.appendingPathComponent("App/RootView.swift")
        )
        let dataset = try contents(
            of: root.appendingPathComponent(
                "Packages/HikerDataset/Sources/HikerDataset/HikerDataset.swift"
            )
        )

        for requiredComposition in [
            "let dataset: HikerDataset.Type",
            "dataset = HikerDataset.self",
            "let mountains = try dataset.loadMountains()",
            "let mapViewModel = MapViewModel(",
            "mountains: officialMountains",
            ".invalidCatalog(message:",
            "The bundled mountain catalog failed integrity validation.",
        ] {
            XCTAssertTrue(
                appContainer.contains(requiredComposition),
                "AppContainer must compose the fixed HikerDataset path: \(requiredComposition)"
            )
        }

        XCTAssertTrue(
            rootView.contains("container.makeMapFeatureView()"),
            "RootView must render the bundled-catalog map composition."
        )

        for requiredBundleLoad in [
            "Bundle.module.url(forResource: name, withExtension: \"json\")",
            "return try Data(contentsOf: url)",
        ] {
            XCTAssertTrue(
                dataset.contains(requiredBundleLoad),
                "HikerDataset must load its catalog from Bundle.module: \(requiredBundleLoad)"
            )
        }

        for forbiddenTransport in ["URLSession", "NWConnection", "NWPathMonitor"] {
            XCTAssertFalse(
                dataset.contains(forbiddenTransport),
                "HikerDataset must not add runtime transport: \(forbiddenTransport)"
            )
        }
    }

    private func repositoryRoot() throws -> URL {
        let fileManager = FileManager.default
        var directory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()

        while true {
            let project = directory.appendingPathComponent("project.yml")
            let manifest = directory.appendingPathComponent("Packages/HikerDomain/Package.swift")
            if fileManager.fileExists(atPath: project.path),
               fileManager.fileExists(atPath: manifest.path) {
                return directory
            }

            let parent = directory.deletingLastPathComponent()
            guard parent.path != directory.path else {
                throw ArchitectureError.repositoryRootNotFound
            }
            directory = parent
        }
    }

    private func contents(of file: URL) throws -> String {
        try String(contentsOf: file, encoding: .utf8)
    }

    private func targetSection(named name: String, in project: String) throws -> String {
        let lines = project.components(separatedBy: .newlines)
        guard let start = lines.firstIndex(where: {
            indentation(of: $0) == 2
                && $0.trimmingCharacters(in: .whitespaces) == "\(name):"
        }) else {
            throw ArchitectureError.targetNotFound(name)
        }

        let end = lines[(start + 1)...].firstIndex(where: {
            indentation(of: $0) == 2 && $0.trimmingCharacters(in: .whitespaces).hasSuffix(":")
        }) ?? lines.endIndex
        return lines[start..<end].joined(separator: "\n")
    }

    private func dependencyNames(in section: String) throws -> Set<String> {
        let lines = section.components(separatedBy: .newlines)
        guard let dependenciesIndex = lines.firstIndex(where: {
            $0.trimmingCharacters(in: .whitespaces) == "dependencies:"
        }) else {
            return []
        }

        let dependenciesIndentation = indentation(of: lines[dependenciesIndex])
        var names: Set<String> = []
        for line in lines.dropFirst(dependenciesIndex + 1) {
            guard line.trimmingCharacters(in: .whitespaces).isEmpty
                || indentation(of: line) > dependenciesIndentation else {
                break
            }
            if let name = dependencyName(in: line) {
                names.insert(name)
            }
        }
        return names
    }

    private func dependencyName(in line: String) -> String? {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        let value = trimmed.hasPrefix("- ") ? String(trimmed.dropFirst(2)) : trimmed

        for key in ["target", "product"] {
            let prefix = "\(key):"
            guard value.hasPrefix(prefix) else { continue }
            return value
                .dropFirst(prefix.count)
                .trimmingCharacters(in: .whitespaces)
                .trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
        }
        return nil
    }

    private func packageDependencies(for target: String, in manifest: String) throws -> Set<String> {
        let declaration = try packageTargetDeclaration(named: target, in: manifest)
        guard let dependenciesRange = declaration.range(of: "dependencies:") else {
            return []
        }
        let remainder = declaration[dependenciesRange.upperBound...]
        guard let openingBracket = remainder.firstIndex(of: "["),
              let closingBracket = remainder.firstIndex(of: "]") else {
            throw ArchitectureError.invalidDependencies(target)
        }

        let dependencyList = remainder[openingBracket...closingBracket]
        let quotedValues = dependencyList.split(separator: "\"")
        return Set(
            quotedValues.enumerated().compactMap { offset, value in
                offset.isMultiple(of: 2) ? nil : String(value)
            }
        )
    }

    private func packageTargetDeclaration(named name: String, in manifest: String) throws -> String {
        let declarationMarker = ".target(\n            name: \"\(name)\""
        guard let targetRange = manifest.range(of: declarationMarker) else {
            throw ArchitectureError.packageTargetNotFound(name)
        }

        let afterTarget = manifest[targetRange.upperBound...]
        let nextDeclaration = [
            afterTarget.range(of: "\n        .target("),
            afterTarget.range(of: "\n        .testTarget("),
        ]
        .compactMap { $0?.lowerBound }
        .min()
        let end = nextDeclaration ?? manifest.endIndex
        return String(manifest[targetRange.lowerBound..<end])
    }

    private func swiftFiles(in directory: URL) throws -> [URL] {
        let fileManager = FileManager.default
        var isDirectory = ObjCBool(false)
        guard fileManager.fileExists(atPath: directory.path, isDirectory: &isDirectory),
              isDirectory.boolValue else {
            throw ArchitectureError.sourceDirectoryNotFound(directory.path)
        }
        guard let enumerator = fileManager.enumerator(
            at: directory,
            includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        ) else {
            throw ArchitectureError.sourceDirectoryNotFound(directory.path)
        }

        let files = enumerator.compactMap { $0 as? URL }
            .filter { $0.pathExtension == "swift" }
            .sorted { $0.path < $1.path }
        guard !files.isEmpty else {
            throw ArchitectureError.noSwiftFiles(directory.path)
        }
        return files
    }

    private func importViolations(
        in files: [URL],
        forbiddenModules: Set<String>,
        root: URL,
        allowedDirectory: URL? = nil
    ) throws -> [String] {
        var violations: [String] = []
        for file in files {
            let imports = try importedModules(in: file).intersection(forbiddenModules)
            guard !imports.isEmpty else { continue }
            if let allowedDirectory,
               file.path.hasPrefix(allowedDirectory.path + "/") {
                continue
            }
            let path = file.path.replacingOccurrences(of: root.path + "/", with: "")
            violations.append("\(path): \(imports.sorted().joined(separator: ", "))")
        }
        return violations
    }

    private func importedModules(in file: URL) throws -> Set<String> {
        let source = try contents(of: file)
        let modifiers: Set<Substring> = ["public", "package", "internal", "fileprivate", "private"]
        let importKinds: Set<Substring> = ["class", "struct", "enum", "protocol", "func", "var", "let", "typealias"]

        let statements = source
            .components(separatedBy: .newlines)
            .flatMap { $0.split(separator: ";", omittingEmptySubsequences: true) }

        return Set(statements.compactMap { statement in
            let trimmed = statement
                .split(separator: "//", maxSplits: 1, omittingEmptySubsequences: false)[0]
                .trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty, !trimmed.hasPrefix("/*") else { return nil }
            let tokens = trimmed.split(whereSeparator: { $0 == " " || $0 == "\t" })
            guard let importIndex = tokens.firstIndex(of: "import"),
                  tokens[..<importIndex].allSatisfy({ $0.hasPrefix("@") || modifiers.contains($0) }) else {
                return nil
            }

            let moduleIndex = importIndex + 1
            guard moduleIndex < tokens.endIndex else { return nil }
            let nameIndex = importKinds.contains(tokens[moduleIndex]) ? moduleIndex + 1 : moduleIndex
            guard nameIndex < tokens.endIndex else { return nil }
            return String(tokens[nameIndex].split(separator: ".")[0])
        })
    }

    private func indentation(of line: String) -> Int {
        line.prefix { $0 == " " || $0 == "\t" }.reduce(0) { count, character in
            count + (character == "\t" ? 2 : 1)
        }
    }
}

private enum ArchitectureError: LocalizedError {
    case repositoryRootNotFound
    case targetNotFound(String)
    case packageTargetNotFound(String)
    case invalidDependencies(String)
    case sourceDirectoryNotFound(String)
    case noSwiftFiles(String)

    var errorDescription: String? {
        switch self {
        case .repositoryRootNotFound:
            return "Could not locate the repository root from #filePath."
        case let .targetNotFound(name):
            return "project.yml does not contain target \(name)."
        case let .packageTargetNotFound(name):
            return "Package.swift does not contain target \(name)."
        case let .invalidDependencies(name):
            return "Package.swift has malformed dependencies for \(name)."
        case let .sourceDirectoryNotFound(path):
            return "Expected source directory does not exist: \(path)"
        case let .noSwiftFiles(path):
            return "Expected Swift source files in: \(path)"
        }
    }
}
