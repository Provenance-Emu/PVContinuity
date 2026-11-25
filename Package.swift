// swift-tools-version:5.9
import Foundation
import PackageDescription

// A version tag resolves to the prebuilt XCFrameworks from that tag's GitHub release;
// `main` always builds from source. The release workflow fills this in on the tagged
// commit only, so it stays `nil` on every branch.
// Set PV_BUILD_FROM_SOURCE=1 to build a tagged version from source instead.
let binaryRelease: (version: String, checksums: [String: String])? = ("1.0.2", ["PVContinuity": "c017f46ae7a68e2ad636deab7812a419fc70e58b9cd436e69c4a578729f87f55", "PVContinuityTesting": "4ebeb47263fabc1e5f19e9c898dbe700cc68ec9c03bcda228f5da402a46669dd"])

let environment = ProcessInfo.processInfo.environment
let buildFromSource = binaryRelease == nil || environment["PV_BUILD_FROM_SOURCE"] != nil
// The release workflow builds the frameworks it publishes from dynamic products, one
// module at a time, and names the ones already built so later modules link them
// instead of compiling them in again.
let buildingRelease = environment["PV_XCFRAMEWORK_BUILD"] != nil
let libraryType: Product.Library.LibraryType? = buildingRelease ? .dynamic : nil
let prebuilt = Set((environment["PV_XCFRAMEWORK_PREBUILT"] ?? "").split(separator: " ").map(String.init))

let module: (Target) -> Target = { source in
    prebuilt.contains(source.name)
        ? .binaryTarget(name: source.name, path: ".xcframework-build/\(source.name).xcframework")
        : source
}
// A product made only of a prebuilt framework cannot ask for a linkage type.
let libraryTypeFor: (String) -> Product.Library.LibraryType? = { module in
    prebuilt.contains(module) ? nil : libraryType
}

let syncRules: Target.Dependency = .product(name: "PVSyncRules", package: "PVSyncRules")
let webServer: Target.Dependency = .product(name: "PVWebServer", package: "PVWebServer")

let sourceTargets: [Target] = [
    module(.target(name: "PVContinuity", dependencies: [syncRules, webServer])),
    // PVSyncRules and PVWebServer are named here too: PVContinuity's interface imports
    // them, and a prebuilt framework does not pass its own dependencies on.
    module(.target(name: "PVContinuityTesting", dependencies: ["PVContinuity", syncRules, webServer]))
] + (buildingRelease ? [] : [
    .testTarget(
        name: "PVContinuityTests",
        dependencies: ["PVContinuity", "PVContinuityTesting"]
    )
])

let binaryTargets: [Target] = binaryRelease.map { release in
    release.checksums.sorted { $0.key < $1.key }.map { module, checksum in
        .binaryTarget(
            name: module,
            url: "https://github.com/Provenance-Emu/PVContinuity/releases/download/\(release.version)/\(module).xcframework.zip",
            checksum: checksum
        )
    } + [
        // What the prebuilt frameworks link against.
        .target(name: "PVContinuityDependencies", dependencies: [syncRules, webServer], path: "Sources/BinaryDependencies")
    ]
} ?? []

let package = Package(
    name: "PVContinuity",
    platforms: [.iOS(.v17), .tvOS(.v17), .macOS(.v14)],
    // Product names are the same in both modes, so consumers never change.
    products: buildFromSource ? [
        .library(name: "PVContinuity", type: libraryTypeFor("PVContinuity"), targets: ["PVContinuity"]),
        .library(name: "PVContinuityTesting", type: libraryTypeFor("PVContinuityTesting"), targets: ["PVContinuityTesting"])
    ] : [
        .library(name: "PVContinuity", targets: ["PVContinuity", "PVContinuityDependencies"]),
        .library(name: "PVContinuityTesting", targets: ["PVContinuityTesting", "PVContinuity", "PVContinuityDependencies"])
    ],
    dependencies: [
        // The shared "what may leave the device" table, owned jointly with the
        // CloudKit sync work. Continuity classifies every user-data file
        // through it so the two features can never disagree about what is
        // allowed off-device.
        // 1.0.3 and 1.3.4 are the first releases of these two with a prebuilt framework.
        // An older one would be compiled into PVContinuity's own framework.
        .package(url: "https://github.com/Provenance-Emu/PVSyncRules.git", from: "1.0.3"),
        // The route registry lives on the app's existing HTTP server; this
        // package registers against it rather than defining a parallel
        // request/response type family and an adapter to translate between them.
        .package(url: "https://github.com/Provenance-Emu/PVWebServer.git", from: "1.3.4")
    ],
    targets: buildFromSource ? sourceTargets : binaryTargets
)
