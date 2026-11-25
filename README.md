# PVContinuity

Nearby library discovery, trust, manifests and file transfer for iCube. Depends on
PVSyncRules for sync classification and PVWebServer for its HTTP route registry.
Includes PVContinuityTesting support for consumers. Extracted with history from
iCube Source/iOS/PVContinuity.

Run `swift test` to verify the package. Database, save and library paths come from
the host app. The existing `_icube-continuity._tcp` discovery protocol is retained
for compatibility with installed iCube peers; sharing across other applications
requires an explicit protocol and authorization compatibility decision.

This is distinct from Provenance-Emu/ContinuityKit, which iFly already consumes.
Do not substitute one for the other: their APIs and wire protocols differ.

The original GPL-2.0-or-later source notices are retained; see COPYING.

## Prebuilt XCFrameworks

A version tag resolves to prebuilt XCFrameworks: the tag's `Package.swift` is a
`binaryTarget` pointing at the tag's GitHub Release, so an app that depends on a version
compiles none of this package. `main` and every other branch build from source.

To build a tagged version from source (to step into it in the debugger, say), set
`PV_BUILD_FROM_SOURCE=1` in the environment `xcodebuild` or Xcode starts in, then resolve
packages again.

To release, run **Release XCFramework** from the Actions tab with the new version. Do not
push version tags by hand: such a tag has no binary and builds from source.
[How releases work](https://github.com/Provenance-Emu/.github/blob/main/docs/xcframework-releases.md).
