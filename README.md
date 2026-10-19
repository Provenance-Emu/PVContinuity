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
