// swift-tools-version: 5.10
//
// SwiftPM harness for unit-testing the iOS app's pure-Foundation helpers
// without booting a simulator. The actual app target lives in
// freeq.xcodeproj and isn't built here — this package only compiles the
// dependency-free model + decision files so their assertions can run under
// `swift test` from the command line (and in CI, mirroring freeq-macos).
//
// Run:  cd freeq-ios && DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer swift test

import PackageDescription

let package = Package(
    name: "freeq-ios",
    platforms: [.iOS("18.0"), .macOS("14.0")],
    products: [
        .library(name: "FreeqIosCore", targets: ["FreeqIosCore"])
    ],
    targets: [
        // Single-source the pure model + decision helpers — the files live
        // where the app expects them (inside the Xcode group), and we point
        // SwiftPM at the same files. No copy, no drift.
        .target(
            name: "FreeqIosCore",
            path: "freeq/Models",
            // App-only files in the same directory (UIKit/CallKit/Keychain
            // dependencies) — named so SwiftPM doesn't warn about them.
            // Mirrors the macOS package.
            exclude: [
                "AppState.swift",
                "AppState+Navigation.swift",
                "AuthSession.swift",
                "AvatarCache.swift",
                "AvStartRace.swift",
                "BlueskyGraph.swift",
                "CallCameraCapture.swift",
                "CallKitManager.swift",
                "CallMicCapture.swift",
                "IntelligenceService.swift",
                "KeychainHelper.swift",
                "NetworkMonitor.swift",
                "Notifications.swift",
                "PhoneWatchBridge.swift",
                "StepUpAuth.swift",
                "VoiceTranscriber.swift",
            ],
            sources: [
                "ChatMessage.swift",
                "CoordinationCard.swift",
                "ActVerbs.swift",
                "ActTasks.swift",
                "DmHistoryOnOpen.swift",
                "Jumbomoji.swift",
                "CallLayoutPolicies.swift",
                "FavoritesSync.swift",
                "ApiAuth.swift",
                "ChannelCrypto.swift",
                "ChannelE2eeState.swift",
                "ChannelAccessNotice.swift",
                "SelfPartResolve.swift",
                "ChannelState.swift",
                "DidDisplay.swift",
                "MessageActions.swift",
                "ServerConfig.swift",
                "FreeqDirectory.swift",
                "BufferNavigation.swift",
                "AvRejoin.swift",
                "OutboundSend.swift",
                "DmResolver.swift",
                "IdentityClaim.swift",
                "SignatureProof.swift",
            ]
        ),
        .testTarget(
            name: "FreeqIosCoreTests",
            dependencies: ["FreeqIosCore"],
            path: "Tests/FreeqIosCoreTests"
        ),
    ]
)
