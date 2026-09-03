// swift-tools-version: 5.10
//
// SwiftPM harness for unit-testing the macOS app's pure-Foundation
// helpers without booting Xcode. The actual app target lives in
// freeq-macos.xcodeproj and isn't built here — this package only
// compiles `Models/Validation.swift` so its assertions can run under
// `swift test` from the command line.
//
// Run:  cd freeq-macos && swift test

import PackageDescription

let package = Package(
    name: "freeq-macos",
    platforms: [.macOS("14.4")],
    products: [
        .library(name: "FreeqMacosCore", targets: ["FreeqMacosCore"])
    ],
    targets: [
        // Single-source the validation helpers — the file lives where
        // the app expects it (inside the Xcode group), and we point
        // SwiftPM at the same file. No copy, no drift.
        .target(
            name: "FreeqMacosCore",
            path: "freeq-macos/Models",
            exclude: [
                "AppState.swift",
                "AvatarCache.swift",
                "CallCameraCapture.swift",
                "CallController.swift",
                "CallMicCapture.swift",
                "ComposeCommands.swift",
                "DebugBridge.swift",
                "E2eeManager.swift",
            ],
            sources: [
                "AudioLevelMeter.swift",
                "MediaDeviceSelection.swift",
                "CallLayoutPolicies.swift",
                "CameraEffects.swift",
                "CameraFrameRatePolicy.swift",
                "Validation.swift",
                "ServerConfig.swift",
                "ChatMessage.swift",
                "ChannelState.swift",
                "DidDisplay.swift",
                "ChannelPolicy.swift",
                "AvStartRace.swift",
                "AvLeftResolve.swift",
                "SelfPartResolve.swift",
                "AvRejoin.swift",
                "ChannelCrypto.swift",
                "ChannelE2eeState.swift",
                "ChannelHydration.swift",
                "ComposeFormatting.swift",
                "ComposeHistory.swift",
                "MessageTimeline.swift",
                "MessageBlocks.swift",
                "SyntaxHighlighter.swift",
                "BufferNavigation.swift",
                "CommandRegistry.swift",
                "UploadResponse.swift",
                "ReconnectPolicy.swift",
                "ConnectGate.swift",
                "MessageTranscript.swift",
                "CoordinationCard.swift",
                "ActVerbs.swift",
                "ActTasks.swift",
                "Jumbomoji.swift",
                "FavoritesSync.swift",
                "ApiAuth.swift",
                "MenuBarModel.swift",
                "MessageActions.swift",
                "OutboundSend.swift",
                "DmResolver.swift",
                "IdentityClaim.swift",
                "Safety.swift",
                "SelfStatus.swift",
                "SignatureProof.swift",
                "ComposeTextExtraction.swift",
                "ShareURL.swift",
                "Logger.swift",
                "KeychainHelper.swift",
                "MessageStore.swift",
            ]
        ),
        .testTarget(
            name: "FreeqMacosCoreTests",
            dependencies: ["FreeqMacosCore"],
            path: "Tests/FreeqMacosCoreTests"
        ),
    ]
)
