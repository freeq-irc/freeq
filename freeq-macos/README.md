# freeq for macOS

## Building

From the repository root, on a Mac:

1. `./freeq-macos/build-rust.sh` builds the Rust SDK into `FreeqSDK.xcframework` and regenerates `Generated/freeq.swift`.
2. `cd freeq-macos && xcodegen generate` writes `freeq-macos.xcodeproj` from `project.yml`. The project file is checked in and CI regenerates it and fails on any difference, so regenerate and commit it whenever `project.yml` or the source tree changes.
3. Open `freeq-macos.xcodeproj` in Xcode and build the `freeq-macos` scheme.

## Local signing identity

A development build is signed ad hoc, so every rebuild is a new code identity and the Keychain prompts for each stored item at launch. To stop that on your own Mac:

1. In Keychain Access: Certificate Assistant, Create a Certificate, name `Freeq Dev`, Self Signed Root, type Code Signing.
2. `cp Local.yml.example Local.yml` (gitignored).
3. `FREEQ_LOCAL_SIGNING=true xcodegen generate`.
4. Build and launch once, choosing Always Allow at each prompt. Later launches prompt nothing.

Run plain `xcodegen generate` when regenerating the project for a commit; `Local.yml` is read only when the variable is set, so the committed project and CI never carry the identity.
