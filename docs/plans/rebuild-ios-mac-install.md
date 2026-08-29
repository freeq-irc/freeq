# Plan: recompile iOS + macOS builds and install

Goal: rebuild the Rust FFI + Swift apps for macOS and iOS from current HEAD
(`e16a2b98 sdk,ffi,macos,ios: badge agents and show what they are doing`) and
install them locally.

## Steps

- [x] 1. macOS: `./freeq-macos/build-rust.sh` (AV feature, arm64 staticlib +
      Swift bindings + xcframework)
- [x] 2. macOS: fix build break in `AppState.swift` — the `.names` case used
      `ch` (out of scope in that branch); now carries prior actorClass/presence
      from `allBuffers` lookup by channel key
- [x] 3. macOS: `scripts/package.sh` → Release arm64, ad-hoc signed,
      `build/dist/freeq-1.0-1.zip`
- [x] 4. macOS: installed → `/Applications/freeq.app` (1.0)
- [x] 5. iOS: `./freeq-ios/build-rust.sh` (device slice with AV + sim stub
      slice)
- [x] 6. iOS: `xcodegen generate` + `xcodebuild` Debug for iOS Simulator →
      BUILD SUCCEEDED; installed on booted `iPhone 17 Pro` simulator
- [ ] 7. iOS device install — **BLOCKED**

## Blocker: iOS device install

`xcodebuild -destination generic/platform=iOS` fails signing:

- `No Accounts: Add a new account in Accounts settings`
- `Signing certificate "Apple Development: Chad Fowler (D6G9BYGH26)" ... is not
  valid for code signing. It may have been revoked or expired.`
- Team provisioning profile `at.freeq.ios` lacks App Groups
  (`group.at.freeq.ios`) capability
- No profile for `at.freeq.ios.liveactivity`

Also `xcrun devicectl list devices` shows the iPhone `cf` (iPhone 15 Pro) as
**unavailable** — not connected.

To unblock: sign into the Apple ID in Xcode → Settings → Accounts, reconnect the
phone, then:

    cd freeq-ios && xcodebuild -project freeq.xcodeproj -scheme freeq \
      -configuration Debug -destination 'generic/platform=iOS' \
      -derivedDataPath build/DerivedData -allowProvisioningUpdates build
    xcrun devicectl device install app --device cf \
      build/DerivedData/Build/Products/Debug-iphoneos/freeq.app

This is part of the pending Apple Developer Program work tracked in
`docs/DEVELOPER-ACCOUNT-TODO.md`.
