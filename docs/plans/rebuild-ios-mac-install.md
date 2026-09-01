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

### Re-checked with the phone plugged in (2026-08-29)

Still blocked, on two independent things:

1. **Device not reachable.** `devicectl` still reports `unavailable` after ~1 min
   of polling; `xctrace list devices` lists `cf (26.5)` under *Devices Offline*;
   `devicectl device info lockState` fails with CoreDeviceError 1011 ("unable to
   locate a device"). The cached `device info details` record still resolves,
   which is why the phone shows in the list at all. Needs: unlocked phone +
   "Trust This Computer" accepted + a data-capable cable.
2. **No usable signing identity.**
   - `security find-identity -v -p codesigning` → the only identity,
     `Apple Development: Chad Fowler (D6G9BYGH26)`, is **CSSMERR_TP_CERT_REVOKED**
   - `defaults read com.apple.dt.Xcode IDEProvisioningTeams` → does not exist
     (no Apple account signed into Xcode)
   - `~/Library/MobileDevice/Provisioning Profiles/` is empty
   - `/var/db/lockdown` is empty (no pairing records)

   A free personal team would not be enough either: `freeq/freeq.entitlements`
   requests App Group `group.at.freeq.ios`, which needs a paid membership.
   Options are (a) wait for the Apple Developer Program approval, or (b) strip
   App Groups + the Live Activity/Watch targets for a throwaway 7-day personal
   -team build (breaks the share extension and Live Activity).

To unblock: sign into the Apple ID in Xcode → Settings → Accounts, reconnect the
phone, then:

    cd freeq-ios && xcodebuild -project freeq.xcodeproj -scheme freeq \
      -configuration Debug -destination 'generic/platform=iOS' \
      -derivedDataPath build/DerivedData -allowProvisioningUpdates build
    xcrun devicectl device install app --device cf \
      build/DerivedData/Build/Products/Debug-iphoneos/freeq.app

This is part of the pending Apple Developer Program work tracked in
`docs/DEVELOPER-ACCOUNT-TODO.md`.
