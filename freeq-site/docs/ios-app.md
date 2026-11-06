# iOS App

The freeq iOS app is a native SwiftUI client built on the Rust SDK via FFI (UniFFI).

## Features

- **Bluesky OAuth login** — ASWebAuthenticationSession flow
- **Full chat** — Channels, DMs, threads, replies, reactions, edits, deletes
- **Media capture** — Photo library, camera, and voice recording (hold-to-record, slide to cancel)
- **Inline media** — Images with pinch-to-zoom lightbox, video with download+play, audio player
- **E2EE DMs** — Full Double Ratchet via Rust FFI
- **Discover tab** — Browse and search public channels
- **Swipe gestures** — Swipe to open sidebar, swipe channel actions (mark read, leave)
- **Haptic feedback** — Throughout the app
- **Push notifications** — On mention/DM (permission requested on first mention)
- **Skeleton loading** — Shimmer placeholders during load
- **Exponential backoff** — Automatic reconnection (1→2→4→8→15s); a refused key goes to the sign-in screen instead, and so does a refused sign-in, after one more try with a new token from the broker when it was refused at sign-in
- **Background/foreground lifecycle** — Reconnects on foreground

## Architecture

```
SwiftUI Views
     ↕
AppState (ObservableObject)
     ↕
SwiftEventHandler (bridges Rust events → SwiftUI)
     ↕
FreeqSDK.xcframework (UniFFI Swift bindings)
     ↕
freeq-sdk-ffi (Rust FFI wrapper)
     ↕
freeq-sdk (Rust SDK)
```

## Building

```bash
# Prerequisites: Xcode, Rust toolchains for iOS
rustup target add aarch64-apple-ios aarch64-apple-ios-sim

# Build the SDK framework
./freeq-ios/build-rust.sh

# Open in Xcode
open freeq-ios/freeq.xcodeproj
```

Requires `sudo xcode-select -s /Applications/Xcode.app/Contents/Developer` (not just Command Line Tools).

## Target

- iOS 18.0+
- iPhone and iPad
