# freeq Android Client

Android client for the freeq IRC network, built with Kotlin and Jetpack Compose (Material 3).
Mirrors the functionality of the [iOS client](../freeq-ios) and uses the same
`freeq-sdk-ffi` library (UniFFI) for IRC connectivity and AT Protocol authentication.

## Screens

- **ConnectScreen** — Bluesky OAuth login (Chrome Custom Tabs) + guest mode
- **ChatsTab** — Channel/DM list with last message preview, unread badges, search
- **ChatDetailScreen** — Full chat with message list, compose bar, member sidebar
- **MessageList** — Message grouping, date separators, system messages, reactions, reply context, typing indicators, context menu (reply/edit/delete/copy)
- **ComposeBar** — Multi-line input, @mention autocomplete, reply/edit context bars, /commands
- **DiscoverTab** — Popular channels + custom channel join
- **SettingsTab** — Account info, theme toggle, connection status, disconnect

### Architecture

```
MainActivity (entry point, deep link handler)
└── FreeqApp (theme + routing)
    ├── ConnectScreen (disconnected)
    └── MainScreen (connected)
        ├── ChatsTab → ChatDetailScreen
        ├── DiscoverTab
        └── SettingsTab
```

- **State**: `AppState` (AndroidViewModel) with Compose `mutableStateOf` / `mutableStateListOf`
- **Events**: `AndroidEventHandler` bridges FFI callbacks → `Dispatchers.Main` → state updates
- **FFI**: UniFFI-generated Kotlin bindings (`freeq.kt`) + JNA → `libfreeq_sdk_ffi.so`
- **Persistence**: SharedPreferences (nick, server, channels, read positions, theme)
- **Theme**: Material 3 dark/light with freeq accent (#6c63ff)

## Prerequisites

- Android Studio (Hedgehog or newer)
- Android NDK (install via SDK Manager → SDK Tools → NDK)
- Rust toolchain via [rustup](https://rustup.rs/)
- `cargo-ndk`: `cargo install cargo-ndk`
- Rust Android targets: `rustup target add aarch64-linux-android x86_64-linux-android`

## Building

### 1. Build the native library

From the repo root:

```sh
./freeq-android/build-rust.sh
```

This cross-compiles `freeq-sdk-ffi` for arm64 and x86_64, generates the Kotlin bindings
via `uniffi-bindgen`, and copies everything into the right places.

### 2. Build the APK

```sh
cd freeq-android
./gradlew assembleDebug
```

### 3. Install on emulator or device

```sh
./gradlew installDebug
```

## Future work

- Rich media rendering (images, YouTube thumbnails, Bluesky embeds)
- Message search
- User profile sheets (Bluesky profile fetch)
- Thread/reply chain view
- Photo upload with cross-post to Bluesky
- Push notifications
- Auto-reconnect with backoff, except after a refusal, which goes to the sign-in screen
