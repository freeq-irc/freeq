# Developer-account TODO (do these once accounts are approved)

Blocked on Apple Developer Program + Google Play Console approval. Each item
below is gated on a signing identity / provisioning / a store account that
doesn't exist yet. Everything is **code-complete or code-ready** — these are
the signing/distribution steps that can't be faked with ad-hoc signing.

Status: created 2026-07-04. Check items off as done and delete this note when
all three platforms ship signed builds.

---

## 0. Accounts & identities (do first)
- [ ] **Apple Developer Program** membership active (the iOS project pins
      `DEVELOPMENT_TEAM = 3DT7XF7L4R` — confirm that's the right/paid team, or
      update it everywhere: `freeq-ios/project.yml`, and add to
      `freeq-macos/project.yml`).
- [ ] **Google Play Console** developer account ($25 one-time) created.
- [ ] Decide bundle/app IDs are final: `at.freeq.macos`, `at.freeq.ios`,
      `com.freeq.app` (+ `.zerosum` flavor on Android).
- [ ] App Store Connect app records (macOS + iOS) and Play Console app record.

---

## macOS (`freeq-macos/`)
Currently ad-hoc signed — this is the root of the "rebuild loses keychain /
session" bug and why the Share Extension may not load. Proper signing fixes
both permanently.

**Tooling is ready** — full runbook in `freeq-macos/docs/DISTRIBUTION.md`;
`scripts/package.sh` (env-driven signing, verified) + `notarize.sh` +
`sparkle-keys.sh` + `generate-appcast.sh` are turnkey. The items below are the
account-gated inputs those scripts need.

- [ ] **Developer ID Application** certificate → set `CODE_SIGN_IDENTITY` +
      `DEVELOPMENT_TEAM` in `freeq-macos/project.yml` (add a `settings.base`
      block; today there is none). Re-run `xcodegen generate`.
- [ ] **Hardened Runtime** on for notarization (`ENABLE_HARDENED_RUNTIME`),
      plus the exceptions the app needs (e.g. `com.apple.security.cs.*` if
      any). Sandbox is already on.
- [ ] **Notarize** the Developer-ID build (`xcrun notarytool submit` +
      `stapler staple`) so Gatekeeper allows it without prompts on other Macs.
- [ ] **Verify the Share Extension loads** — `freeq-share.appex` builds and
      embeds today, but Share-menu registration + extension loading need real
      signing. Confirm "Send to freeq" appears in other apps' Share menus.
- [ ] **App group** for Share Extension images/files: create
      `group.<TEAMID>.at.freeq` (or `group.at.freeq.macos`), add
      `com.apple.security.application-groups` to BOTH
      `freeq-macos/freeq-macos.entitlements` and
      `ShareExtension/ShareExtension.entitlements`, then extend
      `ShareViewController` + the host to pass image/file payloads through the
      shared container (only text/links work via the `freeq://` URL today).
- [ ] **Sparkle** auto-update (design §7.1, dogfood depends on it): add the
      Sparkle 2 SPM package, generate EdDSA keys, host an appcast, wire
      `SUFeedURL` + the updater. Sandbox-compatible XPC install.
- [ ] **Drop / re-verify** the `KeychainHelper` container-file fallback —
      with stable signing the data-protection keychain works, so confirm the
      fallback is only a safety net (it stays harmless, but verify a signed
      build round-trips the token via the keychain, not the file).
- [ ] **MAS target** (separate from Developer ID) if App Store distribution is
      wanted — different provisioning, no Sparkle, `com.apple.application-*`
      review. Build matrix {MAS, Direct} × {debug, release}.
- [ ] Re-install to `/Applications` as a **signed** build and re-run the macOS
      integration checklist (menu bar, hotkey, intents, Writing Tools, Share
      Extension).

---

## iOS (`freeq-ios/`)
Team is set (`3DT7XF7L4R`, automatic "Apple Development"), but device install,
extensions, and TestFlight need the paid program + provisioning in Xcode.

- [ ] **Re-enable the Live Activity extension** — `freeqLiveActivity` target
      is commented out in `freeq-ios/project.yml:55` ("temporarily disabled
      until provisioning is set up in Xcode"). Re-add the
      `- target: freeqLiveActivity` dependency once provisioning exists.
- [ ] **Watch app** (`freeqWatch`) provisioning + a paired app group if it
      shares state.
- [ ] **Push / APNs** if iOS gets notifications: APNs key (.p8) in App Store
      Connect, `aps-environment` entitlement, PushKit + **CallKit** for VoIP
      call pushes (design lists CallKit as iOS-only). None wired yet.
- [ ] **Associated Domains** for universal links (`applinks:irc.freeq.at`) —
      entitlement + host `apple-app-site-association` file. Pairs with the
      macOS `freeq://` scheme and Handoff.
- [ ] **App groups** if the iOS app adds a Share Extension / widgets that
      share data with the main app.
- [ ] **TestFlight**: archive with a Distribution cert + App Store
      provisioning, upload to App Store Connect, invite the dogfood cohort.
- [ ] Confirm the AV FFI catch-up (screen tiles, audio levels, reconnect —
      landed 2026-07-03/04) behaves on a real signed device build.
- [ ] Port the S2 **session-scoping flip** here in lockstep with macOS + web
      (see below, cross-cutting).

---

## Android (`freeq-android/`)
No signing config, no push, no store presence yet. `applicationId com.freeq.app`
(+ `.zerosum` flavor). Deep-link intent-filters already in the manifest.

- [ ] **Upload keystore** + **Play App Signing**: generate a release keystore,
      add `signingConfigs { release { … } }` to
      `freeq-android/freeq/build.gradle.kts` (keys via env/`~/.gradle`, NOT
      committed), and enroll the app in Play App Signing.
- [ ] Build a signed **App Bundle** (`.aab`) and upload to an **internal
      testing** track first.
- [ ] **FCM push** (Firebase Cloud Messaging) if Android gets notifications:
      create a Firebase project, add `google-services.json` (gitignored),
      the `com.google.gms.google-services` plugin, and `firebase-messaging`.
      `POST_NOTIFICATIONS` permission is already declared.
- [ ] **App Links** (verified deep links): host `.well-known/assetlinks.json`
      with the release signing SHA-256 and add `android:autoVerify="true"` to
      the existing intent-filters, so `https://irc.freeq.at/…` opens the app.
- [ ] Play Console compliance: **Data safety** form, **content rating**,
      target-API level, privacy policy link.
- [ ] Decide whether the `.zerosum` flavor ships as a separate listing or
      stays internal.

---

## Cross-cutting (needs a signing/store identity to complete)
- [ ] **S2 session-scoping flip** — the server half is live/deployable; flip
      `SCOPED_SESSIONS = true` in `freeq-sdk-ffi/src/lib.rs` and the web
      client's dial URL **in the same release across native + web + iOS**
      (see the `freeq-server/src/av_sfu.rs` header).
      Not signing-gated per se, but must ship as coordinated signed builds.
- [ ] **App Review 4.8 assessment** (design §7.6): AT Protocol OAuth is a
      decentralized identity protocol, not third-party social login; guest
      mode is the no-account path. Write it down before submitting either
      Apple platform.
- [ ] **Export compliance for E2EE** (encryption declaration; French
      declaration) — both stores.
- [ ] **Privacy nutrition labels** (Apple) + **Data safety** (Google), using
      the §6.4/§6.11 decisions as source of truth.
- [ ] CI: add signed **release** lanes once secrets exist (Apple API key,
      Play service-account JSON) — the current CI only does unsigned checks.

---

See also: `freeq-macos/DESIGN-APP-OF-THE-YEAR.md` §7 (quality gates /
distribution).
