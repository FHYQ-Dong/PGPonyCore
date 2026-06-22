# PGPonyLinkDemo

A minimal iOS app that demonstrates the **"offline primary, subkeys on card"**
link + decrypt flow using only `PGPonyCore` — the case the closed app currently
gets wrong (it matches the card's signing slot against the **primary** fingerprint
instead of treating it as a **subkey**).

What it does, end to end on a real card:

1. parse the sample public key → primary + subkeys
2. read the card's slot fingerprints (`OpenPGPCardService.readCardInfo`)
3. match the card's **decrypt** slot against the **whole keyblock** and accept a
   **subkey** (never `slot == primary`) — this is the fix
4. `PSO:DECIPHER` a message encrypted to the `[E]` subkey, on the card

It is the reference implementation to hand back to NorseHorse, plus the runtime
proof that the only thing broken is the app's match logic.

## Prerequisites

- A **Mac with Xcode 15+** (iOS 17 SDK).
- A **paid Apple Developer Program** membership — the *Near Field Communication
  Tag Reading* entitlement is **not** available to free "Personal Team" signing.
- A physical **iPhone** (NFC can't run in the Simulator) + your **YubiKey**
  (`[E]` subkey `7A019AB78C093065` on it).

## Build & run

### Option A — XcodeGen (recommended; no hand-made project)

```sh
brew install xcodegen                     # one-time
cd examples/PGPonyLinkDemo
xcodegen generate                         # creates PGPonyLinkDemo.xcodeproj
open PGPonyLinkDemo.xcodeproj
```

Then in Xcode: select the **PGPonyLinkDemo** target → **Signing & Capabilities**
→ pick your **Team**. (The *Near Field Communication Tag Reading* capability and
its entitlement/Info.plist keys are already wired by `project.yml`.) Pick your
iPhone as the run destination and **Run**.

### Option B — by hand

1. Xcode → **New → Project → iOS App** (SwiftUI), name `PGPonyLinkDemo`.
2. Delete the generated `ContentView.swift`/`...App.swift`; add the three files
   from `Sources/` instead.
3. **File → Add Package Dependencies → Add Local…** → select the repo root
   (the folder with `Package.swift`) → add the `PGPonyCore` library.
4. Target → **Build Settings** → set **Enable Testability = Yes** (needed for
   `@testable import` while the core is still `internal`).
5. Target → **Signing & Capabilities** → **+ Capability → Near Field
   Communication Tag Reading**; set your Team.
6. **Info.plist** → add:
   - `NFCReaderUsageDescription` (string) — any prompt text.
   - `com.apple.developer.nfc.readersession.iso7816.select-identifiers`
     (array of strings) → one entry: `D27600012401` (the OpenPGP applet AID).
7. Run on your iPhone.

## Using it

1. Paste a ciphertext into the field (one is pre-filled; or copy a fresh one from
   the CI log of `testGenerateSampleCiphertextToEncryptionSubkey` — any message
   encrypted to `7A019AB78C093065` works).
2. Enter your **user PIN (PW1)**.
3. Tap **Link card & decrypt**, then hold the YubiKey to the top of the iPhone;
   touch it if it blinks.

Expected log:

```
Public key: primary cfe702fb746017e1 + 3 subkeys (primary is OFFLINE)
Card decrypt slot fingerprint: …7A019AB78C093065
→ matched [E] SUBKEY 7a019ab78c093065, NOT the primary cfe702fb746017e1
```

and the decrypted plaintext: **`PGPony offline-primary decrypt works.`**

The `→ matched [E] SUBKEY …, NOT the primary …` line is the whole point: the
card slot maps to a **subkey**, which is exactly the comparison the closed app
needs to fix.

## Caveats

- **`@testable import PGPonyCore`** is used because the core's symbols are still
  `internal` (see the package README "Public API surface" roadmap). It resolves in
  **Debug** builds (which is what you run on-device during development). Once the
  core promotes its consumed symbols to `public`, switch to a plain `import`.
- This `examples/` folder is **not** part of the SwiftPM package (`Package.swift`
  only builds `Sources/` + `Tests/`), so it never affects `PGPonyCore`'s build or
  CI. It can be dropped from, or PR'd separately to, the upstream repo.
