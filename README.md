# YouTube One Recommendation — Egern

Working version confirmed on the **official YouTube iPhone app with Egern**, 2026-10-17. No Linux proxy, sideloading, jailbreak or external worker is required.

- Keeps the first regular recommended-video card.
- Replaces the other cards in the observed related sections with the page's own spacers.
- Hides the observed community-post cards, including posts in their separate shelf wrapper.
- Removes the related list's next-page token to stop more recommendations loading.
- Preserves the tested title, description, comments and playback behavior.

## Install

Add this module to Egern:

**https://raw.githubusercontent.com/abylsit/egern-scripts/main/egern/module.yaml**

Keep the existing known-good Egern configuration, DIRECT routing, DNS, ad-blocking/background script, URL rewrites and trusted Egern certificate. Disable the old custom recommendation filters, `/next` rejection and local diagnostic module so only this recommendation module is enabled.

Set the iPhone Wi-Fi HTTP proxy **Off**. Enable Egern, reopen YouTube and open a fresh video. The previous Linux server and local diagnostic receiver are not needed.

The existing ad-blocking, background-audio and PiP setup is not bundled or replaced here. Keep it configured; those features require their own checks after changing the setup.

## Implementation

The script supports both:

1. Plain Protobuf `/youtubei/v1/next` responses — **confirmed filtering inside Egern on the iPhone**.
2. Encrypted Next metadata inside Googlevideo `/initplayback` UMP responses — verified against local captures; the equivalent Linux path was device-tested, but this encrypted branch has not separately been observed filtering inside Egern.

It keeps one unmodified `video_lockup_with_attachment` card without a `pagead` marker, substitutes the other related cards and known community-card layouts, and preserves parent sections and repeated item entries. It removes only the observed next-page continuation, retaining reload commands. There is no broad section deletion.

For encrypted metadata, the script captures the client's config key locally, authenticates and decrypts the appropriate response parts, edits their nested Next payload, then recompresses, encrypts and authenticates them. Player and media UMP parts keep their original wire bytes. A temporary cached-config header removal on `/log_event` stops once a key is captured; playback requests are never redirected.

## Validation and limits

The successful Egern diagnostic recorded **17 replaced renderers, one video kept and one next-page token removed**; the user reported the intended result. Community-card handling was also validated on the working Linux setup and captured Protobuf pages.

Local checks cover five Protobuf pages and 77 encrypted streams, byte-for-byte filtering parity with the working reference, independent authentication/decryption of changed encrypted parts, and the Egern-shaped request/response wrapper. No captures or keys are included in this repository.

- Blank space can remain where cards were replaced; spacer height has not been optimized.
- YouTube can change layouts. Known unsupported bodies, missing keys, failed authentication and incomplete UMP streams pass through, so recommendations may remain in those cases.
- Recognition of a regular video uses observed renderer names and a `pagead` marker check; this is not a universal classifier for every future ad or card variant.
- The default script body limit is 10 MiB for this module; larger responses bypass it.
- No battery benchmark has been performed. Normal use makes no diagnostic requests and does not repeatedly fetch replacement pages through an external service.

## Source and build

`egern/youtube_watch.js` is the self-contained script used by Egern. `egern/src/youtube_watch.mjs` is the editable source. AES-CTR and HMAC use bundled MIT-licensed @noble/ciphers and @noble/hashes 2.4.0; licenses are included.

```sh
npm ci
npm run build
```

For private local replay fixtures:

```sh
PORT_GOLD_DIR=/private/golden-pairs YT_STATE_DIR=/private/state node tests/port.mjs
```

Replay checks do not replace device testing. State, captures, keys, certificates and diagnostic logs are excluded from Git.

## Optional troubleshooting

The script logs `YT Watch` result counts or a short pass-through reason. Config keys remain in Egern storage and are never logged. Without an explicit `DEBUG_URL` environment variable, the script sends no diagnostic HTTP requests and needs no local receiver.

An optional local `DEBUG_URL` can receive execution stages, endpoint paths, byte counts, key count and a short error. It does not receive key bytes, full request URLs or video bodies. Remove that setting after debugging.

References: [Egern scripting](https://egernapp.com/docs/configuration/scriptings/), [Egern JavaScript API](https://doc.egernapp.com/docs/javascript-api/), [UMP format research](https://github.com/davidzeng0/innertube/blob/main/googlevideo/ump.md), [Onesie cryptographic example](https://github.com/LuanRT/googlevideo/blob/main/examples/onesie-request/utils.ts).
