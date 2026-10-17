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

## Combined setup: ad blocking, background playback and one recommendation

Use the configuration below as the base configuration, then enable the recommendation module linked above alongside it. Together they combine the previously working Maasea ad-blocking/background-playback script with this repository's recommendation filter. If the base configuration is already installed, keep it and add only the recommendation module; do not duplicate its rules or scripts.

The Maasea script is pinned to the previously working revision. This setup deliberately uses only its response script; do not add `youtube.request.js` from a newer setup.

```yaml
dns:
  bootstrap:
    - system
  upstreams:
    NextDNS:
      - https://dns.nextdns.io/YOUR_NEXTDNS_ID
  forward:
    - wildcard:
        match: "*"
        value: NextDNS

rules:
  - default:
      policy: DIRECT

url_rewrites:
  - match: '^https?:\/\/[\w-]+\.googlevideo\.com\/(?!(dclk_video_ads|videoplayback\?)).+&oad'
    location: http://reject-200/
  - match: '^https?:\/\/(www|s)\.youtube\.com\/api\/stats\/ads'
    location: http://reject-200/
  - match: '^https?:\/\/(www|s)\.youtube\.com\/(pagead|ptracking)'
    location: http://reject-200/
  - match: '^https?:\/\/s\.youtube\.com\/api\/stats\/qoe\?adcontext'
    location: http://reject-200/

scriptings:
  - http_response:
      name: YouTube Response
      match: '^https:\/\/youtubei\.googleapis\.com\/youtubei\/v1\/(browse|next|player|search|reel\/reel_watch_sequence|guide|account\/get_setting|get_watch)'
      script_url: https://raw.githubusercontent.com/Maasea/sgmodule/65075cd/Script/Youtube/youtube.response.js
      max_size: 10485760
      timeout: 60
      body_required: true
      binary_body: true

mitm:
  ca_p12: egern.p12
  ca_passphrase: egern
  hostnames:
    includes:
      - "*.googlevideo.com"
      - youtubei.googleapis.com
      - www.youtube.com
      - s.youtube.com
```

Replace `YOUR_NEXTDNS_ID` with your own NextDNS configuration ID, or retain your existing DNS settings. Keep your actual Egern certificate settings if they differ from this example, and ensure its CA is installed and trusted on the iPhone. NextDNS is configured inside Egern because the separate iOS DNS profile did not apply normally while Egern's VPN was active in the tested setup.

The recommendation module supplies its own request/response hooks and MITM hostnames; it does not change DNS or DIRECT routing. Leave both the base Maasea response script and the recommendation module enabled. Disable older recommendation scripts, `/next` rejection and the local diagnostic module. Keep the Wi-Fi HTTP proxy Off.

After installation, open a fresh video and check one recommendation, no community cards, the description, ad blocking, background audio and PiP. The base configuration previously provided ad blocking and background playback; those features were not separately revalidated by the final recommendation-filter diagnostic.

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
