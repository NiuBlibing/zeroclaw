# #12453: current-head Web interface evidence

## What ran

- Implementation: `cf6a0473f368268f1661fbe30576ee73a4b9293e`.
- Both the clean Web source and the daemon were taken from that same PR head.
- Daemon build: `CARGO_BUILD_JOBS=4 RUSTC_WRAPPER= cargo build --offline --locked -p zeroclaw --bin zeroclaw` (exit 0).
- Web dependencies: `npm ci --ignore-scripts --no-audit --no-fund` from the locked checkout. The actual Vite application served the unchanged UI and proxied to the locally running daemon.
- Chromium, English locale; desktop **1440×1000**, mobile **390×844**, device scale factor 1. These are direct browser screenshots of the actual application, without HTML reconstruction or image editing.
- Pairing used the normal gateway pairing flow. Only synthetic model/agent names and data were used. No inference request was made.
- [Current-head Quality Gate](https://github.com/zeroclaw-labs/zeroclaw/actions/runs/44944829693) supplies full workspace/platform validation. The newly wired Quickstart model tests are included in its passing Web Permission Tests.

The daemon binary hash and capture time are in [metadata.json](metadata.json).
[observations.json](observations.json) records actual API outcomes and assertions for both widths.

## Evidence by requested workflow

| Workflow | Desktop | Mobile |
|---|---|---|
| Open the editor through `?model=chat.demo.gateway`; literal model keys remain intact | [Open editor](desktop-registry-open.png) | [Open editor](mobile-registry-open.png) |
| Inspect the shared connection; credentials remain masked | [Masked connection](desktop-connections-masked.png) | [Masked connection](mobile-connections-masked.png) |
| Save while the outgoing PUT is pending; editor, Save, Reload and shared Save All are disabled | [Pending save](desktop-save-pending.png) | [Pending save](mobile-save-pending.png) |
| Release the real request; successful saved value is read back from the daemon | [Persisted save](desktop-save-persisted.png) | [Persisted save](mobile-save-persisted.png) |
| A second client changes the registry; stale save is rejected and the draft stays visible | [Concurrent conflict](desktop-concurrent-conflict.png) | [Concurrent conflict](mobile-concurrent-conflict.png) |
| Quickstart selects the existing literal dotted key | [Selected model](desktop-quickstart-existing.png) | [Selected model](mobile-quickstart-existing.png) |
| Complete the remaining Quickstart selectors and create the agent | [Ready to create](desktop-quickstart-ready.png) | [Ready to create](mobile-quickstart-ready.png) |
| Open the agent model picker | [Picker](desktop-agent-picker.png) | [Picker](mobile-agent-picker.png) |
| Switch to the other literal dotted key `chat.backup.prod` | [Switch completed](desktop-agent-switched.png) | [Switch completed](mobile-agent-switched.png) |

### Pending save and conflict methodology

No server response was mocked. The driver paused one outgoing browser PUT
before it reached the daemon, asserted that all relevant controls were
disabled, and took the pending screenshot. It then released that request,
observed HTTP 200 and independently read back the saved model ID.

For the conflict, a second authenticated client read and changed the registry
using the real GET/PUT endpoint. The first editor then submitted its stale
baseline. The existing configuration API returned **HTTP 400** with
`validation_failed` and `provider registry changed; reload before saving`.
The driver verified that the first editor retained its unsaved text and that
the successful earlier saved value was not overwritten. This records the
actual Config API contract, rather than assuming HTTP 409.

Both Quickstart calls returned `kind: "applied"`. The agent picker then used
the real configuration write and WebSocket reconnect to display the selected
backup key. No chat message or paid model request was sent.

## Reproduction

1. Check out the implementation revision above. Build its daemon and install its locked Web dependencies with the commands above.
2. Create an isolated V5 configuration with a synthetic `gateway.prod` OpenAI connection, `chat.demo.gateway` chat model (`model = "gpt-synthetic-before"`), and an enabled agent named `evidence_fresh` selecting that model and a valid supervised risk/runtime profile. Keep the credential synthetic and pairing enabled. Do not use a personal configuration.
3. Start the daemon on `127.0.0.1:42629` and Web with `ZEROCLAW_GATEWAY_PORT=42629 npm run dev -- --host 127.0.0.1 --port 5178 --strictPort`. Pair normally and keep the returned token in a local, untracked file.
4. Run [capture-web.cjs](capture-web.cjs) using an installed Playwright module and Chromium:

   ```sh
   BROWSER_TOKEN_FILE=<local-untracked-token-file> \
   CAPTURE_DIR=<output-dir> \
   PLAYWRIGHT_MODULE=<installed-playwright-module> \
   BROWSER_EXECUTABLE=<chromium-executable> \
   node capture-web.cjs
   ```

The driver creates `evidence_web_desktop` and `evidence_web_mobile`; use a fresh isolated fixture for a repeat. Browser console exceptions fail the capture. The script sends no external inference requests, and tokens/configuration files are excluded from the published evidence.

The local build emitted the existing unused `zeroclaw-dist` and deprecated
`Atomic::fetch_update` warnings, both also present on master. They are not
hidden or changed by this evidence-only update.
