# c2pa-check

Verify Content Credentials (C2PA) in files and URLs, and fail a build when provenance disappears.

```bash
brew install c2pa-design/tap/c2pa-check      # macOS / Linux
npx c2pa-check photo.jpg                      # no install
cargo install c2pa-check                      # from source
```

```console
$ c2pa-check image.jpg
image.jpg
  Content Credentials   PRESENT
  Manifest              VALID
  Trust                 TRUSTED (2026-08-13-a1b2c3d4e5f6)
  Signer                OpenAI Inc. · DigiCert
  Digital source        trainedAlgorithmicMedia (AI generated)
  Actions               c2pa.created
```

```bash
c2pa-check 'dist/**/*.{jpg,png,webp}' --coverage 100     # CI gate
c2pa-check https://cdn.example.com/hero.jpg --expect trusted
c2pa-check photo.jpg --format json | jq .result.credential.status
c2pa-check inspect photo.jpg                              # manifest tree
c2pa-check trust status                                   # which list judged it
c2pa-check mcp                                            # stdio MCP server
c2pa-check 'dist/**/*.jpg' --format junit --output c2pa-check.xml  # report to a file
c2pa-check doctor                                         # key, quota, network, webhook secret, Node
```

`--format text|json|ndjson|junit` (default `text`) and `--output PATH` (default: stdout) apply
to the check command. JUnit marks every target that is not `valid_trusted` as a failure.

| Exit | Meaning |
|---|---|
| `0` | pass |
| `1` | expectation or coverage failed · `doctor` found a failing check · `carry --strict` found an unpaired file |
| `2` | usage or I/O error |
| `3` | unreadable asset (missing or unreadable local file, over 64 MiB, malformed manifest) |
| `4` | a URL could not be fetched |
| `5` | `carry` refused (rule in `--json`) |

## Check your setup

```console
$ npx -y c2pa-check doctor
ok    api_key         live key c2pa_live_AbC…
ok    network         https://api.c2pa.design/v1 answered HTTP 200
ok    whoami          live key, organization Acme, plan team, signatures 940 of 1000 left until 2026-11-01
ok    webhook_secret  valid (whsec_ + base64)
ok    node            Node.js 22.11.0
```

| Check | Reads | Fails when |
|---|---|---|
| `api_key` | `C2PA_API_KEY` (deprecated fallback `C2PA_DESIGN_API_KEY`) | not `c2pa_live_` / `c2pa_test_` + 32 letters and digits (unset is a warning) |
| `network` | `C2PA_API_BASE` (deprecated fallback `C2PA_DESIGN_API_URL`, default `https://api.c2pa.design/v1`) | no HTTP answer |
| `whoami` | `GET {C2PA_API_BASE}/whoami` | the key is refused; an exhausted quota is a warning |
| `webhook_secret` | `C2PA_WEBHOOK_SECRET` | not `whsec_` + standard base64 (unset is skipped) |
| `node` | the Node.js running `npx` | older than 18 |

`doctor --json` prints `{ok, api_base, checks: [{name, state, detail, data?}]}` with `state`
`ok | warn | fail | skip`; the `whoami` check carries the API answer in `data`.

## In CI

```yaml
- uses: c2pa-design/c2pa-check-action@v1
  with:
    paths: "public/**/*.{jpg,png,webp}"
    coverage: 100
    format: junit
    output: c2pa-check.xml
```

The action installs the release named by `version` (default `v0.2.0`) and checks it against the
release's `SHA256SUMS` before running it. Every release publishes `SHA256SUMS` and a GitHub
build-provenance attestation (`gh attestation verify c2pa-check-<target>.tar.gz -R
c2pa-design/c2pa-check`); the npm packages are published with npm provenance
(`npm audit signatures`).

Outside GitHub Actions, any image with Node.js 18+ runs `npx -y c2pa-check@0.2.0`
(`node:22-bookworm-slim` is the smallest that also has the glibc tools most pipelines expect;
the binary itself is static musl, so `node:22-alpine` works too). Pin the version so `npx` hits
its cache instead of resolving `latest` on every run, and cache `~/.npm` between jobs; or skip
Node entirely and download the static binary from the release.

Add `urls:` to check what your CDN actually serves after a deploy — that is where credentials
usually disappear.

## Keep the credential through conversion

Re-encoding, resizing or compressing a file drops its manifest, and copying the old manifest back
does not help: the signature covers the old bytes. `carry` writes a new manifest into the
converted copy with the original as its `parentOf` ingredient, so the chain back to the
generator survives.

```bash
npx -y c2pa-check carry --from hero.png --to hero.webp            # one pair, in place
npx -y c2pa-check carry 'public/**/*.{webp,avif}' --from-dir src/  # pairs by file name
c2pa-check carry --from clip.mov --to clip.mp4 --force            # non-picture media
c2pa-check keygen --out-dir .c2pa                                  # cert.pem + key.pem for CI
c2pa-check carry --from hero.png --to hero.webp --json            # machine-readable result
```

| Signer (first that is set) | Signed as | Verifies as |
|---|---|---|
| `C2PA_SIGN_CERT` + `C2PA_SIGN_KEY` (PEM, a path, or `*_FILE`) | your certificate | `valid_trusted` if your CA is on the C2PA trust list |
| `C2PA_API_KEY` (deprecated fallback `C2PA_DESIGN_API_KEY`) | "<your verified domain> via c2pa.design" | `valid_untrusted` |
| nothing | a local key in `~/.config/c2pa-check/identity` | `valid_untrusted` |

Pictures are compared first by perceptual hash; a different picture or an original without a
credential is refused with exit `5`. With an API key, c2pa.design checks the carry again and
signs only an honest one; if hosted signing is unavailable, `carry` signs locally and warns.
Never `COPY` or `ARG` a key into a Docker image: use `RUN --mount=type=secret`.

`carry --json` prints one object (an array for several files):

```json
{"status": "refused", "rule": "different_picture", "message": "the two files are not the same picture",
 "source": "hero.png", "derived": "hero.webp"}
```

`status` is `carried | composed | skipped | refused | error | unpaired | ambiguous`; `output`
is the file written; `credential_status` is how the written file verifies. `rule` is set on a
refusal: `different_picture`, `source_unsigned`, `low_quality`, `not_comparable`, or the rule
c2pa.design returned with `carry_rejected` (`source_invalid`, `ingredient_mismatch`,
`action_not_allowed`, `generator_changed`, `certificate_mismatch`, …). Refusals exit `5`.

### Composites and generated assets

An atlas, sprite sheet or collage is a new work, not a conversion. `--compose` signs the
rendered file with every source attached as a `componentOf` ingredient (each keeps its own
manifest) and a `c2pa.created` action (digital source type `composite`), plus `c2pa.placed`
per source:

```bash
c2pa-check carry --compose a.png b.png c.png --to atlas.webp
c2pa-check carry --compose base.png logo.png --to banner.webp --edited   # base.png is parentOf
```

`--edited` records `c2pa.opened` on the first source (as `parentOf`), `c2pa.edited`, and
`c2pa.placed` for the rest. Composites are signed with `C2PA_SIGN_CERT` / `C2PA_SIGN_KEY` or
the local key; hosted signing does not accept composites yet, so with only an API key the
composite is signed locally and `carry` warns.

## For AI agents

The agent skill lives in [c2pa-design/skills](https://github.com/c2pa-design/skills):

```bash
npx skills add c2pa-design/skills
```

MCP only: `claude mcp add c2pa-check -- npx -y c2pa-check mcp`. `initialize` echoes the client's
`protocolVersion` when supported (`2026-07-28`, `2025-11-25`, `2025-06-18`, `2025-03-26`), else `2026-07-28`.

## How trust works

A signature proves the bytes have not changed since signing. It says nothing about *who*
signed. "Trusted" means the signer's certificate chains to the official
[C2PA trust list](https://github.com/c2pa-org/conformance-public/tree/main/trust-list), which is
compiled into every release; `c2pa-check trust status` prints the snapshot date and whether
upstream has moved, `trust update` fetches a newer one, and `--offline` pins CI to the bundled
copy. `docs/TRUST.md` has the details.

Absence of a credential proves nothing: most files on the internet carry none.

## Library

`c2pa-check-core` produces the same normalized document (schema v1,
`crates/c2pa-check-core/schema/result.v1.json`) that the browser tools and the c2pa.design API
return, so a local check and a hosted check never disagree.

```rust
let bundle = c2pa_check_core::TrustBundle::bundled();
let report = c2pa_check_core::verify(&bytes, "image/jpeg", &bundle, &Default::default())?;
println!("{}", report.credential.status.as_str());
```

## Licence

[MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE). Contributions under DCO, no CLA.

---

Monitor production provenance across your whole pipeline at **[c2pa.design](https://c2pa.design)**.
