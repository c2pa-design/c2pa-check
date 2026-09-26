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
```

Exit codes: `0` pass · `1` expectation or coverage failed · `2` usage · `3` unreadable asset ·
`4` network.

## In CI

```yaml
- uses: c2pa-design/c2pa-check-action@v1
  with:
    paths: "public/**/*.{jpg,png,webp}"
    coverage: 100
    format: junit
```

Add `urls:` to check what your CDN actually serves after a deploy — that is where credentials
usually disappear.

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

## This directory

Inside the c2pa.design monorepo `cli/` is a **separate git repository**
(`github.com/c2pa-design/c2pa-check`), ignored by the root `.gitignore`. It never depends on
anything private; the private `engine/` depends on **it**.

```bash
cd cli && git init && git remote add origin git@github.com:c2pa-design/c2pa-check.git
```

## Licence

MIT OR Apache-2.0. Contributions under DCO, no CLA.

---

Monitor production provenance across your whole pipeline at **[c2pa.design](https://c2pa.design)**.
