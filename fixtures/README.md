# Fixture corpus

Every file has an `<name>.expected.json` next to it holding the outcome `c2pa-check-core` must
produce for it: either `{"credential": "<status>"}` or `{"error": "<code>"}`, plus a free-text
`note`. `cargo test -p c2pa-check-core --test corpus` runs every fixture and diffs the two; it
also refuses a fixture with no expected document, one larger than 2 MB, and any expectation of
`valid_trusted` while the bundled trust list is still the placeholder.

Wiring the same corpus into the TypeScript analyzer and the Go integration tests is still open:
the browser path needs the C2PA WASM under a headless runner, and the Go path needs a live
engine. Until then only the Rust implementation is held to this corpus.

| File | What it proves |
|---|---|
| `jpeg/no-manifest.jpg` | absence is the default state, not a finding |
| `jpeg/valid-trusted-openai.jpg` | a real generator output chains to the official list |
| `jpeg/valid-interim-only.jpg` | a signer only on the frozen CAI list is `valid_untrusted` under `--trust official` |
| `jpeg/valid-untrusted-selfsigned.jpg` | a self-signed manifest is intact but not trusted |
| `jpeg/tampered-pixels.jpg` | bytes edited after signing → `present_invalid` |
| `jpeg/corrupted-manifest.jpg` | a truncated JUMBF box is an error, not a crash |
| `jpeg/expired-signer.jpg` | expiry is a warning, not an invalid signature |
| `jpeg/multi-ingredient-edited.jpg` | an edit chain keeps its ingredients |
| `png/`, `webp/` | the same table per container |
| `bombs/decompression.png` | a 65 KB file that inflates to 67 MB verifies normally, because pixels are never decoded |
| `bombs/huge-dimensions.png` | a declared 60000×60000 header is refused by `max_pixels`, never allocated |
| `bombs/deep-ingredients.jpg` | ingredient depth is capped |

## What is generated and what is not

`scripts/make-fixtures.mjs` produces every fixture that needs no signing key — the
no-manifest files, the truncated JUMBF, and the two bombs — deterministically, so the corpus is
reproducible from source rather than a pile of committed binaries nobody can regenerate.

```bash
node scripts/make-fixtures.mjs
```

The **signed** fixtures cannot be generated here: they need `c2patool` and a certificate.
Produce them once, commit the asset and its `.expected.json`, and record the exact command in
`fixtures/<name>.cmd` so the next person can rebuild it:

```bash
# valid, untrusted: the SDK test certificate chains to nothing anyone accepts
c2patool jpeg/no-manifest.jpg -m manifests/created.json -o jpeg/valid-untrusted-selfsigned.jpg

# valid, trusted: needs a production certificate from SSL.com or DigiCert
c2patool jpeg/no-manifest.jpg -m manifests/created.json \
  --signer-path certs/production.pem -o jpeg/valid-trusted.jpg

# tampered: sign, then edit one byte of pixel data
c2patool ... -o jpeg/tampered-pixels.jpg && printf '\x00' | dd of=jpeg/tampered-pixels.jpg bs=1 seek=900 conv=notrunc
```

`jpeg/valid-trusted-openai.jpg` is a real generator output, kept because a synthetic fixture
cannot prove that a real signer's chain reaches the official list. Only redistributable assets
go in here: ours, or a vendor sample we have permission for. Never a customer file.
