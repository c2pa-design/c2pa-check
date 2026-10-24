# Contributing

1. `cargo test --workspace` must pass, and `cargo clippy --all-targets -- -D warnings`.
2. Every bug becomes a fixture: put the asset in `fixtures/<format>/`, the expected document in
   `fixtures/<format>/<name>.expected.json`, and the fixture test will hold the behaviour.
3. Fixtures must be redistributable — assets we generated, or vendor samples with permission.
   Never a customer file.
4. Sign off commits (`git commit -s`). DCO, no CLA.
5. The result document is a contract shared with the browser analyzer and the hosted API. A change
   to `schema/result.v1.json` is a new schema version, not an edit.
6. CI runs default features. `avif` and `heic` link dav1d and libheif ≥ 1.23, which the engine
   image builds from source; the engine's CI covers them.

## Audit exceptions

`cargo audit` reads `.cargo/audit.toml`. Every ignored advisory reaches us through the pinned
`c2pa` crate and goes when a `c2pa` release drops it.

| Advisory | Crate | Why it does not apply |
|---|---|---|
| RUSTSEC-2023-0071 | `rsa` 0.9 | Marvin is a timing attack on RSA private-key operations; we only verify RSA signatures and sign with ES256 |
| RUSTSEC-2026-0387 | `crypto-bigint` 0.5 | timing variance in ECDSA signing; the only key we sign with is the local key on the user's own machine, never a remote request |
| RUSTSEC-2026-0367, RUSTSEC-2026-0368, RUSTSEC-2026-0369 | `zip` 8 | all three are in `ZipArchive::extract` / `ZipStreamReader::extract`; `c2pa` reads archives in memory and never calls them |
