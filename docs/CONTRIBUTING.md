# Contributing

1. `cargo test --workspace` must pass, and `cargo clippy --all-targets -- -D warnings`.
2. Every bug becomes a fixture: put the asset in `fixtures/<format>/`, the expected document in
   `fixtures/<format>/<name>.expected.json`, and the fixture test will hold the behaviour.
3. Fixtures must be redistributable — assets we generated, or vendor samples with permission.
   Never a customer file.
4. Sign off commits (`git commit -s`). DCO, no CLA.
5. The result document is a contract shared with the browser analyzer and the hosted API. A change
   to `schema/result.v1.json` is a new schema version, not an edit.
