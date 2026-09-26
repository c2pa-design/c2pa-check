# scripts

| Script | Does |
|---|---|
| `fetch-trust-list.sh` | Refresh the bundled snapshot from `c2pa-org/conformance-public`. Refuses a bundle with fewer than twenty certificates. |
| `make-fixtures.mjs` | Generate every fixture that needs no signing key, deterministically. |

Both are run by CI: the first weekly, opening a pull request when upstream moves; the second
before the fixture tests, so a corpus that drifts from its generator fails rather than rots.
