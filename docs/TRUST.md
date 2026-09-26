# How trust works in c2pa-check

## The three questions

| Question | Field | What a "no" means |
|---|---|---|
| Is there a credential at all? | `credential.present` | Nothing declares an origin. Not evidence of anything. |
| Do the bytes match the signature? | `credential.valid` | The file changed after it was signed. |
| Do we recognise the signer? | `credential.trusted` | The signature is intact but the certificate does not chain to a list we accept. |

`credential.status` collapses those into the one value a user interface colors:
`absent`, `present_invalid`, `valid_untrusted`, `valid_trusted`, `error`.

## Which list

| Selector | List | Use it when |
|---|---|---|
| `official` (default) | `C2PA-TRUST-LIST.pem` from `c2pa-org/conformance-public` | Always, unless you have a reason not to. |
| `interim` | The frozen CAI list (2026-01-01) | Reproducing what CAI Verify shows. |
| `both` | Official plus interim | Migration windows. |
| `none` | No anchors | You only care whether the bytes match the signature. |

Every report carries `engine.trust_list_version` — the snapshot date plus the first twelve hex
characters of the bundle's SHA-256. Two results with different versions are not comparable.

## Pinning

`--offline` uses only the compiled-in snapshot, so a CI run gives the same answer in six months.
Without it, a bundle fetched by `c2pa-check trust update` into `~/.cache/c2pa-check` wins.
`--trust-anchors <path>` replaces both with your own PEM, which is what you want for an internal CA.

## Refreshing

`.github/workflows/trust-list-sync.yml` diffs upstream weekly and opens a pull request when it
changes. A release follows. Nothing is fetched at build time.
