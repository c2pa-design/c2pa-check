# Bundled trust list

`C2PA-TRUST-LIST.pem` and `C2PA-TSA-TRUST-LIST.pem` are snapshots of

    https://github.com/c2pa-org/conformance-public/tree/main/trust-list

taken on the date in `VERSION`. They are compiled into the binary so `--offline` gives a
deterministic answer in CI, and `c2pa-check trust update` fetches a newer pair into
`~/.cache/c2pa-check` without a release.

`.github/workflows/trust-list-sync.yml` opens a pull request whenever upstream changes.
Run `scripts/fetch-trust-list.sh` to refresh them by hand.
