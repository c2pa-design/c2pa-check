# Examples

`curl.sh`, `node.mjs`, `python.py` and `go/main.go` all do the same thing against the hosted
API: check a URL, print `credential.status`, and exit non-zero when the credential is not
trusted. They exist so a reader can copy one file and be integrated in a minute.

The CLI in this repository answers the same question offline; the API answers it for a whole
pipeline on a schedule.
