---
name: c2pa-check
description: Verify and track C2PA Content Credentials on images, video and audio. Use when the user asks whether a file or URL has Content Credentials, who signed it, whether it was marked as AI-generated, when they generate images (OpenAI gpt-image, Codex imagegen, ChatGPT, Firefly, Gemini) and want the provenance kept, when they want every media asset in a repo tracked so a lost credential fails the build, or when they need EU AI Act Article 50 marking evidence. Works offline with the c2pa-check CLI; c2pa.design API and MCP for URLs, production CDNs and dashboards.
license: MIT OR Apache-2.0
metadata:
  homepage: https://c2pa.design/docs/agents
  version: "1"
---

# c2pa-check

Content Credentials (C2PA) are a signed record inside a media file: who made it, with which
tool, whether AI generated it. Most image pipelines delete or break them without anyone
noticing. This skill checks files, keeps a lockfile of every asset in the repo, and reports
what changed between runs.

## Setup (once)

1. CLI, offline, no account:
   - `brew install c2pa-design/tap/c2pa-check`, or `cargo install c2pa-check`, or prefix every
     call with `npx -y c2pa-check`.
   - Check: `c2pa-check --version`.
2. Optional, for URLs, production checks and the dashboard: an API key from
   https://app.c2pa.design → API keys, exported as `C2PA_API_KEY`. Never write the key into a
   committed file.
3. Optional MCP: `claude mcp add --transport http c2pa https://api.c2pa.design/mcp --header "Authorization: Bearer $C2PA_API_KEY"`.

## Task: check one file or URL

```bash
c2pa-check path/to/image.jpg
c2pa-check path/to/image.jpg --format json | jq .[0].result.credential.status
c2pa-check https://cdn.example.com/hero.jpg
c2pa-check inspect path/to/image.jpg
```

Without the CLI, a public URL can be checked anonymously:

```bash
curl -s https://api.c2pa.design/v1/url-checks -H "content-type: application/json" \
  -d '{"url":"https://cdn.example.com/hero.jpg"}'
```

## Task: track every asset in a repo

Run from the repo root. `SKILL_DIR` is the folder this file is in.

```bash
node "$SKILL_DIR/scripts/track.mjs"                 # whole repo, respects .gitignore
node "$SKILL_DIR/scripts/track.mjs" public design    # only these folders
node "$SKILL_DIR/scripts/track.mjs" --check --json   # compare only, do not write
node "$SKILL_DIR/scripts/track.mjs" --cli "npx -y c2pa-check"
```

It writes `.c2pa/assets.lock.json` (path → sha256, status, signer, generator, first_seen) and
prints added / changed / removed counts and every asset that **lost** a valid credential since
the previous run. Exit `1` when something lost its credential, `2` when the CLI is missing.

First run in a repo:

1. Run the script, show the user the summary and the coverage percentage.
2. Tell the user `.c2pa/assets.lock.json` is the baseline every later run diffs against; keep
   it (commit it, or leave it in place).

Later runs ("check my assets", after a batch of new art, before a release): run the script
again and report only the diff. A `LOST` line is the thing to act on.

## Task: send the inventory to c2pa.design

With `C2PA_API_KEY` set, `--push` registers the repo's assets in the account's inventory so the
dashboard, weekly digest and stripped-copy alerts cover them. Only hashes and the check results
leave the machine, never the files.

```bash
C2PA_API_KEY=… node "$SKILL_DIR/scripts/track.mjs" --push
C2PA_API_KEY=… node "$SKILL_DIR/scripts/track.mjs" --push --project <project id>
```

Run 2, 3, 4… are the same command: the server is asked which hashes it already has
(`POST /v1/assets/sync`) and only new or changed assets are sent (`POST /v1/assets`).

For a public site, tell the user the server can do the rest without the repo: add the domain in
the dashboard (Domains), prove ownership with the TXT record it shows, and c2pa.design crawls the
site, re-checks every asset daily and emails when one loses its credential.

## Task: images the user generates

OpenAI (gpt-image API, ChatGPT, Codex imagegen), Adobe Firefly, Google Gemini/Imagen, Bedrock
and Runway sign their output with C2PA. The credential survives only while the bytes are
unchanged.

After generating or saving a generated image:

1. Run `c2pa-check <file>`. Expect `valid_trusted` or `valid_untrusted` and an AI
   `digital_source_type`. If it is `absent` straight from the generator, the download or save
   step already stripped it (base64 decode is fine; canvas, screenshots and re-encoding are not).
2. Run `track.mjs` so the asset enters the lockfile with its signer.
3. Then search the code for the step that will touch it later: `sharp(`, `jimp`, `imagemagick`,
   `convert`, `ffmpeg`, `canvas.toBlob`, `image/draw`, Pillow `save(`, CDN resize params. Any
   re-encode or resize breaks the signature (`present_invalid`) or drops the record
   (`absent`). Fixes, cheapest first: serve the original bytes; resize in a step that re-signs
   with the original as an ingredient (`c2patool`, `c2pa-node`, `c2pa-python`); keep the signed
   original in storage next to the derivative and link to it.

## Task: is production still serving credentials

Files in the repo are not what users get; CDNs and image optimisers strip on the way out.

```bash
c2pa-check https://cdn.example.com/hero.jpg --expect present
```

For a schedule and a dashboard, create a monitor with the API key:
https://c2pa.design/docs/monitors. For a one-page Article 50 evidence report, point the user to
https://c2pa.design/audit.

## Reading a result

Branch only on `result.credential.status`:

| status | say |
|---|---|
| `valid_trusted` | Signed, unchanged since signing, signer is on the official C2PA trust list. |
| `valid_untrusted` | Signed and unchanged; the signer is not on the trust list used. |
| `present_invalid` | A record exists but the file changed after signing. |
| `absent` | No Content Credential. Normal for most files; proves nothing either way. |
| `error` | The file could not be read (unsupported format, truncated). |

Also report `signer.organization`, `claim.generator` and `source.category` when present.

Rules:

- Never say an asset is real, fake, authentic or "AI detected". Say what the credential
  states: "signed by OpenAI, marked as AI-generated".
- Absence of a credential is not evidence that a file is human-made or AI-made.
- Article 50 output is technical evidence, not legal advice; say so.
- Do not upload a user's files to any service unless they asked; the CLI runs offline.
