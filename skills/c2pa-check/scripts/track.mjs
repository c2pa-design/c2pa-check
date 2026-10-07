#!/usr/bin/env node
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, extname, join, relative } from "node:path";

const EXT = new Set([".jpg", ".jpeg", ".png", ".webp", ".avif", ".heic", ".heif", ".tif", ".tiff", ".svg", ".mp4", ".mov", ".mp3", ".wav", ".pdf"]);
const SKIP = new Set(["node_modules", ".git", ".next", "dist", "build", "target", ".c2pa"]);
const SIGNED = new Set(["valid_trusted", "valid_untrusted"]);

const args = process.argv.slice(2);
const flag = (name) => args.includes(name);
const opt = (name, fallback) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : fallback;
};
const VALUED = ["--lock", "--cli", "--project"];
const roots = args.filter((a, i) => !a.startsWith("--") && !VALUED.includes(args[i - 1]));
const lockPath = opt("--lock", ".c2pa/assets.lock.json");
const cli = (opt("--cli", process.env.C2PA_CHECK ?? "c2pa-check")).split(" ");

function gitFiles() {
  try {
    const out = execFileSync("git", ["ls-files", "-z", "--cached", "--others", "--exclude-standard", ...roots], { maxBuffer: 1 << 28, stdio: ["ignore", "pipe", "ignore"] });
    return out.toString().split("\0").filter(Boolean);
  } catch {
    return null;
  }
}

function walk(dir, acc = []) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (SKIP.has(e.name)) continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) walk(p, acc);
    else acc.push(relative(".", p));
  }
  return acc;
}

let files = (gitFiles() ?? (roots.length ? roots : ["."]).flatMap((r) => walk(r)))
  .filter((f) => EXT.has(extname(f).toLowerCase()) && existsSync(f));
files = [...new Set(files)];
const arg = (f) => (f.startsWith("-") ? `./${f}` : f).replace(/[*?[]/g, "[$&]");
const key = (t) => t.replace(/^\.\//, "");

const results = new Map();
for (let i = 0; i < files.length; i += 200) {
  const chunk = files.slice(i, i + 200).map(arg);
  const run = spawnSync(cli[0], [...cli.slice(1), ...chunk, "--format", "ndjson", "--offline"], { maxBuffer: 1 << 28 });
  if (run.error) {
    console.error(`cannot run ${cli.join(" ")}: ${run.error.message}. Install: brew install c2pa-design/tap/c2pa-check, or pass --cli "npx -y c2pa-check".`);
    process.exit(2);
  }
  for (const line of run.stdout.toString().split("\n").filter(Boolean)) {
    const { target, result } = JSON.parse(line);
    results.set(key(target), result);
  }
  if (run.status === 2 || run.status === null) {
    console.error(`${cli.join(" ")} failed: ${run.stderr.toString().trim()}`);
    process.exit(2);
  }
}
const missing = files.filter((f) => !results.has(f));
if (missing.length) {
  console.error(`no result for ${missing.length} files, e.g. ${missing[0]}; lockfile not updated`);
  process.exit(2);
}

const before = existsSync(lockPath) ? JSON.parse(readFileSync(lockPath, "utf8")).assets ?? {} : {};
const now = new Date().toISOString();
const after = {};
const diff = { added: [], changed: [], lost: [], gained: [], removed: [] };

for (const f of files) {
  const r = results.get(f);
  const entry = {
    sha256: r?.asset?.sha256 ?? null,
    status: r?.credential?.status ?? "error",
    signer: r?.signer?.organization ?? null,
    generator: r?.claim?.generator ?? null,
    source: r?.source?.category ?? null,
    first_seen: before[f]?.first_seen ?? now,
  };
  after[f] = entry;
  const prev = before[f];
  if (!prev) diff.added.push(f);
  else if (prev.sha256 !== entry.sha256) diff.changed.push(f);
  if (prev && SIGNED.has(prev.status) && !SIGNED.has(entry.status)) diff.lost.push(f);
  if (prev && !SIGNED.has(prev.status) && SIGNED.has(entry.status)) diff.gained.push(f);
}
for (const f of Object.keys(before)) if (!(f in after)) diff.removed.push(f);

const counts = {};
for (const e of Object.values(after)) counts[e.status] = (counts[e.status] ?? 0) + 1;
const signed = Object.values(after).filter((e) => SIGNED.has(e.status)).length;

if (!flag("--check")) {
  mkdirSync(dirname(lockPath), { recursive: true });
  const sorted = Object.fromEntries(Object.entries(after).sort(([a], [b]) => a.localeCompare(b)));
  writeFileSync(lockPath, JSON.stringify({ version: 1, checked_at: now, counts, assets: sorted }, null, 2) + "\n");
}

const summary = {
  assets: files.length,
  coverage_pct: files.length ? Math.round((signed / files.length) * 1000) / 10 : 0,
  counts,
  added: diff.added.length,
  changed: diff.changed.length,
  removed: diff.removed.length,
  lost_credentials: diff.lost,
  gained_credentials: diff.gained,
  lock: lockPath,
};

if (flag("--json")) console.log(JSON.stringify({ summary, diff }, null, 2));
else {
  console.log(`${summary.assets} assets, ${summary.coverage_pct}% carry a valid Content Credential`);
  console.log(Object.entries(counts).map(([k, v]) => `  ${k}: ${v}`).join("\n"));
  console.log(`added ${summary.added}, changed ${summary.changed}, removed ${summary.removed}`);
  for (const f of diff.lost) console.log(`  LOST  ${f}  (${before[f].status} -> ${after[f].status})`);
  for (const f of diff.gained) console.log(`  GAINED  ${f}`);
}

async function api(path, body) {
  const base = (process.env.C2PA_API_URL ?? "https://api.c2pa.design/v1").replace(/\/$/, "");
  const res = await fetch(base + path, {
    method: "POST",
    headers: { authorization: `Bearer ${process.env.C2PA_API_KEY}`, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`${path} ${res.status}: ${text.slice(0, 300)}`);
  return JSON.parse(text);
}

async function push() {
  if (!process.env.C2PA_API_KEY) {
    console.error("--push needs C2PA_API_KEY (app.c2pa.design → API keys)");
    process.exit(2);
  }
  const project = opt("--project", undefined);
  const hashes = [...new Set(Object.values(after).map((e) => e.sha256).filter(Boolean))];
  const unknown = new Set();
  for (let i = 0; i < hashes.length; i += 5000) {
    const { unknown: u } = await api("/assets/sync", { project_id: project, hashes: hashes.slice(i, i + 5000) });
    u.forEach((h) => unknown.add(h));
  }
  const touched = new Set([...diff.added, ...diff.changed, ...diff.lost, ...diff.gained]);
  const items = files
    .filter((f) => results.get(f)?.asset?.sha256 && (unknown.has(after[f].sha256) || touched.has(f)))
    .map((f) => ({ location: f, project_id: project, source: "skill", result: results.get(f) }));
  for (let i = 0; i < items.length; i += 500) await api("/assets", { items: items.slice(i, i + 500) });
  if (!flag("--json")) console.log(`pushed ${items.length} assets (${unknown.size} new to the inventory)`);
}

if (flag("--push")) {
  try {
    await push();
  } catch (err) {
    console.error(`push failed: ${err.message}`);
    process.exit(2);
  }
}

process.exit(diff.lost.length ? 1 : 0);
