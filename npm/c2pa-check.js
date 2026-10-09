#!/usr/bin/env node
const { spawnSync } = require("node:child_process");

const pkg = `c2pa-check-${process.platform}-${process.arch}`;
const exe = process.platform === "win32" ? "c2pa-check.exe" : "c2pa-check";
let bin;
try {
  bin = require.resolve(`${pkg}/${exe}`);
} catch {
  console.error(`c2pa-check: no prebuilt binary for ${process.platform}-${process.arch}; use cargo install c2pa-check`);
  process.exit(2);
}
const r = spawnSync(bin, process.argv.slice(2), { stdio: "inherit", env: { ...process.env, C2PA_CHECK_NODE_VERSION: process.versions.node } });
if (r.error) throw r.error;
process.exit(r.status ?? 1);
