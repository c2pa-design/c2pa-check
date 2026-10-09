import { chmodSync, copyFileSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join } from "node:path";

const [dist, version, ...npmArgs] = process.argv.slice(2);
if (!dist || !/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(version ?? "")) {
  console.error("usage: node npm/publish.mjs <artifacts-dir> <version> [npm publish args]");
  process.exit(2);
}

const targets = {
  "x86_64-unknown-linux-musl": ["linux", "x64"],
  "aarch64-unknown-linux-musl": ["linux", "arm64"],
  "aarch64-apple-darwin": ["darwin", "arm64"],
  "x86_64-apple-darwin": ["darwin", "x64"],
};
const common = {
  version,
  license: "MIT OR Apache-2.0",
  repository: { type: "git", url: "git+https://github.com/c2pa-design/c2pa-check.git" },
  homepage: "https://c2pa.design",
};
const out = "npm-out";
rmSync(out, { recursive: true, force: true });

const published = (name) => {
  try {
    return execFileSync("npm", ["view", `${name}@${version}`, "version"], { encoding: "utf8" }).trim() === version;
  } catch {
    return false;
  }
};
const publish = (dir) => {
  const { name } = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
  if (published(name)) return console.log(`${name}@${version} already published, skipping`);
  try {
    execFileSync("npm", ["publish", "--access", "public", ...npmArgs], { cwd: dir, stdio: ["inherit", "inherit", "pipe"] });
  } catch (e) {
    const err = String(e.stderr);
    process.stderr.write(err);
    if (!/previously (staged|published)/.test(err)) throw e;
    console.log(`${name}@${version} already on the registry, skipping`);
  }
};

const optional = {};
for (const [target, [os, cpu]] of Object.entries(targets)) {
  const name = `c2pa-check-${os}-${cpu}`;
  const exe = os === "win32" ? "c2pa-check.exe" : "c2pa-check";
  const dir = join(out, name);
  mkdirSync(dir, { recursive: true });
  copyFileSync(join(dist, `c2pa-check-${target}`, exe), join(dir, exe));
  chmodSync(join(dir, exe), 0o755);
  writeFileSync(join(dir, "package.json"), JSON.stringify({
    name, ...common, description: `c2pa-check binary for ${os}-${cpu}`, os: [os], cpu: [cpu], files: [exe],
  }, null, 2));
  publish(dir);
  optional[name] = version;
}

const main = join(out, "c2pa-check");
mkdirSync(join(main, "bin"), { recursive: true });
copyFileSync("npm/c2pa-check.js", join(main, "bin", "c2pa-check.js"));
copyFileSync("README.md", join(main, "README.md"));
writeFileSync(join(main, "package.json"), JSON.stringify({
  name: "c2pa-check", ...common,
  description: "Verify Content Credentials from the command line and fail a build when provenance disappears.",
  bin: { "c2pa-check": "bin/c2pa-check.js" },
  files: ["bin"],
  engines: { node: ">=18" },
  optionalDependencies: optional,
}, null, 2));
publish(main);
