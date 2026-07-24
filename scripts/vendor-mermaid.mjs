#!/usr/bin/env node
// Biniam Demissie Reproducible, deterministic vendoring of the pinned Mermaid runtime.
// Rev·Deck renders Mermaid diagrams entirely from self-hosted assets: there is NO
// runtime CDN and NO `<script src="https://...">`.

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  rmSync,
  readdirSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "..");

// The exact Mermaid version we vendor. Kept in lockstep with package.json /
// package-lock.json; the script asserts the installed version matches so a
// silent drift (e.g. a hand-edited node_modules) fails the build.
const MERMAID_VERSION = "11.16.0";

// Files copied verbatim from node_modules/mermaid/dist into the vendor dir.
// `mermaid.min.js` is the runtime; the license is carried alongside it for
// attribution/compliance.
const SOURCES = [
  { from: "node_modules/mermaid/dist/mermaid.min.js", to: "mermaid.min.js" },
  { from: "node_modules/mermaid/LICENSE", to: "LICENSE" },
];

const VENDOR_DIR = join(ROOT, "webui", "static", "vendor", "mermaid");
const MANIFEST_PATH = join(VENDOR_DIR, "manifest.json");

function sha256(buf) {
  return createHash("sha256").update(buf).digest("hex");
}

function log(msg) {
  process.stdout.write(`[vendor-mermaid] ${msg}\n`);
}

function fail(msg) {
  process.stderr.write(`[vendor-mermaid] ERROR: ${msg}\n`);
  process.exit(1);
}

function ensureInstalled() {
  const pkgPath = join(ROOT, "node_modules", "mermaid", "package.json");
  if (!existsSync(pkgPath)) {
    log("node_modules/mermaid missing; running `npm ci`...");
    execFileSync("npm", ["ci", "--no-audit", "--no-fund"], {
      cwd: ROOT,
      stdio: "inherit",
    });
  }
  const installed = JSON.parse(readFileSync(pkgPath, "utf8")).version;
  if (installed !== MERMAID_VERSION) {
    fail(
      `installed mermaid ${installed} != pinned ${MERMAID_VERSION}. ` +
        "Update MERMAID_VERSION and package.json together, then re-run."
    );
  }
  return installed;
}

function readSource(rel) {
  const p = join(ROOT, rel);
  if (!existsSync(p)) fail(`expected source file missing: ${rel}`);
  return readFileSync(p);
}

function writeManifest(manifest) {
  const ordered = {
    name: manifest.name,
    version: manifest.version,
    algorithm: manifest.algorithm,
    files: Object.fromEntries(
      Object.keys(manifest.files)
        .sort()
        .map((k) => [k, manifest.files[k]])
    ),
  };
  writeFileSync(MANIFEST_PATH, JSON.stringify(ordered, null, 2) + "\n");
}

function doVendor() {
  const version = ensureInstalled();
  log(`vendoring mermaid ${version}`);

  // Recreate the vendor dir cleanly so a removed source file cannot linger.
  if (existsSync(VENDOR_DIR)) {
    for (const entry of readdirSync(VENDOR_DIR)) {
      rmSync(join(VENDOR_DIR, entry), { recursive: true, force: true });
    }
  } else {
    mkdirSync(VENDOR_DIR, { recursive: true });
  }

  const files = {};
  for (const { from, to } of SOURCES) {
    const buf = readSource(from);
    writeFileSync(join(VENDOR_DIR, to), buf);
    files[to] = { sha256: sha256(buf), bytes: buf.length };
    log(`  ${to}  (${buf.length} bytes, sha256 ${files[to].sha256.slice(0, 16)}…)`);
  }

  writeManifest({
    name: "mermaid",
    version: MERMAID_VERSION,
    algorithm: "sha256",
    files,
  });
  log(`wrote manifest ${MANIFEST_PATH}`);
  log("done.");
}

function doVerify() {
  if (!existsSync(MANIFEST_PATH)) {
    fail("manifest.json missing; run `npm run vendor` first.");
  }
  const manifest = JSON.parse(readFileSync(MANIFEST_PATH, "utf8"));
  if (manifest.version !== MERMAID_VERSION) {
    fail(
      `manifest version ${manifest.version} != pinned ${MERMAID_VERSION}`
    );
  }
  let ok = true;
  const expectedNames = SOURCES.map((s) => s.to).sort();
  const manifestNames = Object.keys(manifest.files).sort();
  if (JSON.stringify(expectedNames) !== JSON.stringify(manifestNames)) {
    fail(
      `manifest file set ${JSON.stringify(manifestNames)} != expected ` +
        JSON.stringify(expectedNames)
    );
  }
  for (const { to } of SOURCES) {
    const p = join(VENDOR_DIR, to);
    if (!existsSync(p)) {
      process.stderr.write(`[vendor-mermaid] MISSING vendored file: ${to}\n`);
      ok = false;
      continue;
    }
    const buf = readFileSync(p);
    const actual = sha256(buf);
    const expected = manifest.files[to] && manifest.files[to].sha256;
    if (actual !== expected) {
      process.stderr.write(
        `[vendor-mermaid] HASH MISMATCH ${to}\n  expected ${expected}\n  actual   ${actual}\n`
      );
      ok = false;
    } else {
      log(`  ok ${to}  sha256 ${actual.slice(0, 16)}…`);
    }
  }
  if (!ok) fail("vendored assets do not match the manifest.");
  log(`verify OK — mermaid ${manifest.version} matches manifest.`);
}

const mode = process.argv.includes("--verify") ? "verify" : "vendor";
if (mode === "verify") doVerify();
else doVendor();
