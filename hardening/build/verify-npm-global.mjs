#!/usr/bin/env node
// Install global npm packages and prove that what landed on disk is exactly the
// pinned tarballs (added by the hardening pass; not upstream).
//
//   node verify-npm-global.mjs <pins-file> <spec>...
//
// pins-file: one "<name>@<version> <sha512 integrity>" per line, for every
// package the install may put on disk (the requested ones and their
// dependencies). <spec>... are the packages handed to `npm install -g`.
//
// Steps:
//   1. `npm pack` each pinned package and compare its sha512 with the pin.
//   2. `npm install -g <spec>...`.
//   3. Walk the global node_modules: every installed package must be pinned, and
//      every one of its files must be byte-identical to the verified tarball.
//
// npm's own integrity check trusts the registry's metadata. This check does not:
// the pins live in this repository.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const [pinsFile, ...specs] = process.argv.slice(2);
if (!pinsFile || specs.length === 0) {
  console.error("usage: verify-npm-global.mjs <pins-file> <spec>...");
  process.exit(2);
}
const fail = (msg) => {
  console.error(`[npm-verify] FAIL: ${msg}`);
  process.exit(1);
};
const run = (cmd, args, opts = {}) =>
  execFileSync(cmd, args, { encoding: "utf8", stdio: ["ignore", "pipe", "inherit"], ...opts });

const pins = new Map(); // "name@version" -> integrity
for (const line of fs.readFileSync(pinsFile, "utf8").split(/\r?\n/)) {
  const t = line.trim();
  if (!t || t.startsWith("#")) continue;
  const [spec, integrity] = t.split(/\s+/);
  if (!spec || !/^sha512-[A-Za-z0-9+/=]+$/.test(integrity || "")) fail(`bad pin line: ${t}`);
  pins.set(spec, integrity);
}

// 1. Fetch and verify every pinned tarball.
const work = fs.mkdtempSync(path.join(os.tmpdir(), "npm-verify-"));
const verified = new Map(); // "name@version" -> extracted package dir
let n = 0;
for (const [spec, want] of pins) {
  const dir = path.join(work, String(n++));
  fs.mkdirSync(dir);
  const tgz = run("npm", ["pack", "--silent", spec], { cwd: dir }).trim().split(/\r?\n/).pop();
  const got = "sha512-" + createHash("sha512").update(fs.readFileSync(path.join(dir, tgz))).digest("base64");
  if (got !== want) fail(`integrity mismatch for ${spec}: pinned ${want}, registry served ${got}`);
  const out = path.join(dir, "x");
  fs.mkdirSync(out);
  run("tar", ["-xzf", path.join(dir, tgz), "-C", out]);
  const tops = fs.readdirSync(out);
  if (tops.length !== 1) fail(`${spec}: tarball has ${tops.length} top-level entries`);
  verified.set(spec, path.join(out, tops[0]));
  console.log(`[npm-verify] tarball ok  ${spec}`);
}

// 2. Install.
run("npm", ["install", "-g", "--no-audit", "--no-fund", ...specs], { stdio: "inherit" });

// 3. Compare what is installed with the verified tarballs.
const hashFile = (p) => createHash("sha256").update(fs.readFileSync(p)).digest("hex");
function files(root, skipNodeModules) {
  const out = new Map();
  const walk = (dir, rel) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (skipNodeModules && r === "node_modules") continue;
      const p = path.join(dir, e.name);
      if (e.isDirectory()) walk(p, r);
      else if (e.isFile()) out.set(r, hashFile(p));
      else fail(`${p}: unexpected file type`);
    }
  };
  walk(root, "");
  return out;
}

const globalRoot = run("npm", ["root", "-g"]).trim();
const bundledWithNode = new Set(["npm", "corepack"]); // shipped in the Node tarball, verified by its SHA-256
let checked = 0;
function checkPackage(dir) {
  const meta = JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf8"));
  const spec = `${meta.name}@${meta.version}`;
  const ref = verified.get(spec);
  if (!ref) fail(`${dir}: ${spec} is installed but not pinned in ${pinsFile}`);
  const want = files(ref, false);
  const got = files(dir, true);
  for (const [f, h] of want) {
    if (!got.has(f)) fail(`${spec}: ${f} missing from ${dir}`);
    if (got.get(f) !== h) fail(`${spec}: ${f} differs from the verified tarball`);
  }
  for (const f of got.keys()) if (!want.has(f)) fail(`${spec}: ${f} is not in the verified tarball`);
  checked++;
  console.log(`[npm-verify] installed ok ${spec}  (${want.size} files)  ${dir}`);
  const nested = path.join(dir, "node_modules");
  if (fs.existsSync(nested)) checkTree(nested, false);
}
function checkTree(nm, top) {
  for (const e of fs.readdirSync(nm, { withFileTypes: true })) {
    if (e.name.startsWith(".")) continue; // .bin, .package-lock.json
    if (top && bundledWithNode.has(e.name)) continue;
    const p = path.join(nm, e.name);
    if (!fs.statSync(p).isDirectory()) fail(`${p}: unexpected entry in node_modules`);
    if (e.name.startsWith("@")) {
      for (const s of fs.readdirSync(p)) checkPackage(path.join(p, s));
    } else {
      checkPackage(p);
    }
  }
}
checkTree(globalRoot, true);
if (checked === 0) fail("no installed package was checked");
fs.rmSync(work, { recursive: true, force: true });
console.log(`[npm-verify] ${checked} installed package(s) match their pinned tarballs`);
