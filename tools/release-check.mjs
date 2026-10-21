#!/usr/bin/env node
// Checks a release before .github/workflows/publish.yml stages @clavis.nexus/collatio on npm.
//
//   node tools/release-check.mjs tag v<X.Y.Z>
//   node tools/release-check.mjs tarball <file.tgz> <X.Y.Z>
//
// tag: js/package.json carries that version, go/v<X.Y.Z> tags the same commit, the commit is on
// origin/main, and the version is new on npm and above its latest. Writes version to $GITHUB_OUTPUT
// when set.
// tarball: the packed package.json has that version, this repository's URL (npm refuses trusted
// publishing otherwise), publishConfig {"access":"public"} and no dependencies, and the packed
// collatio.wasm is the module whose digest the packed README names. Writes the module digest, the
// integrity and the file list to $GITHUB_STEP_SUMMARY for whoever approves the staged package.

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFileSync, readFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const NAME = "@clavis.nexus/collatio";
const REGISTRY = "https://registry.npmjs.org/@clavis.nexus%2Fcollatio";
const RELEASE_VERSION = /^\d+\.\d+\.\d+$/;

function fail(message) {
  console.error(`[release-check] ${message}`);
  process.exit(1);
}

function git(...args) {
  return execFileSync("git", args, { cwd: repo, encoding: "utf8" }).trim();
}

function output(file, lines) {
  if (file) appendFileSync(file, `${lines.join("\n")}\n`);
}

function compareVersions(a, b) {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) if (pa[i] !== pb[i]) return pa[i] - pb[i];
  return 0;
}

async function packument() {
  let res;
  try {
    res = await fetch(REGISTRY, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(30_000) });
  } catch (e) {
    fail(`${NAME}: ${e.name === "TimeoutError" ? "registry did not answer in 30 s" : e.message}`);
  }
  if (res.status === 404) return null;
  if (!res.ok) fail(`${NAME}: registry ${res.status} ${res.statusText}`);
  return res.json();
}

async function checkTag(tag) {
  const version = /^v(.+)$/.exec(tag ?? "")?.[1];
  if (!version || !RELEASE_VERSION.test(version)) fail(`tag "${tag}" is not v<X.Y.Z>`);

  const manifestVersion = JSON.parse(readFileSync(join(repo, "js", "package.json"), "utf8")).version;
  if (manifestVersion !== version) fail(`js/package.json has ${manifestVersion}, the tag ${version}`);

  const head = git("rev-parse", "HEAD");
  let goCommit = "";
  try {
    goCommit = git("rev-parse", `go/v${version}^{commit}`);
  } catch {
    fail(`go/v${version} is missing`);
  }
  if (goCommit !== head) fail(`go/v${version} tags ${goCommit.slice(0, 12)}, not ${head.slice(0, 12)}`);

  try {
    execFileSync("git", ["merge-base", "--is-ancestor", "HEAD", "origin/main"], { cwd: repo, stdio: "ignore" });
  } catch {
    fail("the tagged commit is not on origin/main");
  }

  const doc = await packument();
  // An unpublished version stays in time but leaves versions, and npm never accepts it again
  if (doc?.versions?.[version] || doc?.time?.[version]) fail(`${NAME}@${version} is or was on npm`);
  const latest = doc?.["dist-tags"]?.latest;
  if (latest && RELEASE_VERSION.test(latest) && compareVersions(version, latest) <= 0) {
    fail(`${NAME}@${version} is not above latest ${latest}`);
  }

  output(process.env.GITHUB_OUTPUT, [`version=${version}`]);
  console.log(`[release-check] ${NAME}@${version}${latest ? `, latest ${latest}` : ""}`);
}

function checkTarball(file, version) {
  if (!file || !version) fail("tarball needs <file.tgz> <X.Y.Z>");
  const read = (path, encoding) => execFileSync("tar", ["-xzOf", file, `package/${path}`], { encoding, maxBuffer: 64 << 20 });
  const manifest = JSON.parse(read("package.json", "utf8"));
  if (manifest.name !== NAME || manifest.version !== version) {
    fail(`${basename(file)} is ${manifest.name}@${manifest.version}, expected ${NAME}@${version}`);
  }

  const repository = `git+https://github.com/${process.env.GITHUB_REPOSITORY ?? "ClavisNexus/Collatio"}.git`;
  if (manifest.repository?.url !== repository) {
    fail(`repository.url is ${manifest.repository?.url ?? "(none)"}, expected ${repository}`);
  }
  if (JSON.stringify(manifest.publishConfig) !== JSON.stringify({ access: "public" })) {
    fail(`publishConfig is ${JSON.stringify(manifest.publishConfig)}, expected {"access":"public"}`);
  }
  for (const field of ["dependencies", "optionalDependencies", "peerDependencies"]) {
    if (Object.keys(manifest[field] ?? {}).length) fail(`${field} is not empty`);
  }

  const wasm = read("collatio.wasm");
  const digest = `sha256:${createHash("sha256").update(wasm).digest("base64url")}`;
  if (!read("README.md", "utf8").includes(`\`collatio.wasm\` \`${digest}\``)) {
    fail(`the packed README does not name the packed module ${digest}`);
  }

  const data = readFileSync(file);
  const integrity = `sha512-${createHash("sha512").update(data).digest("base64")}`;
  const files = execFileSync("tar", ["-tzf", file], { encoding: "utf8" }).trim().split("\n");
  output(process.env.GITHUB_STEP_SUMMARY, [
    `### ${NAME}@${version}`,
    "",
    `- collatio.wasm: \`${digest}\``,
    `- integrity: \`${integrity}\``,
    "",
    "```",
    ...files,
    "```",
  ]);
  console.log(`[release-check] ${basename(file)} ${digest} ${integrity}`);
}

const [mode, ...rest] = process.argv.slice(2);
if (mode === "tag") await checkTag(rest[0]);
else if (mode === "tarball") checkTarball(rest[0], rest[1]);
else fail("usage: release-check.mjs tag v<X.Y.Z> | tarball <file.tgz> <X.Y.Z>");
