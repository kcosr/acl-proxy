#!/usr/bin/env node
/**
 * bump-version.mjs
 *
 * Updates the version in Cargo.toml with a new semantic version.
 *
 * Usage:
 *   node scripts/bump-version.mjs patch     # 1.0.0 -> 1.0.1
 *   node scripts/bump-version.mjs minor     # 1.0.1 -> 1.1.0
 *   node scripts/bump-version.mjs major     # 1.1.0 -> 2.0.0
 *   node scripts/bump-version.mjs 2.0.0     # Set to specific version
 *   node scripts/bump-version.mjs           # Show current version
 */

import { existsSync, readFileSync, writeFileSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");
const cargoTomlPath = join(ROOT, "Cargo.toml");
const cargoLockPath = join(ROOT, "Cargo.lock");

function readVersion() {
	const content = readFileSync(cargoTomlPath, "utf8");
	const match = content.match(/\[package\][\s\S]*?\nversion\s*=\s*"([^"]+)"/);
	if (!match) {
		console.error("Could not find version in Cargo.toml [package] section");
		process.exit(1);
	}
	return match[1];
}

function parseVersion(version) {
	const match = version.match(/^(\d+)\.(\d+)\.(\d+)(.*)$/);
	if (!match) {
		return null;
	}
	return {
		major: Number.parseInt(match[1], 10),
		minor: Number.parseInt(match[2], 10),
		patch: Number.parseInt(match[3], 10),
		suffix: match[4] || "",
	};
}

function formatVersion(parts) {
	return `${parts.major}.${parts.minor}.${parts.patch}${parts.suffix}`;
}

function updateCargoTomlVersion(newVersion) {
	let content = readFileSync(cargoTomlPath, "utf8");
	const versionRegex =
		/(\[package\][\s\S]*?\nversion\s*=\s*")[^"]*(")/;
	if (!versionRegex.test(content)) {
		console.error("Cargo.toml [package] version not found");
		process.exit(1);
	}

	content = content.replace(versionRegex, `$1${newVersion}$2`);
	writeFileSync(cargoTomlPath, content, "utf8");
}

function updateCargoLockVersion(newVersion) {
	if (!existsSync(cargoLockPath)) {
		return;
	}

	let content = readFileSync(cargoLockPath, "utf8");
	const versionRegex =
		/(\[\[package\]\]\nname = "acl-proxy"\nversion = ")[^"]*(")/;
	if (!versionRegex.test(content)) {
		console.error("Cargo.lock package entry not found for acl-proxy");
		process.exit(1);
	}

	const updated = content.replace(versionRegex, `$1${newVersion}$2`);
	content = updated;
	writeFileSync(cargoLockPath, content, "utf8");
}

const currentVersion = readVersion();
const arg = process.argv[2];

if (!arg) {
	console.log(`Current version: ${currentVersion}`);
	process.exit(0);
}

const parts = parseVersion(currentVersion);
if (!parts) {
	console.error(`Current version "${currentVersion}" is not valid semver (X.Y.Z)`);
	process.exit(1);
}

let newVersion;

switch (arg.toLowerCase()) {
	case "patch":
		parts.patch += 1;
		parts.suffix = "";
		newVersion = formatVersion(parts);
		break;
	case "minor":
		parts.minor += 1;
		parts.patch = 0;
		parts.suffix = "";
		newVersion = formatVersion(parts);
		break;
	case "major":
		parts.major += 1;
		parts.minor = 0;
		parts.patch = 0;
		parts.suffix = "";
		newVersion = formatVersion(parts);
		break;
	default:
		if (!/^\d+\.\d+\.\d+(-[\w.]+)?$/.test(arg)) {
			console.error(
				`Invalid version: "${arg}". Use patch, minor, major, or a semver like 1.2.3`
			);
			process.exit(1);
		}
		newVersion = arg;
}

updateCargoTomlVersion(newVersion);
updateCargoLockVersion(newVersion);
console.log(`Version updated: ${currentVersion} -> ${newVersion}`);
