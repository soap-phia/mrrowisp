import * as path from "node:path";
import * as os from "node:os";
import * as fs from "node:fs";
import { fileURLToPath } from "node:url";

const bin = os.platform() === "win32" ? "mrrowisp.exe" : "mrrowisp";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, "..");

export const configPath = path.join(root, "dist", "config.json");

function findBinPath(): string {
	const candidates = [
		path.join(root, "bin", bin),
		path.join(root, "dist", "bin", bin),
		path.join(__dirname, "bin", bin),
		path.join(__dirname, "..", "bin", bin),
		path.join(root, bin),
	];

	for (const p of candidates) {
		if (fs.existsSync(p)) return p;
	}

	throw new Error(
		"mrrowisp binary not found. Checked: " + candidates.join(", ")
	);
}

export const binPath = findBinPath();
