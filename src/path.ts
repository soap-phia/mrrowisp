import * as path from "node:path";
import * as os from "node:os";
import { fileURLToPath } from "node:url";

const bin = os.platform() === "win32" ? "mrrowisp.exe" : "mrrowisp";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, "..");

export const configPath = path.join(root, "dist", "config.json");
export const binPath = path.join(root, "bin", `${os.platform()}-${os.arch()}`, bin);
