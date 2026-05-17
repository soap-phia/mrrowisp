import * as path from "node:path";
import * as os from "node:os";

const bin = os.platform() === "win32" ? "mrrowisp.exe" : "mrrowisp";

const root = path.resolve(__dirname, "..");

export const configPath = path.join(root, "dist", "config.json");
export const binPath = path.join(root, "bin", bin);
