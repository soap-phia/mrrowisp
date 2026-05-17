import * as path from "node:path";
import * as os from "node:os";

const bin = os.platform() === "win32" ? "mrrowisp.exe" : "mrrowisp";

export const configPath = path.join("..", "dist", "config.json");
export const binPath = path.join(".."   , "bin", bin);
