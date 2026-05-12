import * as os from "os";
import { fileURLToPath } from "url";

const ext = os.platform() === "win32" ? ".exe" : "";

const wispConfigPath = fileURLToPath(new URL("../dist/config.json", import.meta.url));
const wispPath = fileURLToPath(new URL(`../bin/${os.platform()}-${os.arch()}/mrrowisp${ext}`, import.meta.url));

export { wispConfigPath, wispPath };