import * as os from "os";

const arch = os.arch();
const platform = os.platform();
const ext = platform === "win32" ? ".exe" : "";

const wispConfigPath = new URL("../dist/config.json", import.meta.url).pathname;
const wispPath = new URL(`../bin/${platform}-${arch}/mrrowisp${ext}`, import.meta.url).pathname;

export { wispConfigPath, wispPath };