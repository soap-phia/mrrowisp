import * as os from "os";

const arch = os.arch()
const platform = os.platform()

const pkg = `${platform}-${arch}`
const wispConfigPath = new URL("../dist/config.json", import.meta.url).pathname;
const wispPath = new URL(`../bin/mrrowisp`, import.meta.url).pathname;

export { wispConfigPath, wispPath };
