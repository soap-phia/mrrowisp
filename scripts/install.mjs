import { createWriteStream, chmodSync, existsSync, mkdirSync } from "fs";
import { pipeline } from "stream/promises";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const repo = "soap-phia/mrrowisp";

const key = `${process.platform}-${process.arch}`;

if (!process.platform) {
    console.error(`Unsupported platform: ${key}`);
    process.exit(1);
}

const ext = process.platform === "win32" ? ".exe" : "";
const assetName = `mrrowisp${ext}`;
const binDir = join(dirname(fileURLToPath(import.meta.url)), "..", "bin");
const binPath = join(binDir, assetName);

if (!existsSync(binDir)) mkdirSync(binDir, { recursive: true });

async function fetchRelease() {
    const res = await fetch(`https://api.github.com/repos/${repo}/releases/latest`, {
        headers: { Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28" },
    });

    if (!res.ok) throw new Error(`GitHub API error: ${res.status} ${res.statusText}`);
    const release = await res.json();

    const asset = release.assets.find(a => a.name === `${process.platform}-mrrowisp${ext}`);
    if (!asset) throw new Error(`No asset found for platform: ${process.platform}`);

    return asset.browser_download_url;
}

async function download(url) {
    const res = await fetch(url, { redirect: "follow" });
    if (!res.ok) throw new Error(`Download failed: ${res.status} ${res.statusText}`);

    await pipeline(res.body, createWriteStream(binPath));
    if (process.platform !== "win32") chmodSync(binPath, 0o755);

    console.log(`Installed mrrowisp to ${binPath}`);
}

fetchRelease().then(download).catch(err => {
    console.error("Installation failed:", err.message);
    process.exit(1);
});