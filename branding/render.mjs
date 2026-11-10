// Renders the logo SVGs to PNGs with the clients repo's Playwright Chromium.
// Usage: node branding/render.mjs <out-dir> <size>... (run from upstream/clients so playwright resolves)
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(join(process.cwd(), "package.json"));
const { chromium } = require("playwright");

const [outDir, ...sizes] = process.argv.slice(2);
const variants = { "": "pushwarden.svg", _gray: "pushwarden-gray.svg" };
// Any Chromium works; PW_CHROMIUM points at one when Playwright's own build isn't downloaded.
const browser = await chromium.launch({ executablePath: process.env.PW_CHROMIUM || undefined });
const page = await browser.newPage();
for (const size of sizes.map(Number)) {
  await page.setViewportSize({ width: size, height: size });
  for (const [suffix, file] of Object.entries(variants)) {
    const svg = readFileSync(join(here, file), "utf8").replace(/width="512" height="512"/, `width="${size}" height="${size}"`);
    await page.setContent(`<style>html,body{margin:0;background:transparent}</style>${svg}`);
    await page.locator("svg").screenshot({ path: join(outDir, `icon${size}${suffix}.png`), omitBackground: true });
  }
}
await browser.close();
