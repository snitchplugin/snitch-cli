// Post-ncc: rename dist/index.js → dist/cli.js, prepend shebang, chmod +x.
const fs = require("node:fs");
const path = require("node:path");

const dist = path.resolve(__dirname, "..", "dist");
const src = path.join(dist, "index.js");
const dest = path.join(dist, "cli.js");

if (!fs.existsSync(src)) {
  console.error(`postbuild: ${src} not found. Did ncc run?`);
  process.exit(1);
}

let content = fs.readFileSync(src, "utf-8");
if (!content.startsWith("#!")) {
  content = "#!/usr/bin/env node\n" + content;
}
fs.writeFileSync(dest, content, "utf-8");
fs.chmodSync(dest, 0o755);
fs.unlinkSync(src);

// Also move the source map if present.
const srcMap = path.join(dist, "index.js.map");
const destMap = path.join(dist, "cli.js.map");
if (fs.existsSync(srcMap)) {
  fs.renameSync(srcMap, destMap);
}

// ncc sometimes writes `dist/package.json` with {"type":"module"}, which
// forces Node to treat the CJS output as ESM and breaks pkg. Always strip
// it so the nearest package.json is the CLI's own (CJS by default).
const distPkg = path.join(dist, "package.json");
if (fs.existsSync(distPkg)) {
  fs.unlinkSync(distPkg);
}

console.log(`postbuild: wrote ${dest}`);
