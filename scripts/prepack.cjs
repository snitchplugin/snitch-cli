// Strip source maps before npm publish. The pkg-produced static binaries
// in bin/ keep the maps for crash diagnostics, but the npm tarball must
// not ship them — a source map is enough for anyone to reconstruct the
// original TypeScript source with names and paths intact.
const fs = require("node:fs");
const path = require("node:path");

const dist = path.resolve(__dirname, "..", "dist");
const cli = path.join(dist, "cli.js");

if (!fs.existsSync(cli)) {
  console.error("prepack: " + cli + " missing. Did `npm run build` succeed?");
  process.exit(1);
}

// 1. Remove the map files outright.
for (const f of ["cli.js.map", "sourcemap-register.js", "sourcemap-register.cjs"]) {
  const p = path.join(dist, f);
  if (fs.existsSync(p)) {
    fs.unlinkSync(p);
    console.log(`prepack: removed ${f}`);
  }
}

// 2. Strip the sourceMappingURL comment + the require('./sourcemap-register.js')
//    line from cli.js so it doesn't try to load the map at runtime and crash
//    when it's missing.
let content = fs.readFileSync(cli, "utf-8");
const before = content.length;

// Remove require('./sourcemap-register.js') or the .cjs variant. ncc inserts
// it as the first non-shebang statement.
content = content.replace(
  /require\(['"]\.\/sourcemap-register(?:\.cjs|\.js)?['"]\);?/g,
  ""
);

// Remove //# sourceMappingURL=cli.js.map at the bottom.
content = content.replace(/\/\/[#@]\s*sourceMappingURL=.*$/gm, "");

fs.writeFileSync(cli, content, "utf-8");
console.log(
  `prepack: rewrote cli.js (${before} → ${content.length} bytes, source-map plumbing stripped)`
);
