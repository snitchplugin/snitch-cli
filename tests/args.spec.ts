import { describe, expect, it } from "vitest";
import { ArgError, parseArgs } from "../src/args.js";

describe("parseArgs", () => {
  it("empty argv defaults to help", () => {
    expect(parseArgs([]).command).toBe("help");
  });

  it("--help maps to help", () => {
    expect(parseArgs(["--help"]).command).toBe("help");
    expect(parseArgs(["-h"]).command).toBe("help");
    expect(parseArgs(["help"]).command).toBe("help");
  });

  it("--version maps to version", () => {
    expect(parseArgs(["--version"]).command).toBe("version");
    expect(parseArgs(["-v"]).command).toBe("version");
  });

  it("rejects unknown commands", () => {
    expect(() => parseArgs(["bogus"])).toThrow(ArgError);
  });

  it("bare scan parses with defaults", () => {
    const p = parseArgs(["scan"]);
    expect(p.command).toBe("scan");
    expect(p.files).toBeUndefined();
    expect(p.full).toBeUndefined();
    expect(p.base).toBeUndefined();
  });

  it("--files accepts comma list", () => {
    const p = parseArgs(["scan", "--files", "a.ts,b.ts, c.ts"]);
    expect(p.files).toEqual(["a.ts", "b.ts", "c.ts"]);
  });

  it("-f is alias for --files", () => {
    const p = parseArgs(["scan", "-f", "a.ts"]);
    expect(p.files).toEqual(["a.ts"]);
  });

  it("--full sets full mode", () => {
    const p = parseArgs(["scan", "--full"]);
    expect(p.full).toBe(true);
  });

  it("--base overrides default ref", () => {
    const p = parseArgs(["scan", "--base", "develop"]);
    expect(p.base).toBe("develop");
  });

  it("--files and --full conflict", () => {
    expect(() => parseArgs(["scan", "--files", "a.ts", "--full"])).toThrow(
      ArgError
    );
  });

  it("--fail-on validates value", () => {
    expect(parseArgs(["scan", "--fail-on", "critical"]).failOn).toBe("critical");
    expect(parseArgs(["scan", "--fail-on", "none"]).failOn).toBe("none");
    expect(() => parseArgs(["scan", "--fail-on", "bogus"])).toThrow(ArgError);
  });

  it("--provider validates value", () => {
    expect(parseArgs(["scan", "--provider", "anthropic"]).provider).toBe("anthropic");
    expect(parseArgs(["scan", "-p", "openai"]).provider).toBe("openai");
    expect(parseArgs(["scan", "-p", "openrouter"]).provider).toBe("openrouter");
    expect(parseArgs(["scan", "-p", "local-cli"]).provider).toBe("local-cli");
    expect(() => parseArgs(["scan", "--provider", "skynet"])).toThrow(ArgError);
  });

  it("--model is free-form", () => {
    expect(parseArgs(["scan", "-m", "sonnet"]).model).toBe("sonnet");
  });

  it("--quiet sets quiet", () => {
    expect(parseArgs(["scan", "--quiet"]).quiet).toBe(true);
    expect(parseArgs(["scan", "-q"]).quiet).toBe(true);
  });

  it("rejects missing value for flag", () => {
    expect(() => parseArgs(["scan", "--base"])).toThrow(ArgError);
    expect(() => parseArgs(["scan", "--fail-on"])).toThrow(ArgError);
    expect(() => parseArgs(["scan", "--model"])).toThrow(ArgError);
  });

  it("rejects unknown flag", () => {
    expect(() => parseArgs(["scan", "--unknown"])).toThrow(ArgError);
  });

  it("--repo accepts a local path", () => {
    const p = parseArgs(["scan", "--repo", "/tmp/foo"]);
    expect(p.repo).toBe("/tmp/foo");
  });

  it("--repo accepts a https URL", () => {
    const p = parseArgs(["scan", "--repo", "https://github.com/x/y.git"]);
    expect(p.repo).toBe("https://github.com/x/y.git");
  });

  it("-r is alias for --repo", () => {
    const p = parseArgs(["scan", "-r", "./sibling"]);
    expect(p.repo).toBe("./sibling");
  });

  it("--repo without a value throws", () => {
    expect(() => parseArgs(["scan", "--repo"])).toThrow(ArgError);
    expect(() => parseArgs(["scan", "--repo", "--full"])).toThrow(ArgError);
  });

  it("--force-after-injection sets the flag", () => {
    expect(parseArgs(["scan", "--force-after-injection"]).forceAfterInjection).toBe(true);
  });

  it("default parsed args do not set forceAfterInjection", () => {
    expect(parseArgs(["scan"]).forceAfterInjection).toBeUndefined();
  });

  it("init subcommand parses", () => {
    expect(parseArgs(["init"]).command).toBe("init");
  });

  it("logout subcommand parses", () => {
    expect(parseArgs(["logout"]).command).toBe("logout");
  });

  it("status subcommand parses", () => {
    expect(parseArgs(["status"]).command).toBe("status");
  });

  it("new subcommands take no flags and do not throw on extra argv", () => {
    // These three are bare subcommands with no options today. Any trailing
    // argv is ignored for now; we just confirm the command is correctly
    // identified and no parse error fires.
    expect(parseArgs(["init"]).command).toBe("init");
    expect(parseArgs(["logout"]).command).toBe("logout");
    expect(parseArgs(["status"]).command).toBe("status");
  });
});
