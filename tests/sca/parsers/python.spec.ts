import { describe, expect, it } from "vitest";
import { pythonParser } from "../../../src/_shared/sca/parsers/python.js";
import { PIPFILE_LOCK, POETRY_LOCK, REQUIREMENTS_TXT, UV_LOCK } from "./_fixtures.js";

describe("pythonParser: requirements.txt", () => {
  const deps = pythonParser.parse(REQUIREMENTS_TXT, "requirements.txt");
  it("skips comments, -r includes, and VCS URLs", () => {
    const names = deps.map((d) => d.name);
    expect(names).toEqual(["requests", "flask", "django"]);
  });
  it("strips extras and env markers", () => {
    const flask = deps.find((d) => d.name === "flask");
    expect(flask?.version).toBe("3.0.0");
    expect(flask?.ecosystem).toBe("PyPI");
  });
});

describe("pythonParser: poetry.lock", () => {
  it("parses [[package]] arrays", () => {
    const deps = pythonParser.parse(POETRY_LOCK, "poetry.lock");
    expect(deps.length).toBe(2);
    expect(deps.find((d) => d.name === "requests")?.version).toBe("2.31.0");
    expect(deps.find((d) => d.name === "urllib3")?.version).toBe("2.0.7");
  });
});

describe("pythonParser: Pipfile.lock", () => {
  it("merges default and develop sections, strips '==' prefix", () => {
    const deps = pythonParser.parse(PIPFILE_LOCK, "Pipfile.lock");
    const byName = Object.fromEntries(deps.map((d) => [d.name, d.version]));
    expect(byName["requests"]).toBe("2.31.0");
    expect(byName["urllib3"]).toBe("2.0.7");
    expect(byName["pytest"]).toBe("7.4.3");
  });
});

describe("pythonParser: uv.lock", () => {
  it("parses TOML [[package]] like poetry", () => {
    const deps = pythonParser.parse(UV_LOCK, "uv.lock");
    expect(deps.length).toBe(2);
    expect(deps.find((d) => d.name === "anyio")?.version).toBe("4.2.0");
  });
});

describe("pythonParser: malformed input", () => {
  it("returns [] for empty requirements.txt", () => {
    expect(pythonParser.parse("", "requirements.txt")).toEqual([]);
  });
  it("returns [] for fully commented requirements.txt", () => {
    expect(pythonParser.parse("# only comments\n# nothing\n", "requirements.txt")).toEqual([]);
  });
  it("returns [] for invalid TOML in poetry.lock", () => {
    expect(pythonParser.parse("not [valid toml", "poetry.lock")).toEqual([]);
  });
  it("returns [] for invalid Pipfile.lock JSON", () => {
    expect(pythonParser.parse("{bad", "Pipfile.lock")).toEqual([]);
  });
});
