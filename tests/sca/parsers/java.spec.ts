import { describe, expect, it } from "vitest";
import { javaParser } from "../../../src/_shared/sca/parsers/java.js";
import { GRADLE_LOCKFILE, POM_XML } from "./_fixtures.js";

describe("javaParser: pom.xml", () => {
  const deps = javaParser.parse(POM_XML, "pom.xml");
  it("collects each <dependency> as groupId:artifactId", () => {
    expect(deps.length).toBe(2);
    const spring = deps.find((d) => d.name === "org.springframework:spring-core");
    expect(spring).toMatchObject({ ecosystem: "Maven", version: "6.1.2" });
    const guava = deps.find((d) => d.name === "com.google.guava:guava");
    expect(guava?.version).toBe("32.1.3-jre");
  });
});

describe("javaParser: gradle.lockfile", () => {
  const deps = javaParser.parse(GRADLE_LOCKFILE, "gradle.lockfile");
  it("skips comments and the 'empty=' marker", () => {
    expect(deps.length).toBe(2);
    expect(deps.find((d) => d.name === "org.springframework:spring-core")?.version).toBe("6.1.2");
    expect(deps.find((d) => d.name === "com.google.guava:guava")?.version).toBe("32.1.3-jre");
  });
});
