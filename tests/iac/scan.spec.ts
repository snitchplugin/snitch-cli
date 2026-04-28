import { describe, expect, it } from "vitest";
import { runIacScan } from "../../src/_shared/iac/scan.js";

describe("runIacScan", () => {
  it("returns Snitch-shape findings for a vulnerable Terraform file", async () => {
    const tf = `
resource "aws_s3_bucket" "leak" {
  bucket = "demo"
  acl    = "public-read"
}

resource "aws_security_group" "ssh" {
  ingress {
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`;
    const result = await runIacScan({ files: [{ path: "main.tf", content: tf }] });
    expect(result.resourcesScanned).toBe(2);
    expect(result.findings.length).toBeGreaterThanOrEqual(2);
    const ids = result.findings
      .map((f) => f.metadata && f.metadata.kind === "iac" ? f.metadata.ruleId : null)
      .filter(Boolean);
    expect(ids).toContain("IAC-AWS-S3-PUBLIC");
    expect(ids).toContain("IAC-AWS-SG-OPEN-INGRESS");
    for (const f of result.findings) {
      expect(f.title.startsWith("IaC misconfiguration:")).toBe(true);
      expect(f.confidence).toBe("high");
      expect(f.metadata?.kind).toBe("iac");
    }
  });

  it("scans CloudFormation, Kubernetes, and Dockerfile in one pass", async () => {
    const cfn = `
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicRead
`;
    const k8s = `
apiVersion: v1
kind: Pod
metadata: { name: x }
spec:
  containers:
    - name: app
      image: nginx:latest
      securityContext:
        privileged: true
`;
    const df = `FROM alpine:latest
RUN curl -fsSL https://example.com/install.sh | sh
`;
    const result = await runIacScan({
      files: [
        { path: "stack.yaml", content: cfn },
        { path: "pod.yaml", content: k8s },
        { path: "Dockerfile", content: df },
      ],
    });
    const ids = result.findings
      .map((f) => f.metadata && f.metadata.kind === "iac" ? f.metadata.ruleId : null)
      .filter(Boolean);
    expect(ids).toContain("IAC-CFN-S3-PUBLIC");
    expect(ids).toContain("IAC-K8S-PRIVILEGED");
    expect(ids).toContain("IAC-K8S-LATEST-TAG");
    expect(ids).toContain("IAC-DOCKER-LATEST-BASE");
    expect(ids).toContain("IAC-DOCKER-CURL-PIPE-SH");
    expect(ids).toContain("IAC-DOCKER-RUN-AS-ROOT");
  });

  it("returns empty findings when nothing matches", async () => {
    const result = await runIacScan({
      files: [
        { path: "src/index.ts", content: "export const x = 1;" },
        { path: ".github/workflows/ci.yml", content: "name: CI\non: [push]\njobs:\n  b:\n    runs-on: ubuntu\n" },
      ],
    });
    expect(result.findings).toHaveLength(0);
    expect(result.resourcesScanned).toBe(0);
  });

  it("malformed input does not crash the scan", async () => {
    const result = await runIacScan({
      files: [
        { path: "broken.tf", content: 'resource "aws_s3_bucket" "x" { acl = "public-read"' /* unterminated */ },
        { path: "ok.tf", content: 'resource "aws_db_instance" "p" { storage_encrypted = false }' },
      ],
    });
    // The clean file's finding still ships even though the broken file
    // produced no resources.
    const ids = result.findings
      .map((f) => f.metadata && f.metadata.kind === "iac" ? f.metadata.ruleId : null);
    expect(ids).toContain("IAC-AWS-RDS-NO-ENCRYPTION");
  });
});
