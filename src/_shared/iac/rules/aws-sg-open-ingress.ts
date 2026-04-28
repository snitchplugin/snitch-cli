// IAC-AWS-SG-OPEN-INGRESS — flag security groups exposing risky service
// ports to 0.0.0.0/0.
//
// Why we check specific ports instead of "any 0.0.0.0/0 ingress": HTTP/80
// and HTTPS/443 to the world is the entire point of a public web server,
// and so are 53/UDP DNS resolvers, etc. The high-signal failure mode is
// admin / database / cache services accidentally exposed:
//   22 = SSH        — direct shell access
//   3389 = RDP      — direct desktop access
//   3306 = MySQL    — DB
//   5432 = Postgres — DB
//   6379 = Redis    — cache (often unauthenticated by default)
//   27017 = Mongo   — DB (used to ship without auth)
//   9200 = Elastic  — search/index (no auth in OSS distros)
// All Critical: each one of these has been the root cause of public
// breaches reported in the last few years.
import type { IacRule, ResourceContext } from "../types.js";
import { unquoteHcl } from "./_helpers.js";

const RISKY_PORTS = new Set([22, 3389, 3306, 5432, 6379, 27017, 9200]);
const RISKY_PORT_LABEL: Record<number, string> = {
  22: "SSH",
  3389: "RDP",
  3306: "MySQL",
  5432: "PostgreSQL",
  6379: "Redis",
  27017: "MongoDB",
  9200: "Elasticsearch",
};

export const awsSgOpenIngressRule: IacRule = {
  id: "IAC-AWS-SG-OPEN-INGRESS",
  title: "Security group exposes admin/database port to 0.0.0.0/0",
  description:
    "An ingress rule allows traffic from the public internet (0.0.0.0/0) on a port that " +
    "carries administrative or database traffic. These services are typically not designed " +
    "to be world-reachable; they belong behind a bastion, VPN, or VPC peering.",
  severity: "Critical",
  frameworks: ["terraform"],
  check(ctx: ResourceContext) {
    if (typeof ctx.body !== "object") return null;
    const body = ctx.body as Record<string, unknown>;

    // Two flavors:
    //   aws_security_group with embedded ingress {} blocks
    //   aws_security_group_rule with type = "ingress" and cidr_blocks
    if (ctx.resourceType === "aws_security_group_rule") {
      const type = typeof body["type"] === "string" ? unquoteHcl(body["type"] as string) : "";
      if (type !== "ingress") return null;
      const cidr = typeof body["cidr_blocks"] === "string" ? (body["cidr_blocks"] as string) : "";
      if (!cidr.includes("0.0.0.0/0")) return null;
      const fromPort = parseInt(typeof body["from_port"] === "string" ? unquoteHcl(body["from_port"] as string) : "", 10);
      const toPort = parseInt(typeof body["to_port"] === "string" ? unquoteHcl(body["to_port"] as string) : "", 10);
      const hits = portsInRange(fromPort, toPort);
      if (hits.length === 0) return null;
      return mkFinding(ctx, hits, fromPort, toPort);
    }

    if (ctx.resourceType === "aws_security_group") {
      // Each ingress block is captured raw by the parser. Walk them.
      const ingressRaw = body["ingress"];
      const blocks: string[] = Array.isArray(ingressRaw)
        ? (ingressRaw as string[])
        : typeof ingressRaw === "string"
          ? [ingressRaw]
          : [];
      for (const block of blocks) {
        if (!block.includes("0.0.0.0/0")) continue;
        const from = parseInt((block.match(/from_port\s*=\s*([0-9]+)/) ?? [])[1] ?? "", 10);
        const to = parseInt((block.match(/to_port\s*=\s*([0-9]+)/) ?? [])[1] ?? "", 10);
        const hits = portsInRange(from, to);
        if (hits.length > 0) return mkFinding(ctx, hits, from, to);
      }
    }
    return null;
  },
};

function portsInRange(fromPort: number, toPort: number): number[] {
  if (Number.isNaN(fromPort) || Number.isNaN(toPort)) return [];
  // 0-65535 (or any wide range covering all risky ports) is itself a finding —
  // it implicitly opens every risky port. We bail to listing all of them.
  const out: number[] = [];
  for (const p of RISKY_PORTS) {
    if (p >= fromPort && p <= toPort) out.push(p);
  }
  return out;
}

function mkFinding(
  ctx: ResourceContext,
  hits: number[],
  from: number,
  to: number,
): { evidence: string; fix: string } {
  const labels = hits.map((p) => `${p} (${RISKY_PORT_LABEL[p] ?? "?"})`).join(", ");
  const range = from === to ? `port ${from}` : `port range ${from}-${to}`;
  return {
    evidence: `${ctx.resourceType}.${ctx.resourceName} ingress on ${range} from 0.0.0.0/0 covers risky port(s): ${labels}`,
    fix: "Restrict the cidr_blocks to your VPN / bastion / corporate IP range, or front the service with a managed proxy (e.g. AWS Systems Manager Session Manager for SSH, RDS Proxy for databases).",
  };
}
