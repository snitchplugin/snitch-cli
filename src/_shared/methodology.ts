const SNITCH_BASE = process.env.SNITCH_API_BASE ?? "https://snitchplugin.com";

export interface MethodologyBundle {
  version: string;
  skill: string;
  categories: Array<{ id: number; title: string; body: string }>;
}

let cached: MethodologyBundle | null = null;
let cachedKey: string | null = null;

/**
 * Fetch the Snitch methodology bundle. Cached per workflow run by version.
 * The bundle is fetched as JSON; the server takes care of bundling SKILL.md
 * and the entitled categories into a single payload.
 */
export async function fetchMethodology(
  licenseKey: string,
  version: string,
  categories?: number[]
): Promise<MethodologyBundle> {
  const cacheKey = `${version}:${categories?.join(",") ?? "all"}`;
  if (cached && cachedKey === cacheKey) return cached;

  const url = new URL(`${SNITCH_BASE}/api/skill/methodology`);
  url.searchParams.set("version", version);
  if (categories && categories.length > 0) {
    url.searchParams.set("categories", categories.join(","));
  }

  const res = await fetch(url.toString(), {
    headers: { Authorization: `Bearer ${licenseKey}` },
  });

  if (!res.ok) {
    throw new Error(
      `Failed to fetch methodology bundle (${res.status}). Confirm the snitch.io endpoint is reachable from the runner.`
    );
  }

  const bundle = (await res.json()) as MethodologyBundle;
  cached = bundle;
  cachedKey = cacheKey;
  return bundle;
}

/**
 * Concatenate the bundle into a single string suitable for sending to a
 * provider as the methodology section of the audit prompt.
 */
export function flattenMethodology(bundle: MethodologyBundle): string {
  const sections = [
    `# Snitch Methodology v${bundle.version}\n`,
    bundle.skill,
    "\n\n## Active Categories\n",
  ];
  for (const cat of bundle.categories) {
    sections.push(`\n### ${cat.id}. ${cat.title}\n\n${cat.body}\n`);
  }
  return sections.join("\n");
}
