const SNITCH_BASE = process.env.SNITCH_API_BASE ?? "https://snitchplugin.com";

export interface ScanEventRequest {
  repoOwner: string;
  repoName: string;
  prNumber: number;
  fileCount: number;
  scanMode: "smart" | "always" | "manual" | "local" | "gate";
  provider: string;
  model: string;
  categories?: number[];
  triggeredBy:
    | "pull_request"
    | "issue_comment"
    | "schedule"
    | "workflow_dispatch"
    | "cli";
}

export interface ScanEventResponse {
  authorized: true;
  plan: string;
  entitledCategories: number[];
  quotaRemaining: number;
  scanId: string;
}

export class LicenseError extends Error {
  readonly code: number;
  readonly upgradeUrl?: string;

  constructor(code: number, message: string, upgradeUrl?: string) {
    super(message);
    this.name = "LicenseError";
    this.code = code;
    this.upgradeUrl = upgradeUrl;
  }
}

interface ErrorBody {
  error?: string;
  message?: string;
  upgrade_url?: string;
}

async function readErrorBody(res: Response): Promise<ErrorBody> {
  try {
    return (await res.json()) as ErrorBody;
  } catch {
    return { error: await res.text().catch(() => "") };
  }
}

export async function startScanEvent(
  licenseKey: string,
  body: ScanEventRequest
): Promise<ScanEventResponse> {
  const res = await fetch(`${SNITCH_BASE}/api/scan/event`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${licenseKey}`,
    },
    body: JSON.stringify({
      repo_owner: body.repoOwner,
      repo_name: body.repoName,
      pr_number: body.prNumber,
      file_count: body.fileCount,
      scan_mode: body.scanMode,
      provider: body.provider,
      model: body.model,
      categories: body.categories,
      triggered_by: body.triggeredBy,
    }),
  });

  if (res.status === 402) {
    const err = await readErrorBody(res);
    throw new LicenseError(
      402,
      err.error ?? err.message ?? "Scan quota exhausted for this billing period.",
      err.upgrade_url ?? `${SNITCH_BASE}/dashboard/billing`
    );
  }
  if (res.status === 401 || res.status === 403) {
    const err = await readErrorBody(res);
    throw new LicenseError(
      res.status,
      err.error ?? err.message ?? "Snitch license key is invalid or expired."
    );
  }
  if (!res.ok) {
    const err = await readErrorBody(res);
    throw new LicenseError(
      res.status,
      err.error ?? err.message ?? `License endpoint returned ${res.status}.`
    );
  }

  const data = (await res.json()) as {
    authorized?: boolean;
    plan?: string;
    entitled_categories?: number[];
    quota_remaining?: number;
    scan_id?: string;
  };

  if (!data.authorized || !data.scan_id) {
    throw new LicenseError(500, "License endpoint returned a malformed response.");
  }

  return {
    authorized: true,
    plan: data.plan ?? "unknown",
    entitledCategories: data.entitled_categories ?? [],
    quotaRemaining: data.quota_remaining ?? -1,
    scanId: data.scan_id,
  };
}

export interface ScanCompleteBody {
  findingsCount: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  durationMs: number;
  inputTokens: number;
  outputTokens: number;
}

export async function completeScanEvent(
  licenseKey: string,
  scanId: string,
  body: ScanCompleteBody
): Promise<void> {
  const res = await fetch(`${SNITCH_BASE}/api/scan/event/${scanId}/complete`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${licenseKey}`,
    },
    body: JSON.stringify({
      findings_count: body.findingsCount,
      critical_count: body.criticalCount,
      high_count: body.highCount,
      medium_count: body.mediumCount,
      low_count: body.lowCount,
      duration_ms: body.durationMs,
      input_tokens: body.inputTokens,
      output_tokens: body.outputTokens,
    }),
  });

  if (!res.ok) {
    // Telemetry failures are non-fatal. The scan already happened; the report
    // is already posted. Do not throw; the caller logs a warning.
    const err = await readErrorBody(res);
    throw new LicenseError(
      res.status,
      err.error ?? err.message ?? `Telemetry sink returned ${res.status}.`
    );
  }
}

export async function fetchPriorScanResult(
  licenseKey: string,
  repoOwner: string,
  repoName: string,
  prNumber: number
): Promise<{ criticalCount: number; highCount: number } | null> {
  const url = new URL(`${SNITCH_BASE}/api/scan/event/prior`);
  url.searchParams.set("repo_owner", repoOwner);
  url.searchParams.set("repo_name", repoName);
  url.searchParams.set("pr_number", String(prNumber));

  const res = await fetch(url.toString(), {
    headers: { Authorization: `Bearer ${licenseKey}` },
  });

  if (res.status === 404) return null;
  if (!res.ok) return null;

  const data = (await res.json()) as {
    critical_count?: number;
    high_count?: number;
  };
  return {
    criticalCount: data.critical_count ?? 0,
    highCount: data.high_count ?? 0,
  };
}
