const SNITCH_BASE = process.env.SNITCH_API_BASE ?? "https://snitchplugin.com";

export interface LicenseValidation {
  ok: boolean;
  tier?: string;
  quotaUsed?: number;
  quotaMonthly?: number;
  reason?: string;
}

/**
 * Validate a pasted license key against the Snitch API. 200 = good,
 * 401/403 = rejected, anything else is treated as "inconclusive" so
 * setup can continue when snitchplugin.com is intermittently unreachable
 * (the first scan will surface the real error if the key is bad).
 */
export async function validateLicense(key: string): Promise<LicenseValidation> {
  const url = `${SNITCH_BASE}/api/github/billing`;
  let res: Response;
  try {
    res = await fetch(url, {
      headers: { Authorization: `Bearer ${key}` },
    });
  } catch (err) {
    return {
      ok: true,
      reason: `Could not reach ${SNITCH_BASE} (network). Saved anyway; first scan will confirm.`,
    };
  }

  if (res.status === 401 || res.status === 403) {
    return { ok: false, reason: "License key rejected by snitchplugin.com." };
  }

  if (!res.ok) {
    return {
      ok: true,
      reason: `License endpoint returned ${res.status}. Saved anyway; first scan will confirm.`,
    };
  }

  try {
    const data = (await res.json()) as {
      tier?: string;
      quota?: { used?: number; monthly?: number };
    };
    return {
      ok: true,
      tier: data.tier,
      quotaUsed: data.quota?.used,
      quotaMonthly: data.quota?.monthly,
    };
  } catch {
    return { ok: true, reason: "Key accepted, response unparsable (non-fatal)." };
  }
}
