import { minimatch } from "minimatch";

const SKIP_TOKEN = "[skip snitch]";
const COMMENT_TRIGGER = "/snitch";
const TITLE_TRIGGER = "[snitch]";

export interface TriggerContext {
  eventName: string;
  action?: string;
  prTitle?: string;
  prBody?: string;
  commentBody?: string;
  commitMessage?: string;
  isDraft?: boolean;
  priorScanFindings?: { criticalCount: number; highCount: number } | null;
}

export interface TriggerDecision {
  shouldScan: boolean;
  reason: string;
}

export type TriggerMode = "smart" | "always" | "manual";

export function decideTrigger(
  mode: TriggerMode,
  ctx: TriggerContext
): TriggerDecision {
  // Universal escape hatch: explicit /snitch comment always scans.
  if (
    ctx.eventName === "issue_comment" &&
    ctx.commentBody &&
    containsToken(ctx.commentBody, COMMENT_TRIGGER)
  ) {
    return { shouldScan: true, reason: "manual /snitch comment trigger" };
  }

  // Universal opt-in via PR title or body.
  if (titleOrBodyOptIn(ctx)) {
    return { shouldScan: true, reason: "PR title or body opted in" };
  }

  // Universal skip: [skip snitch] in commit message.
  if (ctx.commitMessage && containsToken(ctx.commitMessage, SKIP_TOKEN)) {
    return { shouldScan: false, reason: "[skip snitch] in commit message" };
  }

  // Drafts are skipped unless explicitly opted in (handled above).
  if (ctx.isDraft) {
    return { shouldScan: false, reason: "PR is in draft" };
  }

  if (mode === "manual") {
    return {
      shouldScan: false,
      reason: "manual mode: no /snitch trigger present",
    };
  }

  // Only react to PR events from here.
  if (ctx.eventName !== "pull_request") {
    return {
      shouldScan: false,
      reason: `event ${ctx.eventName} is not a PR event`,
    };
  }

  if (mode === "always") {
    return { shouldScan: true, reason: "always mode: scan every PR event" };
  }

  // Smart mode.
  if (ctx.action === "opened" || ctx.action === "ready_for_review") {
    return {
      shouldScan: true,
      reason: `smart mode: scan on ${ctx.action}`,
    };
  }

  if (ctx.action === "synchronize") {
    const prior = ctx.priorScanFindings;
    if (prior && prior.criticalCount + prior.highCount > 0) {
      return {
        shouldScan: true,
        reason: `smart mode: synchronize re-scan, prior had ${prior.criticalCount + prior.highCount} critical/high`,
      };
    }
    return {
      shouldScan: false,
      reason: "smart mode: synchronize self-throttle, no prior critical/high",
    };
  }

  return {
    shouldScan: false,
    reason: `smart mode: action ${ctx.action ?? "unknown"} not handled`,
  };
}

function titleOrBodyOptIn(ctx: TriggerContext): boolean {
  if (ctx.prTitle && containsToken(ctx.prTitle, TITLE_TRIGGER)) return true;
  if (ctx.prBody && containsToken(ctx.prBody, COMMENT_TRIGGER)) return true;
  return false;
}

function containsToken(haystack: string, token: string): boolean {
  return haystack.toLowerCase().includes(token.toLowerCase());
}

/**
 * Filter changed files by include/ignore globs from .snitch.yml. An empty
 * include list means "include everything"; ignore is applied after include.
 */
export function filterPaths(
  paths: string[],
  include: string[],
  ignore: string[]
): string[] {
  const included =
    include.length === 0
      ? paths
      : paths.filter((p) => include.some((g) => minimatch(p, g, { dot: true })));
  return included.filter(
    (p) => !ignore.some((g) => minimatch(p, g, { dot: true }))
  );
}
