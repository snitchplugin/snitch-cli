// Routes a single file to the right IaC parser. Path heuristics first (cheap),
// content sniffing only for ambiguous extensions (`*.yaml` / `*.yml` / `*.json`
// — could be CFN, K8s, GitHub Actions, or generic config).
import type { IacFramework } from "./types.js";
import { looksLikeCloudFormation } from "./parsers/cloudformation.js";
import { looksLikeKubernetes } from "./parsers/kubernetes.js";

export interface DiscoverInput {
  path: string;
  content: string;
}

export type DiscoverResult = IacFramework | null;

const TF_RE = /\.tf$/i;
const DOCKERFILE_RE = /(^|\/)Dockerfile(\..+)?$/;
const DOCKERFILE_EXT_RE = /\.dockerfile$/i;
const YAML_RE = /\.(ya?ml)$/i;
const JSON_RE = /\.json$/i;

export function discoverFramework(input: DiscoverInput): DiscoverResult {
  const { path, content } = input;
  if (TF_RE.test(path)) return "terraform";
  if (DOCKERFILE_RE.test(path) || DOCKERFILE_EXT_RE.test(path)) return "dockerfile";
  if (YAML_RE.test(path) || JSON_RE.test(path)) {
    // Order matters: CFN check first because CFN templates can contain
    // anything (including `kind:`-shaped fields inside resource properties)
    // but K8s templates almost never include `AWSTemplateFormatVersion` or
    // `Type: AWS::*`.
    if (looksLikeCloudFormation(content)) return "cloudformation";
    if (looksLikeKubernetes(content)) return "kubernetes";
    // Could be a GitHub Actions workflow (`on:` + `jobs:`), a generic config,
    // or anything else. Out of scope for v1 — silent skip rather than noisy.
    return null;
  }
  return null;
}
