// Rule registry. Add new rules by importing them and pushing into RULES.
// Order is informational only — every rule runs against every applicable
// resource, the orchestrator does the framework filtering.
import type { IacRule } from "../types.js";
import { awsS3PublicRule } from "./aws-s3-public.js";
import { awsIamWildcardRule } from "./aws-iam-wildcard.js";
import { awsRdsNoEncryptionRule } from "./aws-rds-no-encryption.js";
import { awsSgOpenIngressRule } from "./aws-sg-open-ingress.js";
import { awsSecretInTfRule } from "./aws-secret-in-tf.js";
import { cfnS3PublicRule } from "./cfn-s3-public.js";
import { cfnIamWildcardRule } from "./cfn-iam-wildcard.js";
import { k8sRunAsRootRule } from "./k8s-run-as-root.js";
import { k8sPrivilegedRule } from "./k8s-privileged.js";
import { k8sHostNetworkRule } from "./k8s-host-network.js";
import { k8sNoResourceLimitsRule } from "./k8s-no-resource-limits.js";
import { k8sLatestTagRule } from "./k8s-latest-tag.js";
import { dockerRunAsRootRule } from "./docker-run-as-root.js";
import { dockerCurlPipeShRule } from "./docker-curl-pipe-sh.js";
import { dockerLatestBaseRule } from "./docker-latest-base.js";

export const RULES: IacRule[] = [
  awsS3PublicRule,
  awsIamWildcardRule,
  awsRdsNoEncryptionRule,
  awsSgOpenIngressRule,
  awsSecretInTfRule,
  cfnS3PublicRule,
  cfnIamWildcardRule,
  k8sRunAsRootRule,
  k8sPrivilegedRule,
  k8sHostNetworkRule,
  k8sNoResourceLimitsRule,
  k8sLatestTagRule,
  dockerRunAsRootRule,
  dockerCurlPipeShRule,
  dockerLatestBaseRule,
];
