// IAC-AWS-RDS-NO-ENCRYPTION — flag RDS instances without storage encryption.
//
// `storage_encrypted` defaults to false on aws_db_instance (the AWS provider
// does not flip it). At-rest encryption is the easiest box to check on a
// compliance audit and the highest-leverage one too — it's a one-line fix
// at create time, an effective rebuild after the fact.
import type { IacRule, ResourceContext } from "../types.js";
import { unquoteHcl } from "./_helpers.js";

export const awsRdsNoEncryptionRule: IacRule = {
  id: "IAC-AWS-RDS-NO-ENCRYPTION",
  title: "RDS instance does not have storage encryption enabled",
  description:
    "`storage_encrypted` is unset or explicitly false. RDS storage encryption uses KMS and " +
    "has zero performance overhead at the application layer; there is no good reason to leave " +
    "a production database unencrypted at rest.",
  severity: "High",
  frameworks: ["terraform"],
  check(ctx: ResourceContext) {
    if (ctx.resourceType !== "aws_db_instance" && ctx.resourceType !== "aws_rds_cluster") {
      return null;
    }
    if (typeof ctx.body !== "object") return null;
    const body = ctx.body as Record<string, unknown>;
    const raw = body["storage_encrypted"];
    // Unset → flagged. Set to "false" → flagged. Set to "true" or any
    // interpolation → assume it's intentionally encrypted (we can't
    // statically prove an interpolated value, so we don't try).
    if (raw === undefined) {
      return {
        evidence: `${ctx.resourceType}.${ctx.resourceName} does not set storage_encrypted (default is unencrypted)`,
        fix: "Add `storage_encrypted = true`. Use the default AWS-managed KMS key, or pass `kms_key_id` to use a customer-managed key.",
      };
    }
    if (typeof raw === "string" && unquoteHcl(raw).toLowerCase() === "false") {
      return {
        evidence: `${ctx.resourceType}.${ctx.resourceName} sets storage_encrypted = false`,
        fix: "Change to `storage_encrypted = true`. Existing unencrypted instances can't be encrypted in place — rebuild from a snapshot copied with encryption enabled.",
      };
    }
    return null;
  },
};
