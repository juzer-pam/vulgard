#!/usr/bin/env node
import { App, LegacyStackSynthesizer } from "aws-cdk-lib";
import { VulgardRolesStack } from "../lib/vulgard-roles-stack.js";

const app = new App();
const context = (key: string): string | undefined => {
  const value: unknown = app.node.tryGetContext(key);
  return value === undefined || value === null || value === "" ? undefined : String(value);
};

const githubOrg = context("githubOrg");
if (!githubOrg) {
  throw new Error("Pass the GitHub org that owns your vulgard fork: npx cdk deploy -c githubOrg=<org>");
}

new VulgardRolesStack(app, "VulgardRoles", {
  env: { account: process.env.CDK_DEFAULT_ACCOUNT, region: process.env.CDK_DEFAULT_REGION },
  description: "IAM roles for vulgard's stale-deployments topic",
  terminationProtection: true,
  // The stack has no assets, so it deploys without `cdk bootstrap`.
  synthesizer: new LegacyStackSynthesizer(),
  githubOrg,
  vulgardRepo: context("vulgardRepo") ?? "vulgard",
  branch: context("branch") ?? "main",
  oidcProviderArn: context("oidcProviderArn"),
  writes: context("writes") === "true",
  sstStateBucket: context("sstStateBucket") ?? "sst-state-*",
  deletePolicyArns: (context("deletePolicyArns") ?? "").split(",").filter(Boolean),
});
