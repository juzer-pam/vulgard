import { Aws, CfnOutput, Duration, RemovalPolicy, Stack, StackProps, Tags } from "aws-cdk-lib";
import * as iam from "aws-cdk-lib/aws-iam";
import { Construct } from "constructs";

export interface VulgardRolesProps extends StackProps {
  /** The GitHub org that owns the vulgard fork. */
  readonly githubOrg: string;
  /** The fork's name. */
  readonly vulgardRepo: string;
  /** The only branch whose workflows may assume the lifecycle role. */
  readonly branch: string;
  /** Reuse the account's GitHub OIDC provider instead of creating one. */
  readonly oidcProviderArn?: string;
  /** Grant the redeploy and delete permissions. Off for report-only and issues-only stages. */
  readonly writes: boolean;
  /** Bucket name or glob of SST's state bucket (the `state` field of SSM `/sst/bootstrap`). */
  readonly sstStateBucket: string;
  /** Policies CloudFormation deletes stacks' resources with. Empty means AdministratorAccess. */
  readonly deletePolicyArns: string[];
}

const GITHUB_OIDC = "token.actions.githubusercontent.com";

/**
 * `VulgardLifecycle`, which the vulgard fork's `nag` workflow assumes through GitHub OIDC, and
 * `VulgardStackDelete`, which CloudFormation uses to delete a stale stack's resources. The
 * lifecycle role never holds delete permissions on resources itself: it can only ask
 * CloudFormation to delete a stack, passing the delete role.
 */
export class VulgardRolesStack extends Stack {
  constructor(scope: Construct, id: string, props: VulgardRolesProps) {
    super(scope, id, props);
    Tags.of(this).add("vulgard:repo", props.vulgardRepo);

    const provider = props.oidcProviderArn
      ? iam.OidcProviderNative.fromOidcProviderArn(this, "GitHubOidc", props.oidcProviderArn)
      : new iam.OidcProviderNative(this, "GitHubOidc", {
          url: `https://${GITHUB_OIDC}`,
          clientIds: ["sts.amazonaws.com"],
          // Other workflows in the account may come to rely on the provider.
          removalPolicy: RemovalPolicy.RETAIN,
        });

    const deleteRole = new iam.Role(this, "StackDelete", {
      roleName: "VulgardStackDelete",
      description: "CloudFormation deletes stale stacks' resources with this role for vulgard",
      assumedBy: new iam.ServicePrincipal("cloudformation.amazonaws.com").withConditions({
        StringEquals: { "aws:SourceAccount": Aws.ACCOUNT_ID },
      }),
      managedPolicies: props.deletePolicyArns.length
        ? props.deletePolicyArns.map((arn, i) =>
            iam.ManagedPolicy.fromManagedPolicyArn(this, `DeletePolicy${i}`, arn),
          )
        : [iam.ManagedPolicy.fromAwsManagedPolicyName("AdministratorAccess")],
    });

    const lifecycle = new iam.Role(this, "Lifecycle", {
      roleName: "VulgardLifecycle",
      description: `Assumed by ${props.githubOrg}/${props.vulgardRepo} to find and clean up stale deployments`,
      maxSessionDuration: Duration.hours(1),
      assumedBy: new iam.WebIdentityPrincipal(provider.oidcProviderArn, {
        StringEquals: {
          [`${GITHUB_OIDC}:aud`]: "sts.amazonaws.com",
          [`${GITHUB_OIDC}:sub`]: `repo:${props.githubOrg}/${props.vulgardRepo}:ref:refs/heads/${props.branch}`,
        },
      }),
    });

    const sstBucket = `arn:${Aws.PARTITION}:s3:::${props.sstStateBucket}`;
    const statements = [
      new iam.PolicyStatement({
        sid: "ReadStacks",
        actions: ["cloudformation:DescribeStacks", "cloudformation:DescribeStackEvents"],
        resources: ["*"],
      }),
      new iam.PolicyStatement({
        sid: "FindSstState",
        actions: ["ssm:GetParameter"],
        resources: [`arn:${Aws.PARTITION}:ssm:*:${Aws.ACCOUNT_ID}:parameter/sst/bootstrap`],
      }),
      new iam.PolicyStatement({
        sid: "ReadSstState",
        actions: ["s3:ListBucket", "s3:GetObject"],
        resources: [sstBucket, `${sstBucket}/*`],
      }),
      new iam.PolicyStatement({
        sid: "ReadAmplify",
        actions: [
          "amplify:ListApps",
          "amplify:ListBranches",
          "amplify:ListJobs",
          "amplify:GetApp",
          "amplify:GetBranch",
        ],
        resources: ["*"],
      }),
    ];
    if (props.writes) {
      const serverlessBucket = `arn:${Aws.PARTITION}:s3:::*-serverlessdeploymentbucket-*`;
      statements.push(
        new iam.PolicyStatement({
          sid: "DeleteStacks",
          actions: ["cloudformation:DeleteStack"],
          resources: ["*"],
        }),
        new iam.PolicyStatement({
          sid: "PassOnlyTheDeleteRole",
          actions: ["iam:PassRole"],
          resources: [deleteRole.roleArn],
          conditions: { StringEquals: { "iam:PassedToService": "cloudformation.amazonaws.com" } },
        }),
        new iam.PolicyStatement({
          sid: "EmptyServerlessBuckets",
          actions: ["s3:ListBucketVersions", "s3:DeleteObject", "s3:DeleteObjectVersion"],
          resources: [serverlessBucket, `${serverlessBucket}/*`],
        }),
        new iam.PolicyStatement({
          sid: "ReleaseAndDeleteAmplifyBranches",
          actions: ["amplify:StartJob", "amplify:DeleteBranch"],
          resources: ["*"],
        }),
      );
    }
    lifecycle.attachInlinePolicy(
      new iam.Policy(this, "LifecyclePolicy", { policyName: "vulgard-lifecycle", statements }),
    );

    new CfnOutput(this, "LifecycleRoleArn", {
      value: lifecycle.roleArn,
      description: "Set as the VULGARD_AWS_ROLE variable on the vulgard fork",
    });
    new CfnOutput(this, "StackDeleteRoleArn", {
      value: deleteRole.roleArn,
      description: "Set as deployments.aws.delete_role_arn in the org config",
    });
  }
}
