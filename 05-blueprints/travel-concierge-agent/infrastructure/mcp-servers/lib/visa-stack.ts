import * as cdk from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';
import { BaseMcpStack } from './base-mcp-stack';

export class VisaStack extends BaseMcpStack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, {
      ...props,
      mcpName: 'visa',
      agentCodePath: 'concierge_agent/mcp_visa_tools',
      // NOTE: We use Secrets Manager (not SSM) because Visa code uses secretsmanager client
      additionalPolicies: [
        new iam.PolicyStatement({
          sid: 'SecretsManagerAccess',
          effect: iam.Effect.ALLOW,
          actions: [
            'secretsmanager:GetSecretValue',
            'secretsmanager:DescribeSecret'
          ],
          resources: [
            `arn:aws:secretsmanager:${cdk.Aws.REGION}:${cdk.Aws.ACCOUNT_ID}:secret:visa/*`
          ]
        })
      ]
    });

    cdk.Tags.of(this).add('Service', 'Visa-MCP');
  }
}
