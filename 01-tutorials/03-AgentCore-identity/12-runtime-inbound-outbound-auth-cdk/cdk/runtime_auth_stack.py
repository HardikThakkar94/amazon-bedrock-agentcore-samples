"""
CDK Stack: AgentCore Runtime Inbound + Outbound Auth (Cognito JWT + API Key)

Deploys everything in one stack:
- Cognito User Pool + App Client for inbound JWT auth
- IAM execution role with required permissions
- Agent code packaged as an S3 asset
- AgentCore Runtime with Cognito JWT authorizer

Post-deploy: run python setup.py --api-key <YOUR_KEY>
"""
import os
from aws_cdk import (
    Duration,
    RemovalPolicy,
    Stack,
    CfnOutput,
    aws_cognito as cognito,
    aws_bedrockagentcore as bedrockagentcore,
    aws_iam as iam,
    aws_ecr_assets as ecr_assets,
)
from constructs import Construct


class RuntimeAuthStack(Stack):

    def __init__(self, scope: Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        region = self.region
        account = self.account

        # ── Cognito ────────────────────────────────────────────────
        user_pool = cognito.UserPool(
            self, "UserPool",
            password_policy=cognito.PasswordPolicy(min_length=8),
            self_sign_up_enabled=False,
            removal_policy=RemovalPolicy.DESTROY,
        )

        app_client = user_pool.add_client(
            "AppClient",
            auth_flows=cognito.AuthFlow(user_password=True),
            generate_secret=False,
            access_token_validity=Duration.hours(1),
        )

        discovery_url = (
            f"https://cognito-idp.{region}.amazonaws.com"
            f"/{user_pool.user_pool_id}/.well-known/openid-configuration"
        )

        # ── Agent code (S3 asset) ──────────────────────────────────
        image_asset = ecr_assets.DockerImageAsset(
            self, "AgentImage",
            directory=os.path.join(os.path.dirname(__file__), "..", "app"),
        )

        # ── IAM role ───────────────────────────────────────────────
        runtime_role = iam.Role(
            self, "RuntimeRole",
            assumed_by=iam.ServicePrincipal("bedrock-agentcore.amazonaws.com"),
            description="AgentCore Runtime execution role",
            inline_policies={
                "RuntimePolicy": iam.PolicyDocument(statements=[
                    iam.PolicyStatement(
                        sid="BedrockModel",
                        actions=[
                            "bedrock:InvokeModel",
                            "bedrock:InvokeModelWithResponseStream",
                        ],
                        resources=[
                            "arn:aws:bedrock:*::foundation-model/*",
                            f"arn:aws:bedrock:{region}:{account}:*",
                        ],
                    ),
                    iam.PolicyStatement(
                        sid="Logging",
                        actions=[
                            "logs:CreateLogGroup", "logs:CreateLogStream",
                            "logs:PutLogEvents", "logs:DescribeLogGroups",
                            "logs:DescribeLogStreams",
                        ],
                        resources=[
                            f"arn:aws:logs:{region}:{account}:log-group:"
                            "/aws/bedrock-agentcore/runtimes/*",
                            f"arn:aws:logs:{region}:{account}:log-group:"
                            "/aws/bedrock-agentcore/runtimes/*:log-stream:*",
                        ],
                    ),
                    iam.PolicyStatement(
                        sid="ECRAccess",
                        actions=[
                            "ecr:GetAuthorizationToken",
                            "ecr:BatchGetImage",
                            "ecr:GetDownloadUrlForLayer",
                        ],
                        resources=["*"],
                    ),
                    iam.PolicyStatement(
                        sid="WorkloadAccessToken",
                        actions=[
                            "bedrock-agentcore:GetWorkloadAccessToken",
                            "bedrock-agentcore:GetWorkloadAccessTokenForJWT",
                        ],
                        resources=[
                            f"arn:aws:bedrock-agentcore:{region}:{account}:"
                            "workload-identity-directory/default",
                            f"arn:aws:bedrock-agentcore:{region}:{account}:"
                            "workload-identity-directory/default/workload-identity/*",
                        ],
                    ),
                    iam.PolicyStatement(
                        sid="IdentityOutbound",
                        actions=[
                            "bedrock-agentcore:GetResourceApiKey",
                            "bedrock-agentcore:GetResourceOauth2Token",
                        ],
                        resources=["*"],
                    ),
                    iam.PolicyStatement(
                        sid="SecretsManager",
                        actions=["secretsmanager:GetSecretValue"],
                        resources=[
                            f"arn:aws:secretsmanager:{region}:{account}:"
                            "secret:bedrock-agentcore*",
                        ],
                    ),
                ]),
            },
        )

        image_asset.repository.grant_pull(runtime_role)

        # ── AgentCore Runtime ──────────────────────────────────────
        runtime = bedrockagentcore.CfnRuntime(
            self, "Runtime",
            agent_runtime_name="RuntimeAuthCdk_Agent",
            agent_runtime_artifact=bedrockagentcore.CfnRuntime.AgentRuntimeArtifactProperty(
                container_configuration=bedrockagentcore.CfnRuntime.ContainerConfigurationProperty(
                    container_uri=image_asset.image_uri,
                )
            ),
            role_arn=runtime_role.role_arn,
            network_configuration=bedrockagentcore.CfnRuntime.NetworkConfigurationProperty(
                network_mode="PUBLIC"
            ),
            protocol_configuration="HTTP",
            authorizer_configuration=bedrockagentcore.CfnRuntime.AuthorizerConfigurationProperty(
                custom_jwt_authorizer=bedrockagentcore.CfnRuntime.CustomJWTAuthorizerConfigurationProperty(
                    discovery_url=discovery_url,
                    allowed_clients=[app_client.user_pool_client_id],
                )
            ),
        )

        # ── Outputs ────────────────────────────────────────────────
        CfnOutput(self, "RuntimeArn", value=runtime.attr_agent_runtime_arn)
        CfnOutput(self, "RuntimeId", value=runtime.attr_agent_runtime_id)
        CfnOutput(self, "UserPoolId", value=user_pool.user_pool_id)
        CfnOutput(self, "ClientId", value=app_client.user_pool_client_id)
        CfnOutput(self, "DiscoveryUrl", value=discovery_url)
        CfnOutput(self, "Region", value=region)
