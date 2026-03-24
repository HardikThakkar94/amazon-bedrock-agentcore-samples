"""
CDK Stack: M2M + Auth Code Flows with AgentCore Runtime (Cognito)

Deploys everything in one stack:
- Cognito User Pool + User Client + Machine Client + Domain + Resource Server
- Token vault KMS policy on the runtime role
- CfnWorkloadIdentity with allowedResourceOauth2ReturnUrls (for 3LO)
- IAM role for AgentCore Runtime with all required permissions
- S3-packaged agent code
- AgentCore Runtime with Cognito JWT inbound auth

Post-deploy: run python setup_oauth_providers.py to create
GitHub/Google/M2M credential providers.
"""
import os
import re
from aws_cdk import (
    Duration,
    RemovalPolicy,
    Stack,
    CfnOutput,
    aws_cognito as cognito,
    aws_bedrockagentcore as bedrockagentcore,
    aws_iam as iam,
    aws_kms as kms,
    aws_ecr_assets as ecr_assets,
    custom_resources as cr,
)
from constructs import Construct


class M2MAuthStack(Stack):

    def __init__(self, scope: Construct, id: str,
                 callback_url: str = "http://localhost:9090/oauth2/callback",
                 **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        region = self.region
        account = self.account

        # ── Cognito User Pool ──────────────────────────────────────
        user_pool = cognito.UserPool(
            self, "UserPool",
            password_policy=cognito.PasswordPolicy(min_length=8),
            self_sign_up_enabled=False,
            removal_policy=RemovalPolicy.DESTROY,
        )

        # User-facing client (for inbound JWT auth)
        user_client = user_pool.add_client(
            "UserClient",
            auth_flows=cognito.AuthFlow(user_password=True),
            generate_secret=False,
            access_token_validity=Duration.hours(1),
        )

        # Resource server for M2M scopes
        resource_server = user_pool.add_resource_server(
            "M2MResourceServer",
            identifier="https://api.m2m-demo.internal",
            user_pool_resource_server_name="M2MDemoAPI",
            scopes=[
                cognito.ResourceServerScope(
                    scope_name="read",
                    scope_description="Read access",
                )
            ],
        )
        m2m_scope = f"https://api.m2m-demo.internal/read"

        # Machine client (for M2M client credentials flow)
        machine_client = user_pool.add_client(
            "MachineClient",
            generate_secret=True,
            auth_flows=cognito.AuthFlow(user_password=False),
            o_auth=cognito.OAuthSettings(
                flows=cognito.OAuthFlows(client_credentials=True),
                scopes=[
                    cognito.OAuthScope.resource_server(resource_server,
                        cognito.ResourceServerScope(scope_name="read", scope_description="Read access"))
                ],
            ),
        )

        # Cognito domain (required for client_credentials token endpoint)
        safe_pool_id = re.sub(r"[^a-z0-9]", "-", "m2m-auth-")
        domain = user_pool.add_domain(
            "CognitoDomain",
            cognito_domain=cognito.CognitoDomainOptions(
                domain_prefix=f"m2m-cdk-{account}-{region}"[:63],
            ),
        )
        token_endpoint = (
            f"https://m2m-cdk-{account}-{region}.auth.{region}"
            ".amazoncognito.com/oauth2/token"
        )

        discovery_url = (
            f"https://cognito-idp.{region}.amazonaws.com"
            f"/{user_pool.user_pool_id}/.well-known/openid-configuration"
        )

        # ── CfnWorkloadIdentity ────────────────────────────────────
        workload_identity = bedrockagentcore.CfnWorkloadIdentity(
            self, "WorkloadIdentity",
            name="M2MAuthCdk_Agent",
            allowed_resource_oauth2_return_urls=[callback_url],
        )

        # ── Agent code ─────────────────────────────────────────────
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
                    # KMS: required for USER_FEDERATION token storage in token vault
                    iam.PolicyStatement(
                        sid="KMSTokenVault",
                        actions=[
                            "kms:Decrypt",
                            "kms:GenerateDataKey",
                            "kms:DescribeKey",
                        ],
                        resources=["*"],
                    ),
                ]),
            },
        )

        image_asset.repository.grant_pull(runtime_role)

        # ── AgentCore Runtime ──────────────────────────────────────
        runtime = bedrockagentcore.CfnRuntime(
            self, "Runtime",
            agent_runtime_name=workload_identity.name,
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
                    allowed_clients=[user_client.user_pool_client_id],
                )
            ),
            environment_variables={
                "CALLBACK_URL": callback_url,
            },
        )

        # Runtime name must match workload identity name
        runtime.add_dependency(workload_identity)

        # ── Outputs ────────────────────────────────────────────────
        CfnOutput(self, "RuntimeArn", value=runtime.attr_agent_runtime_arn)
        CfnOutput(self, "RuntimeId", value=runtime.attr_agent_runtime_id)
        CfnOutput(self, "UserPoolId", value=user_pool.user_pool_id)
        CfnOutput(self, "UserClientId", value=user_client.user_pool_client_id)
        CfnOutput(self, "MachineClientId", value=machine_client.user_pool_client_id)
        CfnOutput(self, "TokenEndpoint", value=token_endpoint)
        CfnOutput(self, "M2MScope", value=m2m_scope)
        CfnOutput(self, "DiscoveryUrl", value=discovery_url)
        CfnOutput(self, "CallbackUrl", value=callback_url)
        CfnOutput(self, "Region", value=region)
