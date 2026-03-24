"""
CDK Stack: AgentCore Gateway Inbound + Outbound Auth (Cognito JWT + MCP)

Deploys everything in one stack:
- Cognito User Pool + User Client + Agent Client
- Lambda MCP test server + HTTP API Gateway (upstream tool target)
- IAM roles for Gateway and Runtime
- AgentCore Gateway with Cognito JWT inbound auth
- AgentCore Gateway Target (Lambda MCP, no outbound auth for simplicity)
- S3-packaged agent code
- AgentCore Runtime

Post-deploy: run python setup.py to create test user + gateway credential
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
    aws_lambda as lambda_,
    aws_apigatewayv2 as apigwv2,
    aws_apigatewayv2_integrations as apigwv2_integrations,
    aws_ecr_assets as ecr_assets,
)
from constructs import Construct

# Zero-dependency MCP test server (get_time + echo tools)
_MCP_HANDLER = """
import json
from datetime import datetime, timezone

TOOLS = [
    {"name": "get_time", "description": "Get current UTC time",
     "inputSchema": {"type": "object", "properties": {}, "required": []}},
    {"name": "echo", "description": "Echo a message",
     "inputSchema": {"type": "object",
                     "properties": {"message": {"type": "string"}},
                     "required": ["message"]}},
]

def handle_request(body):
    method = body.get("method", "")
    params = body.get("params", {})
    req_id = body.get("id")
    if method == "initialize":
        result = {"protocolVersion": params.get("protocolVersion", "2025-03-26"),
                  "capabilities": {"tools": {}},
                  "serverInfo": {"name": "MCPTestServer", "version": "1.0.0"}}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        name = params.get("name")
        args = params.get("arguments", {})
        if name == "get_time":
            text = datetime.now(timezone.utc).isoformat()
        elif name == "echo":
            text = f"Echo: {args.get('message', '')}"
        else:
            return {"jsonrpc": "2.0",
                    "error": {"code": -32601, "message": f"Unknown tool: {name}"},
                    "id": req_id}
        result = {"content": [{"type": "text", "text": text}]}
    elif method in ("notifications/initialized", "notifications/cancelled"):
        return None
    else:
        return {"jsonrpc": "2.0",
                "error": {"code": -32601, "message": f"Method not found: {method}"},
                "id": req_id}
    return {"jsonrpc": "2.0", "result": result, "id": req_id}

def lambda_handler(event, context):
    try:
        body = json.loads(event.get("body") or "{}")
        if isinstance(body, list):
            responses = [r for r in [handle_request(r) for r in body] if r is not None]
            return {"statusCode": 200,
                    "headers": {"Content-Type": "application/json"},
                    "body": json.dumps(responses)}
        response = handle_request(body)
        if response is None:
            return {"statusCode": 202, "body": ""}
        return {"statusCode": 200,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps(response)}
    except Exception as e:
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}
"""


class GatewayAuthStack(Stack):

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

        # Resource server for gateway scope (needed for client_credentials)
        gateway_rs = user_pool.add_resource_server(
            "GatewayResourceServer",
            identifier="https://gateway.example.internal",
            user_pool_resource_server_name="GatewayAPI",
            scopes=[
                cognito.ResourceServerScope(
                    scope_name="invoke",
                    scope_description="Permission to invoke the gateway",
                )
            ],
        )
        gateway_scope = cognito.OAuthScope.resource_server(
            gateway_rs,
            cognito.ResourceServerScope(scope_name="invoke", scope_description="Permission to invoke the gateway"),
        )

        # User-facing client (callers use this to get tokens)
        user_client = user_pool.add_client(
            "UserClient",
            auth_flows=cognito.AuthFlow(user_password=True),
            generate_secret=False,
            access_token_validity=Duration.hours(1),
        )

        # Agent-facing client (agent uses this to call the gateway via client_credentials)
        agent_client = user_pool.add_client(
            "AgentClient",
            auth_flows=cognito.AuthFlow(user_password=False),
            generate_secret=True,
            o_auth=cognito.OAuthSettings(
                flows=cognito.OAuthFlows(client_credentials=True),
                scopes=[gateway_scope],
            ),
        )

        discovery_url = (
            f"https://cognito-idp.{region}.amazonaws.com"
            f"/{user_pool.user_pool_id}/.well-known/openid-configuration"
        )

        # ── Lambda MCP test server ─────────────────────────────────
        mcp_fn = lambda_.Function(
            self, "McpFunction",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="index.lambda_handler",
            code=lambda_.Code.from_inline(_MCP_HANDLER),
            timeout=Duration.seconds(30),
        )

        # HTTP API Gateway wrapping the Lambda
        http_api = apigwv2.HttpApi(
            self, "McpApi",
            cors_preflight=apigwv2.CorsPreflightOptions(
                allow_origins=["*"],
                allow_methods=[apigwv2.CorsHttpMethod.POST, apigwv2.CorsHttpMethod.OPTIONS],
                allow_headers=["Content-Type", "Authorization"],
            ),
        )
        http_api.add_routes(
            path="/mcp",
            methods=[apigwv2.HttpMethod.POST],
            integration=apigwv2_integrations.HttpLambdaIntegration(
                "McpIntegration", mcp_fn
            ),
        )
        mcp_endpoint = f"{http_api.api_endpoint}/mcp"

        # ── Gateway IAM role ───────────────────────────────────────
        gateway_role = iam.Role(
            self, "GatewayRole",
            assumed_by=iam.ServicePrincipal("bedrock-agentcore.amazonaws.com"),
            description="IAM role for AgentCore Gateway",
        )

        # ── AgentCore Gateway ──────────────────────────────────────
        gateway = bedrockagentcore.CfnGateway(
            self, "Gateway",
            name="GatewayAuthCdk-Gateway",
            protocol_type="MCP",
            role_arn=gateway_role.role_arn,
            authorizer_type="CUSTOM_JWT",
            authorizer_configuration=bedrockagentcore.CfnGateway.AuthorizerConfigurationProperty(
                custom_jwt_authorizer=bedrockagentcore.CfnGateway.CustomJWTAuthorizerConfigurationProperty(
                    discovery_url=discovery_url,
                    allowed_audience=[user_pool.user_pool_id],
                    allowed_clients=[user_client.user_pool_client_id],
                )
            ),
        )

        # ── Gateway Target (Lambda MCP) ────────────────────────────
        bedrockagentcore.CfnGatewayTarget(
            self, "GatewayTarget",
            name="McpTools",
            gateway_identifier=gateway.attr_gateway_identifier,
            target_configuration=bedrockagentcore.CfnGatewayTarget.TargetConfigurationProperty(
                mcp=bedrockagentcore.CfnGatewayTarget.McpTargetConfigurationProperty(
                    mcp_server=bedrockagentcore.CfnGatewayTarget.McpServerTargetConfigurationProperty(
                        endpoint=mcp_endpoint,
                    )
                )
            ),
        )

        # ── Agent code ─────────────────────────────────────────────
        image_asset = ecr_assets.DockerImageAsset(
            self, "AgentImage",
            directory=os.path.join(os.path.dirname(__file__), "..", "app"),
        )

        # ── Runtime IAM role ───────────────────────────────────────
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
            agent_runtime_name="GatewayAuthCdk_Agent",
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
                "AGENTCORE_GATEWAY_URL": gateway.attr_gateway_url,
            },
        )

        # ── Outputs ────────────────────────────────────────────────
        CfnOutput(self, "RuntimeArn", value=runtime.attr_agent_runtime_arn)
        CfnOutput(self, "RuntimeId", value=runtime.attr_agent_runtime_id)
        CfnOutput(self, "GatewayId", value=gateway.attr_gateway_identifier)
        CfnOutput(self, "GatewayUrl", value=gateway.attr_gateway_url)
        CfnOutput(self, "McpEndpoint", value=mcp_endpoint)
        CfnOutput(self, "UserPoolId", value=user_pool.user_pool_id)
        CfnOutput(self, "UserClientId", value=user_client.user_pool_client_id)
        CfnOutput(self, "AgentClientId", value=agent_client.user_pool_client_id)
        CfnOutput(self, "DiscoveryUrl", value=discovery_url)
        CfnOutput(self, "Region", value=region)
