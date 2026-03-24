#!/usr/bin/env python3
import aws_cdk as cdk
from gateway_auth_stack import GatewayAuthStack

app = cdk.App()
GatewayAuthStack(app, "AgentCore-GatewayAuthCdk")
app.synth()
