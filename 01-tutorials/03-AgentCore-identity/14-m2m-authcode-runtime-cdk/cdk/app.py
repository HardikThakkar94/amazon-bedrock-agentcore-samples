#!/usr/bin/env python3
import aws_cdk as cdk
from m2m_auth_stack import M2MAuthStack

app = cdk.App()

# Pass callback_url as a CDK context parameter:
#   cdk deploy -c callback_url=http://localhost:9090/oauth2/callback
callback_url = app.node.try_get_context("callback_url") or "http://localhost:9090/oauth2/callback"

M2MAuthStack(app, "AgentCore-M2MAuthCdk", callback_url=callback_url)
app.synth()
