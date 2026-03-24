#!/usr/bin/env python3
import aws_cdk as cdk
from runtime_auth_stack import RuntimeAuthStack

app = cdk.App()
RuntimeAuthStack(app, "AgentCore-RuntimeAuthCdk")
app.synth()
