# Support agent image for AgentCore Runtime. Built by CodeBuild (ARM64) from the repo's src/ dir;
# never built on a laptop. AgentCore Runtime requires linux/arm64 and port 8080.
FROM public.ecr.aws/docker/library/python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app

COPY sec310_agent/requirements.txt ./requirements.txt
RUN pip install -r requirements.txt

# Read-only for the runtime user, whatever modes the checkout had (a synced folder can leave 0700).
COPY sec310_agent ./sec310_agent
RUN chmod -R a+rX,go-w sec310_agent && useradd --uid 10001 --create-home agent
USER agent

EXPOSE 8080
CMD ["opentelemetry-instrument", "python", "-m", "sec310_agent.app"]
