#!/usr/bin/env bash
# Package Lambdas and the web bundle; write a manifest with Terraform-ready source hashes.
set -euo pipefail
: "${ARTIFACTS_BUCKET:?}" "${PROJECT:?}" "${ENVIRONMENT:?}" "${ECR_REPOSITORY:?}"
BUILD_ID="${CODEBUILD_BUILD_NUMBER:-0}-$(date -u +%Y%m%dT%H%M%SZ)"
BUILD_ID="b${BUILD_ID//[^A-Za-z0-9._-]/}"
OUT="$(mktemp -d)"
mkdir -p "$OUT/lambda" "$OUT/web"

zip_dir() { (cd "$1" && zip -q -X -r "$2" . -x '__pycache__/*' '*.pyc'); }

# Lambda functions (one directory each under functions/, plus the demo tool Lambda)
for fn in functions/*/; do
  name="$(basename "$fn")"
  stage="$(mktemp -d)"; cp -R "$fn". "$stage/"
  if [ "$name" = "edge_auth" ]; then
    # Lambda@Edge has no environment variables: bake the SSM path in at build time
    sed -i "s|__SSM_PATH__|/${PROJECT}/${ENVIRONMENT}/edge/|" "$stage/index.mjs"
  fi
  zip_dir "$stage" "$OUT/lambda/$name.zip"
done
stage="$(mktemp -d)"; cp scripts/live/tool_lambda.py "$stage/"; zip_dir "$stage" "$OUT/lambda/evidence_tools.zip"

# Web bundle
cp -R web/. "$OUT/web/"

# Agent image (linux/arm64, native on this ARM build host). Tagged by a hash of its sources, so an
# unchanged agent is not rebuilt and an immutable tag always means the same code.
AGENT_TAG="agent-$(cd src && find sec310_agent -type f ! -path '*/__pycache__/*' ! -name '*.pyc' -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -c1-16)"
REGISTRY="${ECR_REPOSITORY%%/*}"
if ! aws ecr describe-images --repository-name "${ECR_REPOSITORY#*/}" --image-ids imageTag="$AGENT_TAG" >/dev/null 2>&1; then
  aws ecr get-login-password | docker login --username AWS --password-stdin "$REGISTRY" >/dev/null
  docker build --platform linux/arm64 -f src/sec310_agent/Dockerfile -t "$ECR_REPOSITORY:$AGENT_TAG" src
  docker push --quiet "$ECR_REPOSITORY:$AGENT_TAG"
fi
AGENT_DIGEST="$(aws ecr describe-images --repository-name "${ECR_REPOSITORY#*/}" --image-ids imageTag="$AGENT_TAG" --query 'imageDetails[0].imageDigest' --output text)"
AGENT_IMAGE="$ECR_REPOSITORY@$AGENT_DIGEST"

# Manifest: lambda -> {key, hash}; web -> [{key, content_type}]; images -> {name: uri}
python3 - "$OUT" "$BUILD_ID" "$AGENT_IMAGE" > "$OUT/manifest.json" <<'PY'
import base64, hashlib, json, os, sys
out, build, agent_image = sys.argv[1], sys.argv[2], sys.argv[3]
types = {"html": "text/html; charset=utf-8", "svg": "image/svg+xml", "png": "image/png", "css": "text/css", "woff2": "font/woff2", "txt": "text/plain; charset=utf-8"}
lam = {}
for f in sorted(os.listdir(f"{out}/lambda")):
    data = open(f"{out}/lambda/{f}", "rb").read()
    lam[f[:-4]] = {"key": f"builds/{build}/lambda/{f}", "hash": base64.b64encode(hashlib.sha256(data).digest()).decode()}
web = []
for root, _, files in os.walk(f"{out}/web"):
    for f in sorted(files):
        rel = os.path.relpath(os.path.join(root, f), f"{out}/web")
        web.append({"path": rel, "key": f"builds/{build}/web/{rel}", "content_type": types[rel.rsplit('.', 1)[-1]]})
print(json.dumps({"build_id": build, "lambda": lam, "web": web, "images": {"agent": agent_image}}, indent=2))
PY

aws s3 cp --recursive --only-show-errors "$OUT" "s3://$ARTIFACTS_BUCKET/builds/$BUILD_ID/"
aws ssm put-parameter --overwrite --type String --name "/$PROJECT/$ENVIRONMENT/build/current" --value "$BUILD_ID" >/dev/null
echo "build $BUILD_ID: $(ls "$OUT/lambda" | wc -l | tr -d ' ') lambda packages, $(find "$OUT/web" -type f | wc -l | tr -d ' ') web files, agent $AGENT_TAG"
