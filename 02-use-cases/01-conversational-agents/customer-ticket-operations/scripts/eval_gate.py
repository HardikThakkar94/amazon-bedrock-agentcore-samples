"""Release gate: run the eval suite on one build and exit non-zero unless it passes.

    make eval BUILD=v5 PROFILE=<aws-profile>

Starts the suite runner Lambda (deployed by the evals root) and follows its progress in the state
table, then prints the per-case matrix. The suite resets the demo when it finishes.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import uuid

import boto3

GREEN, PINK, DIM, RESET = "\033[38;2;110;231;80m", "\033[38;2;255;77;139m", "\033[2m", "\033[0m"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", default="v5", choices=[f"v{i}" for i in range(6)])
    ap.add_argument("--project", default="sec310")
    ap.add_argument("--env", default="burner")
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--timeout", type=int, default=1200)
    a = ap.parse_args()
    ssm = boto3.client("ssm", region_name=a.region)
    param = lambda k: ssm.get_parameter(Name=f"/{a.project}/{a.env}/{k}")["Parameter"]["Value"]  # noqa: E731
    function, table = param("evals/runner_function"), param("app/state_table")
    state = boto3.resource("dynamodb", region_name=a.region).Table(table)
    suite_id = str(uuid.uuid4())
    boto3.client("lambda", region_name=a.region).invoke(
        FunctionName=function,
        InvocationType="Event",
        Payload=json.dumps({"build": a.build, "suite_id": suite_id}).encode(),
    )
    print(f"eval suite {suite_id} on {a.build.upper()} started ({function})")
    deadline, last = time.time() + a.timeout, ""
    while time.time() < deadline:
        item = state.get_item(Key={"customer_id": f"evals#{a.build}"}, ConsistentRead=True).get(
            "Item"
        )
        suite = json.loads(item["suite"]) if item else {}
        if suite.get("suite_id") == suite_id:
            line = f"{suite.get('status')} {suite.get('progress', '')}".strip()
            if line != last:
                print(f"  {DIM}{line}{RESET}")
                last = line
            if suite.get("status") == "ERROR":
                print(f"{PINK}suite error: {suite.get('error')}{RESET}")
                return 2
            if suite.get("status") == "DONE":
                return report(suite)
        time.sleep(10)
    print(f"{PINK}timed out waiting for the suite{RESET}")
    return 2


def report(suite: dict) -> int:
    gate = suite["gate"]
    rows = {c["id"]: c for c in gate["cases"]}
    print()
    for case in suite["cases"]:
        r = rows[case["id"]]
        mark = f"{GREEN}PASS{RESET}" if r["safety"] == "PASS" else f"{PINK}FAIL{RESET}"
        judge = [
            (s.get("scores") or {}).get("ticket_text_as_data", {}).get("label", "-")
            for s in case["samples"]
        ]
        verdicts = ", ".join(s.get("verdict", "?") for s in case["samples"])
        print(
            f"  {mark}  {case['title']:<46} {r['passed']}/{r['k']}  runs: {verdicts:<24} judge: {'/'.join(judge)}"
        )
    q = gate["quality"]
    print(f"\n  quality: mean Helpfulness {q['helpfulness_mean']} (floor {q['floor']})")
    ok = gate["passed"]
    print(
        f"\n{GREEN if ok else PINK}{suite['build'].upper()} release gate: {'PASS' if ok else 'FAIL'}{RESET}"
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
