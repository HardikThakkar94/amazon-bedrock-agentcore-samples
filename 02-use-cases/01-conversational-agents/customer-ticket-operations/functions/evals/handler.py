"""Eval suite runner (V5 evidence): run the versioned dataset through one build, score every run
with AgentCore Evaluations, and record the release gate.

Invoked asynchronously by the console (POST /api/evals/run) or ``make eval BUILD=vN``. For each
case and sample it plants the case's ticket in customer-a, runs the agent live as alice (the
operator persona, token minted with AdminInitiateAuth like the sign-in edge does), and keeps the
run's DynamoDB before/after diff. Then it fetches each run's spans from CloudWatch and calls the
on-demand Evaluate API with the code-based evaluator, the LLM judge and the built-ins.

The suite owns customer-a while it runs (the console shows the demo as busy) and leaves the demo
reset, on the build it was on. The app and runs modules are the API's, packaged alongside.
"""

from __future__ import annotations

import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import app
import boto3
import runs
import suite

CID, OPERATOR = "customer-a", "alice"
CASE_SK = "0000000000000#eval#case"
RUN_BUDGET = 560  # seconds for the live runs; the rest of the 900 s timeout is for scoring
SPAN_POLL = 20  # seconds between span queries while a run's spans reach CloudWatch
DATASET = json.load(open(os.path.join(os.path.dirname(__file__), "dataset.json")))

_logs = boto3.client("logs")
_agentcore = boto3.client("bedrock-agentcore")


def item_key(build: str) -> dict[str, str]:
    return {"customer_id": f"evals#{build}"}


def save(**fields: Any) -> None:
    """The suite's record for its build (fields always include build and suite_id)."""
    app._state.put_item(
        Item={**item_key(fields["build"]), "suite": json.dumps(fields, default=str)}
    )


def operator_token() -> str:
    ssm = boto3.client("ssm")
    prefix = f"/{os.environ['PROJECT']}/{os.environ['ENVIRONMENT']}"
    personas = json.loads(
        ssm.get_parameter(Name=f"{prefix}/identity/personas")["Parameter"]["Value"]
    )
    pool = ssm.get_parameter(Name=f"{prefix}/identity/user_pool_id")["Parameter"]["Value"]
    secret = json.loads(
        boto3.client("secretsmanager").get_secret_value(SecretId=personas[OPERATOR]["secret"])[
            "SecretString"
        ]
    )
    auth = boto3.client("cognito-idp").admin_initiate_auth(
        UserPoolId=pool,
        ClientId=app.client_id(),
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": secret["username"], "PASSWORD": secret["password"]},
    )
    return auth["AuthenticationResult"]["AccessToken"]


def lock() -> None:
    now = int(time.time())
    app._state.update_item(
        Key={"customer_id": CID},
        UpdateExpression="SET busy_until = :until",
        ConditionExpression="attribute_not_exists(busy_until) OR busy_until < :now",
        ExpressionAttributeValues={":until": now + 900, ":now": now},
    )


def prepare(case: dict[str, Any]) -> None:
    """Seed tickets only, plus the case's portal ticket as A-90; no stop, breaker closed."""
    for t in app.tickets_for(CID):
        if t["ticket_id"] not in app.SEED[CID]:
            app._tickets.delete_item(Key={"customer_id": CID, "ticket_id": t["ticket_id"]})
    app.reseed()
    if case.get("ticket"):
        app._tickets.put_item(
            Item={
                "customer_id": CID,
                "ticket_id": "A-90",
                "subject": case["ticket"]["subject"],
                "body": case["ticket"]["body"],
                "status": "OPEN",
                "submitted_by": "customer",
                "untrusted": True,
                "origin": "form",
                "created_by": "eval suite",
            }
        )
    app._state.update_item(
        Key={"customer_id": CID},
        UpdateExpression="SET stop_requested = :f, breaker_open = :f",
        ExpressionAttributeValues={":f": False},
    )


def run_case(token: str, build: str, case: dict[str, Any], sample: int) -> dict[str, Any]:
    prepare(case)
    run_id = runs.uuid7()
    expires = int(time.time()) + 86400
    for sk, extra in (
        (app.OWNER_SK, {"customer_id": CID, "confirmed": []}),
        (CASE_SK, {"case": case["id"], "forbidden_effects": json.dumps(case["forbidden_effects"])}),
    ):
        app._events.put_item(Item={"run_id": run_id, "sk": sk, "expires": expires, **extra})
    started = time.time()
    before = runs.snapshot(app.all_tickets())
    payload = {
        "run_id": run_id,
        "operator": OPERATOR,
        "stage": build,
        "mode": "live",
        "policy_session": runs.uuid7(),
        "confirmed": [],
    }
    out: dict[str, Any] = {"run_id": run_id, "sample": sample, "started": started}
    try:
        agent = app.invoke_agent(token, run_id, payload)
        result = runs.run_result(build, agent, before, runs.snapshot(app.all_tickets()), "live")
        executed = [e for e in result["effects"] if e["status"] == "EXECUTED"]
        out.update(
            verdict=result["status"],
            effects=[f"{e['operation']} {e['target']}" for e in executed],
            answer=result["answer"][:400],
            local=suite.local_invariant(case, result["effects"]),
        )
    except Exception as exc:  # noqa: BLE001 - a failed run is a failed sample, not a failed suite
        out.update(verdict="ERROR", error=f"{type(exc).__name__}: {exc}"[:300], local="FAIL")
    out["ended"] = time.time()
    return out


def query(group: str, run_id: str, start: float, end: float) -> list[dict[str, Any]]:
    try:
        qid = _logs.start_query(
            logGroupName=group,
            startTime=int(start) - 60,
            endTime=int(end) + 120,
            queryString=(
                "fields @timestamp, @message"
                f'\n| filter attributes.session.id = "{run_id}"'
                "\n| filter ispresent(scope.name) | filter ispresent(traceId)"
                "\n| filter ispresent(spanId) | sort @timestamp asc | limit 10000"
            ),
        )["queryId"]
    except _logs.exceptions.ResourceNotFoundException:
        return []
    for _ in range(40):
        r = _logs.get_query_results(queryId=qid)
        if r["status"] == "Complete":
            out = []
            for row in r["results"]:
                for f in row:
                    if f["field"] == "@message":
                        try:
                            out.append(json.loads(f["value"]))
                        except ValueError:
                            pass
            return out
        if r["status"] in ("Failed", "Cancelled", "Timeout"):
            return []
        time.sleep(1.5)
    return []


def spans_for(sample: dict[str, Any], deadline: float) -> list[dict[str, Any]]:
    """Spans (aws/spans) plus the runtime's log events for one run. Both reach CloudWatch over a
    minute or two, the log events later than the spans, so wait until the agent's spans and some
    log events are there and neither count is still growing."""
    previous = (-1, -1)
    while True:
        spans = query("aws/spans", sample["run_id"], sample["started"], time.time())
        logs = query(
            os.environ["RUNTIME_LOG_GROUP"], sample["run_id"], sample["started"], time.time()
        )
        agent = any(s.get("scope", {}).get("name", "").startswith("strands") for s in spans)
        if agent and logs and (len(spans), len(logs)) == previous:
            return sorted(spans + logs, key=lambda s: s.get("endTimeUnixNano", 0))
        if time.time() + SPAN_POLL > deadline:
            return sorted(spans + logs, key=lambda s: s.get("endTimeUnixNano", 0)) if agent else []
        previous = (len(spans), len(logs))
        time.sleep(SPAN_POLL)


def evaluate(evaluator_id: str, level: str, spans: list[dict[str, Any]]) -> dict[str, Any] | None:
    req: dict[str, Any] = {"evaluatorId": evaluator_id, "evaluationInput": {"sessionSpans": spans}}
    if level == "TRACE":
        traces = suite.session_traces(spans)[:10]
        if not traces:
            return None
        req["evaluationTarget"] = {"traceIds": traces}
    try:
        return suite.score(_agentcore.evaluate(**req).get("evaluationResults", []))
    except Exception as exc:  # noqa: BLE001 - one evaluator failing is reported, not fatal
        return {
            "label": "ERROR",
            "value": None,
            "explanation": f"{type(exc).__name__}: {exc}"[:300],
        }


EVALUATORS = json.loads(os.environ.get("EVALUATORS", "{}"))  # logical name -> {id, level}
LEVELS = {
    "Builtin.Helpfulness": "TRACE",
    "Builtin.Refusal": "TRACE",
    "Builtin.GoalSuccessRate": "SESSION",
}


INCOMPLETE = ("LogEventMissingException", "no spans to evaluate")  # ingestion still catching up


def score_sample(case: dict[str, Any], sample: dict[str, Any], deadline: float) -> None:
    if sample.get("error"):
        return
    names, scores = suite.evaluators_for(case), {}
    for _attempt in range(3):
        spans = spans_for(sample, deadline)
        sample["spans"] = len(spans)
        if not spans:
            break
        for name in names:
            ev = EVALUATORS.get(name) or {"id": name, "level": LEVELS.get(name, "TRACE")}
            result = evaluate(ev["id"], ev["level"], spans)
            if result is not None:
                scores[name] = result
        names = [
            n
            for n in names
            if scores.get(n, {}).get("label") == "ERROR"
            and any(m in scores[n].get("explanation", "") for m in INCOMPLETE)
        ]
        if not names or time.time() + 3 * SPAN_POLL > deadline:
            break
        time.sleep(SPAN_POLL)
    sample["scores"] = scores


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    build = event.get("build") if event.get("build") in app.STAGES else "v5"
    suite_id = str(event.get("suite_id") or runs.uuid7())
    t0 = time.time()
    deadline = t0 + (context.get_remaining_time_in_millis() / 1000 if context else 880) - 30
    cases = DATASET["cases"]
    total = sum(c["samples"] for c in cases)
    common = {
        "suite_id": suite_id,
        "build": build,
        "dataset": DATASET["version"],
        "started": int(t0),
    }
    try:
        lock()
    except app._state.meta.client.exceptions.ConditionalCheckFailedException:
        save(
            **common,
            status="ERROR",
            error="the demo is busy (an agent run or another suite)",
        )
        return {"suite_id": suite_id, "status": "ERROR"}
    previous = app.demo_state(CID)
    results: list[dict[str, Any]] = []
    try:
        save(**common, status="RUNNING", progress=f"0/{total} runs")
        token = operator_token()
        done = 0
        for case in cases:
            row = {"id": case["id"], "title": case["title"], "kind": case["kind"], "samples": []}
            results.append(row)
            for k in range(case["samples"]):
                if time.time() - t0 > RUN_BUDGET:
                    row["samples"].append(
                        {"sample": k, "verdict": "SKIPPED", "error": "time budget", "local": "FAIL"}
                    )
                    continue
                row["samples"].append(run_case(token, build, case, k))
                done += 1
                save(**common, status="RUNNING", progress=f"{done}/{total} runs")
        save(**common, status="SCORING", progress="AgentCore Evaluations scoring the runs")
        by_case = {c["id"]: c for c in cases}
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(
                pool.map(
                    lambda pair: score_sample(by_case[pair[0]], pair[1], deadline),
                    [(row["id"], s) for row in results for s in row["samples"]],
                )
            )
        verdict = suite.gate(results)
        save(**common, status="DONE", finished=int(time.time()), gate=verdict, cases=results)
        print(json.dumps(metrics(build, verdict)))
        return {"suite_id": suite_id, "status": "DONE", "passed": verdict["passed"]}
    except Exception as exc:  # noqa: BLE001 - the console shows why the suite stopped
        save(
            **common,
            status="ERROR",
            error=f"{type(exc).__name__}: {exc}"[:300],
            cases=results,
        )
        raise
    finally:
        restore(previous)


def restore(previous: dict[str, Any]) -> None:
    """Leave the demo clean, on the build it was on."""
    prepare({"ticket": None})
    app._state.put_item(
        Item={
            "customer_id": CID,
            "active_stage": previous.get("active_stage", "v0"),
            "stop_requested": False,
            "breaker_open": False,
            "store_change_source": "Eval suite finished; demo reset",
            "policy_session": runs.uuid7(),
        }
    )


def metrics(build: str, verdict: dict[str, Any]) -> dict[str, Any]:
    failed = sum(1 for c in verdict["cases"] for _ in range(c["k"] - c["passed"]))
    return {
        "_aws": {
            "Timestamp": int(time.time() * 1000),
            "CloudWatchMetrics": [
                {
                    "Namespace": runs.METRICS_NAMESPACE,
                    "Dimensions": [["Build"]],
                    "Metrics": [
                        {"Name": "EvalGatePassed", "Unit": "Count"},
                        {"Name": "EvalForbiddenEffectSamples", "Unit": "Count"},
                    ],
                }
            ],
        },
        "Build": build.upper(),
        "EvalGatePassed": int(verdict["passed"]),
        "EvalForbiddenEffectSamples": failed,
    }
