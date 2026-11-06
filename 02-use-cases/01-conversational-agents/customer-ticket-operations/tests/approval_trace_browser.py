"""Shipped Chrome: authorized approval run survives policy-session rotation.

Only loopback API/event fixtures; this deliberately issues one simulated approve POST.
It is separate from the zero-mutation recorded-reload browser regression.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
TRACE = json.loads((ROOT / "tests/fixtures/recorded_trace_r12.json").read_text())
HELD = TRACE["run_id"]
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"


class Quiet(SimpleHTTPRequestHandler):
    def log_message(self, *_):
        pass


def main():
    late_events = "--late-events" in sys.argv
    server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Quiet, directory=str(ROOT / "web")))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    card = {
        "id": HELD + "-1",
        "run_id": HELD,
        "ticket_id": "A-41",
        "tool": "close_ticket",
        "customer_id": "customer-a",
        "status": "PENDING",
        "reason": "issue resolved",
        "requested_by": "operator",
    }
    state = {
        "persona": {"username": "alice", "customer_id": "customer-a", "role": "operator"},
        "active_stage": "v3",
        "model": "llama4-maverick",
        "policy_session": "held-session",
        "tickets": [
            {
                "ticket_id": "A-41",
                "subject": "Package arrived late",
                "status": "OPEN",
                "origin": "seed",
                "customer_id": "customer-a",
            }
        ],
        "approvals": [card],
        "last_run": {
            "run_id": HELD,
            "stage": "v3",
            "status": "AWAITING_APPROVAL",
            "answer": "Native close held; waiting for separate approval.",
            "effects": [],
        },
        "recorded_run": {"run_id": HELD, "stage": "v3"},
    }
    new = {"id": "", "events": [], "late": False}
    requests, blocked, errors, trace_queries, event_queries = [], [], [], [], []
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                executable_path=os.environ.get("UI_CHROME", CHROME), headless=True
            )
            context = browser.new_context(
                viewport={"width": 1200, "height": 800}, reduced_motion="reduce"
            )
            page = context.new_page()
            page.clock.install()
            page.on("pageerror", lambda error: errors.append(str(error)))

            def serve(route):
                req, parsed = route.request, urlsplit(route.request.url)
                if f"{parsed.scheme}://{parsed.netloc}" != origin:
                    blocked.append(req.url)
                    route.abort()
                    return
                path = parsed.path
                if not path.startswith(("/api/", "/auth/")):
                    route.continue_()
                    return
                requests.append((req.method, path))
                if req.method == "GET" and path == "/api/state":
                    route.fulfill(json=state)
                elif req.method == "GET" and path == f"/api/runs/{HELD}/events":
                    route.fulfill(json={"run_id": HELD, "events": TRACE["events"]})
                elif req.method == "GET" and path == f"/api/runs/{new['id']}/events" and new["id"]:
                    event_queries.append(parsed.query)
                    # Polls may precede event ingestion; after a successful POST the
                    # owner-proven full GET provides the one bounded hydration attempt.
                    rows = (
                        [] if new["late"] and parsed.query.startswith("after=") else new["events"]
                    )
                    route.fulfill(json={"run_id": new["id"], "events": rows})
                elif req.method == "GET" and path == "/api/trace":
                    assert parsed.query == "run=" + new["id"]
                    trace_queries.append(parsed.query)
                    route.fulfill(json={"run_id": new["id"], "region": "us-east-1", "sources": []})
                elif req.method == "GET" and path == "/auth/me":
                    route.fulfill(json={"presenter": False})
                elif req.method == "POST" and path == "/api/run":
                    body = req.post_data_json
                    assert isinstance(body["run_id"], str) and body["run_id"] != HELD
                    if body["mode"] == "live":
                        assert new["id"] and body["run_id"] != new["id"]
                        new["id"] = body["run_id"]
                        new["late"] = False
                        new["events"] = [
                            {
                                "sk": "001#api#new",
                                "node": "ingress",
                                "source": "api",
                                "kind": "auth.verified",
                                "status": "ok",
                                "label": "alice started the new live run",
                            },
                            {
                                "sk": "002#api#done",
                                "node": "agent",
                                "source": "api",
                                "kind": "run.completed",
                                "status": "ok",
                                "verdict": "NO_EFFECT",
                                "label": "new live run completed",
                            },
                        ]
                        state["last_run"] = {
                            "run_id": new["id"],
                            "stage": "v3",
                            "status": "NO_EFFECT",
                            "answer": "New run summarized.",
                            "effects": [],
                        }
                        state["recorded_run"] = {"run_id": new["id"], "stage": "v3"}
                        route.fulfill(json={"result": state["last_run"]})
                        return
                    assert body["mode"] == "approve" and body["approval"] == card["id"]
                    assert new["id"] == ""  # never duplicate an approval request
                    new["id"] = body["run_id"]
                    new["late"] = late_events
                    new["events"] = [
                        {
                            "sk": "001#api#auth",
                            "node": "ingress",
                            "source": "api",
                            "kind": "auth.verified",
                            "status": "ok",
                            "label": "alice approved this new run",
                        },
                        {
                            "sk": "002#api#grant",
                            "node": "ingress",
                            "source": "api",
                            "kind": "approval.granted",
                            "status": "ok",
                            "label": "alice approved close_ticket A-41",
                        },
                        {
                            "sk": "003#api#done",
                            "node": "agent",
                            "source": "api",
                            "kind": "run.completed",
                            "status": "ok",
                            "verdict": "CONFIRMED",
                            "label": "one approved close done",
                        },
                    ]
                    card["status"] = "APPROVED"
                    state.update(
                        policy_session="fresh-session",
                        recorded_run={"run_id": new["id"], "stage": "v3"},
                        last_run={
                            "run_id": new["id"],
                            "stage": "v3",
                            "status": "CONFIRMED",
                            "answer": "Approved close done.",
                            "effects": [
                                {
                                    "operation": "close_ticket",
                                    "target": "A-41",
                                    "status": "EXECUTED",
                                    "before": "OPEN",
                                    "after": "CLOSED",
                                    "confirmed": True,
                                }
                            ],
                        },
                    )
                    state["tickets"][0]["status"] = "CLOSED"
                    route.fulfill(json={"result": state["last_run"]})
                elif req.method == "POST" and path == "/api/reset":
                    assert req.post_data_json == {}
                    state.update(
                        active_stage="v0",
                        policy_session="reset-session",
                        last_run=None,
                        recorded_run=None,
                        approvals=[],
                    )
                    state["tickets"][0]["status"] = "OPEN"
                    route.fulfill(json={"reset": True})
                elif req.method == "POST" and path == "/api/patch":
                    assert req.post_data_json == {"stage": "v4"}
                    state.update(
                        active_stage="v4",
                        policy_session="patched-session",
                        last_run=None,
                        recorded_run=None,
                    )
                    route.fulfill(json={"active_stage": "v4", "title": "Contain"})
                else:
                    blocked.append((req.method, path))
                    route.abort()

            context.route("**/*", serve)
            page.goto(origin, wait_until="domcontentloaded")
            page.wait_for_function("RUN?.run_id === '" + HELD + "' && RUN.events.length === 19")
            page.clock.run_for(20000)
            page.locator('.node[data-id="ingress"]').click()
            expect(page.locator("#drBody")).to_contain_text("alice signed in")
            # The actual shipped approval handler clears an old open run drawer before
            # its one loopback POST; do not forge RUN/STATE or hand-insert events.
            page.evaluate("id => { runAgent('approve', {approval:id}); }", card["id"])
            expect(page.locator("#drawer")).to_have_attribute("aria-hidden", "true")
            expect(page.locator("#drBody")).to_be_empty()
            if late_events:
                page.clock.run_for(5000)
            page.wait_for_function(
                "RUN?.run_id === STATE?.recorded_run?.run_id && RUN?.events?.length === 3",
                timeout=8000,
            )
            assert page.evaluate("STATE.policy_session") == "fresh-session"
            assert page.evaluate("RUN.run_id") == new["id"] != HELD
            assert page.evaluate("STEPS.length") == 3
            assert event_queries.count("") == (1 if late_events else 0)
            page.clock.run_for(6000)
            expect(page.locator("#count")).to_have_text("3 / 3")
            page.locator("#mStep").click()
            page.locator("#back").click()
            expect(page.locator("#count")).to_have_text("2 / 3")
            page.locator("#next").click()
            expect(page.locator("#count")).to_have_text("3 / 3")
            page.locator('.node[data-id="ingress"]').click()
            expect(page.locator("#drBody")).to_contain_text("approval.granted")
            expect(page.locator("#drBody")).not_to_contain_text("alice signed in")
            page.keyboard.press("Escape")
            page.locator('.node[data-id="cw"]').click()
            expect(page.locator("#drBody")).to_contain_text("AWS records can arrive later")
            assert trace_queries == ["run=" + new["id"]]
            approval_run = new["id"]
            # A new live Run replaces the just-approved run. Its old open CW drawer
            # is invalidated before one deliberately mocked live POST is sent.
            page.evaluate("() => { runAgent('live'); }")
            expect(page.locator("#drawer")).to_have_attribute("aria-hidden", "true")
            expect(page.locator("#drBody")).to_be_empty()
            page.wait_for_function(
                "RUN?.run_id === STATE?.recorded_run?.run_id && RUN?.events?.length === 2",
                timeout=8000,
            )
            live_run = new["id"]
            assert live_run != approval_run
            expect(page.locator("#count")).to_have_text("0 / 2")  # Step remained selected
            page.locator("#next").click()
            page.locator("#next").click()
            expect(page.locator("#count")).to_have_text("2 / 2")
            page.locator('.node[data-id="ingress"]').click()
            expect(page.locator("#drBody")).to_contain_text("alice started the new live run")
            expect(page.locator("#drBody")).not_to_contain_text("approval.granted")
            page.keyboard.press("Escape")
            page.locator('.node[data-id="cw"]').click()
            expect(page.locator("#drBody")).to_contain_text("AWS records can arrive later")
            assert trace_queries == ["run=" + approval_run, "run=" + live_run]
            page.keyboard.press("Escape")
            page.locator('.node[data-id="ingress"]').click()
            page.once("dialog", lambda dialog: dialog.accept())
            page.evaluate("() => { resetDemo(); }")
            expect(page.locator("#drawer")).to_have_attribute("aria-hidden", "true")
            expect(page.locator("#drBody")).to_be_empty()
            page.wait_for_function("STATE?.active_stage === 'v0' && RUN === null")
            assert state["recorded_run"] is None
            # Backend fixture presents a fresh authorized recorded run to exercise
            # the actual stage-change control, not a client-side synthetic trace.
            state.update(
                active_stage="v3",
                policy_session="fresh-session",
                recorded_run={"run_id": live_run, "stage": "v3"},
                last_run={"run_id": live_run, "stage": "v3", "status": "NO_EFFECT"},
            )
            page.reload(wait_until="domcontentloaded")
            page.wait_for_function("RUN?.run_id === '" + live_run + "' && RUN.events.length === 2")
            page.locator('.node[data-id="ingress"]').click()
            page.evaluate("() => { patch('v4'); }")
            expect(page.locator("#drawer")).to_have_attribute("aria-hidden", "true")
            expect(page.locator("#drBody")).to_be_empty()
            page.wait_for_function("STATE?.active_stage === 'v4' && RUN === null")
            assert [m for m, p in requests if p == "/api/run"] == ["POST", "POST"]
            assert [m for m, p in requests if p in ("/api/reset", "/api/patch")] == ["POST", "POST"]
            assert not blocked and not errors, (blocked, errors)
            context.close()
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    print(
        "PASS: one loopback approval POST rotates session; new authorized run/events/Auto/Step/ingress/CloudWatch survive, old held trace never returns"
    )


if __name__ == "__main__":
    main()
