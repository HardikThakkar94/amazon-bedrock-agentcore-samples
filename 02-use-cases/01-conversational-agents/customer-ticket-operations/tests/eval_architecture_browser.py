"""Exercise the shipped console in installed Chrome with loopback-only mock APIs.

Run with a Python that already has Playwright installed. No browser/tool downloads.
UI_SCREENSHOTS optionally keeps desktop/small-viewport evidence outside the repo.
"""

from __future__ import annotations

import copy
import os
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *_args):
        pass


def exercise(browser, origin, screenshots):
    state = {
        "active_stage": "v0",
        "model": "llama4-maverick",
        "persona": {"username": "alice", "customer_id": "customer-a"},
        "tickets": [
            {
                "ticket_id": "A-41",
                "subject": "Delivery delayed",
                "status": "OPEN",
                "origin": "seed",
            },
            {
                "ticket_id": "A-90",
                "subject": "Portal request",
                "body": "Please investigate delivery.",
                "status": "OPEN",
                "origin": "form",
                "submitted_by": "customer",
            },
        ],
        "other_tickets": [],
        "approvals": [],
        "store_comparison": {},
        "last_run": None,
    }
    calls, errors, unexpected, pending = [], [], [], {}
    fixture = {"evals": {}, "hold_state": True, "hold_evals": False, "hold_trace": False}
    context = browser.new_context(viewport={"width": 1920, "height": 1080}, reduced_motion="reduce")
    page = context.new_page()
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.clock.install()

    def intercept(route):
        request = route.request
        url = urlsplit(request.url)
        if f"{url.scheme}://{url.netloc}" != origin:
            unexpected.append(request.url)
            route.abort()
            return
        path = url.path
        if not path.startswith(("/api/", "/auth/")):
            route.continue_()
            return
        body = request.post_data_json if request.post_data else None
        calls.append((request.method, path, body))
        if path == "/api/state":
            if fixture["hold_state"]:
                pending.setdefault("state", []).append(route)
                return
            result = state
        elif path == "/api/evals":
            if fixture["hold_evals"]:
                pending.setdefault("evals", []).append(route)
                return
            result = {"builds": fixture["evals"]}
        elif path == "/api/patch":
            assert request.method == "POST"
            assert body == {} or body.get("stage") in [f"v{i}" for i in range(6)]
            state["active_stage"] = body.get("stage", f"v{int(state['active_stage'][1]) + 1}")
            state["last_run"] = None
            result = {"active_stage": state["active_stage"], "title": "Mock build"}
        elif path == "/api/tickets/delete":
            assert request.method == "POST" and body == {"ticket_id": "A-90"}
            state["tickets"] = [
                ticket for ticket in state["tickets"] if ticket["ticket_id"] != "A-90"
            ]
            result = {"deleted": "A-90"}
        elif path == "/api/evals/run":
            assert request.method == "POST" and body == {}
            result = {"status": "QUEUED"}
        elif path == "/api/trace":
            if fixture["hold_trace"]:
                pending.setdefault("trace", []).append(route)
                return
            result = {"run_id": "mock-run", "region": "mock-region", "sources": []}
        elif path == "/api/runs/mock-run/events":
            result = {
                "events": [
                    {
                        "kind": "auth.verified",
                        "node": "ingress",
                        "label": "Signed in",
                        "status": "ok",
                    }
                ]
            }
        elif path == "/auth/me":
            result = {
                "presenter": True,
                "acting_as": {"op": state["persona"]["username"]},
                "personas": [
                    {"role": "operator", "username": "alice", "customer_id": "customer-a"},
                    {"role": "operator", "username": "bob", "customer_id": "customer-b"},
                ],
            }
        elif path == "/auth/switch":
            assert parse_qs(url.query)["u"] == ["bob"]
            state["persona"] = {"username": "bob", "customer_id": "customer-b"}
            state["tickets"] = [
                {
                    "ticket_id": "B-77",
                    "subject": "Billing question",
                    "status": "OPEN",
                    "origin": "seed",
                }
            ]
            state["last_run"] = None
            state.pop("run_id", None)
            route.fulfill(status=302, headers={"Location": "/"})
            return
        else:
            unexpected.append(path)
            route.abort()
            return
        route.fulfill(json=result)

    context.route("**/*", intercept)
    page.goto(origin, wait_until="domcontentloaded")
    expect(page.locator("#custTitle")).to_have_text("Tickets · loading identity…")
    assert page.locator("#codeBtn").count() == 0
    fixture["hold_state"] = False
    for route in pending.pop("state"):
        route.fulfill(json=state)
    expect(page.locator("#custTitle")).to_have_text("Region A tickets (Operator Alice)")
    assert page.evaluate("typeof openCode") == "function"
    assert not errors, errors

    def mutations():
        return [call for call in calls if call[0] != "GET"]

    def refresh():
        page.evaluate("refresh(false)")

    def screenshot(name):
        if screenshots:
            page.clock.run_for(4300)  # Let real UI toasts expire before capturing the page.
            page.screenshot(
                path=str(screenshots / name), full_page=page.viewport_size["width"] > 600
            )

    # Rendering and background GET refreshes never apply fixes. Each V0-V4 user click does.
    assert mutations() == []
    for build in range(5):
        expect(page.locator("#nextFix")).to_contain_text(f"Apply V{build + 1}")
        refresh()
        assert len(mutations()) == build
        page.locator("#nextFix").click()
        expect(page.locator(f'.step[data-stage="v{build + 1}"]')).to_have_attribute(
            "aria-current", "true"
        )
        assert mutations()[-1] == ("POST", "/api/patch", {})
    expect(page.locator("#nextFix")).to_have_text("Evaluations architecture")
    expect(page.locator("#nextFix")).to_be_enabled()
    assert len(mutations()) == 5

    # A prior run and pending playback must survive opening and closing the static diagram.
    state["last_run"] = {"status": "NO_EFFECT", "answer": "Recorded answer", "effects": []}
    state["run_id"] = "mock-run"
    page.evaluate("refresh()")
    page.evaluate("N = 0; renderPanel()")
    history = page.evaluate(
        "JSON.stringify({RUN, STEPS, N, last: STATE.last_run, asks: [...ASKS]})"
    )
    mutation_count = len(mutations())
    for key in ("Enter", "Space"):
        page.locator("#nextFix").focus()
        page.keyboard.press(key)
        expect(page.locator("#drawer")).to_have_attribute("data-from", "evalarch")
        expect(page.locator("#drClose")).to_be_focused()
        assert (
            page.evaluate("JSON.stringify({RUN, STEPS, N, last: STATE.last_run, asks: [...ASKS]})")
            == history
        )
        assert len(mutations()) == mutation_count
        arch = page.locator("#drBody")
        expect(arch).to_contain_text("static explanation, not live evidence")
        expect(arch).to_contain_text("100% sampling configured, with a 2-minute session timeout")
        expect(arch).to_contain_text("No automatic enforcement")
        expect(arch).to_contain_text("not the LLM’s self-report")
        expect(arch).to_contain_text(
            "every benign sample needs a valid Helpfulness score, with mean ≥ 0.5"
        )
        expect(arch).to_contain_text("not proof that every session was scored")
        expect(arch).to_contain_text("k10 variance study is separate")
        assert page.locator(".ea img").count() == 8
        assert page.locator(".ea img").evaluate_all(
            "imgs => imgs.every(i => i.complete && i.naturalWidth > 0)"
        )
        screenshot(f"desktop-v5-architecture-{key.lower()}.png")
        if key == "Enter":
            page.locator("#drBody").evaluate("el => el.scrollTop = el.scrollHeight")
            screenshot("desktop-v5-architecture-evaluators.png")
        if key == "Enter":
            page.locator("#drClose").click()
        else:
            page.keyboard.press("Escape")
        expect(page.locator("#drawer")).to_have_attribute("aria-hidden", "true")
        expect(page.locator("#nextFix")).to_be_focused()

    # V5 architecture is read-only and stays available even while a run is polling.
    page.evaluate("polling = 123; renderChrome()")
    expect(page.locator("#nextFix")).to_be_enabled()
    page.locator("#nextFix").click()
    page.keyboard.press("Escape")
    page.evaluate("polling = null")
    assert len(mutations()) == mutation_count

    # On V0 the Evals drawer offers the same diagram, without a build switch.
    state["active_stage"] = "v0"
    refresh()
    for key in ("Enter", "Space"):
        page.locator("#evalBtn").click()
        expect(page.locator("#evalArchBtn")).to_be_visible()
        page.locator("#evalArchBtn").focus()
        if key == "Enter":
            screenshot("desktop-v0-evals-link.png")
        # Polling's matrix re-render preserves focused controls.
        page.evaluate("renderEvals()")
        expect(page.locator("#evalArchBtn")).to_be_focused()
        page.keyboard.press(key)
        expect(page.locator("#drawer")).to_have_attribute("data-from", "evalarch")
        static_html = page.locator("#drBody").inner_html()
        page.evaluate("renderEvals(); renderChrome(); renderPanel()")
        assert page.locator("#drBody").inner_html() == static_html
        if key == "Enter":
            page.locator("#drClose").click()
        else:
            page.keyboard.press("Escape")
        expect(page.locator("#drawer")).to_have_attribute("data-from", "evals")
        expect(page.locator("#evalArchBtn")).to_be_focused()
        page.keyboard.press("Escape")
        expect(page.locator("#evalBtn")).to_be_focused()
    assert state["active_stage"] == "v0"
    assert len(mutations()) == mutation_count
    assert page.evaluate("N") == 0

    # Late Evals responses and scheduled eval polling cannot replace the architecture/trace.
    state["active_stage"] = "v5"
    refresh()
    fixture["hold_evals"] = True
    page.locator("#evalBtn").click()
    expect(page.locator("#drBody")).to_contain_text("Loading eval suites")
    page.locator("#nextFix").click()
    fixture["hold_evals"] = False
    fixture["evals"] = {"v5": {"status": "RUNNING"}}
    for route in pending.pop("evals"):
        route.fulfill(json={"builds": fixture["evals"]})
    page.wait_for_function("EVALS?.v5?.status === 'RUNNING'")
    page.clock.run_for(5100)
    expect(page.locator("#drTitle")).to_have_text("Evaluations architecture")
    page.keyboard.press("Escape")
    page.locator('.node[data-id="policy"]').click()
    page.clock.run_for(5100)
    expect(page.locator("#drTitle")).to_contain_text("Trace · AgentCore Policy")
    page.keyboard.press("Escape")
    assert len(mutations()) == mutation_count

    # CloudWatch's actual drawer still renders, and a late response cannot overwrite the diagram.
    page.locator('.node[data-id="cw"]').click()
    expect(page.locator("#drBody")).to_contain_text("AWS records can arrive later")
    expect(page.locator("#drBody")).to_contain_text("Policy (agent inference)")
    page.keyboard.press("Escape")
    expect(page.locator('.node[data-id="cw"]')).to_be_focused()
    fixture["hold_trace"] = True
    page.locator('.node[data-id="cw"]').click()
    expect(page.locator("#drBody")).to_contain_text("Querying CloudWatch")
    page.locator("#nextFix").click()
    for route in pending.pop("trace"):
        route.fulfill(json={"run_id": "mock-run", "sources": []})
    expect(page.locator("#drTitle")).to_have_text("Evaluations architecture")
    expect(page.locator("#drBody")).to_contain_text("static explanation")
    fixture["hold_trace"] = False
    page.keyboard.press("Escape")

    # The existing eval execution button still requires its own explicit click and confirmation.
    fixture["evals"] = {}
    page.locator("#evalBtn").click()
    expect(page.locator("#evalRun")).to_be_enabled()
    page.once("dialog", lambda dialog: dialog.dismiss())
    page.locator("#evalRun").click()
    assert len(mutations()) == mutation_count
    page.once("dialog", lambda dialog: dialog.accept())
    page.locator("#evalRun").click()
    page.wait_for_function(
        "document.querySelector('#toast').textContent.includes('Eval suite started')"
    )
    assert mutations()[-1] == ("POST", "/api/evals/run", {})
    page.keyboard.press("Escape")

    # No default Region or fake identity before/without an authenticated persona.
    for persona, label in (
        (None, "Unknown Region tickets (Operator unknown)"),
        (
            {"username": "carol", "customer_id": "unmapped"},
            "Unknown Region tickets (Operator Carol)",
        ),
        ({"customer_id": "customer-b"}, "Region B tickets (Operator unknown)"),
        (
            {"username": '<img src=x onerror="window.pwned=1">', "customer_id": "customer-b"},
            'Region B tickets (Operator <img src=x onerror="window.pwned=1">)',
        ),
    ):
        state["persona"] = persona
        refresh()
        expect(page.locator("#custTitle")).to_have_text(label)
        page.evaluate("N = STEPS.length; renderPanel()")
        assert page.locator("#custTitle img, #capx img").count() == 0
        if persona and persona.get("username"):
            expect(page.locator("#capx")).to_contain_text(persona["username"])
        assert page.evaluate("window.pwned") is None
        assert page.evaluate("STATE.persona") == persona

    state["persona"] = {"username": "alice", "customer_id": "customer-a"}
    state["active_stage"] = "v0"
    refresh()
    screenshot("desktop-alice-v0.png")
    # Existing portal deletion UI still cancels safely and issues only the intended delete on confirm.
    page.once("dialog", lambda dialog: dialog.dismiss())
    before = copy.deepcopy(mutations())
    page.locator('[data-delete="A-90"]').click()
    assert mutations() == before
    page.once("dialog", lambda dialog: dialog.accept())
    page.locator('[data-delete="A-90"]').click()
    expect(page.locator('[data-delete="A-90"]')).to_have_count(0)
    assert mutations()[-1] == ("POST", "/api/tickets/delete", {"ticket_id": "A-90"})

    page.locator("#gearBtn").click()
    page.locator('#personas a:has-text("bob")').click()
    expect(page.locator("#custTitle")).to_have_text("Region B tickets (Operator Bob)")
    assert page.evaluate("STATE.persona.customer_id") == "customer-b"
    expect(page.locator("#tickets")).to_contain_text("B-77")
    screenshot("desktop-bob-v0.png")

    # Use the actual page at a phone-sized viewport, not an isolated diagram fixture.
    page.set_viewport_size({"width": 390, "height": 844})
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    screenshot("small-v0-console.png")
    page.locator("#evalBtn").click()
    screenshot("small-v0-evals-link.png")
    page.locator("#evalArchBtn").click()
    screenshot("small-v0-architecture-top.png")
    page.locator(".eal").nth(1).evaluate("el => el.scrollIntoView({block: 'start'})")
    screenshot("small-v0-architecture-online.png")
    page.locator("#drBody").evaluate("el => el.scrollTop = el.scrollHeight")
    screenshot("small-v0-architecture-evaluators.png")
    assert page.locator("#drBody").evaluate("el => el.scrollWidth <= el.clientWidth"), (
        "architecture overflows"
    )
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), "page overflows"
    page.locator("#drClose").click()
    expect(page.locator("#evalArchBtn")).to_be_focused()
    assert errors == [], errors
    assert unexpected == [], unexpected
    assert [call[1] for call in mutations()] == ["/api/patch"] * 5 + [
        "/api/evals/run",
        "/api/tickets/delete",
    ]
    print(
        "PASS: shipped full-script boot, five click-only fixes, read-only architecture from both triggers,"
    )
    print(
        "Enter/Space/Escape and focus, polling races, authenticated headings/persona switch, CloudWatch,"
    )
    print(
        "Evals confirmation, deletion, desktop/small screenshots; no external requests or JS errors."
    )
    print(
        f"Mock API calls: {len(calls)}; mutations: 5 explicit patches, 1 explicit eval, 1 explicit delete."
    )
    context.unroute_all(behavior="wait")
    context.close()


def main():
    output = os.environ.get("UI_SCREENSHOTS")
    screenshots = Path(output) if output else None
    if screenshots:
        screenshots.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0), partial(QuietHandler, directory=str(ROOT / "web"))
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                executable_path=os.environ.get("UI_CHROME", CHROME), headless=True
            )
            exercise(browser, f"http://127.0.0.1:{server.server_port}", screenshots)
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


if __name__ == "__main__":
    main()
