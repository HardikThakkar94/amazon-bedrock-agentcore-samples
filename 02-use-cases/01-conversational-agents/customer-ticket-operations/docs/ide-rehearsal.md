# One-window IDE rehearsal (from Dry Run 1, 2026-10-13)

The dry-run feedback was consistent: the audience loses the thread when the speakers switch
between a slide deck, a browser, a terminal and the AWS console. The agreed structure is:

1. **Open with slides** (about 8 minutes): the problem, the trust boundaries, the two shapes of
   agent, the architecture of the demo you are about to see, and the five controls at high level.
2. **Switch once to the IDE and stay there** (about 40 minutes): the live demo, the real code diff
   for every patch, and the trace all live inside one editor window.
3. **Return to slides for the close** (about 8 minutes): the production rules, where the code lives,
   contacts.

Everything in this guide runs inside one VS Code window (any VS Code-based IDE with the Simple
Browser command works the same way).

## Window layout

```
┌───────────────────────────────┬────────────────────────────────────┐
│ Editor group 1                │ Simple Browser                     │
│ src/sec310_sample/            │ http://127.0.0.1:8765/             │
│   ticket_demo_patches.py      │ Live Demo · Code Diff · Trace ·    │
│   (v0 … v5, the actual code)  │ Architecture tabs                  │
├───────────────────────────────┴────────────────────────────────────┤
│ Terminal: uv run python -m sec310_sample.ticket_demo --live        │
└────────────────────────────────────────────────────────────────────┘
```

- `View → Editor Layout → Two Columns`.
- Left column: `src/sec310_sample/ticket_demo_patches.py`. Fold everything except the function for
  the patch you are explaining; the UI's Code Diff tab shows the same function, so the audience can
  look at either.
- Right column: `Command Palette → Simple Browser: Show → http://127.0.0.1:8765/`. The demo page
  is self-contained HTML served by the Python process; nothing else needs to be installed.
- The malicious submission form opens in a **second Simple Browser tab**
  (`http://127.0.0.1:8765/submit`). Drag it into the right column so switching between operator
  and attacker is one click, not an app switch.
- Terminal panel at the bottom, zoomed so the audience can read the startup lines and any error.
- Set editor zoom to 150% or more (`View → Appearance → Zoom In`). The demo page scales with the
  browser zoom as well (`Cmd +` inside Simple Browser).

## Before the session

```bash
cd sec310-sample
uv sync --extra aws --group dev

export AWS_PROFILE=<named-development-profile> AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1
unset AWS_BEARER_TOKEN_BEDROCK
aws sts get-caller-identity --profile "$AWS_PROFILE"      # right account? stop if not

export SEC310_MODEL_ID='us.meta.llama4-maverick-17b-instruct-v1:0'   # last verified to follow the attack
export SEC310_RUN_ID="sec310-$(date +%Y%m%d-%H%M%S)"
# optional: export SEC310_INVOCATION_LOG_GROUP=<log group> so the Trace tab prints the CloudWatch query
uv run python -m sec310_sample.ticket_demo --live
```

Checklist:

- [ ] `aws sts get-caller-identity` shows the development account, not a customer profile.
- [ ] A fresh `SEC310_RUN_ID` so the CloudWatch query on the Trace tab matches today's calls.
- [ ] One clean V0 run before the audience arrives (model access, latency, no throttling).
- [ ] Simple Browser tabs open: `/` and `/submit`.
- [ ] Reset to clean V0 right before you start.
- [ ] Phone or watch for time: the IDE segment is the long one.

## The IDE segment, beat by beat

| Beat | Where | Say |
|---|---|---|
| Normal run | Live Demo → Run Bedrock live | "A real model, real summary, nothing changes." |
| Attack | Simple Browser `/submit` → Submit | "A Customer A user writes this into a support ticket. Any field a user can write is an input." |
| Compromise | Live Demo → Run Bedrock live | "The model read the ticket as an instruction; V0 executed it. Watch A-42: OPEN → CLOSED." |
| Flow strip | bottom of Live Demo | Point at proposal → boundary → effect. "Three different things. We will separate them." |
| Patch V1 | Apply next patch → Code Diff, then Test exact live response | "Identity passes, because this attack stays inside Customer A. Still vulnerable." |
| Patch V2 | same | "Screening and a typed response are not permission. Still vulnerable." |
| Patch V3 | same | "A deterministic policy outside the model denies close_ticket. Protected." |
| Patch V4 | Apply next patch → Test exact live response | "The first denied action ends the run. The agent stops itself and stays stopped until an operator resets it. Nobody had to press a button." Then test again: refused at admission. Click **Agent halted itself · Reset stop** to clear it. |
| Manual brake (optional) | Request durable stop, then test | "An operator can also stop it on purpose. Same refusal at admission, different reason." Clear it before V5. |
| Patch V5 | Apply, test | "Proposal, decision and effect are recorded separately, and the release invariant passes." |
| Architecture | Architecture tab | "What was real: Bedrock inference, CloudWatch records. What stayed local: the ticket store and this policy." |
| Trace | Trace & CloudWatch tab | Show the run id and the Logs Insights query; mention delivery lag before switching. |

Use **Test exact live response** for the patch comparison. It replays the exact Bedrock response that
caused the V0 effect, so differences between builds come from the code, not from a new sample. Use
**Run Bedrock live** on a later build only when you want to show model variability on purpose, and
say so.

## If something goes wrong on stage

- **Model does not follow the ticket**: the UI says so ("did not follow the ticket instruction on this
  take"). Run V0 live once more; if it still declines, switch the terminal to the rehearsal model
  (restart without `--live`) and say explicitly that you are now on a scripted stand-in.
- **Model output is malformed or truncated**: the UI shows ERROR and executes nothing. Name it as an
  error, not a refusal, and rerun.
- **No network**: restart without `--live`. The header turns to REHEARSAL. Do not call it live.
- **CloudWatch shows nothing yet**: delivery lags by minutes. Say that, show the run id, move on.
- **Capture turns stale**: you edited or added a ticket after the V0 run. Run V0 live again to
  capture a response against the current tickets.

## What stays out of the IDE

- No AWS console windows. The Trace tab carries the log group name and the query; open the console
  only if a question demands it and the recording has already been shown.
- No slide deck during the IDE segment. The Architecture tab and the flow strip replace the per-patch
  diagram slides from the earlier deck.
