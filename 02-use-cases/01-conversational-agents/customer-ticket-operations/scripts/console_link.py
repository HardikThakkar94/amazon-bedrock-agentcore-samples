"""Copy a one-time AWS console sign-in link to the clipboard, for the console tab next to the demo.

    python3 scripts/console_link.py --account <authorized-account> [--page <console URL>]

Source-only optional helper; run manually only with separate operator authorization. When invoked,
fetches fresh credentials from ada (not the profile's cache), so the console session lasts as
long as the role allows: one hour for the Conduit admin role. The link
itself must be used within 15 minutes. It is a credential: it goes to the clipboard, never stdout.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import urllib.parse
import urllib.request
from datetime import UTC, datetime

FEDERATION = "https://signin.aws.amazon.com/federation"


def fresh_credentials(account: str, provider: str, role: str) -> dict:
    out = subprocess.run(
        [
            "ada",
            "credentials",
            "print",
            f"--account={account}",
            f"--provider={provider}",
            f"--role={role}",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if out.returncode != 0:
        sys.exit(f"ada could not get credentials for {account} ({role}); run mwinit and retry")
    return json.loads(out.stdout)


def sign_in_link(creds: dict, destination: str) -> str:
    session = json.dumps(
        {
            "sessionId": creds["AccessKeyId"],
            "sessionKey": creds["SecretAccessKey"],
            "sessionToken": creds["SessionToken"],
        }
    )
    query = urllib.parse.urlencode({"Action": "getSigninToken", "Session": session})
    with urllib.request.urlopen(f"{FEDERATION}?{query}", timeout=20) as r:
        token = json.load(r)["SigninToken"]
    return f"{FEDERATION}?" + urllib.parse.urlencode(
        {"Action": "login", "Issuer": "sec310", "Destination": destination, "SigninToken": token}
    )


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--account", required=True)
    p.add_argument("--region", default="us-east-1")
    p.add_argument("--provider", default="conduit")
    p.add_argument("--role", default="IibsAdminAccess-DO-NOT-DELETE")
    p.add_argument("--page", default="")
    a = p.parse_args()
    page = (
        a.page
        or f"https://{a.region}.console.aws.amazon.com/bedrock-agentcore/home?region={a.region}"
    )

    creds = fresh_credentials(a.account, a.provider, a.role)
    link = sign_in_link(creds, page)
    subprocess.run(["pbcopy"], input=link, text=True, check=True)
    ends = datetime.fromisoformat(creds["Expiration"].replace("Z", "+00:00")).astimezone()
    left = int((ends - datetime.now(UTC)).total_seconds() // 60)
    print("Console sign-in link copied to the clipboard (use it within 15 minutes).")
    print(
        f"Paste it into the browser's address bar; the session lasts until {ends:%H:%M} ({left} min)."
    )


if __name__ == "__main__":
    main()
