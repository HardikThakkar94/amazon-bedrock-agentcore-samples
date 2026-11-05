"""The optional console-link helper is never executed against an account in this suite."""

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("console_link_test", ROOT / "scripts/console_link.py")
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


def test_federation_payload_and_clipboard_are_mocked(monkeypatch, capsys):
    calls = []
    credentials = {
        "AccessKeyId": "example-key",
        "SecretAccessKey": "example-secret",
        "SessionToken": "example-token",
        "Expiration": "2099-01-01T01:00:00Z",
    }

    def process(args, **kwargs):
        calls.append((args, kwargs))
        if args == ["pbcopy"]:
            return SimpleNamespace(returncode=0)
        return SimpleNamespace(returncode=0, stdout=json.dumps(credentials))

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def read(self):
            return b'{"SigninToken":"example-signin"}'

    def fake_urlopen(url, timeout):
        assert timeout == 20
        assert urlsplit(url).hostname == "signin.aws.amazon.com"
        request = parse_qs(urlsplit(url).query)
        assert request["Action"] == ["getSigninToken"]
        assert json.loads(request["Session"][0]) == {
            "sessionId": "example-key",
            "sessionKey": "example-secret",
            "sessionToken": "example-token",
        }
        return Response()

    monkeypatch.setattr(helper.subprocess, "run", process)
    monkeypatch.setattr(helper.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(helper.sys, "argv", ["console_link.py", "--account", "example-account"])
    helper.main()
    assert calls[0][0][:3] == ["ada", "credentials", "print"]
    assert calls[-1][0] == ["pbcopy"]
    login = parse_qs(urlsplit(calls[-1][1]["input"]).query)
    assert login["SigninToken"] == ["example-signin"]
    assert login["Destination"] == [
        "https://us-east-1.console.aws.amazon.com/bedrock-agentcore/home?region=us-east-1"
    ]
    assert all(
        s not in capsys.readouterr().out
        for s in ("example-key", "example-secret", "example-token", "example-signin")
    )
