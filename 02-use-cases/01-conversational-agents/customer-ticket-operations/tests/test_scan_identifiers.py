"""The disclosure scanner is a publication gate. A gate that silently opens is not a gate."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "scan_identifiers.py"


@pytest.fixture(scope="module")
def scanner():
    spec = importlib.util.spec_from_file_location("scan_identifiers", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_missing_explicit_denylist_is_an_error_not_a_downgrade(scanner, tmp_path, capsys):
    (tmp_path / "clean.py").write_text("x = 'acct-a'\n")

    with pytest.raises(SystemExit) as exc:
        scanner.main(["--denylist", str(tmp_path / "does-not-exist.txt"), str(tmp_path)])

    assert exc.value.code != 0
    assert "denylist not found" in str(exc.value)


def test_seeded_tree_is_caught_by_builtins_and_denylist(scanner, tmp_path, capsys):
    denylist = tmp_path / "deny.txt"
    denylist.write_text("# internal names\nProjectNimbus\n")
    tree = tmp_path / "repo"
    tree.mkdir()
    # Built by concatenation so this test file does not itself trip the scanner.
    fake_arn = "arn:" + "aws:iam::" + "1234567890" + "12:role/Demo"
    fake_host = "build.internal." + "amazon" + ".com"
    (tree / "leak.py").write_text(
        f"role = '{fake_arn}'\nhost = '{fake_host}'\nnote = 'talk about projectnimbus here'\n"
    )

    code = scanner.main(["--denylist", str(denylist), str(tree)])

    out = capsys.readouterr().out
    assert code == 1
    assert "12-digit-account-id" in out and "arn" in out and "internal-host" in out
    assert "denylist: <denylisted term>" in out  # the term itself is never echoed
    assert "ProjectNimbus" not in out and "projectnimbus" not in out


def test_public_aws_docs_hosts_are_allowed(scanner, tmp_path, capsys):
    tree = tmp_path / "repo"
    tree.mkdir()
    (tree / "README.md").write_text(
        "See https://docs.aws.amazon.com/bedrock/ and https://aws.amazon.com/.\n"
    )

    code = scanner.main([str(tree)])

    assert code == 0
    assert "no denylist" in capsys.readouterr().out


def test_account_free_and_templated_arns_are_allowed_but_real_ones_are_not(
    scanner, tmp_path, capsys
):
    tree = tmp_path / "repo"
    tree.mkdir()
    (tree / "ok.py").write_text(
        'MANAGED = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"\n'
        'prefix = f"arn:aws:bedrock-agentcore:{region}:{account}"\n'
    )
    assert scanner.main([str(tree)]) == 0

    real_arn = "arn:" + "aws:iam::" + "1234567890" + "12:role/some-role"  # concatenated: see above
    (tree / "leak.py").write_text(f'ROLE = "{real_arn}"\n')
    assert scanner.main([str(tree)]) == 1
    out = capsys.readouterr().out
    assert "leak.py:1" in out and "ok.py" not in out


def test_scanner_skips_itself_and_ignored_dirs(scanner, tmp_path):
    tree = tmp_path / "repo"
    (tree / ".venv").mkdir(parents=True)
    (tree / ".venv" / "vendored.py").write_text("arn:" + "aws:s3:::bucket\n")

    assert scanner.main([str(tree)]) == 0
    assert scanner.main([str(SCRIPT)]) == 0  # the pattern definitions do not flag themselves


if __name__ == "__main__":
    sys.exit(pytest.main([__file__]))
