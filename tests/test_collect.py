import os
from pathlib import Path
import subprocess
import sys
import pytest
import botocore.exceptions

import collect
from iam_models import IAMInventory, IAMUser
from snapshot import load_snapshot


def test_parse_args_defaults_and_overrides():
    args = collect.parse_args([])
    assert args.profile is None
    assert args.region is None
    assert args.prefix == "test"
    assert args.out == "snapshots/scan.json"

    args2 = collect.parse_args([
        "--profile", "prod",
        "--region", "us-west-2",
        "--prefix", "",
        "--out", "custom.json",
    ])
    assert args2.profile == "prod"
    assert args2.region == "us-west-2"
    assert args2.prefix == ""
    assert args2.out == "custom.json"


def test_collect_main_flow(tmp_path, monkeypatch, capsys):
    out_file = tmp_path / "out_scan.json"

    dummy_inv = IAMInventory(
        users=[IAMUser(name="testuser", id="u-1", arn="arn:aws:iam::123456789012:user/testuser")],
        groups=[],
        roles=[],
        policies=[],
        relationships=[],
    )

    filter_called = []
    configure_called = []

    monkeypatch.setattr(collect, "configure_client", lambda profile, region: configure_called.append((profile, region)))
    monkeypatch.setattr(collect, "build_inventory", lambda: dummy_inv)
    monkeypatch.setattr(collect, "filter_", lambda inv, prefix: filter_called.append(prefix) or inv)
    monkeypatch.setattr(collect, "build_permission_map", lambda inv: {dummy_inv.users[0].arn: []})

    class FakeSTS:
        def get_caller_identity(self):
            return {"Account": "123456789012"}

    class FakeSession:
        def __init__(self, **kwargs):
            pass

        def client(self, name):
            assert name == "sts"
            return FakeSTS()

    import boto3
    monkeypatch.setattr(boto3, "Session", FakeSession)

    ret = collect.main(["--out", str(out_file), "--prefix", "test", "--profile", "myprof"])
    assert ret == 0
    assert len(filter_called) == 1
    assert filter_called[0] == "test"
    assert len(configure_called) == 1
    assert configure_called[0] == ("myprof", None)
    assert out_file.is_file()

    loaded_inv, loaded_pm, meta = load_snapshot(out_file)
    assert len(loaded_inv.users) == 1
    assert meta["account_id"] == "123456789012"
    assert meta["prefix"] == "test"

    out = capsys.readouterr().out
    assert "Snapshot saved to" in out


def test_collect_empty_prefix_skips_filter(tmp_path, monkeypatch):
    out_file = tmp_path / "nofilter.json"
    dummy_inv = IAMInventory(users=[], groups=[], roles=[], policies=[], relationships=[])

    filter_called = []
    monkeypatch.setattr(collect, "configure_client", lambda profile, region: None)
    monkeypatch.setattr(collect, "build_inventory", lambda: dummy_inv)
    monkeypatch.setattr(collect, "filter_", lambda inv, prefix: filter_called.append(prefix) or inv)
    monkeypatch.setattr(collect, "build_permission_map", lambda inv: {})

    ret = collect.main(["--out", str(out_file), "--prefix", ""])
    assert ret == 0
    assert len(filter_called) == 0


def test_collect_aws_error_handling(monkeypatch, capsys):
    monkeypatch.setattr(
        collect,
        "build_inventory",
        lambda: (_ for _ in ()).throw(botocore.exceptions.NoCredentialsError()),
    )
    ret = collect.main([])
    assert ret == 1
    err = capsys.readouterr().out
    assert "AWS Error" in err
    assert "Please check your AWS credentials" in err


def test_collect_help_subprocess():
    src_dir = str(Path(__file__).resolve().parent.parent / "src")
    env = dict(os.environ)
    env["PYTHONPATH"] = src_dir
    res = subprocess.run(
        [sys.executable, str(Path(src_dir) / "collect.py"), "--help"],
        capture_output=True,
        text=True,
        env=env,
    )
    assert res.returncode == 0
    assert "--profile" in res.stdout
    assert "--prefix" in res.stdout


@pytest.mark.aws
def test_live_collect_aws():
    """Live AWS collection test. Marked aws, never run in offline suite."""
    ret = collect.main(["--prefix", "test", "--out", "snapshots/live_test.json"])
    assert ret == 0

