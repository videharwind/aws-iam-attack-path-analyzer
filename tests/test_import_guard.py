import os
from pathlib import Path
import subprocess
import sys


def test_import_guard_attack_path_and_graph():
    src_dir = str(Path(__file__).resolve().parent.parent / "src")
    env = dict(os.environ)
    env["PYTHONPATH"] = src_dir
    cmd = [
        sys.executable,
        "-c",
        "import attack_path, graph, sys; assert 'boto3' not in sys.modules, f'boto3 unexpectedly imported'; assert 'pyvis' not in sys.modules, f'pyvis unexpectedly imported'",
    ]
    result = subprocess.run(cmd, env=env, capture_output=True, text=True)
    assert result.returncode == 0, f"Import guard failed: {result.stderr}"


def test_import_guard_assume_role_and_effective_permission():
    src_dir = str(Path(__file__).resolve().parent.parent / "src")
    env = dict(os.environ)
    env["PYTHONPATH"] = src_dir
    cmd = [
        sys.executable,
        "-c",
        "import assume_role, effective_permission, IAM_Enumerator; assert IAM_Enumerator._client is None, f'IAM_Enumerator._client unexpectedly initialized'",
    ]
    result = subprocess.run(cmd, env=env, capture_output=True, text=True)
    assert result.returncode == 0, f"Import guard failed: {result.stderr}"

