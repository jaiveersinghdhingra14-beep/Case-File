import subprocess
import sys


def test_manage_list_command():
    res = subprocess.run([sys.executable, "manage.py", "list"], check=False, capture_output=True, text=True)
    assert res.returncode == 0
    assert "CaseFile v2 - Registered Datasets" in res.stdout


def test_manage_help():
    res = subprocess.run([sys.executable, "manage.py", "--help"], check=False, capture_output=True, text=True)
    assert res.returncode == 0
    assert "run-all" in res.stdout
    assert "ingest" in res.stdout
    assert "patterns" in res.stdout
    assert "test" in res.stdout
