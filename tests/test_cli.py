import sys
import json
import subprocess
from pathlib import Path

PYTHON_EXE = sys.executable
PROJECT_ROOT = Path(__file__).resolve().parent.parent

def run_lre(args, stdin_text=None):
    cmd = [PYTHON_EXE, "-m", "reflex_engine.cli"] + args
    res = subprocess.run(
        cmd,
        input=stdin_text,
        text=True,
        capture_output=True,
        cwd=str(PROJECT_ROOT)
    )
    return res

def test_cli_check_safe():
    res = run_lre(["check", "git status", "pwd"])
    assert res.returncode == 0
    assert "[SAFE]" in res.stdout
    assert "git status" in res.stdout
    assert "pwd" in res.stdout

def test_cli_check_dangerous():
    res = run_lre(["check", "rm -rf /", "git status"])
    assert res.returncode == 1
    assert "[DANGEROUS]" in res.stdout
    assert "Recursive forced deletion" in res.stdout

def test_cli_check_json():
    res = run_lre(["check", "--json", "pytest tests/"])
    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["command"] == "pytest tests/"
    assert data[0]["level"] == "SAFE"
    assert "latency_us" in data[0]

def test_cli_check_quiet():
    res = run_lre(["check", "-q", "git status"])
    assert res.returncode == 0
    assert res.stdout.strip() == ""

    res_dang = run_lre(["check", "-q", "rm -rf /"])
    assert res_dang.returncode == 1
    assert res_dang.stdout.strip() == ""

def test_cli_check_stdin():
    lines = "ls -la\npwd\nrm -rf /root\n"
    res = run_lre(["check"], stdin_text=lines)
    assert res.returncode == 1
    assert "[SAFE]" in res.stdout
    assert "[DANGEROUS]" in res.stdout

def test_cli_exec_safe():
    res = run_lre(["exec", "echo 'lre_cli_exec_test_marker'"])
    assert res.returncode == 0
    assert "lre_cli_exec_test_marker" in res.stdout

def test_cli_exec_blocked_dangerous():
    res = run_lre(["exec", "rm -rf /"])
    assert res.returncode == 126
    assert "[LRE BLOCKED]" in res.stderr
    assert "Dangerous command rejected" in res.stderr

def test_cli_exec_force():
    # Echoing a pattern that would be caught by rules, but forced
    res = run_lre(["exec", "-f", "echo 'forced bypass'"])
    assert res.returncode == 0
    assert "forced bypass" in res.stdout

def test_cli_bench():
    res = run_lre(["bench", "-n", "10"])
    assert res.returncode == 0
    assert "Running LRE Benchmark" in res.stdout
    assert "Overall" in res.stdout
    assert "Mean Latency" in res.stdout

def test_cli_hook_bash():
    res = run_lre(["hook", "bash"])
    assert res.returncode == 0
    assert "__lre_preexec" in res.stdout
    assert "DEBUG" in res.stdout
    assert "shopt -s extdebug" in res.stdout

def test_cli_hook_zsh():
    res = run_lre(["hook", "zsh"])
    assert res.returncode == 0
    assert "__lre_zsh_preexec" in res.stdout
    assert "add-zsh-hook" in res.stdout
