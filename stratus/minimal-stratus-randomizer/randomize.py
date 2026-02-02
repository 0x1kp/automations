#!/usr/bin/env python3
"""
Minimal Stratus Red Team Randomizer

A simple script to randomly select and detonate a Stratus Red Team attack
for blind incident response training. No bells and whistles - just pick
a random attack and run it.

Usage:
    python3 randomize.py --account 123456789012 --region us-east-1
    python3 randomize.py --account 123456789012 --region us-east-1 --cleanup
    python3 randomize.py --reveal <run_id>
"""

import argparse
import json
import os
import random
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

RUNS_DIR = Path(__file__).parent / "runs"


def run_cmd(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    """Run a command and return the result."""
    result = subprocess.run(cmd, capture_output=True, text=True)
    if check and result.returncode != 0:
        print(f"Command failed: {' '.join(cmd)}", file=sys.stderr)
        print(f"stderr: {result.stderr}", file=sys.stderr)
        sys.exit(1)
    return result


def get_aws_account() -> str:
    """Get current AWS account ID."""
    result = run_cmd(["aws", "sts", "get-caller-identity", "--output", "json"])
    return json.loads(result.stdout)["Account"]


def get_techniques() -> list[str]:
    """Get list of AWS techniques from stratus."""
    result = run_cmd(["stratus", "list", "--platform", "aws"])
    techniques = []
    for line in result.stdout.splitlines():
        # Technique IDs start with "aws." and are the first column
        if line.strip().startswith("aws."):
            technique = line.split()[0]
            techniques.append(technique)
    return techniques


def do_run(args: argparse.Namespace) -> int:
    """Run a random attack."""
    # Safety check
    current_account = get_aws_account()
    if current_account != args.account:
        print(f"ERROR: Running in account {current_account}, expected {args.account}", file=sys.stderr)
        return 1

    # Set region
    os.environ["AWS_DEFAULT_REGION"] = args.region
    os.environ["AWS_REGION"] = args.region

    # Pick random technique
    techniques = get_techniques()
    if not techniques:
        print("ERROR: No techniques found", file=sys.stderr)
        return 1

    technique = random.choice(techniques)

    # Create run record
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    RUNS_DIR.mkdir(parents=True, exist_ok=True)

    run_data = {
        "run_id": run_id,
        "technique": technique,
        "account": current_account,
        "region": args.region,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "cleanup": args.cleanup,
    }

    # Save run data (hidden from terminal output)
    (RUNS_DIR / f"{run_id}.json").write_text(json.dumps(run_data, indent=2))

    # Print only the run_id - technique is hidden for blind IR
    print(f"RUN_ID: {run_id}")
    print("Attack launched. Check your detections.")

    # Warmup and detonate
    run_cmd(["stratus", "warmup", technique])

    det_cmd = ["stratus", "detonate", technique]
    if args.cleanup:
        det_cmd.append("--cleanup")

    run_cmd(det_cmd)

    return 0


def do_reveal(args: argparse.Namespace) -> int:
    """Reveal what technique was used for a run."""
    run_file = RUNS_DIR / f"{args.run_id}.json"
    if not run_file.exists():
        print(f"ERROR: Run {args.run_id} not found", file=sys.stderr)
        return 1

    run_data = json.loads(run_file.read_text())
    print(f"Run ID:    {run_data['run_id']}")
    print(f"Technique: {run_data['technique']}")
    print(f"Account:   {run_data['account']}")
    print(f"Region:    {run_data['region']}")
    print(f"Started:   {run_data['started_at']}")
    print(f"Cleanup:   {run_data['cleanup']}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Stratus Red Team Randomizer")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Run subcommand
    run_parser = subparsers.add_parser("run", help="Run a random attack")
    run_parser.add_argument("--account", required=True, help="Expected AWS account ID (safety check)")
    run_parser.add_argument("--region", required=True, help="AWS region")
    run_parser.add_argument("--cleanup", action="store_true", help="Auto-cleanup after detonation")

    # Reveal subcommand
    reveal_parser = subparsers.add_parser("reveal", help="Reveal technique for a run")
    reveal_parser.add_argument("run_id", help="Run ID to reveal")

    # List runs subcommand
    subparsers.add_parser("list-runs", help="List all runs")

    args = parser.parse_args()

    if args.command == "run":
        return do_run(args)
    elif args.command == "reveal":
        return do_reveal(args)
    elif args.command == "list-runs":
        if not RUNS_DIR.exists():
            print("No runs yet.")
            return 0
        for f in sorted(RUNS_DIR.glob("*.json")):
            print(f.stem)
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
