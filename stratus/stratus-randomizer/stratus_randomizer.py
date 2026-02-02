#!/usr/bin/env python3
"""
Stratus Red Team Randomizer

A tool to randomly select and detonate Stratus Red Team attacks for blind
incident response training. Supports training mode (leave artifacts for IR)
and validation mode (auto-cleanup for detection testing).

Features:
- Random technique selection with optional tactic filtering
- Train mode: leaves artifacts for full IR lifecycle practice
- Validate mode: auto-cleanup for detection validation loops
- Run history tracking with technique hiding for blind exercises
- Technique history to avoid repetition
- Proper concurrency control with stale lock detection
- Graceful error handling and cleanup paths

Usage:
    stratus_randomizer.py run --account 123456789012 --region us-east-1
    stratus_randomizer.py run --account 123456789012 --region us-east-1 --mode validate
    stratus_randomizer.py run --account 123456789012 --region us-east-1 --tactic persistence
    stratus_randomizer.py reveal <run_id>
    stratus_randomizer.py cleanup <run_id>
    stratus_randomizer.py list [--runs | --techniques]
    stratus_randomizer.py status
"""

import argparse
import fcntl
import json
import os
import random
import signal
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

# Directories
BASE_DIR = Path(__file__).parent
RUNS_DIR = BASE_DIR / "runs"
LOCK_FILE = BASE_DIR / ".lock"
HISTORY_FILE = BASE_DIR / ".history.json"

# Valid MITRE ATT&CK tactics for filtering
VALID_TACTICS = [
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "exfiltration",
    "impact",
]


class RunMode(Enum):
    TRAIN = "train"      # Leave artifacts for IR practice
    VALIDATE = "validate"  # Auto-cleanup for detection testing


class RunStatus(Enum):
    STARTED = "started"
    WARMUP_COMPLETE = "warmup_complete"
    DETONATED = "detonated"
    CLEANED = "cleaned"
    FAILED = "failed"


@dataclass
class RunRecord:
    run_id: str
    technique: str
    account: str
    region: str
    mode: str
    tactic_filter: Optional[str]
    started_at: str
    status: str
    warmup_at: Optional[str] = None
    detonated_at: Optional[str] = None
    cleaned_at: Optional[str] = None
    error: Optional[str] = None

    def save(self) -> None:
        RUNS_DIR.mkdir(parents=True, exist_ok=True)
        (RUNS_DIR / f"{self.run_id}.json").write_text(json.dumps(asdict(self), indent=2))

    @classmethod
    def load(cls, run_id: str) -> "RunRecord":
        run_file = RUNS_DIR / f"{run_id}.json"
        if not run_file.exists():
            raise FileNotFoundError(f"Run {run_id} not found")
        data = json.loads(run_file.read_text())
        return cls(**data)


class LockManager:
    """File-based lock with stale lock detection."""

    def __init__(self, lock_path: Path):
        self.lock_path = lock_path
        self.lock_fd: Optional[int] = None

    def acquire(self) -> bool:
        """Acquire lock, returns True if successful."""
        try:
            self.lock_fd = os.open(str(self.lock_path), os.O_CREAT | os.O_RDWR)
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            # Write our PID
            os.ftruncate(self.lock_fd, 0)
            os.write(self.lock_fd, f"{os.getpid()}\n".encode())
            return True
        except (OSError, BlockingIOError):
            if self.lock_fd is not None:
                os.close(self.lock_fd)
                self.lock_fd = None
            return False

    def release(self) -> None:
        """Release the lock."""
        if self.lock_fd is not None:
            try:
                fcntl.flock(self.lock_fd, fcntl.LOCK_UN)
                os.close(self.lock_fd)
            except OSError:
                pass
            finally:
                self.lock_fd = None

    def get_holder_pid(self) -> Optional[int]:
        """Get PID of current lock holder, if any."""
        try:
            content = self.lock_path.read_text().strip()
            return int(content) if content else None
        except (FileNotFoundError, ValueError):
            return None


def run_cmd(
    cmd: list[str],
    check: bool = True,
    env: Optional[dict] = None,
) -> subprocess.CompletedProcess:
    """Run a command with optional environment override."""
    actual_env = os.environ.copy()
    if env:
        actual_env.update(env)

    result = subprocess.run(cmd, capture_output=True, text=True, env=actual_env)

    if check and result.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\nstderr: {result.stderr}")

    return result


def get_aws_identity() -> tuple[str, str]:
    """Get current AWS account ID and ARN."""
    result = run_cmd(["aws", "sts", "get-caller-identity", "--output", "json"])
    data = json.loads(result.stdout)
    return data["Account"], data["Arn"]


def get_techniques(tactic: Optional[str] = None) -> list[dict]:
    """
    Get list of AWS techniques from stratus.
    Returns list of dicts with 'id' and 'name' keys.
    """
    cmd = ["stratus", "list", "--platform", "aws"]
    if tactic:
        cmd.extend(["--mitre-attack-tactic", tactic])

    result = run_cmd(cmd)

    techniques = []
    lines = result.stdout.strip().splitlines()

    # Skip header lines (usually first 2 lines with column names and separator)
    for line in lines:
        line = line.strip()
        # Technique IDs start with "aws."
        if line.startswith("aws."):
            parts = line.split(None, 1)  # Split on whitespace, max 2 parts
            if parts:
                tech_id = parts[0]
                tech_name = parts[1] if len(parts) > 1 else ""
                techniques.append({"id": tech_id, "name": tech_name})

    return techniques


def get_stratus_status() -> str:
    """Get stratus status output."""
    result = run_cmd(["stratus", "status"], check=False)
    return result.stdout + result.stderr


def load_history() -> list[str]:
    """Load technique history (recently used techniques)."""
    if not HISTORY_FILE.exists():
        return []
    try:
        return json.loads(HISTORY_FILE.read_text())
    except (json.JSONDecodeError, KeyError):
        return []


def save_history(history: list[str], max_size: int = 20) -> None:
    """Save technique history, keeping only recent entries."""
    history = history[-max_size:]
    HISTORY_FILE.write_text(json.dumps(history, indent=2))


def select_technique(
    techniques: list[dict],
    avoid_recent: bool = True,
    recent_count: int = 5,
) -> dict:
    """
    Select a random technique, optionally avoiding recently used ones.
    """
    if not techniques:
        raise ValueError("No techniques available")

    if avoid_recent:
        history = load_history()
        recent = set(history[-recent_count:])
        candidates = [t for t in techniques if t["id"] not in recent]
        # Fall back to all techniques if we've used them all recently
        if not candidates:
            candidates = techniques
    else:
        candidates = techniques

    return random.choice(candidates)


def now_iso() -> str:
    """Get current UTC time in ISO format."""
    return datetime.now(timezone.utc).isoformat()


def generate_run_id() -> str:
    """Generate a unique run ID."""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    random_suffix = os.urandom(4).hex()
    return f"{timestamp}-{random_suffix}"


# ============================================================================
# Command handlers
# ============================================================================

def cmd_run(args: argparse.Namespace) -> int:
    """Execute a random attack."""
    lock = LockManager(LOCK_FILE)

    if not lock.acquire():
        holder_pid = lock.get_holder_pid()
        print(f"ERROR: Another run is in progress (PID: {holder_pid})", file=sys.stderr)
        print("If this is stale, the lock will auto-release when the process exits.", file=sys.stderr)
        return 1

    run_record: Optional[RunRecord] = None
    env = {"AWS_DEFAULT_REGION": args.region, "AWS_REGION": args.region}

    try:
        # Safety check: verify AWS account
        current_account, current_arn = get_aws_identity()
        if current_account != args.account:
            print(f"ERROR: Running in account {current_account}, expected {args.account}", file=sys.stderr)
            return 1

        # Get techniques (optionally filtered by tactic)
        techniques = get_techniques(tactic=args.tactic)
        if not techniques:
            print(f"ERROR: No techniques found", file=sys.stderr)
            if args.tactic:
                print(f"Tactic filter: {args.tactic}", file=sys.stderr)
            return 1

        # Select random technique
        technique = select_technique(
            techniques,
            avoid_recent=not args.allow_repeat,
            recent_count=args.avoid_last_n,
        )

        # Create run record
        run_id = generate_run_id()
        run_record = RunRecord(
            run_id=run_id,
            technique=technique["id"],
            account=current_account,
            region=args.region,
            mode=args.mode,
            tactic_filter=args.tactic,
            started_at=now_iso(),
            status=RunStatus.STARTED.value,
        )
        run_record.save()

        # Print minimal info (technique hidden for blind IR)
        print(f"RUN_ID: {run_id}")
        print(f"MODE: {args.mode}")
        if args.tactic:
            print(f"TACTIC: {args.tactic}")
        print("Attack launching...")
        print()

        # Warmup
        try:
            run_cmd(["stratus", "warmup", technique["id"]], env=env)
            run_record.warmup_at = now_iso()
            run_record.status = RunStatus.WARMUP_COMPLETE.value
            run_record.save()
        except RuntimeError as e:
            run_record.status = RunStatus.FAILED.value
            run_record.error = f"Warmup failed: {e}"
            run_record.save()
            print(f"ERROR: Warmup failed: {e}", file=sys.stderr)
            return 1

        # Optional dwell time
        if args.dwell_min or args.dwell_max:
            dwell = random.randint(args.dwell_min, args.dwell_max)
            if dwell > 0:
                print(f"Dwelling for {dwell}s...")
                time.sleep(dwell)

        # Detonate
        try:
            det_cmd = ["stratus", "detonate", technique["id"]]
            if args.mode == RunMode.VALIDATE.value:
                det_cmd.append("--cleanup")

            run_cmd(det_cmd, env=env)
            run_record.detonated_at = now_iso()
            run_record.status = RunStatus.DETONATED.value
            if args.mode == RunMode.VALIDATE.value:
                run_record.cleaned_at = now_iso()
                run_record.status = RunStatus.CLEANED.value
            run_record.save()
        except RuntimeError as e:
            run_record.status = RunStatus.FAILED.value
            run_record.error = f"Detonate failed: {e}"
            run_record.save()
            print(f"ERROR: Detonate failed: {e}", file=sys.stderr)
            return 1

        # Update history
        history = load_history()
        history.append(technique["id"])
        save_history(history)

        print("Attack launched successfully.")
        print("Your move: detect, investigate, respond.")
        print(f"When done, run: stratus_randomizer.py reveal {run_id}")
        return 0

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        if run_record:
            run_record.status = RunStatus.FAILED.value
            run_record.error = str(e)
            run_record.save()
        return 1

    finally:
        lock.release()


def cmd_reveal(args: argparse.Namespace) -> int:
    """Reveal what technique was used for a run."""
    try:
        record = RunRecord.load(args.run_id)
    except FileNotFoundError:
        print(f"ERROR: Run {args.run_id} not found", file=sys.stderr)
        # List available runs
        if RUNS_DIR.exists():
            runs = sorted(RUNS_DIR.glob("*.json"))
            if runs:
                print("\nAvailable runs:", file=sys.stderr)
                for r in runs[-5:]:  # Show last 5
                    print(f"  {r.stem}", file=sys.stderr)
        return 1

    print(f"{'='*60}")
    print(f"RUN DETAILS: {record.run_id}")
    print(f"{'='*60}")
    print(f"Technique:  {record.technique}")
    print(f"Account:    {record.account}")
    print(f"Region:     {record.region}")
    print(f"Mode:       {record.mode}")
    print(f"Status:     {record.status}")
    if record.tactic_filter:
        print(f"Tactic:     {record.tactic_filter}")
    print(f"Started:    {record.started_at}")
    if record.warmup_at:
        print(f"Warmup:     {record.warmup_at}")
    if record.detonated_at:
        print(f"Detonated:  {record.detonated_at}")
    if record.cleaned_at:
        print(f"Cleaned:    {record.cleaned_at}")
    if record.error:
        print(f"Error:      {record.error}")
    print(f"{'='*60}")

    # Show stratus documentation link
    print(f"\nDocumentation:")
    print(f"  https://stratus-red-team.cloud/attack-techniques/{record.technique.replace('.', '/')}/")

    return 0


def cmd_cleanup(args: argparse.Namespace) -> int:
    """Clean up a specific run."""
    try:
        record = RunRecord.load(args.run_id)
    except FileNotFoundError:
        print(f"ERROR: Run {args.run_id} not found", file=sys.stderr)
        return 1

    if record.status == RunStatus.CLEANED.value:
        print(f"Run {args.run_id} is already cleaned.")
        return 0

    env = {"AWS_DEFAULT_REGION": record.region, "AWS_REGION": record.region}

    print(f"Cleaning up run {args.run_id}...")
    print(f"Technique: {record.technique}")

    try:
        # First try revert (undoes detonation effects)
        print("Running stratus revert...")
        run_cmd(["stratus", "revert", record.technique], env=env, check=False)

        # Then cleanup (removes warmup infrastructure)
        print("Running stratus cleanup...")
        run_cmd(["stratus", "cleanup", record.technique], env=env, check=False)

        record.cleaned_at = now_iso()
        record.status = RunStatus.CLEANED.value
        record.save()

        print("Cleanup complete.")
        return 0

    except Exception as e:
        print(f"ERROR during cleanup: {e}", file=sys.stderr)
        return 1


def cmd_list(args: argparse.Namespace) -> int:
    """List runs or techniques."""
    if args.runs or (not args.runs and not args.techniques):
        # List runs (default)
        if not RUNS_DIR.exists():
            print("No runs yet.")
            return 0

        runs = sorted(RUNS_DIR.glob("*.json"), reverse=True)
        if not runs:
            print("No runs yet.")
            return 0

        print(f"{'RUN ID':<30} {'STATUS':<15} {'MODE':<10}")
        print("-" * 55)
        for run_file in runs[:20]:  # Show last 20
            try:
                record = RunRecord.load(run_file.stem)
                print(f"{record.run_id:<30} {record.status:<15} {record.mode:<10}")
            except Exception:
                print(f"{run_file.stem:<30} {'(error)':<15}")

    elif args.techniques:
        # List available techniques
        techniques = get_techniques(tactic=args.tactic)
        print(f"{'TECHNIQUE ID':<50} {'NAME'}")
        print("-" * 80)
        for t in techniques:
            print(f"{t['id']:<50} {t['name']}")
        print(f"\nTotal: {len(techniques)} techniques")

    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """Show stratus status and recent runs."""
    print("STRATUS STATUS:")
    print("-" * 40)
    status = get_stratus_status()
    print(status if status.strip() else "(no active state)")
    print()

    # Show recent runs
    if RUNS_DIR.exists():
        runs = sorted(RUNS_DIR.glob("*.json"), reverse=True)[:5]
        if runs:
            print("RECENT RUNS:")
            print("-" * 40)
            for run_file in runs:
                try:
                    record = RunRecord.load(run_file.stem)
                    print(f"  {record.run_id}: {record.status}")
                except Exception:
                    pass

    return 0


# ============================================================================
# Main
# ============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Stratus Red Team Randomizer - Blind IR Training Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s run --account 123456789012 --region us-east-1
  %(prog)s run --account 123456789012 --region us-east-1 --mode validate
  %(prog)s run --account 123456789012 --region us-east-1 --tactic persistence
  %(prog)s reveal 20240115T120000Z-abc123
  %(prog)s cleanup 20240115T120000Z-abc123
  %(prog)s list --techniques --tactic credential-access
        """,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Run subcommand
    run_p = subparsers.add_parser("run", help="Run a random attack")
    run_p.add_argument("--account", required=True, help="Expected AWS account ID (safety check)")
    run_p.add_argument("--region", required=True, help="AWS region")
    run_p.add_argument(
        "--mode",
        choices=[m.value for m in RunMode],
        default=RunMode.TRAIN.value,
        help="train=leave artifacts for IR, validate=auto-cleanup (default: train)",
    )
    run_p.add_argument("--tactic", choices=VALID_TACTICS, help="Filter techniques by MITRE ATT&CK tactic")
    run_p.add_argument("--dwell-min", type=int, default=0, help="Min seconds between warmup and detonate")
    run_p.add_argument("--dwell-max", type=int, default=0, help="Max seconds between warmup and detonate")
    run_p.add_argument("--allow-repeat", action="store_true", help="Allow recently-used techniques")
    run_p.add_argument("--avoid-last-n", type=int, default=5, help="Avoid last N techniques (default: 5)")

    # Reveal subcommand
    reveal_p = subparsers.add_parser("reveal", help="Reveal technique for a completed run")
    reveal_p.add_argument("run_id", help="Run ID to reveal")

    # Cleanup subcommand
    cleanup_p = subparsers.add_parser("cleanup", help="Clean up a run (revert + cleanup)")
    cleanup_p.add_argument("run_id", help="Run ID to clean up")

    # List subcommand
    list_p = subparsers.add_parser("list", help="List runs or techniques")
    list_group = list_p.add_mutually_exclusive_group()
    list_group.add_argument("--runs", action="store_true", help="List runs (default)")
    list_group.add_argument("--techniques", action="store_true", help="List available techniques")
    list_p.add_argument("--tactic", choices=VALID_TACTICS, help="Filter techniques by tactic (with --techniques)")

    # Status subcommand
    subparsers.add_parser("status", help="Show stratus status and recent runs")

    args = parser.parse_args()

    # Dispatch to command handler
    handlers = {
        "run": cmd_run,
        "reveal": cmd_reveal,
        "cleanup": cmd_cleanup,
        "list": cmd_list,
        "status": cmd_status,
    }

    return handlers[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
