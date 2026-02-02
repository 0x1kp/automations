# Stratus Randomizer

A full-featured tool to randomly select and detonate Stratus Red Team attacks for blind incident response training.

## Features

- **Random technique selection** with optional MITRE ATT&CK tactic filtering
- **Two modes**: train (leave artifacts) and validate (auto-cleanup)
- **Run history tracking** to avoid repeating recent techniques
- **Blind IR support**: technique hidden until you reveal it
- **Proper concurrency control** with stale lock detection
- **Graceful error handling** with status tracking
- **Built-in cleanup** command for post-IR remediation

## Prerequisites

- Python 3.10+
- AWS CLI configured with credentials
- [Stratus Red Team](https://stratus-red-team.cloud) installed

## Usage

### Run a random attack (train mode - default)

```bash
python3 stratus_randomizer.py run --account 123456789012 --region us-east-1
```

This leaves all artifacts in place for you to practice the full IR lifecycle.

### Run with auto-cleanup (validate mode)

```bash
python3 stratus_randomizer.py run --account 123456789012 --region us-east-1 --mode validate
```

Use this for detection validation loops ("do my detections fire?").

### Filter by MITRE ATT&CK tactic

```bash
python3 stratus_randomizer.py run --account 123456789012 --region us-east-1 --tactic persistence
python3 stratus_randomizer.py run --account 123456789012 --region us-east-1 --tactic credential-access
```

Valid tactics: `initial-access`, `execution`, `persistence`, `privilege-escalation`, `defense-evasion`, `credential-access`, `discovery`, `lateral-movement`, `collection`, `exfiltration`, `impact`

### Add dwell time between warmup and detonate

```bash
python3 stratus_randomizer.py run --account 123456789012 --region us-east-1 \
    --dwell-min 60 --dwell-max 300
```

### Reveal what technique was used

```bash
python3 stratus_randomizer.py reveal <run_id>
```

### Clean up a run

```bash
python3 stratus_randomizer.py cleanup <run_id>
```

This runs both `stratus revert` (undo detonation effects) and `stratus cleanup` (remove warmup infrastructure).

### List runs

```bash
python3 stratus_randomizer.py list           # List recent runs (default)
python3 stratus_randomizer.py list --runs    # Same as above
```

### List available techniques

```bash
python3 stratus_randomizer.py list --techniques
python3 stratus_randomizer.py list --techniques --tactic persistence
```

### Check status

```bash
python3 stratus_randomizer.py status
```

## Directory Structure

```
stratus-randomizer/
├── stratus_randomizer.py   # Main script
├── README.md               # This file
├── .lock                   # Lock file (created during runs)
├── .history.json           # Technique history (avoid repeats)
└── runs/                   # Run records
    └── *.json              # One file per run
```

## Example Workflow

```bash
# 1. Launch an attack focused on persistence techniques
$ python3 stratus_randomizer.py run --account 123456789012 --region us-east-1 --tactic persistence
RUN_ID: 20240115T143022Z-a1b2c3d4
MODE: train
TACTIC: persistence
Attack launching...

Attack launched successfully.
Your move: detect, investigate, respond.
When done, run: stratus_randomizer.py reveal 20240115T143022Z-a1b2c3d4

# 2. Go investigate in your Security-Tooling/Log-Archive accounts
#    - Check GuardDuty findings
#    - Review CloudTrail events
#    - Analyze Security Hub findings
#    - Follow your IR lifecycle: Monitor → Triage → Investigate → Scope/Hunt → Decide/Contain → Eradicate/Recover → Prevent recurrence

# 3. After completing your investigation, reveal the attack
$ python3 stratus_randomizer.py reveal 20240115T143022Z-a1b2c3d4
============================================================
RUN DETAILS: 20240115T143022Z-a1b2c3d4
============================================================
Technique:  aws.persistence.iam-backdoor-user
Account:    123456789012
Region:     us-east-1
Mode:       train
Status:     detonated
Tactic:     persistence
Started:    2024-01-15T14:30:22.123456+00:00
Warmup:     2024-01-15T14:30:25.234567+00:00
Detonated:  2024-01-15T14:30:28.345678+00:00
============================================================

Documentation:
  https://stratus-red-team.cloud/attack-techniques/aws/persistence/iam-backdoor-user/

# 4. Clean up
$ python3 stratus_randomizer.py cleanup 20240115T143022Z-a1b2c3d4
Cleaning up run 20240115T143022Z-a1b2c3d4...
Technique: aws.persistence.iam-backdoor-user
Running stratus revert...
Running stratus cleanup...
Cleanup complete.
```

## Safety Features

1. **Account verification**: The script verifies you're in the expected AWS account before running any attack
2. **Concurrency control**: Only one run can execute at a time (file-based locking)
3. **Status tracking**: Each run's status is tracked (started, warmup_complete, detonated, cleaned, failed)
4. **Technique history**: Avoids running the same technique repeatedly (configurable)
5. **Error recovery**: Partial failures are tracked and can be cleaned up later

## Comparison with Minimal Version

| Feature | Minimal | Full |
|---------|---------|------|
| Random selection | ✓ | ✓ |
| Account safety check | ✓ | ✓ |
| Train/validate modes | ✓ | ✓ |
| Reveal command | ✓ | ✓ |
| Cleanup command | - | ✓ |
| Tactic filtering | - | ✓ |
| Dwell time | - | ✓ |
| Avoid recent techniques | - | ✓ |
| Concurrency control | - | ✓ |
| Status tracking | - | ✓ |
| Error recovery | - | ✓ |
