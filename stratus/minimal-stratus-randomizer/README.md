# Minimal Stratus Randomizer

A simple script to randomly select and detonate Stratus Red Team attacks for blind incident response training.

## Prerequisites

- Python 3.10+
- AWS CLI configured with credentials
- [Stratus Red Team](https://stratus-red-team.cloud) installed

## Usage

### Run a random attack

```bash
python3 randomize.py run --account 123456789012 --region us-east-1
```

This will:
1. Verify you're in the expected AWS account (safety check)
2. Pick a random AWS technique
3. Warmup and detonate the attack
4. Print only the run ID (technique is hidden for blind IR)

### Run with auto-cleanup (validation mode)

```bash
python3 randomize.py run --account 123456789012 --region us-east-1 --cleanup
```

### Reveal what technique was used

After completing your investigation:

```bash
python3 randomize.py reveal <run_id>
```

### List all runs

```bash
python3 randomize.py list-runs
```

## Directory Structure

```
minimal-stratus-randomizer/
├── randomize.py      # Main script
├── README.md         # This file
└── runs/             # Run records (created automatically)
    └── *.json        # One file per run
```

## Example Workflow

```bash
# 1. Launch an attack (you won't know what it is)
$ python3 randomize.py run --account 123456789012 --region us-east-1
RUN_ID: 20240115T143022Z
Attack launched. Check your detections.

# 2. Go investigate in your Security-Tooling/Log-Archive accounts
#    - Check GuardDuty, Security Hub, CloudTrail, etc.
#    - Follow your IR lifecycle

# 3. After completing your investigation, reveal the attack
$ python3 randomize.py reveal 20240115T143022Z
Run ID:    20240115T143022Z
Technique: aws.credential-access.ec2-get-password-data
Account:   123456789012
Region:    us-east-1
Started:   2024-01-15T14:30:22.123456+00:00
Cleanup:   False

# 4. Clean up manually with stratus if needed
$ stratus cleanup aws.credential-access.ec2-get-password-data
```
