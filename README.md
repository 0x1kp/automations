# automations

A collection of small, purpose-built automation scripts organized by domain.

## Prereqs

- Python 3.10+ recommended
- `pip` (or `uv`/`poetry` if you later standardize tooling)


## Quick start

Clone and run a script:

```
git clone <REPO_URL>
cd automations
python3 --version
```

## Conventions
Each automation lives in its own folder and includes a local README.md.
Keep scripts runnable from their folder with python3 <script>.py.
Prefer minimal dependencies; if you add any, document them in the automation’s folder README.
