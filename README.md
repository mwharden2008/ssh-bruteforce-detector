# Auth Log Analyzer & Brute-Force Detector

![Python](https://img.shields.io/badge/Python-3.9%2B-blue) ![Purpose](https://img.shields.io/badge/Purpose-Defensive%20Security-blue)

An offline Python cybersecurity portfolio project that examines Linux-style SSH authentication logs for bursts of failed login attempts. It is designed to demonstrate Python programming, log analysis, Security Operations Center (SOC) fundamentals, and MITRE ATT&CK **T1110 (Brute Force)** detection concepts.

**Project deadline:** December 15, 2026.

## What it does

- Reads local `auth.log`-style text files that you own or have permission to analyze.
- Recognizes failed SSH passwords, including `invalid user` entries.
- Groups login failures by source IPv4 or IPv6 address.
- Detects when an address reaches **5 failures in 60 seconds** by default (configurable).
- Outputs an easy-to-read report or exports structured JSON/CSV.
- Includes **synthetic sample logs** and automated unit tests.
- Uses **Python's standard library only**—no package installation required.

## Quick start on Windows

1. Download and **Extract All** from the ZIP. Do not run directly inside the ZIP.
2. Install Python 3.9 or newer from the official [Python website](https://www.python.org/downloads/) if needed.
3. Open the extracted `ssh-bruteforce-detector` folder.
4. Double-click **`run_demo_windows.bat`**, or use Terminal from this folder:

   ```powershell
   py -3 src\parser.py --year 2026
   ```

   If your computer uses `python` instead of `py`, use `python src\parser.py --year 2026`.

**Expected result:** two alerts, for `192.168.1.105` (six failures) and `203.0.113.42` (five failures). The single failed login from `10.0.0.15` is ignored.

## Cross-platform commands

From the project's root folder:

```bash
python3 src/parser.py --year 2026
python3 src/parser.py --year 2026 --threshold 4 --window-seconds 120
python3 src/parser.py --year 2026 --format json --output reports/alerts.json
python3 src/parser.py --year 2026 --format csv --output reports/alerts.csv
python3 -m unittest discover -s tests -v
```

On Windows, replace `python3` with `py -3` or `python`.

To analyze your **own authorized local log**:

```bash
python3 src/parser.py --log /path/to/auth.log --year 2026
```

`--log` chooses the file. `--year` is necessary because ordinary syslog records include month/day/time but not year. Timestamps are treated as local wall time; this educational version does not infer time zones or correlate events across year boundaries.

## Sample output

```text
SSH AUTH LOG ANALYZER — DEFENSIVE REPORT
Log file: samples/sample_auth.log
Analyzed: 15 lines; 12 failed SSH logins
Alert rule: 5+ failures from one IP within 60 seconds
Alerts found: 2
[MEDIUM] 192.168.1.105
Failed attempts: 6
[MEDIUM] 203.0.113.42
Failed attempts: 5
```

## Detection approach

1. Parse failed password records from `sshd` log entries using a regular expression.
2. Validate and normalize source IP addresses using `ipaddress`.
3. Sort failures for each IP by timestamp.
4. Use a **sliding time window** to locate the largest burst for each source IP.
5. Flag an IP if the burst meets the threshold. Severity is **MEDIUM** for 5–9 matched events and **HIGH** for 10+ (an illustrative rubric, not an industry standard).

Each reported alert describes the **largest qualifying burst per IP**, not every burst. A detected burst is a sign to investigate, **not proof of an attack or compromised account**.

## Project structure

```text
ssh-bruteforce-detector/
├── src/
│   ├── __init__.py
│   └── parser.py               # Log parser, sliding-window detection, CLI
├── samples/
│   └── sample_auth.log         # Entirely fabricated training data
├── tests/
│   └── test_parser.py          # Python unittest cases
├── examples/
│   └── sample_report.json      # Example export from the synthetic data
├── .gitignore
├── README.md
├── SECURITY.md
├── LICENSE
├── requirements.txt
├── run_demo_windows.bat
└── START_HERE.txt
```

## Publish to GitHub

Create a new repository named **`ssh-bruteforce-detector`**. Keep it public only if you are comfortable sharing these files. Upload the **contents** of the extracted folder, including the `src`, `samples`, and `tests` folders. Do **not** upload actual client, workplace, or personal authentication logs; the included log is synthetic and safe to share. You can use GitHub's **Add file → Upload files** to upload them, or a Git-enabled terminal to commit and push.

Suggested repository description: *Python SOC project: offline SSH auth-log analysis, brute-force detection, and JSON/CSV reporting.*

**Suggested resume bullet (only after you have personally run and tested the project):**
> Built and tested a Python SSH authentication log analyzer with configurable brute-force detection, IP validation, 60-second sliding-window rules, and structured security report exports.

## Future improvements

- Add true streaming log ingestion and rotation handling.
- Handle structured JSON logs and syslog year-rollover/timezone details.
- Aggregate multiple detection windows per IP.
- Add optional baseline tracking, dashboards, and incident ticket integrations.

## Ethical use

This tool does **not** scan networks, attempt logins, or access any remote computer. Use only logs you are authorized to review. See [SECURITY.md](SECURITY.md).
