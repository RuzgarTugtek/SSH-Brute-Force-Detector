# SSH Brute Force Detector

A Python command-line tool for offline analysis of SSH authentication logs. It detects bursts of failed password attempts using a configurable time window, identifies how many distinct accounts were targeted, and exports findings as text, JSON, or CSV.

**Python:** 3.10+ • **Dependencies:** standard library only

## Quick start

```bash
python -m ssh_detector --log samples/auth.log --threshold 3 --window-minutes 5 --year 2026
python -m ssh_detector --log samples/auth.log --threshold 3 --window-minutes 5 --year 2026 --json
python -m ssh_detector --log samples/auth.log --threshold 3 --window-minutes 5 --year 2026 --csv
python -m unittest discover -s tests -v
```

The sample file contains synthetic SSH logs and documentation IP addresses.

## Method

The parser handles traditional Linux syslog `sshd[PID]: Failed password` events, validates IPv4/IPv6 source addresses and TCP source ports (`1`–`65535`), and counts failed attempts per source within a rolling window. Findings include the peak window, failed-attempt count and distinct usernames targeted. An alert is an investigation signal, not proof of an intrusion.

**Limits:** This is not a live intrusion prevention system. Syslog records need an explicit log year (`--year`); analyze rotated logs and year boundaries separately. Input formats such as journald JSON are not supported. Never publish real authentication logs or credentials.

## Files

- [Core detection](ssh_detector/core.py)
- [CLI](ssh_detector/__main__.py)
- [Unit tests](tests/test_detector.py)
- [Synthetic sample](samples/auth.log)

The GitHub Actions workflow runs the tests on new commits and pull requests.
