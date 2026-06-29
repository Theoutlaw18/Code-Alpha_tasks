# Secure Code Review Tool

A simple Python-based static analysis tool for detecting common security issues in Python source code. It scans files or directories for risky patterns and reports them with severity levels, remediation advice, and optional JSON/HTML output.

## Features

- Scans Python files for common security vulnerabilities
- Detects issues such as:
  - SQL injection
  - command injection
  - code injection via `eval()` / `exec()`
  - weak hashing (MD5, SHA-1)
  - hardcoded secrets
  - insecure randomness
  - SSL/TLS verification bypass
  - unsafe deserialization
  - path traversal risks
  - debug mode exposure
  - insecure `assert` usage and bare `except`
- Supports console, JSON, and HTML reports
- Exits with a non-zero status when critical or high severity issues are found

## Requirements

- Python 3.8+

## Usage

Run the script against a file or folder:

```bash
python Codealpha_SecureCodeReview.py path/to/file.py
python Codealpha_SecureCodeReview.py path/to/project
```

### Optional arguments

- `--output`, `-o`: Save the report to a file
- `--format`, `-f`: Choose report format (`console`, `json`, or `html`)
- `--verbose`, `-v`: Show each scanned file

### Examples

Console output:

```bash
python Codealpha_SecureCodeReview.py app.py
```

JSON output:

```bash
python Codealpha_SecureCodeReview.py ./myproject --format json --output report.json
```

HTML output:

```bash
python Codealpha_SecureCodeReview.py ./myproject --format html --output report.html
```

If no target is provided, the tool scans a built-in demo file to show how the review works.

## Output

The tool prints findings in the terminal and can also save them as:

- plain text report
- JSON report
- HTML report

## Notes

This tool is intended for educational and security review purposes. It is not a replacement for a full security analyzer or professional code review process.
