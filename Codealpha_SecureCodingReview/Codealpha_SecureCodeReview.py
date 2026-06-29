#!/usr/bin/env python3
"""
CodeAlpha Internship — Task 3: Secure Coding Review
Description:
    Static-analysis tool that scans Python source files for common
    security vulnerabilities, reports findings, and suggests fixes.

Usage:
    python3 secure_code_review.py <file_or_directory> [options]
    python3 secure_code_review.py app.py
    python3 secure_code_review.py ./myproject --output report.html
    python3 secure_code_review.py ./myproject --format json
"""

import argparse
import ast
import contextlib
import datetime
import io
import json
import os
import re
import sys
import tempfile
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List

LEVEL_WEIGHT = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
ANSI_STYLES = {
    "CRITICAL": "\033[95m",
    "HIGH": "\033[91m",
    "MEDIUM": "\033[93m",
    "LOW": "\033[94m",
    "INFO": "\033[96m",
}
RESET = "\033[0m"
BOLD = "\033[1m"


@dataclass
class Finding:
    rule_id: str
    severity: str
    category: str
    title: str
    description: str
    line: int
    col: int
    code_snippet: str
    remediation: str
    cwe: str = ""
    owasp: str = ""
    file: str = ""


REGEX_RULES = [
    (
        "INJ-001", "HIGH", "SQL Injection",
        "Possible SQL Injection via string formatting",
        r'(execute|cursor\.execute)\s*\(\s*[f"\'].*%(s|d)|f".*SELECT|f\'.*INSERT|f\'.*UPDATE|f\'.*DELETE|".*"\s*%\s*\(',
        "Untrusted input used directly in SQL query construction. An attacker can alter the query logic.",
        "Use parameterised queries / prepared statements:\n  cursor.execute('SELECT * FROM users WHERE id=%s', (user_id,))",
        "CWE-89", "A03:2021 - Injection"
    ),
    (
        "INJ-002", "HIGH", "Command Injection",
        "Possible OS Command Injection",
        r'os\.system\(|subprocess\.call\(.*shell\s*=\s*True|subprocess\.Popen\(.*shell\s*=\s*True|commands\.getoutput\(',
        "shell=True passes the command through the shell, enabling command injection if user input is included.",
        "Use subprocess with a list of arguments instead:\n  subprocess.run(['ls', '-la'], shell=False)",
        "CWE-78", "A03:2021 - Injection"
    ),
    (
        "INJ-003", "CRITICAL", "Code Injection",
        "Use of eval() — arbitrary code execution risk",
        r'\beval\s*\(',
        "eval() executes arbitrary Python code from a string. If user input reaches eval(), an attacker can run any code.",
        "Avoid eval() entirely. Use ast.literal_eval() for safe parsing of Python literals.",
        "CWE-95", "A03:2021 - Injection"
    ),
    (
        "INJ-004", "CRITICAL", "Code Injection",
        "Use of exec() — arbitrary code execution risk",
        r'\bexec\s*\(',
        "exec() executes arbitrary Python code. Never pass untrusted input to exec().",
        "Remove exec() usage. Refactor to use proper functions or data structures instead.",
        "CWE-95", "A03:2021 - Injection"
    ),
    (
        "CRY-001", "HIGH", "Weak Cryptography",
        "Use of MD5 hashing algorithm",
        r'hashlib\.md5|md5\(',
        "MD5 is cryptographically broken. Collisions can be generated in seconds.",
        "Use SHA-256 or stronger:\n  hashlib.sha256(data).hexdigest()",
        "CWE-327", "A02:2021 - Cryptographic Failures"
    ),
    (
        "CRY-002", "HIGH", "Weak Cryptography",
        "Use of SHA-1 hashing algorithm",
        r'hashlib\.sha1\b|sha1\(',
        "SHA-1 is deprecated and vulnerable to collision attacks since 2017.",
        "Use SHA-256 or SHA-3:\n  hashlib.sha256(data).hexdigest()",
        "CWE-327", "A02:2021 - Cryptographic Failures"
    ),
    (
        "CRY-003", "CRITICAL", "Weak Cryptography",
        "Hardcoded secret key / password detected",
        r'(?i)(password|passwd|secret|api_key|apikey|token|private_key)\s*=\s*["\'][^"\']{4,}["\']',
        "Hardcoded credentials in source code can be extracted by anyone with access to the repository.",
        "Store secrets in environment variables or a secrets manager:\n  os.environ.get('DB_PASSWORD')",
        "CWE-798", "A07:2021 - Identification and Authentication Failures"
    ),
    (
        "CRY-004", "MEDIUM", "Weak Cryptography",
        "Use of DES or 3DES encryption",
        r'(?i)\bDES\b|Blowfish|des\.new|cipher\.DES',
        "DES (56-bit) is completely broken; 3DES is deprecated by NIST as of 2023.",
        "Use AES-256-GCM for symmetric encryption.",
        "CWE-326", "A02:2021 - Cryptographic Failures"
    ),
    (
        "RNG-001", "MEDIUM", "Insecure Randomness",
        "Use of random module for security-sensitive operations",
        r'\brandom\.(random|randint|choice|shuffle|seed|sample)\(',
        "The random module is not cryptographically secure and should not be used for tokens, passwords, or session IDs.",
        "Use the secrets module for cryptographic randomness:\n  secrets.token_hex(32)",
        "CWE-338", "A02:2021 - Cryptographic Failures"
    ),
    (
        "NET-001", "HIGH", "Insecure Transport",
        "SSL/TLS certificate verification disabled",
        r'verify\s*=\s*False|ssl\.CERT_NONE|check_hostname\s*=\s*False',
        "Disabling certificate verification makes HTTPS connections vulnerable to man-in-the-middle attacks.",
        "Always keep verify=True (the default). If using self-signed certs, provide the CA bundle path:\n  requests.get(url, verify='/path/to/ca.pem')",
        "CWE-295", "A02:2021 - Cryptographic Failures"
    ),
    (
        "DSR-001", "CRITICAL", "Insecure Deserialization",
        "Use of pickle.loads() — arbitrary code execution risk",
        r'pickle\.loads?\(',
        "Unpickling untrusted data executes arbitrary Python code. This is a critical vulnerability.",
        "Use JSON, MessagePack, or similar safe serialisation formats. Never unpickle untrusted data.",
        "CWE-502", "A08:2021 - Software and Data Integrity Failures"
    ),
    (
        "DSR-002", "HIGH", "Insecure Deserialization",
        "Use of yaml.load() without Loader — code execution risk",
        r'yaml\.load\s*\([^,)]+\)',
        "yaml.load() with untrusted data can execute arbitrary Python objects.",
        "Use yaml.safe_load() instead:\n  yaml.safe_load(stream)",
        "CWE-502", "A08:2021 - Software and Data Integrity Failures"
    ),
    (
        "PTH-001", "HIGH", "Path Traversal",
        "Potential path traversal using os.path.join with user input",
        r'os\.path\.join\s*\(.*request|open\s*\(.*request',
        "Joining user-supplied paths can escape the intended directory (e.g. '../../etc/passwd').",
        "Sanitise and validate paths:\n  safe_path = os.path.realpath(os.path.join(base_dir, user_input))\n  assert safe_path.startswith(base_dir)",
        "CWE-22", "A01:2021 - Broken Access Control"
    ),
    (
        "DBG-001", "LOW", "Information Disclosure",
        "Debug mode enabled in web framework",
        r'(?i)debug\s*=\s*True|app\.run\(.*debug\s*=\s*True',
        "Debug mode exposes stack traces, environment variables, and an interactive console to users.",
        "Disable debug mode in production:\n  app.run(debug=False)",
        "CWE-215", "A05:2021 - Security Misconfiguration"
    ),
    (
        "DBG-002", "INFO", "Information Disclosure",
        "print() statement detected — possible info leak",
        r'\bprint\s*\(',
        "print() statements may leak sensitive data, stack traces, or configuration to logs/console.",
        "Replace print() with Python's logging module and control log levels per environment.",
        "CWE-532", ""
    ),
    (
        "XSS-001", "HIGH", "Cross-Site Scripting",
        "Jinja2 template with autoescape disabled",
        r'autoescape\s*=\s*False|Markup\s*\(',
        "Disabling autoescape or using Markup() with untrusted input allows XSS attacks.",
        "Keep autoescape enabled (default in Flask/Jinja2). Never wrap untrusted data in Markup().",
        "CWE-79", "A03:2021 - Injection"
    ),
    (
        "SSRF-001", "HIGH", "SSRF",
        "HTTP request made with user-supplied URL — potential SSRF",
        r'requests\.(get|post|put|patch)\s*\(\s*(?:request\.|url\b|user_?input)',
        "Making HTTP requests to user-supplied URLs can lead to Server-Side Request Forgery (SSRF), allowing internal network access.",
        "Validate and whitelist URLs before making requests. Block internal/private IP ranges.",
        "CWE-918", "A10:2021 - SSRF"
    ),
    (
        "LOG-001", "MEDIUM", "Sensitive Data Exposure",
        "Possible logging of sensitive data (password/token/secret)",
        r'(?i)(log|logger|logging)\.(debug|info|warning|error|critical)\s*\(.*(?:password|token|secret|key)',
        "Logging credentials or tokens writes them to log files which may be accessible to unauthorised parties.",
        "Mask or redact sensitive values before logging:\n  logger.info('Login attempt for user: %s', username)  # not password",
        "CWE-532", "A09:2021 - Security Logging and Monitoring Failures"
    ),
]


class SecureCodeReviewer:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.compiled_rules = []
        for rule in REGEX_RULES:
            rule_id, severity, category, title, pattern, description, remedy, cwe, owasp = rule
            self.compiled_rules.append((rule_id, severity, category, title, re.compile(pattern), description, remedy, cwe, owasp))

    def scan_file(self, filepath: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as handle:
                lines = handle.readlines()
            source_text = "".join(lines)
        except Exception as exc:
            print(f"  [!] Could not read {filepath}: {exc}")
            return findings

        findings.extend(self._regex_hits(lines, filepath))

        try:
            tree = ast.parse(source_text, filename=filepath)
            findings.extend(self._tree_hits(tree, filepath, lines))
        except SyntaxError as exc:
            findings.append(
                Finding(
                    rule_id="SYNTAX",
                    severity="INFO",
                    category="Code Quality",
                    title="Syntax error — file could not be fully parsed",
                    description=str(exc),
                    line=exc.lineno or 0,
                    col=exc.offset or 0,
                    code_snippet="",
                    remediation="Fix the syntax error to enable full analysis.",
                    file=filepath,
                )
            )
        return findings

    def _regex_hits(self, lines: List[str], filepath: str) -> List[Finding]:
        findings: List[Finding] = []
        for lineno, raw_line in enumerate(lines, start=1):
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            for rule_id, severity, category, title, pattern, description, remedy, cwe, owasp in self.compiled_rules:
                if pattern.search(raw_line):
                    findings.append(
                        Finding(
                            rule_id=rule_id,
                            severity=severity,
                            category=category,
                            title=title,
                            description=description,
                            line=lineno,
                            col=self._column_for(raw_line),
                            code_snippet=stripped[:120],
                            remediation=remedy,
                            cwe=cwe,
                            owasp=owasp,
                            file=filepath,
                        )
                    )
        return findings

    def _column_for(self, line: str) -> int:
        stripped = line.lstrip()
        return len(line) - len(stripped) if stripped else 0

    def _tree_hits(self, tree: ast.AST, filepath: str, lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []

        def snippet(lineno: int) -> str:
            if lines and 0 < lineno <= len(lines):
                return lines[lineno - 1].strip()[:120]
            return ""

        for node in ast.walk(tree):
            if isinstance(node, ast.Assert):
                findings.append(
                    Finding(
                        rule_id="AST-001",
                        severity="MEDIUM",
                        category="Security Bypass",
                        title="assert statement used for security check",
                        description="assert statements are removed when Python is run with -O (optimised mode), bypassing the check.",
                        line=node.lineno,
                        col=node.col_offset,
                        code_snippet=snippet(node.lineno),
                        remediation="Replace assert with explicit if/raise:\n  if not condition:\n      raise ValueError('...')",
                        cwe="CWE-617",
                        file=filepath,
                    )
                )

            if isinstance(node, ast.ExceptHandler) and node.type is None:
                findings.append(
                    Finding(
                        rule_id="AST-002",
                        severity="LOW",
                        category="Error Handling",
                        title="Bare except clause — catches all exceptions including SystemExit",
                        description="'except:' silently swallows all exceptions, hiding errors and making debugging and auditing very difficult.",
                        line=node.lineno,
                        col=node.col_offset,
                        code_snippet=snippet(node.lineno),
                        remediation="Catch specific exceptions:\n  except (ValueError, KeyError) as e:\n      logger.error(e)",
                        cwe="CWE-390",
                        file=filepath,
                    )
                )

            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                elif isinstance(node.func, ast.Name):
                    func_name = node.func.id

                if func_name in ("call", "Popen", "run", "check_output"):
                    for kw in node.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            findings.append(
                                Finding(
                                    rule_id="AST-003",
                                    severity="HIGH",
                                    category="Command Injection",
                                    title="subprocess called with shell=True",
                                    description="shell=True passes the command through the shell interpreter, enabling injection if any argument contains user input.",
                                    line=node.lineno,
                                    col=node.col_offset,
                                    code_snippet=snippet(node.lineno),
                                    remediation="Use shell=False (default) and pass arguments as a list:\n  subprocess.run(['cmd', arg1, arg2])",
                                    cwe="CWE-78",
                                    owasp="A03:2021",
                                    file=filepath,
                                )
                            )

        return findings

    def scan_path(self, path: str) -> List[Finding]:
        entry = Path(path)
        all_findings: List[Finding] = []
        if entry.is_file():
            if entry.suffix == ".py":
                all_findings.extend(self.scan_file(str(entry)))
        elif entry.is_dir():
            py_files = list(entry.rglob("*.py"))
            print(f"[*] Found {len(py_files)} Python files to scan...")
            for py_file in py_files:
                if self.verbose:
                    print(f"    Scanning: {py_file}")
                all_findings.extend(self.scan_file(str(py_file)))
        else:
            print(f"[-] Path not found: {path}")
        return all_findings


def report_console(findings: List[Finding]):
    if not findings:
        print(f"\n{BOLD}\033[92m[+] No issues found. Great work!{RESET}\n")
        return

    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    grouped = defaultdict(list)
    for item in findings:
        grouped[item.severity].append(item)

    print(f"\n{BOLD}{'═'*70}{RESET}")
    print(f"{BOLD}  SECURE CODE REVIEW REPORT  —  {len(findings)} issue(s) found{RESET}")
    print(f"{'═'*70}")

    for severity in sev_order:
        if severity not in grouped:
            continue
        colour = ANSI_STYLES[severity]
        print(f"\n{colour}{BOLD}  ▶ {severity} ({len(grouped[severity])}){RESET}")
        for item in grouped[severity]:
            print(f"  {'─'*65}")
            print(f"  {BOLD}[{item.rule_id}] {item.title}{RESET}")
            print(f"  File    : {item.file}  (line {item.line})")
            print(f"  Code    : {item.code_snippet}")
            print(f"  Why     : {item.description}")
            print(f"  Fix     : {item.remediation}")
            if item.cwe:
                print(f"  CWE     : {item.cwe}")
            if item.owasp:
                print(f"  OWASP   : {item.owasp}")

    print(f"\n{'═'*70}")
    print(f"{BOLD}  SUMMARY{RESET}")
    print(f"{'─'*70}")
    for severity in sev_order:
        colour = ANSI_STYLES[severity]
        count = len(grouped.get(severity, []))
        bar = "█" * count
        print(f"  {colour}{severity:<10}{RESET}  {bar:<20} {count}")
    print(f"{'═'*70}\n")


def report_json(findings: List[Finding], output_file: str):
    data = {
        "generated": datetime.datetime.now().isoformat(),
        "total": len(findings),
        "findings": [asdict(item) for item in findings],
    }
    with open(output_file, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
    print(f"[+] JSON report saved: {output_file}")


def report_html(findings: List[Finding], output_file: str):
    from html import escape

    sev_colour = {"CRITICAL": "#f85149", "HIGH": "#ff8c00", "MEDIUM": "#e3b341", "LOW": "#58a6ff", "INFO": "#56d364"}
    rows: List[str] = []
    for item in findings:
        colour = sev_colour.get(item.severity, "#aaa")
        rows.append(
            f"""
            <tr>
              <td><span class="badge" style="background:{colour}15;color:{colour};border:1px solid {colour}">{item.severity}</span></td>
              <td><code>{escape(item.rule_id)}</code></td>
              <td>{escape(item.title)}</td>
              <td>{escape(os.path.basename(item.file))}:{item.line}</td>
              <td><code>{escape(item.code_snippet[:80])}</code></td>
              <td>{escape(item.cwe)}</td>
            </tr>"""
        )

    html = f"""<!DOCTYPE html>
<html><head><meta charset='UTF-8'><title>Secure Code Review Report</title>
<style>
  body{{font-family:system-ui;background:#0d1117;color:#e6edf3;margin:0;padding:2rem}}
  h1{{color:#f0883e}} table{{width:100%;border-collapse:collapse;margin-top:1rem}}
  th{{background:#21262d;padding:.7rem;text-align:left;border:1px solid #30363d}}
  td{{padding:.6rem;border:1px solid #30363d;font-size:.88rem;vertical-align:top}}
  .badge{{padding:.2rem .6rem;border-radius:12px;font-size:.75rem;font-weight:700}}
  code{{background:#161b22;padding:.1rem .4rem;border-radius:4px;font-size:.82rem}}
</style></head><body>
<h1>🔐 Secure Code Review Report</h1>
<p>Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Total issues: <strong>{len(findings)}</strong></p>
<table><thead><tr><th>Severity</th><th>Rule</th><th>Title</th><th>Location</th><th>Code Snippet</th><th>CWE</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
</body></html>"""

    with open(output_file, "w", encoding="utf-8") as handle:
        handle.write(html)
    print(f"[+] HTML report saved: {output_file}")


DEMO_CODE = '''#!/usr/bin/env python3
"""
DEMO VULNERABLE FILE — for testing secure_code_review.py
DO NOT USE IN PRODUCTION
"""
import hashlib, pickle, random, os, subprocess, yaml, sqlite3

# CRY-003: Hardcoded secret
SECRET_KEY = "supersecretpassword123"
API_TOKEN  = "sk-abc123xyz"

def login(username, password):
    # CRY-001: Weak MD5 hash
    hashed = hashlib.md5(password.encode()).hexdigest()
    return hashed

def get_user(user_id, conn):
    cursor = conn.cursor()
    # INJ-001: SQL injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()

def run_command(user_input):
    # INJ-002: Command injection
    os.system("ls " + user_input)
    # Also bad:
    subprocess.call("ping " + user_input, shell=True)

def calculate(expr):
    # INJ-003: Code injection via eval
    return eval(expr)

def load_data(data):
    # DSR-001: Unsafe pickle
    return pickle.loads(data)

def load_config(stream):
    # DSR-002: Unsafe yaml
    return yaml.load(stream)

def generate_token():
    # RNG-001: Non-cryptographic random
    return random.randint(100000, 999999)

def debug_app():
    # DBG-001: Debug mode
    app.run(debug=True)

def check_admin(user):
    # AST-001: assert for security
    assert user.is_admin, "Not an admin"
    return True

def risky_fetch(url):
    # NET-001: SSL disabled
    import requests
    return requests.get(url, verify=False)

try:
    risky_fetch("http://example.com")
except:   # AST-002: Bare except
    pass
'''


def banner():
    print(f"""
{BOLD}╔══════════════════════════════════════════════════════╗
║    CodeAlpha — Secure Coding Review Tool             ║
║    Task 3 | Cybersecurity Internship                 ║
╚══════════════════════════════════════════════════════╝{RESET}""")


def main():
    banner()
    parser = argparse.ArgumentParser(description="Scan Python source files for security vulnerabilities.")
    parser.add_argument("target", nargs="?", help="File or directory to scan (omit to scan a built-in demo)")
    parser.add_argument("--output", "-o", default=None, help="Output file path for the report")
    parser.add_argument("--format", "-f", choices=["console", "json", "html"], default="console", help="Report format (default: console)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show each file being scanned")
    args = parser.parse_args()

    reviewer = SecureCodeReviewer(verbose=args.verbose)

    if not args.target:
        demo_file = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8")
        demo_path = demo_file.name
        demo_file.write(DEMO_CODE)
        demo_file.close()
        print(f"[*] No target specified. Scanning built-in demo file: {demo_path}")
        findings = reviewer.scan_file(demo_path)
    else:
        print(f"[*] Scanning: {args.target}")
        findings = reviewer.scan_path(args.target)

    if args.format == "json":
        out = args.output or "report.json"
        report_json(findings, out)
    elif args.format == "html":
        out = args.output or "report.html"
        report_html(findings, out)
    else:
        report_console(findings)
        if args.output:
            import contextlib as _contextlib
            import io as _io
            buf = _io.StringIO()
            with _contextlib.redirect_stdout(buf):
                report_console(findings)
            with open(args.output, "w", encoding="utf-8") as handle:
                clean = re.sub(r'\033\[[0-9;]*m', '', buf.getvalue())
                handle.write(clean)
            print(f"[+] Text report saved: {args.output}")

    high_count = sum(1 for item in findings if item.severity in ("CRITICAL", "HIGH"))
    sys.exit(1 if high_count > 0 else 0)


if __name__ == "__main__":
    main()
