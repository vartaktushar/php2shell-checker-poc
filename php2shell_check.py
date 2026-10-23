#!/usr/bin/env python3
"""Non-destructive PHP2Shell exposure checker (CVE-2026-109618/109619).

Remote mode makes ordinary GET requests and evaluates only PHP version
disclosures. It does not send exploit payloads, malformed multipart bodies,
or requests intended to exhaust memory/crash workers. A negative remote result
is inconclusive because PHP versions and headers are commonly hidden.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from typing import Iterable

FIXED = {
    (8, 2): (35,),
    (8, 3): (36,),
    (8, 4): (27,),
    (8, 5): (12,),
}
VERSION_RE = re.compile(r"(?<![\d.])(?:PHP/|PHP\s+|X-Powered-By:\s*PHP/)(\d+\.\d+\.\d+)", re.I)
UA = "php2shell-checker/1.0 (non-destructive version fingerprint)"

def paint(text: str, code: str, enabled: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if enabled else text


def print_report(results: list[Finding], color: bool = False) -> None:
    cyan = "38;5;45"
    muted = "38;5;245"
    red = "1;38;5;196"
    green = "1;38;5;82"
    amber = "1;38;5;214"
    width = 58
    rule = "─" * width
    title = " PHP2SHELL CHECK "
    tagline = " TEST POC ONLY · NOT AN EXPLOIT "
    top = "╭" + title + "─" * (width - len(title) - 2) + "╮"
    middle = "│" + tagline + " " * (width - len(tagline) - 2) + "│"

    print(paint(top, cyan, color))
    print(paint(middle, cyan, color))
    print(paint("╰" + rule[1:-1] + "╯", cyan, color))
    print(paint("  Normal GET requests only · no exploit or crash payloads\n", muted, color))

    for index, result in enumerate(results, start=1):
        if result.status == "version_in_affected_range":
            label, shade, symbol = "AFFECTED VERSION FINGERPRINT", red, "!"
        elif result.status == "version_at_or_above_upstream_fix":
            label, shade, symbol = "UPSTREAM FIX VERSION FINGERPRINT", green, "+"
        elif result.status in {"no_php_version_disclosed", "unreachable"}:
            label, shade, symbol = "INCONCLUSIVE", amber, "?"
        else:
            label, shade, symbol = "VERIFY VENDOR / UNSUPPORTED BRANCH", amber, "?"

        print(paint(f"  {symbol}  {label}", shade, color))
        print(f"  {index:02d}  {result.target}")
        if result.php_version:
            print(f"      PHP {result.php_version}  ·  confidence: {result.confidence}")
        elif result.status == "unreachable":
            print(f"      Confidence: {result.confidence}")
        for item in result.evidence:
            print(paint(f"      {item}", muted, color))
        print(paint("      Version fingerprint only; verify the server runtime and vendor patch.", muted, color))
        if index < len(results):
            print(paint(f"  {rule}", muted, color))

    print(paint(f"\n  {rule}", cyan, color))
    print(paint("  TEST POC ONLY — does not test RCE or prove exploitability.\n", cyan, color))


@dataclass
class Finding:
    target: str
    status: str
    confidence: str
    php_version: str | None
    evidence: list[str]
    note: str


def parse_version(text: str) -> tuple[int, int, int] | None:
    m = re.search(r"(?<!\d)(\d+)\.(\d+)\.(\d+)(?!\d)", text)
    return tuple(map(int, m.groups())) if m else None


def assess(version: tuple[int, int, int]) -> tuple[str, str]:
    major, minor, patch = version
    fixed_patch = FIXED.get((major, minor))
    if fixed_patch is None:
        # Official PHP project fixes are published for 8.2+; older branches
        # are EOL and require vendor-specific verification/migration.
        return "affected_or_unmaintained", "high"
    if patch < fixed_patch[0]:
        return "version_in_affected_range", "high"
    return "version_at_or_above_upstream_fix", "high"


def candidate_urls(raw: str) -> list[str]:
    raw = raw.strip()
    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw
    parsed = urllib.parse.urlsplit(raw)
    if not parsed.hostname:
        raise ValueError("Provide a valid hostname or http(s) URL")
    urls = [urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))]
    if parsed.scheme == "https":
        urls.append(urllib.parse.urlunsplit(("http", parsed.netloc, parsed.path or "/", parsed.query, "")))
    return urls


def probe(url: str, timeout: float) -> tuple[int | None, str, list[str]]:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html,*/*;q=0.8"}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as response:
            headers = response.headers
            body = response.read(256_000).decode("latin-1", errors="replace")
            status = response.status
    except urllib.error.HTTPError as exc:
        headers = exc.headers
        try:
            body = exc.read(64_000).decode("latin-1", errors="replace")
        except Exception:
            body = ""
        status = exc.code
    except (urllib.error.URLError, TimeoutError, socket.timeout, ssl.SSLError) as exc:
        return None, "", [f"request error: {exc}"]

    evidence = [f"HTTP {status}"]
    candidates: list[str] = []
    for name in ("X-Powered-By", "Server"):
        value = headers.get(name)
        if value:
            evidence.append(f"{name}: {value[:200]}")
            candidates.append(value)
    # Only detect explicit PHP version strings; CMS names alone are not proof.
    candidates.append(body[:256_000])
    for value in candidates:
        m = VERSION_RE.search(value)
        if m:
            evidence.append(f"PHP version fingerprint: {m.group(1)}")
            return status, m.group(1), evidence
    return status, "", evidence


def scan_target(target: str, timeout: float) -> Finding:
    errors: list[str] = []
    for url in candidate_urls(target):
        status, version, evidence = probe(url, timeout)
        if status is None:
            errors.extend(evidence)
            continue
        if version:
            parsed = parse_version(version)
            if parsed:
                disposition, confidence = assess(parsed)
                return Finding(target, disposition, confidence, version, evidence,
                               "HTTP version fingerprint only; runtime may differ behind proxies, pools, or vendor backports. Confirm on the server.")
        return Finding(target, "no_php_version_disclosed", "inconclusive", None, evidence,
                       "No explicit PHP version found in this ordinary GET response. This does not establish that PHP is absent or patched.")
    return Finding(target, "unreachable", "none", None, errors,
                   "No HTTP response obtained. Check the URL, network, TLS, and timeout.")


def local_check() -> Finding:
    import subprocess
    try:
        result = subprocess.run(["php", "-r", "echo PHP_VERSION;"], capture_output=True, text=True, timeout=5, check=True)
    except (OSError, subprocess.SubprocessError) as exc:
        return Finding("local PHP CLI", "php_not_available", "none", None, [str(exc)],
                       "This checks only the local CLI binary, not a web server's PHP runtime.")
    version = result.stdout.strip()
    parsed = parse_version(version)
    status, confidence = assess(parsed) if parsed else ("unknown_version", "none")
    return Finding("local PHP CLI", status, confidence, version,
                   [f"php -r reported PHP_VERSION={version}"],
                   "CLI version does not prove the web SAPI uses the same binary or vendor patch level.")


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Non-destructive PHP2Shell version exposure checker")
    parser.add_argument("targets", nargs="*", help="site URL(s) you own or are authorized to assess")
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--local", action="store_true", help="check local PHP CLI version")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("--no-color", action="store_true", help="disable terminal colors")
    args = parser.parse_args(argv)
    if not args.targets and not args.local:
        parser.error("provide at least one URL, or use --local")
    results = [scan_target(target, args.timeout) for target in args.targets]
    if args.local:
        results.append(local_check())
    if args.json:
        print(json.dumps([asdict(r) for r in results], indent=2))
    else:
        print_report(results, color=sys.stdout.isatty() and not args.no_color and "NO_COLOR" not in os.environ)
    return 0


if __name__ == "__main__":
    sys.exit(main())
