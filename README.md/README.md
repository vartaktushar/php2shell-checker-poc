# PHP2Shell version fingerprint checker

> **Testing proof of concept only — not an exploit.** This tool checks PHP version strings disclosed by a normal HTTP GET and compares them with upstream fix thresholds. It does not send exploit payloads, test remote code execution, or establish exploitability.

Use it only on systems you own or are authorized to assess. Results are version fingerprints: hidden headers, vendor backports, proxies, and runtime mismatches can make them misleading. Verify the actual web SAPI and package advisory.

## What it does

- Makes an ordinary GET and looks for an explicit PHP version in common response headers or body.
- Compares disclosed versions with upstream fix thresholds.
- Optionally checks local PHP CLI with `--local`; this does not establish the web server runtime.
- Displays red for below-threshold, green for at-or-above-threshold, amber for inconclusive/vendor verification.

## Requirements

- Python 3.10+
- Docker Desktop with Compose for the local lab

## Run

```sh
python3 php2shell_check.py https://your-authorized-host.example
python3 php2shell_check.py --local
python3 php2shell_check.py https://your-authorized-host.example --json
```

The HTTP check is read-only. It does not submit multipart forms, upload files, execute commands, exhaust memory, or intentionally crash workers. No disclosed version means inconclusive, not safe.

## Reproduce the Docker lab

The lab deliberately exposes the PHP version at `127.0.0.1:18080`. Its page does not process uploads or execute commands. Run both versions with:

```sh
./lab/run_poc.sh
```

It uses official `php:8.5.11-apache` (pre-fix upstream version; expected red classification), then `php:8.5.12-apache` (at upstream fix threshold; expected green). It records transcripts, headers, and response bodies in `evidence/` and stops each container.

Manual phases:

```sh
PHP_TAG=8.5.11 docker compose -f lab/docker-compose.yml up -d --pull always
python3 php2shell_check.py http://127.0.0.1:18080/
PHP_TAG=8.5.11 docker compose -f lab/docker-compose.yml down --remove-orphans
PHP_TAG=8.5.12 docker compose -f lab/docker-compose.yml up -d --pull always
python3 php2shell_check.py http://127.0.0.1:18080/
PHP_TAG=8.5.12 docker compose -f lab/docker-compose.yml down --remove-orphans
```

## Screenshots

These iTerm captures illustrate classification of the disclosed version only. They do not demonstrate exploitation or patch efficacy beyond that fingerprint.

## Limitations

A below-threshold string is not proof of exploitability. An at-threshold string is not proof of vendor patch state. Vendors may backport fixes, and the web runtime may differ from the probed endpoint. Use vendor advisories and inspect the deployed web runtime.

## Sources

- PHP security release: https://www.php.net/archive/2026.php#2026-10-21-5
- PHP releases: https://www.php.net/downloads.php
- NCSC: https://www.ncsc.gov.uk/news/critical-security-issue-affecting-php
- Red Hat: https://access.redhat.com/security/vulnerabilities/RHSB-2026-013

## License

Apache License 2.0; see [LICENSE](LICENSE).
