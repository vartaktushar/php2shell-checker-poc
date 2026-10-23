# Reproduction evidence

These records come from the isolated Docker lab bound to `127.0.0.1:18080`. The lab intentionally exposes its PHP version so the checker has deterministic input.

- `end-to-end.txt` combines the pre-fix and at-threshold run transcripts.
- `vulnerable-run.txt` and `patched-run.txt` contain the separate transcripts.
- `vulnerable-headers.txt` and `patched-headers.txt` contain the raw response headers.
- `vulnerable-response.txt` and `patched-response.txt` contain the response bodies.
- `jazzy-vulnerable-run.txt` and `jazzy-patched-run.txt` show the colored terminal output.

The images at the repository root are the iTerm screenshots. Together these artifacts demonstrate version fingerprinting only. They are not an exploit and do not establish RCE, exploitability, or production patch status.
