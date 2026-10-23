🧪 PHP2Shell: a version check is a clue, not a verdict.

A hosted checker is convenient: enter a URL and get a result. I prefer an approach you can inspect, clone, and run yourself. The included Docker lab reproduces the check locally, so you can see the code and its behavior without probing a live site.

This open-source project is a testing POC, not an exploit. It makes a normal HTTP GET, reads an explicitly disclosed PHP version, and compares it with the upstream fixed-version threshold. In the lab, PHP 8.5.11 is below the threshold; PHP 8.5.12 is at it.

This demonstrates version fingerprinting only. It does not attempt RCE or prove exploitability or production patch status. Proxies, vendor backports, and runtime differences can affect the result. The checker sends no exploit or memory-exhaustion payloads.

The repo includes the source, Docker reproduction steps, iTerm screenshots, transcripts, and limitations. Fork it and reproduce the lab locally. Only assess remote systems you own or are authorized to test.

https://github.com/vartaktushar/php2shell-checker-poc

#PHP #CyberSecurity #AppSec #OpenSource #Docker
