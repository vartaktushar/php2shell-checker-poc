I built a small PHP2Shell **testing POC, not an exploit**. It sends a normal HTTP GET, reads an explicitly disclosed PHP version, and compares it with the upstream fix threshold. It does not attempt code execution or test exploitability.

I exercised it in an isolated Docker lab using PHP 8.5.11 and 8.5.12. The demo endpoint deliberately reveals its version; the checker changes from an affected-version fingerprint to a version at the upstream fix threshold. The lab binds to localhost and is stopped after each run.

This demonstrates version classification only. Hidden headers, vendor backports, proxies, or a different production runtime can invalidate the inference. A green result does not prove a site is safe, and a red result does not prove RCE. Verify the actual web runtime and vendor advisory.

Reproduction steps, source, evidence, and iTerm screenshots: see this repository's README.

#PHP #CyberSecurity #AppSec #Docker
