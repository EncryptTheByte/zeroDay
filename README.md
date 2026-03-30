# LiteLLM Supply Chain Attack Scanner

A static analysis tool that scans a local repository or directory for indicators of compromise related to the **LiteLLM PyPI supply chain attack** disclosed on **March 24, 2026**.

---

## Background

On March 24, 2026, two PyPI releases of LiteLLM were found to be compromised:

| Version | Payload |
|---------|---------|
| `1.82.7` | Malicious code in `proxy_server.py` |
| `1.82.8` | Malicious code in `proxy_server.py` **+** a startup-execution hook via `litellm_init.pth` |

The attack window was **10:39 UTC – 16:00 UTC** on March 24, 2026. Any `pip install litellm` or `pip upgrade litellm` executed during that window without a pinned version could have silently installed the compromised release.

### Why `litellm_init.pth` Was Especially Dangerous

Python's `site` module automatically processes `.pth` files found in `site-packages` **at interpreter startup** — before your application code runs, before any web framework initialises, before anything. A single line in that file:

```
import payload; payload.bootstrap()
```

...is enough to trigger code execution the moment any Python process starts in that environment. The malicious payload harvested and exfiltrated:

- Environment variables (API keys, tokens, passwords)
- SSH private keys
- Cloud provider credentials (AWS, GCP, Azure)
- Kubernetes service account tokens
- Database connection strings

Harvested data was encrypted and POSTed to `models.litellm.cloud` — a domain **not** affiliated with BerriAI or the legitimate LiteLLM project.

> Customers running the **official LiteLLM Proxy Docker image** (`ghcr.io/berriai/litellm`) were **not** impacted, as that image pins its dependencies and does not pull from PyPI directly.

---

## What This Scanner Does

`litellm_supply_chain_scanner.py` walks a repository tree and checks every relevant file for:

1. **Pinned compromised versions** — `litellm==1.82.7` or `litellm==1.82.8` anywhere in your dependency manifests
2. **Loose version ranges** — version specifiers like `>=1.82.0,<1.82.9` that could resolve to a compromised release
3. **Lock file entries** — exact pinned versions recorded in `poetry.lock`, `uv.lock`, `Pipfile.lock`
4. **The malicious `.pth` file itself** — if `litellm_init.pth` is present in the repository
5. **IOC strings** — known artifact paths (`.config/sysmon/sysmon.py`, systemd persistence) and the exfiltration domain `models.litellm.cloud`
6. **Python source imports** — files that `import litellm` flagged as informational, since they will load malicious code if a compromised version is installed

### File Types Scanned

| File | Checker |
|------|---------|
| `requirements*.txt`, `constraints*.txt`, `pip-freeze.txt` | Exact pins + range specifiers |
| `pyproject.toml` | Dependency tables (Poetry, PDM, Hatch, PEP 621) |
| `setup.py`, `setup.cfg` | `install_requires` entries |
| `poetry.lock` | Resolved version in lock block |
| `uv.lock`, `pdm.lock` | Resolved version in lock block |
| `Pipfile.lock` | `default` and `develop` sections |
| `environment.yml`, `conda-lock.yml` | Conda pinned versions |
| `Dockerfile`, `docker-compose.yml` | `pip install` instructions |
| `.github/**/*.yml`, CI config files | Install steps in workflows |
| `*.py` | `import litellm` / `from litellm import ...` |
| `litellm_init.pth` | Hard IOC — malicious startup hook |
| Any file | IOC string patterns (sysmon, exfil domain) |

---

## Installation

No dependencies beyond the Python standard library.

```bash
# Python 3.8+ required
python3 litellm_supply_chain_scanner.py --help
```

---

## Usage

```bash
# Scan current directory
python3 litellm_supply_chain_scanner.py .

# Scan a specific repository
python3 litellm_supply_chain_scanner.py /path/to/your/project

# JSON output (CI-friendly)
python3 litellm_supply_chain_scanner.py /path/to/repo --json

# Suppress INFO findings, show only CRITICAL and HIGH
python3 litellm_supply_chain_scanner.py . --quiet

# Disable colour output
python3 litellm_supply_chain_scanner.py . --no-color
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No vulnerability or compromise indicator found |
| `1` | CRITICAL or HIGH finding — repository is vulnerable or compromised |
| `2` | Scanner error (bad path, unreadable root, etc.) |

This makes the scanner safe to drop into any CI pipeline:

```yaml
# GitHub Actions example
- name: Scan for LiteLLM supply chain compromise
  run: python3 litellm_supply_chain_scanner.py . --json --quiet
```

---

## Severity Levels

| Severity | Meaning |
|----------|---------|
| **CRITICAL** | Compromised version pinned, malicious file found, or IOC string in a non-scanner file |
| **HIGH** | Version range that may resolve to a compromised release |
| **INFO** | `litellm` is imported — risk depends on the installed version at runtime |

---

## Sample Output

```
=================================================================
  litellm Supply Chain Attack Scanner
  Affected versions: 1.82.7, 1.82.8 (March 24, 2026)
=================================================================
  Repo scanned : /home/user/myproject
  Files scanned: 14

  [CRITICAL] requirements.txt:3
         litellm pinned to COMPROMISED version 1.82.8: `litellm==1.82.8`
         → Upgrade to litellm>=1.82.9 — remove or replace this line.

  [HIGH] pyproject.toml:12
         pyproject.toml version spec may include compromised versions: `litellm = ">=1.82.0,<1.82.9"`
         → Constrain litellm to >=1.82.9.

  [INFO] app/main.py:0
         File imports litellm — if a compromised version is installed, this file will load malicious code
         → Ensure litellm installed in this environment is >= 1.82.9.

=================================================================
  RESULT: This repository is VULNERABLE or COMPROMISED

  Immediate actions:
    1. Do NOT run this code until litellm is upgraded.
    2. Upgrade: pip install --upgrade 'litellm>=1.82.9'
    3. Update ALL lock files (poetry.lock, uv.lock, etc.).
    4. If the compromised version was ever INSTALLED and run:
       a. Rotate all secrets (AWS, GCP, Azure, SSH, API keys)
       b. Check ~/.config/sysmon/ for persistence backdoor
       c. Check kubectl kube-system for node-setup-* pods
       d. Check outbound DNS for models.litellm.cloud
=================================================================
```

---

## Indicators of Compromise (IoCs)

If you installed LiteLLM during the affected window, check for these immediately.

### 1. Malicious `.pth` file

```bash
# Linux / macOS
find $(python3 -c "import site; print(site.getsitepackages()[0])") -name "litellm_init.pth"

# Any Python environment
python3 -c "import site; print(site.getsitepackages())"

# Windows PowerShell
Get-ChildItem -Recurse -Filter "litellm_init.pth"
```

### 2. Installed version

```bash
pip show litellm
```

### 3. Persistence backdoor

```bash
ls -la ~/.config/sysmon/
ls -la ~/.config/systemd/user/ | grep sysmon
```

### 4. Network logs

Search for outbound POST requests to `models.litellm.cloud` in firewall, proxy, or DNS logs.

### 5. Kubernetes

```bash
kubectl get pods -n kube-system | grep node-setup
```

---

## Remediation

If any CRITICAL or HIGH finding is reported:

1. **Upgrade immediately**
   ```bash
   pip install --upgrade 'litellm>=1.82.9'
   ```

2. **Update lock files**
   ```bash
   poetry update litellm          # Poetry
   uv lock --upgrade-package litellm  # uv
   pipenv update litellm          # Pipenv
   ```

3. **If the compromised version was ever installed and executed**, treat the machine as compromised:
   - Rotate **all** secrets: AWS, GCP, Azure, OpenAI, Anthropic, SSH keys, database passwords
   - Remove `litellm_init.pth` from every virtual environment on that machine
   - Preserve forensic artifacts before wiping if your security team needs them
   - File an incident report with your cloud provider if credentials were leaked

---

## Who Was Affected

### Potentially affected ✗

- Ran `pip install litellm` or `pip upgrade litellm` on March 24, 2026 between 10:39 – 16:00 UTC
- Used an unpinned `litellm` dependency that resolved to `1.82.7` or `1.82.8`
- Built a Docker image during that window with an unpinned `pip install litellm`
- Used AI agent frameworks, MCP servers, or LLM orchestration tools that pull `litellm` as a transitive unpinned dependency

### Not affected ✓

- Using **LiteLLM Cloud**
- Running the official Docker image: `ghcr.io/berriai/litellm`
- On `litellm<=1.82.6` and did not upgrade during the affected window
- Installed LiteLLM from the **GitHub source repository** (not compromised)

---

## Defensive Takeaways

1. **Pin your dependencies.** A single `pip install litellm` was the entire attack surface. Use lockfiles. Verify hashes.
2. **`.pth` files in `site-packages` are high-value forensic artifacts.** A legitimate package has no reason to place an import-executing `.pth` file.
3. **Monitor network traffic during Python startup.** Calls that happen before application logic runs are easy to miss in standard logging.
4. **Incident response requires file inspection, not just version checking.** Knowing a bad version was installed is not enough — verify what files it left behind.
5. **Audit transitive dependencies.** The attack required no deliberate developer error — only an unpinned install.

---

## References

1. LiteLLM — [Security Update, March 24, 2026](https://docs.litellm.ai/blog/security-update-march-2026)
2. FutureSearch — [LiteLLM PyPI Supply Chain Attack](https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/)
3. Pluto Security — [Analyzing the Supply Chain Attack](https://blog.pluto.security/p/analyzing-the-supply-chain-attack)
4. Cycode — [LiteLLM Supply Chain Attack](https://cycode.com/blog/lite-llm-supply-chain-attack/)
5. Kaspersky — [Critical Supply Chain Attack (Trivy / LiteLLM)](https://www.kaspersky.com/blog/critical-supply-chain-attack-trivy-litellm-checkmarx-teampcp/55510/)
6. SISA InfoSec — [LiteLLM Supply Chain Compromise](https://www.sisainfosec.com/blogs/litellm-supply-chain-compromise-when-your-ai-dependency-becomes-an-attack-vector/)
7. GitHub Issue — [BerriAI/litellm #24512](https://github.com/BerriAI/litellm/issues/24512)
8. Python Docs — [site module](https://docs.python.org/3/library/site.html)

---

*Built by Bytes Encrypt as part of a safe local proof-of-concept lab documenting the LiteLLM March 2026 supply chain incident. No real credentials are read or transmitted by this scanner.*
