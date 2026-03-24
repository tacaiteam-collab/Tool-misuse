# Tool Misuse

A specialized security scanner designed to detect **Tool Misuse** vulnerabilities in LLM-integrated applications. It automates adversarial testing against APIs to identify risks such as unauthorized tool chaining, parameter manipulation, and privilege escalation via AI agents.

##  Features

- **Tool Misuse Detection:** Specifically targets vulnerabilities where LLM tools are exploited (e.g., Database, File System, Auth).
- **Multi-Vector Attacks:** Tests for Prompt Injection, SQL Injection, IDOR, Path Traversal, and Tool Chaining.
- **Safe by Default:** Runs in **Dry Run Mode** unless explicitly authorized for live scanning.
- **Plugin Architecture:** Extensible attack plugins (e.g., `parameter_manipulation`, `tool_chaining`).
- **Comprehensive Reporting:** Generates reports in JSON, HTML, SARIF, and Console formats.
- **Rate Limiting & Timeout:** Configurable controls to prevent overwhelming target systems.

---

##  Getting Started

### Prerequisites
- Python 3.8+

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/your-org/tool-misuse.git
   cd tool-misuse
   ```
---

##  Usage

### Basic Scan (Dry Run)
By default, the tool runs in safe mode. It simulates attacks without sending harmful payloads to production systems.

```bash
python -m scripts.run_scan --url http://localhost:8000/api
```

### Live Scan (Requires Authorization)
 **Warning:** Only use live mode on systems you own or have explicit permission to test.

```bash
python -m scripts.run_scan \
  --url https://staging.example.com/api \
  --live \
  --api-key $API_KEY
```

### Customizing Attacks & Reports
You can select specific attack types (e.g., parameter manipulation) and output formats.

```bash
python -m scripts.run_scan \
  --url https://app.example.com/api \
  --live \
  --attacks prompt_injection,parameter_manipulation \
  --reports json,html \
  --output-dir ./scan-results
```

### CLI Arguments Overview

| Argument | Short | Description |
| :--- | :--- | :--- |
| `--url` | `-u` | **Required.** Target API endpoint URL. |
| `--live` | `-l` | Enable live mode (sends real requests). |
| `--api-key` | `-k` | API key for authentication. |
| `--attacks` | `-a` | Comma-separated list of attack types to run. |
| `--reports` | `-r` | Comma-separated list of report formats (json, html, sarif). |
| `--timeout` | `-t` | Request timeout in seconds (5-300). |
| `--rate-limit` | `-rl` | Max requests per minute (1-600). |
| `--verbose` | `-v` | Enable detailed logging. |

---

##  Configuration

### Attack Payloads
Attack definitions are stored in [`attacks.yaml`](attacks.yaml). You can customize prompts, parameters, and risk levels here.

**Example (`attacks.yaml`):**
```yaml
parameter_manipulation:
  sql_injection:
    - id: "PARAM-SQL-01"
      tool: "database"
      args:
        sql: "SELECT * FROM users WHERE id = $1"
        params: ["1 OR 1=1"]
      risk: "HIGH"
  tool_chaining:
    exfiltration_chain:
      - id: "CHAIN-EXFIL-01"
        sequence:
          - tool: "read_database"
          - tool: "send_webhook"
        risk: "CRITICAL"
```

### Safety Settings
The tool includes a `SafetyLock` mechanism (`config/safety.py`).
- **Dry Run:** Enabled by default.
- **Scope Validation:** Ensures scans only run against allowed domains.
- **Authorization:** Requires user confirmation for live scans.

---

##  Architecture

1.  **CLI (`run_scan.py`):** Parses arguments and initializes the scan session.
2.  **Scanner (`scanner.py`):** Orchestrates the workflow (Validate → Discover → Attack → Report).
3.  **Plugins (`attacks/`):** Modular attack logic inheriting from `AttackPlugin` (e.g., `parameter_manipulation.py`).
4.  **Executors:** Handle the actual HTTP/Tool requests based on target capabilities.

---

## Security Disclaimer

This tool is intended for **authorized security testing only**.
- Do not use against third-party services without permission.
- The authors are not responsible for misuse or damages caused by this software.
- Always start with `--url http://localhost` to verify behavior before live scanning.
