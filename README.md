<img width="1157" height="251" alt="Screenshot 2026-09-19 164623" src="https://github.com/user-attachments/assets/45de1962-3eeb-4a8b-89c4-d6bd4601a392" />


# Recon Framework v2

A fast, automated reconnaissance tool for authorized security testing.

Give it a domain, and it automatically performs subdomain discovery, HTTP probing, URL collection, crawling, JavaScript analysis, and security scanning.

> ⚠️ **Use only on targets you are authorized to test** — your own systems, or programs where you have explicit permission.

---

## Table of Contents

- [Requirements](#-requirements)
- [Installation](#-installation)
- [Usage](#️-usage)
- [Scan Modes](#-scan-modes)
- [Output](#-output)
- [What's New in v2](#-whats-new-in-v2)
- [API Keys](#-api-keys)
- [Testing](#-testing)
- [Responsible Use](#️-responsible-use)
- [Roadmap](#-roadmap)
- [License](#-license)

---

## 📋 Requirements

- Linux / Kali Linux (Kali recommended — most tools install easily there)
- Python 3
- Go
- Git
- Internet connection

---

## 📦 Installation

### 1. Clone the repository

```bash
git clone https://github.com/anujsec/GHOST-EYE.git
cd GHOST-EYE/GHOST-EYE-recon
```

### 2. Create a virtual environment (recommended)

```bash
python3 -m venv venv
source venv/bin/activate        # Linux / Mac
venv\Scripts\activate           # Windows
```

### 3. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 4. Install the required recon tools

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
```

Make sure Go tools are on your `PATH`:

```bash
export PATH="$PATH:$(go env GOPATH)/bin"
```

Verify the install:

```bash
subfinder -version
httpx -version
nuclei -version
```

---

## ▶️ Usage

### Basic scan

```bash
python3 recon.py example.com
```

That's it — results are saved automatically.

### Interactive mode

Run without arguments and you'll be prompted for a target:

```bash
python3 recon.py
```

---

## ⚡ Scan Modes

| Mode | Command | Description |
|---|---|---|
| Fast (default) | `python3 recon.py example.com` | Recommended for normal use |
| Deep | `python3 recon.py example.com --deep` | Runs additional, more expensive recon |
| DNS brute force | `python3 recon.py example.com --bruteforce` | Adds brute-force subdomain discovery |
| Screenshots | `python3 recon.py example.com --screenshots` | Captures screenshots of live hosts |
| No Nuclei | `python3 recon.py example.com --no-nuclei` | Skips vulnerability scanning |

Flags can be combined:

```bash
python3 recon.py example.com --deep --screenshots
```

---

## 📂 Output

Results are saved under `runs/`, organized by target and timestamp:

```
runs/
└── Example/
    └── 20260917T090623/
        ├── summary.json
        ├── subdomains.txt
        ├── dns.jsonl
        ├── httpx.jsonl
        ├── urls.txt
        ├── js_endpoints.txt
        └── nuclei.jsonl
```

If `--screenshots` is enabled, images are saved to `screenshots/`.

---

## 🔄 What's New in v2

- **Faster** — multiple reconnaissance tasks run concurrently
- **Prioritized targets** — interesting hosts (e.g. `api.`, `admin.`, `staging.` subdomains) are flagged for higher priority
- **Scan memory** — scan history is stored in SQLite so the tool can identify new or changed assets between runs
- **Organized results** — each scan gets its own timestamped folder
- **Graceful degradation** — if an optional tool isn't installed, the framework skips it and continues with what's available

---

## 🔐 API Keys

Basic reconnaissance works without any API keys. Configuring API keys for supported services is optional and unlocks additional passive results.

---

## 🧪 Testing

```bash
python3 -m unittest discover -s tests -v
```

---

## ⚠️ Responsible Use

This project is intended for:

- Bug bounty programs where testing is permitted
- Your own infrastructure
- Security labs
- Systems where you have written authorization

**Do not scan systems without permission.** Always follow the target's scope and rate limits.

---

## ⭐ Roadmap

- Better result visualization
- More reconnaissance sources
- Improved change detection
- More integrations
- Better reporting

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.
