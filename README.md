<img width="1157" height="251" alt="Screenshot 2026-09-19 164623" src="https://github.com/user-attachments/assets/45de1962-3eeb-4a8b-89c4-d6bd4601a392" />



# Recon Framework v2

A fast and automated reconnaissance tool for authorized security testing.

Give it a domain, and it automatically performs subdomain discovery, HTTP probing, URL collection, crawling, JavaScript analysis, and security scanning.

> ⚠️ **Use only on targets you are authorized to test**, such as your own systems or programs where you have permission.

---

## 🚀 Quick Start

### 1. Clone the project

```
git clone https://github.com/anujsec/GHOST-EYE.git
cd GHOST-EYE
cd GHOST-EYE-recon
python recon.py example.com
```

### 2. Install Python dependencies

```
pip install -r requirements.txt
```

### 3. Install the required recon tools

The framework uses several popular security tools:

```
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
```

Make sure Go tools are available:

```
export PATH="$PATH:$(go env GOPATH)/bin"
```

Check:

```
subfinder -version
httpx -version
nuclei -version
```

---

## ▶️ Run the Tool

### Basic scan

```
python3 recon.py example.com
```

That's it.

The tool will automatically create a folder containing the results.

### Interactive mode

You can also run:

```
python3 recon.py
```

It will ask you for the target.

---

## ⚡ Scan Modes

### Fast mode

Recommended for normal use:

```
python3 recon.py example.com
```

### Deep mode

Runs additional and more expensive reconnaissance:

```
python3 recon.py example.com --deep
```

### DNS brute force

```
python3 recon.py example.com --bruteforce
```

### Take screenshots

```
python3 recon.py example.com --screenshots
```

### Disable Nuclei

```
python3 recon.py example.com --no-nuclei
```

You can combine options:

```
python3 recon.py example.com --deep --screenshots
```

---

## 📂 Where Are the Results?

Results are saved automatically inside:

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

Screenshots are saved inside:

```
screenshots/
```

when `--screenshots` is enabled.

---

## 🔄 What's Special About v2?

The tool is designed to avoid doing unnecessary work every time you run it.

### ⚡ Faster

Multiple reconnaissance tasks can run at the same time.

### 🔎 Prioritized targets

Interesting hosts such as:

```
api.example.com
admin.example.com
staging.example.com
```

can receive higher priority.

### 🧠 Remembers previous scans

The tool stores scan history in SQLite and can identify new or changed assets between runs.

### 📊 Organized results

Each scan gets its own timestamped folder.

### 🛠️ Missing tools don't necessarily break the scan

If an optional tool isn't installed, the framework can skip it and continue with the available tools.

---

## 🔐 API Keys

Basic reconnaissance works without API keys.

Some services can provide additional passive results when their API keys are configured.

These are optional.

---

## 🧪 Run Tests

To test the framework:

```
python3 -m unittest discover -s tests -v
```

---

## 📋 Requirements

- Linux / Kali Linux
- Python 3
- Go
- Git
- Internet connection
- Recon tools listed above

Kali Linux is recommended because many security tools are easier to install there.

---

## ⚠️ Responsible Use

This project is intended for:

- Bug bounty programs where testing is allowed
- Your own infrastructure
- Security labs
- Systems where you have written authorization

Do not scan systems without permission.

Always follow the target's scope and rate limits.

---

## ⭐ Future Improvements

Planned improvements may include:

- Better result visualization
- More reconnaissance sources
- Improved change detection
- More integrations
- Better reporting

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.