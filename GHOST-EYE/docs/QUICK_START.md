# Ghost-Eye v2.1 Quick Start

## Installation (30 seconds)

```bash
cd /data/ghost-eye
pip install -r requirements.txt

# Required tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

## Check Tool Status

```bash
python3 << 'EOF'
from tool_check import print_tool_status
print_tool_status()
