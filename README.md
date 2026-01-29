# ReconCombo Go

A powerful reconnaissance tool written in Go that automates the process of gathering information about target domains. It combines multiple tools to provide comprehensive reconnaissance data.

![Made by nickyqqq](https://img.shields.io/badge/Made%20by-nickyqqq-blue)

## Features

- **Subdomain Enumeration** - Find all subdomains using subfinder
- **URL Collection** - Gather URLs from multiple sources (gau, katana, ffuf)
- **Directory Discovery** - Scan for directories and endpoints using feroxbuster
- **GF Pattern Extraction** - Extract vulnerable patterns (XSS, SQLi, SSRF, etc.)
- **JavaScript Analysis** - Identify and filter JavaScript files
- **Resume Functionality** - Resume interrupted scans from where they left off
- **Concurrent Processing** - Process multiple domains concurrently

## Prerequisites

Before running ReconCombo, ensure the following tools are installed:

- `subfinder` - https://github.com/projectdiscovery/subfinder
- `httpx-toolkit` - https://github.com/projectdiscovery/httpx
- `gau` - https://github.com/lc/gau
- `ffuf` - https://github.com/ffuf/ffuf
- `nuclei` - https://github.com/projectdiscovery/nuclei
- `anew` - https://github.com/tomnomnom/anew
- `katana` - https://github.com/projectdiscovery/katana
- `uro` - https://github.com/s0md3v/uro
- `feroxbuster` - https://github.com/epi052/feroxbuster
- `dirsearch` - https://github.com/maurosoria/dirsearch
- `gf` - https://github.com/tomnomnom/gf

## Installation

```bash
go install github.com/nickyqqq/reconcomboGo@latest
```

This will automatically download, build, and install the `reconcombo` binary to your `$GOPATH/bin` directory (usually `~/go/bin`).

Make sure `$GOPATH/bin` is in your `$PATH`:
```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

## Usage

### Scan a Single Domain

```bash
reconcombo --url target.com
```

### Scan Multiple Domains from a File

```bash
reconcombo -l domains.txt
```

## Output

All results are saved in the `reconcombo/` directory organized by domain:

## Resume Functionality

If you interrupt a scan using `Ctrl+C`, ReconCombo will save your progress. Simply run the same command again to resume from where it left off:

```bash
# Press Ctrl+C during scan
# Progress is automatically saved to .resume.json

# Resume the scan
reconcombo --url target.com
```

## Building for Different Platforms

```bash
# Build for all platforms
make release

# Build for specific platform
GOOS=linux GOARCH=amd64 go build -o reconcombo-linux .
GOOS=darwin GOARCH=amd64 go build -o reconcombo-darwin .
GOOS=windows GOARCH=amd64 go build -o reconcombo-windows.exe .
```

## Make Commands

```bash
make help      # Show all available commands
make build     # Build the binary
make install   # Build and install to ~/.local/bin
make clean     # Remove all built binaries
make release   # Build for all platforms
```

## Example Workflow

```bash
# 1. Build and install
make install

# 2. Scan a single domain
reconcombo --url example.com

# 3. Check results
ls -la reconcombo/example.com/

# 4. Scan multiple domains
reconcombo -l targets.txt
```

## Tips & Tricks

- Use `anew` to add only new URLs to existing results
- Combine results with `sort -u` for deduplication
- Export GF patterns for use in other tools
- JavaScript files can be analyzed with tools like `secretsdump` or `semgrep`

## Troubleshooting

### "Tool not found" error
Make sure all required tools are installed and in your PATH:
```bash
which subfinder
which httpx-toolkit
# etc...
```

### Permission Denied
If you get permission denied when running, make the binary executable:
```bash
chmod +x reconcombo
```

### Scan is slow
The tool respects rate limits of external services. You can:
- Reduce the number of concurrent scans (modify `Makefile` semaphore value)
- Run during off-peak hours
- Use smaller wordlists

## License

This project is open source and available under the MIT License.

## Author

Made by **nickyqqq**

## Contributing

Contributions are welcome! Feel free to submit issues and pull requests.

---

**Happy Hacking!**
