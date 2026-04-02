# SNI Reconnaissance Tool

Find valid SNIs for V2Ray/Xray by testing both TLS and site reachability.

## What It Does

Tests domains on port 443 (HTTPS/TLS) AND verifies they're not blocked by your firewall.

### Results:
- **Valid SNI** - TLS works AND site is reachable - USE this!
- **Blocked** - Site is blocked by firewall - DON'T use

## How It Works

Two-step testing process:
1. **TLS Handshake**: Tests if SNI works on port 443
2. **Reachability Check**: Verifies site isn't blocked by your firewall/filter

Only domains that pass BOTH tests are marked as "Valid SNI".

## Installation

```bash
pip install -r requirements.txt
python main.py
```

## Usage

1. Click "New Scan"
2. Choose scan type (DNS Cache, Common Sites, or Custom)
3. Wait for scan to complete
4. Use domains marked as **Valid SNI** in V2Ray/Xray
5. Export results if needed


Only use domains marked as **Valid SNI** in your config!

## Features

- Dual testing (TLS + Reachability)
- Firewall-aware detection
- DNS Cache scan (Windows)
- Common sites scan
- Custom domain scan
- Export results (CSV/JSON/TXT)
- Subdomain grouping
- Result history

## Keyboard Shortcuts

- Ctrl+N - New Scan
- Ctrl+H - History  
- Ctrl+S - Save
- Esc - Dashboard

## Why Two Tests?

Some sites pass TLS handshake but are blocked by your firewall. Using them as SNI won't work. This tool ensures the domain is:
1. Valid for TLS/SNI 
2. Actually reachable 
