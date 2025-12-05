<div align="center">

<pre>
  __          __          .__.__            
_/  |______  |  | __ ____ |__|  |__   ____  
\   __\__  \ |  |/ // __ \|  |  |  \ /    \ 
 |  |  / __ \|    <\  ___/|  |   Y  \   |  \
 |__| (____  /__|_ \\___  >__|___|  /___|  /
           \/     \/    \/        \/     \/ 
   Subdomain Takeover Scanner
</pre>  

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License: MIT">
  <img src="https://img.shields.io/badge/Async-Powered-purple?style=for-the-badge&logo=python" alt="Async Powered">
</p>

**A fast, accurate, and extensible subdomain takeover detector built by iihhn.**  
Fully supports HTTP fingerprints, DNS dangling checks (A, AAAA, CNAME),  
and **NS / MX takeover heuristics**, with optional aggressive probing mode.

</div>

---

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [How It Works](#how-it-works)
- [Installation](#installation)
- [Usage](#usage)
  - [Scan List Mode](#scan-list-mode)
  - [Single Host Verbose Mode](#single-host-verbose-mode)
  - [Output Example](#output-example)
- [Columns & Flags](#columns--flags)
- [Fingerprinting System](#fingerprinting-system)
- [Architecture](#architecture)
- [Performance Notes](#performance-notes)
- [Roadmap](#roadmap)
- [License](#license)

---

## Overview

`takeihn` is a fully-featured, robust, and extensible **subdomain takeover detection** tool written in Python.  
It combines DNS heuristics, provider fingerprinting, HTTP analysis, optional WHOIS validation, and multi-threaded scanning to identify possible takeover conditions with high accuracy.

It is designed for:

- penetration testers  
- bug bounty hunters  
- security researchers  
- automated pipeline integrations  

The tool **does not** perform actual exploitation — only detection, aligned with responsible and ethical security testing practices.

---

## Features

### ✓ DNS Dangling Detection
- A / AAAA dangling (0.0.0.0 or invalid / unassigned IP blocks)
- CNAME pointing to unclaimed domains
- NS misconfigurations  
- MX misconfigurations  

### ✓ HTTP Fingerprinting Engine
Identifies takeover-prone providers via:
- HTML body signatures  
- header patterns  
- redirect fingerprints  
- status-based heuristics

Aggressive mode deepens detection and helps reveal subtle fingerprints.

### ✓ NS / MX Takeover Heuristics
Includes optional WHOIS lookups for:
- name server root domain  
- MX provider root domain  

Detects patterns like:
- expired domain  
- unregistered domain  
- provider misconfiguration  

### ✓ High-Speed Engine
- Threaded concurrency (default: 16 threads)
- Tunable launch rate (`--rate`)
- Persistent HTTP session reuse

### ✓ Flexible Output
- Human readable  
- Machine-friendly one-line format  
- Optional output file (`--output`)
- Column toggles (`--show-type`, `--show-provider`, etc.)

### ✓ Cross-Platform Safe
- Avoids system dependencies whenever possible  
- Falls back to external `whois` only when available

---

## How It Works

At a high level:

1. **Extract hosts**  
   Regex-based extraction from input file, supporting messy text.

2. **DNS Resolution Pipeline**  
   - lookup A / AAAA / CNAME  
   - lookup NS / MX  
   - detect dangling patterns  

3. **HTTP Probing**  
   - HEAD + GET  
   - follow redirects  
   - capture headers + body snippet  

4. **Provider Fingerprint Matching**  
   - context-based signature matcher  
   - aggressive double-check via CNAME  

5. **NS/MX Takeover Heuristics**  
   - WHOIS on root domain  
   - detect "NOT FOUND", "AVAILABLE", "No match"  

6. **Final Classification**  
   Any host with confirmed provider fingerprint or dangerous CNAME is marked as **potential takeover**.

---

## Installation

### 1. Clone
```
git clone https://github.com/ihsanlearn/takeihn.git
cd takeihn
```

### 2. Install Python modules
```
pip install -r requirements.txt
```

### 3. (Optional) Install WHOIS binary for NS/MX root analysis
```
sudo apt install whois
```

---

## Usage

### Scan List Mode
```
python3 takeihn.py -l targets.txt --threads 32 --timeout 8 --aggressive
```

### Single Host Verbose Mode
```
python3 takeihn.py -d sub.example.com
```

### Write Output File
```
python3 takeihn.py -l list.txt -o results.txt --show-type --show-provider
```

---

## Output Example

### Terminal Output (List Mode)
```
🔥 api.dev.example.com [CNAME] [aws.amazon.com] [AWS S3] [404]
green.example.com [-] [-] [-] [200]
```

### Verbose Mode Snippet
```
CNAME: abandoned-service.example.io
A: <none>
NS: ns1.expired-domain.com
WHOIS: NOT FOUND
Provider: GitHub Pages
Evidence: "There isn't a GitHub Pages site here."
```

---

## Columns & Flags

| Flag | Description |
|------|-------------|
| `--show-type` | Show dangling type (A/AAAA/CNAME/NS/MX) |
| `--show-resolver` | Show DNS resolver value (CNAME target, NS, etc.) |
| `--show-provider` | Show detected provider fingerprint |
| `--show-status` | Show HTTP status code |
| `--aggressive` | Enable deeper heuristics and fallback matching |
| `--quiet` | Silence per-target logs; summary only |

---

## Fingerprinting System

The fingerprint engine uses three layers:

1. **STATIC fingerprints** — provider patterns  
2. **CONTEXT fingerprints** — combined header+body detection  
3. **CNAME domain heuristics** — for ambiguous takeovers  
4. **Aggressive fallback mode** — deeper secondary matching

Fingerprints are easy to extend and can be externalized into a JSON file (planned in Roadmap).

---

## Architecture

```
takeihn.py
│
├── DNS Layer
│   ├── resolve_a()
│   ├── resolve_aaaa()
│   ├── dns_cname()
│   ├── lookup_ns()
│   └── lookup_mx()
│
├── HTTP Layer
│   └── http_probe()
│
├── Fingerprint Layer
│   ├── match_provider_from_text_with_context()
│   └── disambiguate_provider()
│
├── NS/MX Heuristics
│   └── whois_root_domain()
│
├── List Scanner
│   └── check_host_for_list()
│
└── Verbose Inspector
    └── verbose_single_host()
```

---

## Performance Notes

- For large lists (10k+ hosts), use:
```
--threads 32  --rate 0.002
```

- For highly unstable networks, increase timeout:
```
--timeout 12
```

- For CI pipelines:
```
--quiet --output report.txt
```

---

## Roadmap

### Planned
- External fingerprint database (`fingerprints.json`)
- HTML report generator
- DNS caching layer
- Cloud provider takeover matrix
- Async version (uvloop + aiohttp)
- Full Windows compatibility (no subprocess requirements)

### Under Evaluation
- Built-in subdomain enumeration  
- Direct integration with `dnsx`, `httpx`, `subfinder` binaries  
- JSON/CSV output modes  

PRs and improvements are always welcome.

---
