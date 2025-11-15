# 🔎 Enhanced URL Enumeration & Subdomain Discovery Toolkit  
### High-Performance Recon Script for Bug Bounty Hunters

This repository contains an optimized Bash script designed for **high-speed URL & parameter discovery**, pulling data from multiple intelligence sources, and optionally probing discovered URLs for liveness & technologies.

It includes **parallelized enumeration**, **API integrations**, **subfinder -all**, **Wayback Machine harvesting**, **CommonCrawl**, **AlienVault**, **VirusTotal**, and **httpx-toolkit live probing**.

Built specifically for **bug bounty hunters**, **pentesters**, and **security researchers**.

---

## 🚀 Features

- 🔥 **Parallelized execution** (up to 5× speed boost)
- 🌐 **Multi-source URL collection**  
  - Subfinder (`-all`)  
  - AlienVault OTX  
  - VirusTotal (auto-rotating keys, anti-rate-limit logic)  
  - Wayback Machine (optimized filtering)  
  - CommonCrawl index  
- ⚙️ **Smart URL filtering** (only URLs containing parameters `?x=`)  
- 🧪 **Live URL probing** (optional using httpx-toolkit)
- 🖥️ **Thread customization**
- 🧼 Automatic deduplication + sorting
- 🗂️ Clean output to file
- ⚡ Fully automatic, no user interaction
- 🌈 Beautiful colored terminal UI

---

## 📦 Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/your-repo-name.git
cd your-repo-name
chmod +x enum.sh


sudo apt install jq curl -y
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest



Notes for Bug Bounty Hunters

This script only uses passive sources (safe).

No exploitation involved.

You are responsible for using it on assets you are authorized to test.

Perfect for:

Recon automation

Endpoint discovery

API hunting

Parameter fuzzing

XSS & SSRF enumeration

Wayback parameter mining


Usage

Basic usage:

./enum.sh -d example.com -o results.txt


With live probing:

./enum.sh -d example.com -o live.txt -p


Increase threads:

./enum.sh -d example.com -o result.txt -p -t 100
