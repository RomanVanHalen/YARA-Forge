# 🛡️ YARA-Forge: Malware Signatures & Research

A curated repository of YARA rules developed through static and dynamic analysis of various malware families. This project aims to assist Blue Teams and SOC analysts in detecting artifacts, persistence mechanisms, and malicious capabilities.

---

## 📂 Repository Structure

| Directory | Description |
| :--- | :--- |
| **`/rules/malware_families`** | Family-specific rules (e.g., Emotet, AgentTesla, RedLine). |
| **`/rules/capabilities`** | Generic rules for behaviors (Anti-VM, Packed binaries, Crypto). |
| **`/rules/apt`** | Signatures linked to known Advanced Persistent Threat groups. |
| **`/tools`** | Helper scripts for rule validation and false-positive testing. |

---

## 🚀 Getting Started

### Prerequisites
Ensure you have YARA installed on your system:
- **Linux:** `sudo apt-get install yara`
- **Windows:** Download the latest binary from the [YARA releases page](https://github.com/VirusTotal/yara/releases).

### Usage
To scan a suspicious file or directory using these rules:
```bash
yara -r rules/malware_families/specific_rule.yar /path/to/suspicious_files
