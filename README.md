# 🔐 Security Learning Path

My documented journey into **IT security** and **cloud security**, with notes, labs and my own scripts.

## 👤 About me

Technical Application Owner in a regulated banking environment (reporting, observability, workload automation).
Goal: specialize as an **IT security / cloud security consultant** with a focus on regulated industries.

## 🎯 Goals

| Certification | Topic | Status |
|---|---|---|
| CompTIA Security+ | Security fundamentals | ⏳ planned |
| eJPT | Hands-on penetration testing | ⏳ planned |
| Microsoft Azure (AZ-900 → SC-900) | Cloud & identity | ⏳ planned |
| OSCP | Advanced penetration testing | 🔭 long-term |

## 🧪 Lab environment

- **VirtualBox** for virtualization
- **Kali Linux** as the attacker system
- **Metasploitable2** as an intentionally vulnerable target
- Isolated host-only network, no testing against third-party systems

## 📂 Structure

```
security-learning-path/
├── notes/      # Study notes per topic (networking, cryptography, IAM, ...)
├── labs/       # Write-ups of exercises (e.g. Metasploitable2, TryHackMe)
├── scripts/    # My own tools, e.g. a PowerShell security check for Windows
└── cloud/      # Azure and cloud security exercises
```

## 🛠️ Projects

- [x] **[Windows Security Check (PowerShell)](scripts/windows-security-check/)**: checks updates, firewall, Defender, open ports and startup programs
- [ ] Lab write-up: first steps with Metasploitable2
- [ ] Notes: authentication vs. authorization, SSO & SAML

## ⚖️ Disclaimer

All exercises take place exclusively in my own lab environment or on legal training platforms.
This repository contains no internal information from any employer.
