# 🛡️ Maverick Infrastructure Automation

<p align="center">
  <b>Safe and transparent automation for repetitive Microsoft infrastructure operations.</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/PowerShell-Readable-blue?logo=powershell" />
  <img src="https://img.shields.io/badge/Focus-Microsoft%20Infrastructure-0078D4?logo=microsoft" />
  <img src="https://img.shields.io/badge/Status-Active-success" />
  <img src="https://img.shields.io/badge/License-MIT-green" />
</p>

---

# 🚀 Overview

**Maverick Infrastructure Automation** is a PowerShell-based toolkit designed to reduce repetitive manual tasks in Microsoft infrastructure environments while keeping all logic fully readable, administrator-friendly, and operationally safe.

It is built for environments where transparency and control matter:

- 📧 Microsoft Exchange
- 🌐 IIS
- 🔐 ADFS
- 🛡️ Web Application Proxy / WAP
- ☁️ Hybrid Microsoft environments

Unlike opaque executables or obfuscated scripts, Maverick keeps automation visible so administrators can review exactly what is being executed on production systems.

---

# ⚡ Quick Start

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\Maverick-Certificate-Toolkit.ps1
```

Place your `.pfx` or `.p12` certificate file in the same folder as the script before running.
Run the script directly on the server where the certificate is being renewed or replaced.

---

# ✅ Current Features

## 🔐 Certificate Management Automation

The current toolkit can safely automate certificate replacement for:

| Platform | Supported |
|---|---|
| IIS | ✅ |
| Exchange | ✅ |
| ADFS | ✅ |
| WAP | ✅ |

---

# 🧠 Safety-Oriented Design

Maverick was built with operational safety in mind.

Features include:

- ✅ Readable PowerShell code
- ✅ Detection before modification
- ✅ Confirmation before apply
- ✅ Existing certificate visibility
- ✅ Thumbprint and expiry verification
- ✅ SAN coverage validation
- ✅ Safe IIS binding handling
- ✅ Protection against modifying Exchange Backend port `444`
- ✅ Reuse of existing imported certificates
- ✅ Administrator privilege awareness
- ✅ Role detection and availability checks

---

# 🧩 Current Capabilities

## 🌐 IIS

- Detect HTTPS bindings
- Replace certificates on port `443` only
- Skip Exchange Backend `444` automatically
- Validate hostname coverage before apply
- Preserve old certificates

## 📧 Exchange

- Detect currently assigned public certificates
- Validate SAN coverage
- Safely import and assign certificates
- Preserve previous certificates

## 🔐 ADFS

- Replace Service-Communications certificate
- Replace SSL certificate binding
- Restart ADFS services safely

## 🛡️ Web Application Proxy / WAP

- Replace WAP SSL certificate
- Reinitialize trust
- Update IIS bindings where applicable
- Restart WAP services safely

---

# 🔍 Philosophy

This project intentionally avoids:

- ❌ Hidden binaries
- ❌ Obfuscated scripts
- ❌ Forced telemetry
- ❌ Opaque installers
- ❌ Credential collection websites

Infrastructure administrators should always be able to review and understand automation executed on production systems.

---

# 🛣️ Future Roadmap

Planned future features:

- 🔄 Script version checking
- ⬇️ Optional automatic update downloads
- 🆓 Automatic free certificate generation
- 🔐 ACME / Let's Encrypt support
- ♻️ Automated renewal workflows
- 📅 Certificate expiration monitoring
- 📊 HTML reporting
- 🖥️ Multi-server orchestration
- 📦 Centralized inventory reporting
- 🌍 Public endpoint certificate validation
- ⚖️ F5 / load balancer mismatch detection
- ⏱️ Scheduled automation tasks
- 📧 Email alerting
- 🧪 TLS validation and reporting
- 🩺 Infrastructure health checks

---

# 🛠️ Automation Services

Maverick Infrastructure Automation is not limited to certificate management.

The goal is broader operational automation for Microsoft infrastructure environments.

Examples include:

- Reducing repetitive administrative tasks
- Standardizing operational procedures
- Minimizing human error
- Automating infrastructure maintenance
- Simplifying complex operational workflows

---

# 💼 Enterprise Automation

We can help automate repetitive manual infrastructure workloads while keeping processes transparent, maintainable, and administrator-friendly.

Potential automation areas include:

- Exchange operations
- IIS management
- Microsoft 365 administration
- Certificate lifecycle management
- Hybrid identity tasks
- Reporting and auditing
- Scheduled maintenance workflows
- PowerShell operational tooling

---

# ⭐ Why Maverick

| Principle | Meaning |
|---|---|
| 🔎 Transparent | Fully readable automation |
| 🛡️ Safe | Designed with production safeguards |
| 🧑‍💻 Admin-friendly | Built for real infrastructure admins |
| ⚙️ Practical | Focused on real repetitive workloads |
| 🚫 No hidden behavior | No obfuscation or forced telemetry |

---

# ⚠️ Disclaimer

Always validate scripts in a non-production environment before applying changes to production systems.

The authors are not responsible for service interruption, data loss, or configuration issues caused by improper use.

---

# 🤝 Contributions

Suggestions, improvements, and feedback are welcome.

---

# 👤 Author

**Maverick Infrastructure Automation**  
Created and maintained by **Ralph**

---

# 📄 License

This project is provided as-is for educational and operational use.

### [Buy me a Coffee?](https://www.paypal.com/donate/?hosted_button_id=HV9H8JQ6XHGZY)

