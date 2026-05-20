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
- 🖥️ Remote Desktop Services / RDS
- 🔑 Local RDP listener certificate handling
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

# ⭐ Why Maverick

| Principle | Meaning |
|---|---|
| 🔎 Transparent | Fully readable automation |
| 🛡️ Safe | Designed with production safeguards |
| 🧑‍💻 Admin-friendly | Built for real infrastructure admins |
| ⚙️ Practical | Focused on real repetitive workloads |
| 🚫 No hidden behavior | No obfuscation or forced telemetry |

---

# ✅ Current Features

## 🔐 Certificate Management Automation

The current toolkit can safely automate certificate replacement for:

| Platform | Supported |
|---|---:|
| IIS | ✅ |
| Exchange | ✅ |
| ADFS | ✅ |
| WAP / Web Application Proxy | ✅ |
| RDS deployment certificates | ✅ |
| Local RDP-Tcp listener certificate | ✅ |

## 🎨 Certificate Health Menu

The toolkit now shows a quick role health dashboard during role selection.

The menu can show the shortest certificate lifetime detected for each available role:

```text
==== Select Role ====
1. IIS [194 days left]
2. ADFS [Unavailable - Role not installed]
3. WAP / Web Application Proxy [Unavailable - Role not installed]
4. Exchange [Unavailable - run from Exchange Management Shell]
5. Remote Desktop Services [194 days left]
```

Color meaning:

| Color | Meaning |
|---|---|
| 🟢 Green | 30+ days remaining |
| 🟡 Yellow | Less than 30 days remaining |
| 🔴 Red | Less than 7 days remaining |

When a role has multiple assigned certificates, Maverick shows the **shortest remaining lifetime** so the menu reflects the most urgent certificate risk.

---

# 🆓 Free Wildcard Certificate Generation

Maverick also includes a standalone PowerShell-based wildcard certificate generator using:

- Let's Encrypt
- ACME protocol
- Manual DNS-01 challenge validation
- No opaque executables

Generated Let's Encrypt certificates are valid for approximately **90 days / 3 months**.

## Supported Features

| Feature | Supported |
|---|---:|
| Wildcard certificates (`*.domain.com`) | ✅ |
| Manual DNS TXT validation | ✅ |
| PFX export generation | ✅ |
| Custom PFX password | ✅ |
| Transparent PowerShell workflow | ✅ |
| DNS API automatic renewals | 🚧 Planned |

## Example Workflow

1. Run the wildcard generation script
2. Enter the root domain
3. Add the displayed DNS TXT records
4. Confirm once DNS records are created
5. Script validates ownership with Let's Encrypt
6. Generated PFX is copied beside the script
7. Use the PFX with the main Maverick Certificate Toolkit

## Notes

- Wildcard certificates require DNS validation and cannot use regular HTTP validation.
- Manual DNS validation is ideal for environments behind WAFs, F5, reverse proxies, or blocked port 80 access.
- Future versions may support automatic DNS provider integrations for unattended renewals.

---

# 🧠 Safety-Oriented Design

Maverick was built with operational safety in mind.

Features include:

- ✅ Readable PowerShell code
- ✅ Detection before modification
- ✅ Confirmation before apply
- ✅ Existing certificate visibility
- ✅ Certificate thumbprint and expiry verification
- ✅ Colored certificate expiry health indicators
- ✅ SAN coverage validation where appropriate
- ✅ Safe IIS binding handling
- ✅ Protection against modifying Exchange Backend port `444`
- ✅ Reuse of already imported certificates
- ✅ Administrator privilege awareness
- ✅ Role detection and availability checks
- ✅ Old certificates are not removed automatically

---

# 🧩 Current Capabilities

## 🌐 IIS

- Detect HTTPS bindings
- Show certificate expiry beside detected bindings
- Show menu health based on the shortest IIS certificate lifetime
- Replace certificates on port `443` only
- Skip Exchange Backend `444` automatically
- Validate hostname coverage before apply
- Run `iisreset` after assignment
- Preserve old certificates

## 📧 Exchange

- Detect currently assigned public certificates
- Show certificate expiry and assigned services
- Show menu health based on the shortest assigned Exchange certificate lifetime
- Validate SAN coverage against the certificate being replaced
- Import and assign certificates to the same services
- Preserve previous certificates

> Exchange operations should be run from the **Exchange Management Shell**.

## 🔐 ADFS

- Detect ADFS SSL certificate binding
- Detect ADFS Service-Communications certificate
- Show certificate expiry status
- Replace Service-Communications certificate
- Replace SSL certificate binding
- Restart ADFS service safely
- Preserve old certificates

## 🛡️ Web Application Proxy / WAP

- Detect current WAP SSL certificate
- Show certificate expiry status
- Replace WAP SSL certificate
- Reinitialize WAP trust
- Update local IIS `443` bindings where applicable
- Restart WAP service safely
- Preserve old certificates

## 🖥️ Remote Desktop Services / RDS

- Detect RDS deployment certificates using `Get-RDCertificate`
- Support RD Connection Broker detection and local server fallback
- Show RDS certificate expiry status
- Show menu health based on the shortest RDS certificate lifetime
- Update only existing assigned RDS certificate roles
- Avoid applying certificates to non-existing roles such as RD Gateway when not present
- Preserve old certificates

Supported RDS deployment roles can include:

- RDWebAccess
- RDRedirector
- RDPublishing
- RDGateway, when present

## 🔑 Local RDP-Tcp Listener

- Detect existing local RDP listener certificate
- Show current listener thumbprint and expiry
- Replace the RDP listener certificate only when an existing assigned listener certificate is detected
- Skip listener replacement when no custom listener certificate exists
- Preserve old certificates

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
- ♻️ Automated certificate renewal workflows
- ☁️ DNS provider API integrations for automatic DNS-01 validation
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
- 🔁 Optional certificate cleanup assistant

---

# 💼 Enterprise Automation

Maverick Infrastructure Automation is not limited to certificate management.

The goal is broader operational automation for Microsoft infrastructure environments.

We can help automate repetitive manual infrastructure workloads while keeping processes transparent, maintainable, and administrator-friendly.

Examples include:

- Reducing repetitive administrative tasks
- Standardizing operational procedures
- Minimizing human error
- Automating infrastructure maintenance
- Simplifying complex operational workflows
- Microsoft 365 administration
- Certificate lifecycle management
- Hybrid identity tasks
- Reporting and auditing
- Scheduled maintenance workflows
- PowerShell operational tooling

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

# ☕ Support The Project

If Maverick Infrastructure Automation helps simplify your operational workload or saves you time during deployments and maintenance, consider supporting the project.

Your support helps improve:

- New automation features
- Enterprise integrations
- Future tooling and maintenance

### ❤️ Support Maverick Infrastructure Automation

[![Support via PayPal](https://img.shields.io/badge/Support-PayPal-00457C?logo=paypal&logoColor=white)](https://www.paypal.com/donate/?hosted_button_id=HV9H8JQ6XHGZY)

---

# 📄 License

This project is provided as-is for educational and operational use.
