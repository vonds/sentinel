# Sentinel — Automated Linux Security Hardening & Compliance Toolkit

**Sentinel** is a production-minded Linux server hardening and security automation toolkit designed to enforce baseline security policies, reduce attack surface, and generate actionable audit reports.

The goal of sentinel is not simply to “secure a system,” but to codify security best practices into a reusable, auditable, and extensible workflow. Rather than relying on manual configuration, tribal knowledge, or one-off shell commands, sentinel applies a consistent security baseline that can be safely deployed across environments and validated through automated reporting.

The name **Sentinel** reflects the philosophy behind the tool: a persistent guardian that enforces security posture, monitors system hygiene, and helps prevent configuration drift over time.

---

## Design Philosophy

Instead of abstracting away system details, sentinel operates directly on real configuration files, services, and security subsystems. This ensures that engineers using the tool are interacting with Linux as it exists in production, not a simulated or simplified environment. Sentinel is built around the idea that:

- Security should be codified 
- Hardening steps should be scriptable and reproducible  
- Changes should be auditable and reversible  
- Systems should be hardened consistently 

The project emphasizes clarity, safety, and operational realism. Every modification is backed up before being applied, validation steps are performed where possible, and detailed logging is generated for review and auditing.

---

## What sentinel Does

sentinel automates five core areas of Linux system hardening:

### 1) SSH Hardening
- Disables root login  
- Disables password authentication (key-based auth recommended)  
- Enforces safer SSH defaults  
- Supports port changes and IP-based access restrictions  
- Validates configuration before restarting SSH  

### 2) Firewall Configuration
- Configures UFW (Debian/Ubuntu) or firewalld (RHEL/Fedora)  
- Applies default deny policies  
- Restricts inbound SSH access  
- Falls back to iptables if higher-level firewalls are unavailable  

### 3) Sudo Hardening
- Enforces pseudo-terminal usage  
- Enables full sudo I/O logging  
- Sets secure execution paths  
- Reduces credential reuse windows  

### 4) Password Policy Enforcement
- Enforces strong password complexity requirements  
- Configures password aging policies  
- Applies hardened default umask values  

### 5) Security Auditing & Reporting
- Generates structured system audit reports  
- Summarizes SSH, firewall, sudo, and password configurations  
- Highlights risky filesystem permissions  
- Enumerates listening services and SUID binaries  
- Captures recent authentication failures  

Each hardening stage can be enabled or disabled independently, allowing sentinel to be used flexibly across development, staging, and production environments.

---

## How to Run sentinel

sentinel is designed to run directly on Linux systems using Bash and standard Unix utilities. It should be executed with root privileges.

Clone the repository
```git clone https://github.com/vonds/sentinel.git```
cd sentinel

Make the script executable
```chmod +x sentinel.sh```

Run sentinel
```sudo ./sentinel.sh```

Common Usage Patterns
Dry-run mode (recommended first step)

Preview all changes without modifying the system:

```sudo ./sentinel.sh --dry-run```

Change SSH port and restrict access
```sudo ./sentinel.sh --ssh-port 2222 --allow-ssh-from 203.0.113.10/32```

Skip specific hardening stages
```sudo ./sentinel.sh --no-firewall```
```sudo ./sentinel.sh --no-ssh```
```sudo ./sentinel.sh --no-sudo```
```sudo ./sentinel.sh --no-password-policy```
```sudo ./sentinel.sh --no-audit```

Logging and Audit Reports

sentinel generates two forms of output:

Execution logs
Stored in:

```/var/log/hardening-toolkit/```

Security audit reports

Timestamped reports containing a snapshot of the system’s security posture. These artifacts make sentinel suitable for environments that require auditability, compliance documentation, and security validation.

## What Makes sentinel Different

Sentinel combines the following:

- Automated enforcement
- Safe configuration backups
- Service validation
- Security posture auditing
- Enterprise-friendly logging

Rather than acting as a black box, sentinel is intentionally transparent. All changes are visible, traceable, and reversible. The codebase is designed to be readable and extensible, making it suitable for both direct operational use and as a learning reference for Linux security engineering.

## Roadmap & Future Work

Planned expansions include:

- CIS benchmark alignment
- NIST security control mapping
- Modular hardening profiles (dev / prod / regulated)
- SELinux policy enforcement
- Intrusion detection integration
- Centralized logging pipelines
- Ansible automation modules

## Collaboration and Contributions

sentinel is actively evolving and is built in the open. Contributions are welcome, including:

- Hardening improvements
- Compliance expansions
- Security auditing enhancements
- Code quality refinements
- Documentation improvements

