# Sentinel: Automated Linux Security Hardening & Compliance Toolkit

**Sentinel** is a production-minded Linux server hardening and security automation toolkit designed to enforce baseline security policies, reduce attack surface, and generate actionable audit reports.

The goal of Sentinel is not simply to “secure a system,” but to codify security best practices into a reusable, auditable, and extensible workflow. Rather than relying on manual configuration, or one-off shell commands, Sentinel applies a consistent security baseline that can be safely deployed across environments and validated through automated reporting.

The name **Sentinel** reflects the philosophy behind the tool: a persistent guardian that enforces security posture, monitors system hygiene, and helps prevent configuration drift over time.


## Design Philosophy

Instead of abstracting away system details, Sentinel operates directly on real configuration files, services, and security subsystems. This ensures that engineers using the tool are interacting with Linux as it exists in production, not a simulated or simplified environment. Sentinel is built around the idea that:

- Security should be codified 
- Hardening steps should be scriptable and reproducible  
- Changes should be auditable and reversible  
- Systems should be hardened consistently 

The project emphasizes clarity, safety, and operational realism. Every modification is backed up before being applied, validation steps are performed where possible, and detailed logging is generated for review and auditing.


## What Sentinel Does

Sentinel automates five core areas of Linux system hardening:

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
- Falls back to temporary nftables or iptables emergency rules with explicit warnings 

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

Each hardening stage can be enabled or disabled independently, allowing Sentinel to be used flexibly across development, staging, and production environments.


### Read This First

Sentinel makes real, persistent changes to system security configuration and should be used with care. Always start with ```--dry-run``` to review what will change before applying it. Be especially cautious when running Sentinel over SSH, as it can modify SSH authentication, ports, and firewall rules in ways that may lock you out if misused. Test Sentinel on a non-production system first, and verify access before making irreversible changes. Behavior can vary across Linux distributions, particularly for PAM, SSH, and firewall tooling, so review warnings carefully. Emergency firewall modes are intentionally temporary and must be replaced with proper firewall configuration afterward. Sentinel favors safety over convenience, uses conservative defaults, and may require explicit confirmation for risky actions. It is designed to establish and audit a security baseline, not to replace configuration management systems or human judgment.

## How to Run Sentinel

Sentinel is designed to run directly on Linux systems using Bash and standard Unix utilities. It should be executed with root privileges.

Clone the repository
```git clone https://github.com/vonds/sentinel.git```
cd Sentinel

Make the script executable
```chmod +x sentinel.sh```

Run Sentinel
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

Sentinel generates two forms of output:

Execution logs
Stored in:

```/var/log/hardening-toolkit/```

Security audit reports

Timestamped reports containing a snapshot of the system’s security posture. These artifacts make Sentinel suitable for environments that require auditability, compliance documentation, and security validation.

## What Makes Sentinel Different

Sentinel combines the following:

- Automated enforcement
- Safe configuration backups
- Service validation
- Security posture auditing
- Enterprise-friendly logging

Rather than acting as a black box, Sentinel is intentionally transparent. All changes are visible, traceable, and reversible. The codebase is designed to be readable and extensible, making it suitable for both direct operational use and as a learning reference for Linux security engineering.

## Roadmap & Future Work

Planned expansions include:

- CIS benchmark alignment
- NIST security control mapping
- Modular hardening profiles (dev / prod / regulated)
- SELinux policy enforcement
- Intrusion detection integration
- Centralized logging pipelines
- Ansible automation modules

## What Still Needs Work

This project is usable today, but it is intentionally conservative and still evolving. Below are the most important remaining work items, grouped by priority.

### Safety, Rollback, and Operational Guarantees
- **Add a clear rollback mode** (example: `--rollback` or `--restore-backups`) to revert:
  - SSH drop-in / managed block
  - sudoers drop-in
  - pwquality.conf managed block
  - umask profile.d file
  - firewall rules created by this tool (when feasible)
- **Stronger preflight checks** before risky actions:
  - Verify current SSH access method (key-based) more explicitly before disabling passwords
  - Validate that the chosen SSH port is open and listening before finalizing removal of port 22
- **Make changes more atomic** where possible (write temp → validate → swap) to reduce partial-config states after failure.

### SSH Hardening Improvements
- **Broaden distro support for sshd config**:
  - Confirm drop-in directory behavior across major distros (Debian/Ubuntu, RHEL, SUSE)
  - Add detection and warnings for systems that do not honor `sshd_config.d`
- **Add optional features behind flags**:
  - Allowlist users/groups (`AllowUsers`, `AllowGroups`)
  - Set `Ciphers`, `MACs`, and `KexAlgorithms` safely (distro/version-dependent)
  - Optional `PasswordAuthentication yes` compatibility mode for break-glass scenarios
- **Improve reporting**:
  - Report *effective* SSH settings via `sshd -T` in the audit report, not only base file greps.

### Firewall Strategy and Port-Migration Hardening
- **Make port migration more explicit and safer**:
  - Add a built-in “two-session” checklist printed before disabling password auth or removing port 22
  - Add an optional “verify SSH on new port” check (best-effort) before `--finalize-ssh-port`
- **Expand firewall coverage**:
  - Better detection of existing rules to avoid duplication
  - Consider support for nftables persistence (optional) rather than only temporary emergency mode
  - Optional support for common cloud firewall tooling guidance (UFW/firewalld are local-only)

### PAM / Password Policy Robustness
- **Reduce lockout risk for PAM edits**:
  - Improve PAM stack detection (RHEL: `password-auth`, `system-auth`; Debian: `common-password`)
  - Add distro-specific implementation notes and safer insertion logic
  - Prefer “managed include file” approaches where possible rather than editing system-auth directly
- **Authselect integration**:
  - On RHEL-like systems using `authselect`, add a supported path for creating a custom profile rather than warning and continuing.
- **Policy customization**:
  - Make pwquality values configurable via flags or a config file rather than hard-coded defaults.

### Audit Report Quality and Structure
- **Improve signal-to-noise**:
  - Group results into “PASS/WARN/FAIL” sections
  - Add a summary header of key posture changes (SSH port, root login, password auth, firewall status)
- **More reliable parsing**:
  - Prefer structured commands where available (e.g., `sshd -T`, `firewall-cmd --list-all`, `ufw status numbered`)
  - Avoid brittle greps of base config files where the effective config differs

### Test Coverage and CI
- **Add automated linting**:
  - ShellCheck in CI (GitHub Actions)
  - shfmt formatting checks
- **Add minimal tests**:
  - Unit-test helper functions (CIDR validation, file upsert behavior, argument parsing)
  - Integration tests using containers/VMs (Ubuntu + Rocky/Alma + openSUSE) to verify idempotency
- **Add a “demo mode” harness**:
  - Run against a mock filesystem (or a temp root) to validate file edits without touching `/etc`.

### UX / CLI Ergonomics
- **Add a config file option** (example: `--config sentinel.conf`) so common settings don’t require long flags
- **Improve output readability**:
  - Consistent section headers and bullet summaries
  - Clear “what changed” vs “what was detected”
- **Add `--version` and `--print-effective-settings`** for easier troubleshooting.

### Platform and Environment Support
- **macOS clarification**:
  - Explicitly document that this is primarily a Linux server hardening tool (macOS use is limited and different).
- **Systemd vs non-systemd**:
  - Better service restart logic when `systemctl` isn’t present
- **Container awareness**:
  - Detect container environments (Docker/LXC) and avoid changes that don’t apply or will fail.

## Non-Goals

Sentinel is intentionally not:
- A full compliance automation framework
- A replacement for configuration management systems
- A one-click “secure everything” solution

## Collaboration and Contributions

Sentinel is actively evolving and is built in the open. Contributions are welcome, including:

- Hardening improvements
- Compliance expansions
- Security auditing enhancements
- Code quality refinements
- Documentation improvements

