# Workstation Security Audit — macOS

A local audit script that shows you how exposed your machine would be if a supply chain attack ran as your user today.

**This script runs entirely offline. No network calls are made. No data leaves your machine. Secret values are never read or displayed — only metadata like file paths and value lengths.**

I strongly encourage you to read the source code before running it. It's around 1000 lines of bash and is written to be readable. Never run a security script you haven't read.

> This script was created with the assistance of Claude (Anthropic). No assurances are made as to its accuracy, completeness, or fitness for any particular purpose. Use it as a starting point for understanding your exposure, not as a definitive security assessment.

---

## Background

In March 2026, the threat actor **TeamPCP** compromised the `litellm` PyPI package. Anyone who installed the affected versions had their credentials silently exfiltrated — SSH keys, cloud credentials, shell history, git tokens, and more — encrypted and sent to an attacker-controlled server.

The attack didn't exploit any vulnerability. It simply ran as your user and read files and environment variables it had natural access to. That's what makes supply chain attacks so effective.

This script was created to answer a simple question: **if that code had run on my machine, what would it have found?**

The answer is useful beyond this specific attack. Supply chain attacks are increasingly common, and the credentials and files this script checks are the same ones any malicious package, compromised dependency, or rogue script would target. Understanding your exposure is the first step to reducing it — and hopefully it teaches some better security habits along the way.

---

## What it checks

| Section | What's audited |
|---|---|
| Environment variables | Secret-like vars in memory and exported from shell config files |
| SSH keys | Passphrase protection, key algorithm strength, Keychain integration |
| Cloud credentials | AWS, GCP, Azure — credential type, whether long-lived or temporary |
| Kubernetes | kubeconfig auth method, service account tokens |
| Git credentials | Plaintext credential store, credential helper, GitHub CLI token |
| Docker | Inline auth tokens vs credential store |
| .env files | Files containing secrets in your home directory tree |
| Shell history | History files with accidentally typed secrets |
| Package manager credentials | npm, Vault, netrc, MySQL, PostgreSQL, MongoDB |
| Cryptocurrency wallets | 10 wallet types including Bitcoin, Ethereum, Solana |
| SSL/TLS keys | System and Let's Encrypt private keys |
| Active compromise indicators | Known TeamPCP malware artifacts and persistence mechanisms |

Each finding is rated **Critical**, **Exposed**, **Warning**, or **Safe**, with an explanation of what attack it enables and how to fix it.

---

## Requirements

- macOS
- bash (pre-installed on macOS)

---

## Usage

Download the script, read it, then run it:

1. [Download audit.sh](https://github.com/Command-N/workstation-exposure-audit/blob/main/audit.sh) — click **Raw**, then save the file
2. Open it in a text editor and read through it
3. Run it:

```bash
chmod +x audit.sh
./audit.sh
```

An optional `--simulate` flag enables an attacker simulation mode that shows how process environment inheritance works and why exporting secrets in your shell config is dangerous:

```bash
./audit.sh --simulate
```

---

## What to do with the results

The script explains each finding inline, but the underlying principle behind most fixes is the same:

- **Don't store long-lived secrets in plaintext files.** Use a credential manager like 1Password CLI, `aws-vault`, or macOS Keychain.
- **Don't export secrets in shell config files.** Use per-process injection (`op run`, `aws-vault exec`) so secrets are only in memory when actually needed.
- **Passphrase-protect your SSH keys** and integrate them with macOS Keychain so the friction doesn't push you back to unprotected keys.
- **Use short-lived credentials wherever possible.** AWS SSO, GCP user credentials, and exec-based kubeconfig auth all limit the damage window if credentials are stolen.

The goal isn't a perfect score — it's understanding your actual exposure and making informed decisions about what to harden.

---

## Limitations

- **macOS only.** Linux and Windows are not currently supported.
- **.pth file scan** checks common Python install locations (system, Homebrew, pyenv, conda, user installs). Custom or deeply nested virtual environments may not be covered.
- The script checks for **known** TeamPCP indicators of compromise. A different attacker or modified payload may leave different artifacts.
- This script was built with AI assistance. It may not be complete, accurate, or up to date. Treat it as a helpful prompt for reflection, not a professional security audit.

---

## License

MIT
