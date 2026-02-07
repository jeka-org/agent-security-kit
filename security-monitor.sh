#!/bin/bash
# security-monitor.sh - Real-time security monitoring for AI agents
# Detects anomalous patterns and alerts via file/log
#
# Usage: ./security-monitor.sh [--daemon] [--full]
# In daemon mode, runs continuously. Otherwise, single check.
# --full includes heavy checks (permissions, SUID, secrets)

set -uo pipefail

# Configurable paths (override with environment variables)
STATE_DIR="${OPENCLAW_STATE_DIR:-$HOME/.openclaw}"
WORKSPACE="${OPENCLAW_WORKSPACE_DIR:-$STATE_DIR/workspace}"

ALERT_FILE="${WORKSPACE}/security-alerts.log"
STATE_FILE="${WORKSPACE}/memory/security-state.json"
BASELINE_FILE="${WORKSPACE}/security-baseline.json"

# Thresholds
MAX_OUTBOUND_CONNS=50
MAX_FILE_CHANGES_PER_MIN=100

# Credential files to monitor (customize for your setup)
CREDENTIAL_FILES=(
    "$HOME/.github_token_*"
    "$STATE_DIR/openclaw.json"
    "$STATE_DIR/google-service-account.json"
    "$HOME/.config/gh/hosts.yml"
    # Add your own credential paths here
)

alert() {
    local severity="$1"
    local message="$2"
    local timestamp=$(date -Iseconds)
    echo "[$timestamp] [$severity] $message" >> "$ALERT_FILE"
    echo "[$severity] $message"
    
    # For critical alerts, also write to a trigger file
    if [[ "$severity" == "CRITICAL" ]]; then
        echo "$message" > "${WORKSPACE}/SECURITY_ALERT"
    fi
}

# Initialize state file if missing
init_state() {
    if [[ ! -f "$STATE_FILE" ]]; then
        cat > "$STATE_FILE" << 'EOF'
{
    "lastCheck": 0,
    "credentialHashes": {},
    "knownProcesses": [],
    "knownConnections": []
}
EOF
    fi
}

# Check for credential file modifications
check_credential_files() {
    local changed=0
    shopt -s nullglob
    for pattern in "${CREDENTIAL_FILES[@]}"; do
        for file in $pattern; do
            if [[ -f "$file" ]]; then
                current_hash=$(sha256sum "$file" 2>/dev/null | cut -d' ' -f1)
                stored_hash=$(jq -r ".credentialHashes[\"$file\"] // \"\"" "$STATE_FILE" 2>/dev/null)
                
                if [[ -n "$stored_hash" && "$current_hash" != "$stored_hash" ]]; then
                    alert "CRITICAL" "Credential file modified: $file"
                    changed=1
                fi
                
                # Update hash
                jq ".credentialHashes[\"$file\"] = \"$current_hash\"" "$STATE_FILE" > "${STATE_FILE}.tmp" && mv "${STATE_FILE}.tmp" "$STATE_FILE"
            fi
        done
    done
    return $changed
}

# Check for unusual outbound connections
check_outbound_connections() {
    local conns=$(ss -tnp 2>/dev/null | grep -v "Local Address" | wc -l)
    
    if [[ "$conns" -gt "$MAX_OUTBOUND_CONNS" ]]; then
        alert "WARNING" "High number of network connections: $conns"
    fi
    
    # Check for connections to suspicious ports (crypto mining, C2)
    local suspicious_ports="3333|4444|5555|6666|7777|8888|9999|14433|14444"
    local sus_conns=$(ss -tnp 2>/dev/null | grep -E ":($suspicious_ports)" || true)
    if [[ -n "$sus_conns" ]]; then
        alert "CRITICAL" "Connection to suspicious port detected: $sus_conns"
    fi
}

# Check for new SUID binaries
check_suid_binaries() {
    local current_suid=$(find /usr -type f -perm -4000 2>/dev/null | sort | sha256sum | cut -d' ' -f1)
    local stored_suid=$(jq -r ".suidHash // \"\"" "$STATE_FILE" 2>/dev/null)
    
    if [[ -n "$stored_suid" && "$current_suid" != "$stored_suid" ]]; then
        alert "CRITICAL" "SUID binaries changed! Potential privilege escalation"
    fi
    
    jq ".suidHash = \"$current_suid\"" "$STATE_FILE" > "${STATE_FILE}.tmp" && mv "${STATE_FILE}.tmp" "$STATE_FILE"
}

# Check for processes running as root that shouldn't be
check_suspicious_processes() {
    # Known malware/miner patterns
    local patterns="xmrig|cryptonight|minerd|kinsing|kdevtmpfsi"
    local found=$(ps aux 2>/dev/null | grep -iE "$patterns" | grep -v grep || true)
    
    if [[ -n "$found" ]]; then
        alert "CRITICAL" "Suspicious process detected: $found"
    fi
    
    # Check for hidden processes (starts with dot or in /tmp)
    local hidden=$(ps aux 2>/dev/null | awk '$11 ~ /^\./ || $11 ~ /^\/tmp/' | grep -v grep || true)
    if [[ -n "$hidden" ]]; then
        alert "WARNING" "Process running from suspicious location: $hidden"
    fi
}

# Check for unauthorized SSH keys
check_ssh_keys() {
    local auth_keys="$HOME/.ssh/authorized_keys"
    if [[ -f "$auth_keys" ]]; then
        local current_hash=$(sha256sum "$auth_keys" | cut -d' ' -f1)
        local stored_hash=$(jq -r ".sshKeysHash // \"\"" "$STATE_FILE" 2>/dev/null)
        
        if [[ -n "$stored_hash" && "$current_hash" != "$stored_hash" ]]; then
            alert "CRITICAL" "SSH authorized_keys modified!"
        fi
        
        jq ".sshKeysHash = \"$current_hash\"" "$STATE_FILE" > "${STATE_FILE}.tmp" && mv "${STATE_FILE}.tmp" "$STATE_FILE"
    fi
}

# Check OpenClaw config for tampering
check_openclaw_config() {
    local config="${STATE_DIR}/openclaw.json"
    if [[ -f "$config" ]]; then
        # Check for suspicious tool additions or policy changes
        local has_full_security=$(jq -r '.security // "deny"' "$config" 2>/dev/null)
        if [[ "$has_full_security" == "full" ]]; then
            alert "WARNING" "OpenClaw running with full security mode (no restrictions)"
        fi
    fi
}

# Check for rapid file changes (potential exfiltration or ransomware)
check_file_activity() {
    # Count recent file changes in sensitive directories
    local recent_changes=$(find "$HOME" -type f -mmin -1 2>/dev/null | wc -l)
    
    if [[ "$recent_changes" -gt "$MAX_FILE_CHANGES_PER_MIN" ]]; then
        alert "WARNING" "High file activity: $recent_changes files modified in last minute"
    fi
}

# Check for failed sudo/su attempts
check_auth_failures() {
    local failures=$(grep -c "authentication failure" /var/log/auth.log 2>/dev/null || echo "0")
    local stored=$(jq -r ".lastAuthFailures // 0" "$STATE_FILE" 2>/dev/null)
    
    local new_failures=$((failures - stored))
    if [[ "$new_failures" -gt 10 ]]; then
        alert "WARNING" "$new_failures new authentication failures since last check"
    fi
    
    jq ".lastAuthFailures = $failures" "$STATE_FILE" > "${STATE_FILE}.tmp" && mv "${STATE_FILE}.tmp" "$STATE_FILE"
}

# ============================================
# SKILL SUPPLY-CHAIN CHECK (hash-based)
# Runs every 5 min, only deep scans on change
# ============================================

# Get hash of skills directory contents
get_skills_hash() {
    local skills_dirs=("${STATE_DIR}/skills" "${WORKSPACE}/skills")
    local hash_input=""
    
    for dir in "${skills_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            hash_input+=$(find "$dir" -type f -printf '%p %T@\n' 2>/dev/null | sort)
        fi
    done
    
    echo "$hash_input" | sha256sum | cut -d' ' -f1
}

# Deep scan for dangerous patterns
scan_skill_patterns() {
    local DANGEROUS='(curl|wget|nc|netcat)\s*[|]|eval\s*\$|base64\s*-d.*[|]'
    local skills_dirs=("${STATE_DIR}/skills" "${WORKSPACE}/skills")
    
    for dir in "${skills_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            local matches=""
            if command -v rg &>/dev/null; then
                matches=$(rg -l "$DANGEROUS" "$dir" 2>/dev/null || true)
            else
                matches=$(grep -rlE "$DANGEROUS" "$dir" 2>/dev/null || true)
            fi
            
            if [[ -n "$matches" ]]; then
                alert "WARNING" "Risky patterns in skills: $matches"
            fi
        fi
    done
}

# Check skills - hash first, deep scan only if changed
check_skills_supply_chain() {
    local current_hash=$(get_skills_hash)
    local stored_hash=$(jq -r ".skillsHash // \"\"" "$STATE_FILE" 2>/dev/null)
    
    if [[ -z "$stored_hash" ]]; then
        # First run - scan and store hash
        echo "  Skills: First run, scanning..."
        scan_skill_patterns
        jq ".skillsHash = \"$current_hash\"" "$STATE_FILE" > "${STATE_FILE}.tmp" && mv "${STATE_FILE}.tmp" "$STATE_FILE"
    elif [[ "$current_hash" != "$stored_hash" ]]; then
        # Changed - deep scan
        echo "  Skills: Change detected, scanning..."
        alert "INFO" "Skills directory changed, running supply-chain scan"
        scan_skill_patterns
        jq ".skillsHash = \"$current_hash\"" "$STATE_FILE" > "${STATE_FILE}.tmp" && mv "${STATE_FILE}.tmp" "$STATE_FILE"
    else
        echo "  Skills: No changes"
    fi
}

# ============================================
# HEAVY CHECKS (every 15 min)
# Inspired by ClawdStrike
# ============================================

# Check filesystem permission drift
check_permission_drift() {
    # Uses global STATE_DIR
    
    # Expected permissions
    declare -A expected=(
        ["$STATE_DIR"]="700"
        ["$STATE_DIR/openclaw.json"]="600"
        ["$STATE_DIR/credentials"]="700"
        ["$STATE_DIR/agents"]="700"
    )
    
    for path in "${!expected[@]}"; do
        if [[ -e "$path" ]]; then
            local actual=$(stat -c "%a" "$path" 2>/dev/null)
            if [[ "$actual" != "${expected[$path]}" ]]; then
                alert "WARNING" "Permission drift: $path is $actual (expected ${expected[$path]})"
            fi
        fi
    done
    
    # Check for world-writable files in state dir
    local ww_files=$(find "$STATE_DIR" -xdev -perm -0002 -type f 2>/dev/null | head -5)
    if [[ -n "$ww_files" ]]; then
        alert "WARNING" "World-writable files in state dir: $ww_files"
    fi
}

# Check for secrets exposed in config (not using env refs)
check_secrets_exposure() {
    local config="${STATE_DIR}/openclaw.json"
    if [[ -f "$config" ]]; then
        # Count inline secrets (keys that look like tokens but aren't env refs)
        local inline=$(grep -oE '"(token|password|secret|api_?key)"[[:space:]]*:[[:space:]]*"[^$][^"]{20,}' "$config" 2>/dev/null | wc -l)
        local stored=$(jq -r ".inlineSecrets // 0" "$STATE_FILE" 2>/dev/null)
        
        if [[ "$inline" -gt "$stored" ]]; then
            alert "WARNING" "New inline secrets in config: $inline (was $stored). Consider using env refs."
        fi
        
        jq ".inlineSecrets = $inline" "$STATE_FILE" > "${STATE_FILE}.tmp" && mv "${STATE_FILE}.tmp" "$STATE_FILE"
    fi
}

# Run heavy checks (called less frequently)
run_heavy_checks() {
    echo "[$(date -Iseconds)] Running heavy security checks..."
    check_permission_drift
    check_secrets_exposure
    check_suid_binaries
}

run_checks() {
    echo "[$(date -Iseconds)] Running security checks..."
    init_state
    
    check_credential_files
    check_outbound_connections
    check_suspicious_processes
    check_ssh_keys
    check_openclaw_config
    check_file_activity
    check_auth_failures
    check_skills_supply_chain  # Hash-based, only deep scans on change
    
    # Update last check time
    jq ".lastCheck = $(date +%s)" "$STATE_FILE" > "${STATE_FILE}.tmp" && mv "${STATE_FILE}.tmp" "$STATE_FILE"
}

# Main
if [[ "${1:-}" == "--daemon" ]]; then
    echo "Starting security monitor daemon..."
    local iteration=0
    while true; do
        run_checks
        
        # Run heavy checks every 15 min (3 iterations × 5 min = 15 min)
        iteration=$((iteration + 1))
        if [[ $((iteration % 3)) -eq 0 ]]; then
            run_heavy_checks
        fi
        
        sleep 300  # Check every 5 minutes
    done
elif [[ "${1:-}" == "--full" ]]; then
    run_checks
    run_heavy_checks
else
    run_checks
fi
