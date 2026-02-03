#!/bin/bash
# security-monitor.sh - Real-time security monitoring for Spark
# Detects anomalous patterns and alerts via file/log
#
# Usage: ./security-monitor.sh [--daemon]
# In daemon mode, runs continuously. Otherwise, single check.

set -uo pipefail

ALERT_FILE="/root/.openclaw/workspace/security-alerts.log"
STATE_FILE="/root/.openclaw/workspace/memory/security-state.json"
BASELINE_FILE="/root/.openclaw/workspace/security-baseline.json"

# Thresholds
MAX_OUTBOUND_CONNS=50
MAX_FILE_CHANGES_PER_MIN=100
CREDENTIAL_FILES=(
    "/root/.github_token_*"
    "/root/.openclaw/openclaw.json"
    "/root/.openclaw/google-service-account.json"
    "/root/.config/gh/hosts.yml"
    "/root/.config/moltbook/credentials.json"
)

alert() {
    local severity="$1"
    local message="$2"
    local timestamp=$(date -Iseconds)
    echo "[$timestamp] [$severity] $message" >> "$ALERT_FILE"
    echo "[$severity] $message"
    
    # For critical alerts, also write to a trigger file
    if [[ "$severity" == "CRITICAL" ]]; then
        echo "$message" > /root/.openclaw/workspace/SECURITY_ALERT
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
    local auth_keys="/root/.ssh/authorized_keys"
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
    local config="/root/.openclaw/openclaw.json"
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
    local recent_changes=$(find /root -type f -mmin -1 2>/dev/null | wc -l)
    
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
    # check_suid_binaries  # Can be slow, enable if needed
    
    # Update last check time
    jq ".lastCheck = $(date +%s)" "$STATE_FILE" > "${STATE_FILE}.tmp" && mv "${STATE_FILE}.tmp" "$STATE_FILE"
}

# Main
if [[ "${1:-}" == "--daemon" ]]; then
    echo "Starting security monitor daemon..."
    while true; do
        run_checks
        sleep 300  # Check every 5 minutes
    done
else
    run_checks
fi
