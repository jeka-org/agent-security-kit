#!/usr/bin/env bash
# Agent Security Kit - Quick Audit
# One-shot security check for OpenClaw deployments
set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

STATE_DIR="${OPENCLAW_STATE_DIR:-$HOME/.openclaw}"
CONFIG_PATH="${STATE_DIR}/openclaw.json"
WORKSPACE="${OPENCLAW_WORKSPACE_DIR:-$STATE_DIR/workspace}"

warn_count=0
ok_count=0

warn() { echo -e "${YELLOW}⚠ WARN:${NC} $1"; warn_count=$((warn_count + 1)); }
ok() { echo -e "${GREEN}✓ OK:${NC} $1"; ok_count=$((ok_count + 1)); }
info() { echo -e "  ℹ $1"; }

echo "═══════════════════════════════════════════════"
echo "  Agent Security Kit - Quick Audit"
echo "  $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
echo "═══════════════════════════════════════════════"
echo

# --- Identity ---
echo "## Identity"
if [[ $(id -u) -eq 0 ]]; then
  warn "Running as root"
else
  ok "Running as $(whoami) (non-root)"
fi
echo

# --- Permissions ---
echo "## Permissions"

check_perm() {
  local path="$1"
  local expected="$2"
  local desc="$3"
  if [[ ! -e "$path" ]]; then
    info "$desc: missing"
    return
  fi
  local actual=$(stat -c "%a" "$path" 2>/dev/null || stat -f "%Lp" "$path" 2>/dev/null)
  if [[ "$actual" == "$expected" ]]; then
    ok "$desc ($actual)"
  else
    warn "$desc is $actual (expected $expected)"
  fi
}

check_perm "$STATE_DIR" "700" "State dir"
check_perm "$CONFIG_PATH" "600" "Config file"
check_perm "$STATE_DIR/credentials" "700" "Credentials dir"
check_perm "$STATE_DIR/agents" "700" "Agents dir"
echo

# --- Filesystem Hygiene ---
echo "## Filesystem Hygiene"

# World-writable in state dir
ww_files=$(find "$STATE_DIR" -xdev -perm -0002 -type f 2>/dev/null | head -5 || true)
if [[ -n "$ww_files" ]]; then
  warn "World-writable files in state dir:"
  echo "$ww_files" | while read f; do info "$f"; done
else
  ok "No world-writable files in state dir"
fi

# SUID/SGID
suid_files=$(find "$STATE_DIR" -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -5 || true)
if [[ -n "$suid_files" ]]; then
  warn "SUID/SGID files found:"
  echo "$suid_files" | while read f; do info "$f"; done
else
  ok "No SUID/SGID files in state dir"
fi
echo

# --- Secrets Exposure ---
echo "## Secrets"
if [[ -f "$CONFIG_PATH" ]]; then
  # Count inline secrets (not env refs)
  inline_secrets=$(grep -oE '"(token|password|secret|api_?key|apikey)"[[:space:]]*:[[:space:]]*"[^$][^"]+' "$CONFIG_PATH" 2>/dev/null | wc -l || echo 0)
  env_refs=$(grep -oE '"\$\{[A-Z_]+\}"' "$CONFIG_PATH" 2>/dev/null | wc -l || echo 0)
  
  if [[ $inline_secrets -gt 0 ]]; then
    warn "$inline_secrets secrets stored inline in config (consider env refs)"
  else
    ok "No inline secrets detected"
  fi
  [[ $env_refs -gt 0 ]] && info "$env_refs env refs in use"
fi
echo

# --- Network ---
echo "## Network Exposure"

# Check if gateway is localhost-only
if command -v ss &>/dev/null; then
  gateway_bind=$(ss -tlnp 2>/dev/null | grep -E ":1878[0-9]" | head -1 || true)
  if [[ "$gateway_bind" == *"127.0.0.1"* ]] || [[ "$gateway_bind" == *"[::1]"* ]]; then
    ok "Gateway bound to localhost"
  elif [[ -n "$gateway_bind" ]]; then
    warn "Gateway may be exposed: $gateway_bind"
  else
    info "Gateway port not detected"
  fi
fi

# Firewall
if command -v ufw &>/dev/null; then
  if ufw status 2>/dev/null | grep -q "Status: active"; then
    ok "UFW firewall active"
  else
    warn "UFW firewall not active"
  fi
elif command -v firewall-cmd &>/dev/null; then
  if firewall-cmd --state 2>/dev/null | grep -q "running"; then
    ok "firewalld active"
  else
    warn "firewalld not running"
  fi
else
  info "No firewall detected (ufw/firewalld)"
fi
echo

# --- Skill Supply Chain ---
echo "## Skill Supply Chain"

DANGEROUS='(curl|wget|nc|netcat|socat)\s*[|]|eval\s*\$|base64\s*-d.*[|]|\bchmod\s+\+x\b'
skills_dirs=("$STATE_DIR/skills" "$WORKSPACE/skills")

found_risky=0
for dir in "${skills_dirs[@]}"; do
  if [[ -d "$dir" ]]; then
    if command -v rg &>/dev/null; then
      matches=$(rg -l -S "$DANGEROUS" "$dir" 2>/dev/null || true)
    else
      matches=$(grep -rlE "$DANGEROUS" "$dir" 2>/dev/null || true)
    fi
    if [[ -n "$matches" ]]; then
      warn "Risky patterns in skills:"
      echo "$matches" | head -5 | while read f; do info "$f"; done
      found_risky=1
    fi
  fi
done
if [[ $found_risky -eq 0 ]]; then
  ok "No obvious risky patterns in skills"
fi
echo

# --- Summary ---
echo "═══════════════════════════════════════════════"
echo -e "  Summary: ${GREEN}$ok_count OK${NC}, ${YELLOW}$warn_count warnings${NC}"
echo "═══════════════════════════════════════════════"

exit 0
