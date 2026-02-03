# Security Heartbeat Checklist

Add these checks to your agent's heartbeat routine (periodic health checks, typically every 10-30 minutes) to catch security issues quickly.

## Quick Checks (Every Heartbeat)

```markdown
### Urgent Security Check
1. Security alert file exists? → Handle immediately
2. Critical service down? Quick status check
3. Unusual process activity? Quick ps scan
```

## Tier 2: Every 30 Minutes

```markdown
### Light Security Audit
- [ ] Check for new auth failures in logs
- [ ] Verify credential files haven't changed (hash check)
- [ ] Check for suspicious network connections
- [ ] Verify security monitor daemon still running
```

**Implementation:**
```bash
# Quick credential hash check
for file in ~/.github_token_* ~/.openclaw/openclaw.json; do
    sha256sum "$file" 2>/dev/null
done | sha256sum  # Compare to known-good hash

# Check security monitor
pgrep -f security-monitor.sh || echo "WARNING: Security monitor not running"

# Count auth failures
grep "authentication failure" /var/log/auth.log | wc -l
```

## Tier 3: Every 2 Hours

```markdown
### Medium Security Audit
- [ ] Review security alert log
- [ ] Check for unauthorized SSH keys
- [ ] Verify no new SUID binaries
- [ ] Check for processes running from /tmp
- [ ] Scan for known malware/miner patterns
```

**Implementation:**
```bash
# Check SSH keys
sha256sum ~/.ssh/authorized_keys

# Check for suspicious processes
ps aux | grep -iE "xmrig|cryptonight|minerd|kinsing" | grep -v grep

# Check for hidden processes
ps aux | awk '$11 ~ /^\./ || $11 ~ /^\/tmp/'
```

## Daily: Memory Verification

```markdown
### Verify Yesterday's Claims
1. Read last 2 days of memory files
2. Find claims with `[✓]` or "installed/configured/created/completed"
3. Pick 3-5 claims and actually verify them:
   - "Created X file" → `ls -la X`
   - "Installed X" → `which X` or `systemctl status X`
   - "Configured X" → check config exists and looks right
4. If claim is FALSE: mark with `[?]` and strikethrough, add note
5. Log verification results in today's memory file
```

**Why:** Prevents false memory contamination. Agents can hallucinate defenses they don't actually have.

## Weekly: Deep Security Audit

```markdown
### Sunday Deep Dive
1. **Memory audit** - Scan all memory files from past 7 days for false claims
2. **Credential audit** - Verify all API keys/tokens still valid and secure
3. **Permission audit** - Check file permissions on sensitive files
4. **Log review** - Look for patterns in auth.log, syslog
5. **Update check** - OpenClaw, skills, system packages
6. **Dependency audit** - Check for known vulnerabilities
```

**Implementation:**
```bash
# Check file permissions
find ~/.openclaw -name "*.json" -o -name "*token*" | xargs ls -la

# Check for updates
openclaw status  # Look for available updates

# Scan for vulnerable packages (if using npm)
cd ~/.openclaw && npm audit
```

## Alert Thresholds

Define what triggers immediate notification vs logged warning:

| Severity | Condition | Action |
|----------|-----------|--------|
| CRITICAL | Credential file modified | Alert immediately + halt agent |
| CRITICAL | New SSH key added | Alert immediately |
| CRITICAL | Known malware process detected | Alert + kill process |
| WARNING | High auth failure count (>10 new) | Log + alert if sustained |
| WARNING | Unusual network activity | Log + monitor |
| INFO | System update available | Log only |

## State Tracking

Create `memory/heartbeat-state.json` to track last check times:

```json
{
  "lastTier2": "2026-02-03T06:00:00Z",
  "lastTier3": "2026-02-03T04:00:00Z",
  "lastMemoryVerify": "2026-02-03T00:00:00Z",
  "lastDeepAudit": "2026-02-02T00:00:00Z",
  "credentialHashes": {
    "~/.github_token": "abc123...",
    "~/.openclaw/openclaw.json": "def456..."
  },
  "notes": {
    "last_alert": "2026-02-01: High auth failures",
    "security_monitor_pid": "12345"
  }
}
```

## Integration with HEARTBEAT.md

Add to your agent's `HEARTBEAT.md`:

```markdown
## TIER 1: Every Heartbeat (~10m)

### Urgent Check
1. Security alert file exists? → Handle immediately
   ```bash
   test -f /tmp/security-alert.txt && cat /tmp/security-alert.txt
   ```

## TIER 2: Every 30m

Run if `now - lastTier2 > 30 minutes`:
- [ ] Run security-monitor.sh --once
- [ ] Check credential file hashes
- [ ] Verify security processes still running

## TIER 3: Every 2h

Run if `now - lastTier3 > 2 hours`:
- [ ] Review security logs
- [ ] Check for unusual processes
- [ ] Verify no unauthorized changes

## DAILY: Memory Verification

Run once per day:
- [ ] Verify 3-5 claims from yesterday's memory
- [ ] Update any false claims with [?] marker
```

## Response Procedures

### If Credential File Changed

1. **HALT** - Don't make any external API calls
2. **Investigate** - Review recent memory for what changed
3. **Verify** - Was this a legitimate update by the user?
4. **Rotate** - If compromise suspected, rotate the credential
5. **Alert** - Notify user immediately

### If Suspicious Process Detected

1. **Capture** - Get full process info (`ps aux`, `lsof -p <pid>`)
2. **Network** - Check what it's connecting to (`lsof -i -p <pid>`)
3. **Kill** - Terminate if clearly malicious
4. **Preserve** - Save process binary for analysis if unknown
5. **Alert** - Notify user with findings

### If SSH Key Added

1. **HALT** - Assume compromise
2. **Review** - Check `/var/log/auth.log` for login source
3. **Remove** - Delete unauthorized key immediately
4. **Rotate** - Change user password, rotate all credentials
5. **Alert** - Critical notification to user

---

## Tuning

Adjust check frequency based on your threat model:

- **High security** (production, handles money): Every 5 minutes
- **Medium security** (personal use, sensitive data): Every 10-30 minutes  
- **Low security** (development, sandboxed): Hourly

Monitor for alert fatigue. Too many false positives = real alerts get ignored.
