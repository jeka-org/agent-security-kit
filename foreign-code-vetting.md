# Foreign Code Vetting Checklist

Before your agent uses ANY external code (OpenClaw skills, npm packages, scripts from GitHub, CLI tools), audit it against this checklist.

## The Rule

**No exceptions for convenience.** If it looks suspicious, don't run it. Getting hacked isn't worth saving 10 minutes.

## Pre-Installation Audit

### 1. Network Destinations

**Check:** Where does this code connect?

```bash
# Search source for network calls
grep -rE "fetch|axios|http|https|curl|wget|socket" .
grep -rE "\.post|\.get|\.send|\.connect" .

# Look for hardcoded IPs/domains
grep -rE "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" .
grep -rE "https?://[a-zA-Z0-9\-\.]+" .
```

**Red flags:**
- Connections to unfamiliar domains
- Hardcoded IPs (especially in suspicious ranges)
- Base64-encoded URLs (obfuscation)
- Connections to paste sites (pastebin, dpaste, etc.)

**Questions:**
- Is the destination legitimate for this tool's purpose?
- Why does it need network access?
- Could this be data exfiltration?

---

### 2. Code Execution

**Check:** Can it run arbitrary commands?

```bash
# Search for dangerous functions
grep -rE "eval\(|exec\(|execSync|spawn|child_process" .
grep -rE "system\(|shell_exec|passthru|proc_open" .  # PHP
grep -rE "subprocess|os\.system|__import__" .  # Python
```

**Red flags:**
- `eval()` or `exec()` on user input
- Dynamic code generation from external sources
- Shell command injection patterns
- Deserialization of untrusted data

**Questions:**
- Does it execute user-provided code?
- Can commands be injected via input?
- Is there validation/sanitization?

---

### 3. Credential Access

**Check:** What secrets can it see?

```bash
# Look for environment variable access
grep -rE "process\.env|os\.getenv|ENV\[" .

# Look for file reads of sensitive paths
grep -rE "\.openclaw/openclaw\.json|\.ssh|\.aws|\.github" .
grep -rE "readFileSync|readFile|open\(" .

# Look for credential patterns
grep -rE "password|token|api_key|secret|bearer" .
```

**Red flags:**
- Reads config files without clear need
- Accesses SSH keys or cloud credentials
- Logs or transmits environment variables
- Hardcoded credential extraction patterns

**Questions:**
- Why does it need credential access?
- Where do those credentials go?
- Is access scoped to what's necessary?

---

### 4. Data Exfiltration Patterns

**Check:** Does it send your data elsewhere?

```bash
# Look for data collection
grep -rE "\.map|\.filter|\.reduce" . | grep -E "password|token|key"

# Look for encoding/obfuscation
grep -rE "btoa|atob|Buffer\.from|base64|JSON\.stringify" .

# Look for compression before sending
grep -rE "gzip|deflate|compress" .
```

**Red flags:**
- Collecting system info without displaying it
- Base64-encoding data before network calls
- Reading files and POSTing them
- Analytics or telemetry not disclosed in docs

**Questions:**
- What data is being collected?
- Where is it being sent?
- Is this disclosed in the README?

---

### 5. Permissions & Scope

**Check:** What access does it need?

- File system access beyond its stated purpose?
- Network access when it claims to be local-only?
- Elevated privileges (sudo, root)?
- Broad environment variable access?

**Red flags:**
- Requests more permissions than needed
- "Just run as root" without explanation
- Modifies system files outside its domain

---

## Decision Matrix

| Finding | Action |
|---------|--------|
| No network calls, no exec, reads only own config | ✅ Safe to use |
| Network calls to documented/expected endpoints | ⚠️ Review carefully, monitor in use |
| Undocumented network calls | ❌ Don't use |
| `eval()` on user input | ❌ Don't use |
| Reads credentials + makes network calls | ❌ Don't use |
| Base64-encoded URLs or obfuscation | ❌ Don't use |
| "Trust me" without source available | ❌ Don't use |

---

## Post-Installation Monitoring

Even if code passes initial audit:

1. **Monitor network activity** when running it
   ```bash
   # Watch what it connects to
   sudo tcpdump -i any -n | grep <process>
   ```

2. **Check for unexpected file changes**
   ```bash
   # See what files it touches
   sudo fs_usage -w -f filesystem | grep <process>
   ```

3. **Review logs** for anomalies
   - Unexpected API calls
   - Failed authentication attempts
   - Error patterns suggesting probing

---

## When in Doubt

**Don't run it.**

Better to spend 10 minutes finding an alternative than to spend 10 hours recovering from a breach.

If you need the functionality:
1. Fork and audit the source
2. Remove suspicious code
3. Run in isolated sandbox first
4. Monitor closely in production

---

## Example: Auditing an OpenClaw Skill

```bash
# Download skill source
cd ~/.openclaw/skills/suspicious-skill

# Check network activity
grep -r "fetch\|axios\|http" .

# Check for code execution
grep -r "eval\|exec\|spawn" .

# Check credential access
grep -r "openclaw.json\|\.env\|process.env" .

# Check what it imports
grep -r "^import\|^require" .

# Read the SKILL.md
cat SKILL.md  # Does behavior match documentation?
```

If anything looks off, ask on Discord or skip it. Not every skill is worth the risk.
