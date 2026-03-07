# PCI Auditor — Demo Recording Scripts

**Setup before recording — run once in Windows Terminal (not VS Code terminal):**
```powershell
# Use Windows Terminal for correct box-drawing character rendering
$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONIOENCODING = "utf-8"
$env:PYTHONUTF8 = "1"
$env:PATH += ";C:\Users\nilav\AppData\Roaming\Python\Python313\Scripts"
cd c:\codebase\innovation-challenge-mar-26\sample-vulnerable-app
```

**ScreenToGif settings:** 10 fps · trim to terminal only · keep under 5 MB

---

## GIF 1 — PR Scan: Violations Found (~20s)

**What it shows:** Core value prop — scanning a PR and catching critical violations instantly.

```powershell
pci-auditor scan pr --repo-path . --base-branch origin/main
```

**What to record:** Type the command → press Enter → watch AI scan run → Rich violation
blocks appear (CRITICAL / HIGH / MEDIUM) → summary table → red FAIL banner at the end.

---

## GIF 2 — PR Scan: Pattern-Only Mode (Fast, No AI) (~12s)

**What it shows:** Works without Azure credentials — pure regex pattern scan, sub-second.

```powershell
pci-auditor scan pr --repo-path . --base-branch origin/main --no-ai
```

**What to record:** Type command → instant results (no API latency) → violations found →
summary table. Great for showing offline / CI speed.

---

## GIF 3 — PR Scan: SARIF Output for CI/CD (~12s)

**What it shows:** Structured machine-readable output for GitHub Actions / Azure DevOps.

```powershell
pci-auditor scan pr --repo-path . --base-branch origin/main --no-ai --output-format sarif --output-file pci-results.sarif
cat pci-results.sarif | python -m json.tool | Select-Object -First 30
```

**What to record:** Run the scan (quiet, no console output) → cat the SARIF file → show
the structured JSON with ruleId, level, message fields.

---

## GIF 4 — PR Scan: JSON Report (~12s)

**What it shows:** JSON output for custom tooling / dashboards.

```powershell
pci-auditor scan pr --repo-path . --base-branch origin/main --no-ai --output-format json --output-file pci-results.json
cat pci-results.json | python -m json.tool | Select-Object -First 40
```

**What to record:** Run command → cat JSON → show findings array with ruleId, severity,
line, message, recommendation fields.

---

## GIF 5 — PR Scan: Verbose Mode (Rule Explanations) (~20s)

**What it shows:** Verbose output explains *why* each line violates PCI DSS.

```powershell
pci-auditor scan pr --repo-path . --base-branch origin/main --no-ai --verbose
```

**What to record:** Run command → extra log lines appear showing which rules matched and
why → full violation output with detailed guidance.

---

## Cleanup after recording (optional)

```powershell
Remove-Item pci-results.sarif, pci-results.json -ErrorAction SilentlyContinue
```
