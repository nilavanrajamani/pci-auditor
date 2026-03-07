# PCI Auditor — Demo Recording Scripts

> GIFs don't need to be committed to the repo. Save them locally and embed directly in presentation slides or docs.

---

## How Azure credentials are picked up automatically

The CLI uses `python-dotenv` — on every run it calls `load_dotenv()` which reads the `.env`
file from the **current working directory** (or any parent folder). So as long as you run
`pci-auditor` from inside the `pci-auditor/` folder (which contains a `.env`), all Azure
keys are loaded silently. No manual shell export needed.

---

## One-time setup — run once in Windows Terminal

> **Use Windows Terminal** (not VS Code integrated terminal) — box-drawing characters
> render correctly there.

```powershell
$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONIOENCODING = "utf-8"
$env:PYTHONUTF8 = "1"
$env:PATH += ";C:\Users\nilav\AppData\Roaming\Python\Python313\Scripts"
cd c:\codebase\innovation-challenge-mar-26\pci-auditor   # .env is here
```

**ScreenToGif settings:** Recorder → resize frame to terminal only · 10 fps · save as GIF

---

## GIF 1 — PR Scan with AI (~20s)

**Shows:** Core value — AI-powered scan of changed lines, catches critical violations.

**Steps to record:**
1. Open ScreenToGif → Recorder, frame around the terminal
2. Type (don't run yet):
   ```powershell
   pci-auditor scan pr --repo-path c:\codebase\innovation-challenge-mar-26\sample-vulnerable-app --base-branch origin/main
   ```
3. Hit record → press Enter
4. Let the scan run — AI analysis takes ~10s
5. Violation blocks appear (CRITICAL / HIGH / MEDIUM)
6. Summary table and red FAIL banner appear → stop recording

---

## GIF 2 — PR Scan Pattern-Only / Fast Mode (~10s)

**Shows:** Instant offline scan — no Azure needed, sub-second results in CI.

**Steps to record:**
1. Start recording
2. Type and run:
   ```powershell
   pci-auditor scan pr --repo-path c:\codebase\innovation-challenge-mar-26\sample-vulnerable-app --base-branch origin/main --no-ai
   ```
3. Results appear almost instantly
4. Summary table visible → stop recording

---

## GIF 3 — GitHub Actions PR Build Blocking (~20s)

**Shows:** CI/CD integration — the pipeline automatically runs on every PR and blocks merge on violations.

**Steps to record:**
1. Open browser to `https://github.com/nilavanrajamani/sample-vulnerable-app/actions`
2. Start recording
3. Click on a recent `PCI DSS Audit` workflow run
4. Show the steps expanding: checkout → pci-auditor scan → red ❌ step failure
5. Scroll to show the violation summary in the step logs
6. Stop recording

---

## GIF 4 — Verbose Mode: Why Each Line Fails (~15s)

**Shows:** Detailed rule explanations — useful for developers who want to understand the violation.

**Steps to record:**
1. Start recording
2. Type and run:
   ```powershell
   pci-auditor scan pr --repo-path c:\codebase\innovation-challenge-mar-26\sample-vulnerable-app --base-branch origin/main --no-ai --verbose
   ```
3. Extra log lines appear showing rule IDs matched and why
4. Full violation output with remediation guidance → stop recording

---

## Cleanup

```powershell
Remove-Item pci-results.* -ErrorAction SilentlyContinue
```
