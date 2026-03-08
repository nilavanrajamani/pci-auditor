# PCI Auditor — Demo Video Script

**Target length:** 5 minutes  
**Format:** Screen recording with voiceover

---

## Timing Summary

| Section | Duration |
|---|---|
| Hook — The Problem | 30 sec |
| Solution Overview | 30 sec |
| Architecture + Detection Evolution | 60 sec |
| Demo — VS Code Extension | 60 sec |
| Demo — CI/CD via GitHub | 50 sec |
| Production Readiness | 30 sec |
| Why LLMs? | 30 sec |
| Close | 20 sec |
| **Total** | **5 min 00 sec** |

---

## 🎬 00:00 – 00:30 · Hook — The Problem

**[Screen: `demo_layer2_ai.py` open in VS Code, no scan running. Variable names like `auth_element`, `account_digits`, `instrument` visible.]**

> "PCI DSS 4.0 became mandatory in March 2024.
> Any team that handles payment card data — card numbers, CVVs, cryptographic keys —
> must comply with roughly 260 controls, or face fines up to a hundred thousand dollars
> a month and lose the right to process card payments.
>
> But most teams only find compliance gaps during an annual audit.
> By then, the code has already shipped.
>
> And annual audits don't catch semantic violations — logic buried in business code
> that no regex will ever flag."

---

## 🎬 00:30 – 01:00 · Solution Overview

**[Screen: VS Code with the PCI Auditor extension panel visible in the activity bar. Briefly show the repo name and the README open to the What It Does table.]**

> "PCI Auditor moves compliance checks left — into the pull request,
> before a single line ships to production.
>
> It's a Python CLI paired with a VS Code extension.
> It layers three detection approaches: regex for instant, free pattern matching;
> Azure OpenAI to reason about business-logic violations regex can't see;
> and a RAG pipeline with `text-embedding-3-small` to narrow the model's focus
> to only the rules relevant to each chunk of code.
>
> Zero configuration for the developer. It just runs."

---

## 🎬 01:00 – 02:00 · Architecture + Detection Evolution

**[Screen: README scrolled to the End-to-End Flow Mermaid diagram. Hold on Phase 1 (Index Build), then Phase 2 (PR Scan). Then scroll down to the Detection Evolution diagram and hold on each tier as you name it.]**

> "Here's the architecture.
>
> Phase one runs once: the 27 PCI DSS rule descriptions are sent to
> `text-embedding-3-small`, which converts each one to a 1,536-float vector.
> Those vectors are stored — either locally as JSON or in Azure AI Search
> for team and CI/CD use.
>
> Phase two runs on every pull request: the CLI extracts only the changed diff lines,
> splits them into chunks, runs Stage 1 regex instantly — free, offline, zero latency —
> then in Stage 2 each chunk is embedded and compared against the rule vectors.
> The `RuleRetriever` returns the top-8 most relevant rules.
> Only those eight are injected into the gpt-4.1-mini prompt.
> Findings from both stages are deduplicated by rule ID, file, and line number,
> then emitted as a SARIF 2.1 report.
>
> The Detection Evolution diagram shows what each Azure service unlocks:
> pattern-only with no cloud at all, then add the GPT deployment for semantic reasoning,
> then add the embedding deployment for precise rule citations,
> then add Azure AI Search for hybrid BM25-plus-vector disambiguation
> and a shared cloud index across all CI runners."

---

## 🎬 02:00 – 03:00 · Demo — VS Code Extension

**[Screen: VS Code, `demo_layer2_ai.py` active, extension panel closed. The file has obfuscated variable names — `auth_element`, `account_digits`, `SKIP_SECOND_FACTOR`, etc.]**

> "Let me show you the VS Code extension.
> I've got a payment service open — the variable names look completely innocent:
> `auth_element`, `account_digits`, `instrument`.
> No regex in the world catches these."

**[Click the PCI Auditor icon in the activity bar → sidebar opens → click Scan]**

> "I trigger a scan from the sidebar."

**[Findings populate in the sidebar panel. Inline squiggles appear in the editor. Hover over one.]**

> "Six findings — all flagged by the AI — appear as inline annotations directly in the file.
>
> Rule 3.3.1: the security code is being retained in an audit log.
> Rule 8.4.2: TOTP multi-factor authentication is being skipped via an environment flag.
>
> Neither of those has a fixed pattern. The model understood the *intent* of the code,
> not just the text."

**[Scroll the sidebar to show all 6 findings — severities, rule IDs, line numbers.]**

> "Every finding shows the rule ID, severity, the exact line, and a concrete remediation step.
> The developer sees this inline, in the file, before they even open a PR."

---

## 🎬 03:00 – 03:50 · Demo — CI/CD via GitHub

**[Screen: browser, open the GitHub repo → navigate to the Pull Requests tab → open a PR against `main` that has the `pci-audit` workflow run.]**

> "The same engine runs automatically on every pull request via GitHub Actions —
> and via the included Azure DevOps pipeline for teams on that platform."

**[Show the PR status checks — red ✗ on `pr-scan`]**

> "This PR is blocked. The `pr-scan` job exited with code 1 — the merge button is greyed out."

**[Click the failing check → Actions run log → scroll to the findings output in the log]**

> "In the Actions log you can see exactly which rules fired and on which lines."

**[Switch to the PR's Files Changed tab — show red inline SARIF annotations on the diff lines]**

> "Because the tool emits SARIF 2.1 — the industry standard for static analysis —
> GitHub renders every finding as an inline annotation directly on the diff.
> The reviewer sees the violation on the exact line it was introduced,
> with a remediation suggestion, without leaving the PR.
> Azure DevOps renders the same SARIF output natively in its Security tab."

---

## 🎬 03:50 – 04:20 · Production Readiness

**[Screen: README scrolled to the Security Notes section, then briefly to Project Structure showing the tests/ folder.]**

> "This is production-ready, not a prototype.
>
> 76 unit tests cover the scanner, reporters, rule retrieval, and the AI client.
>
> No secrets ever touch the codebase — all credentials flow in through environment
> variables, and code sent to the LLM stays entirely within your own Azure tenant.
>
> The tool degrades gracefully: if Azure credentials are absent it falls back to
> pattern-only mode and still runs. The build never silently skips.
>
> And PCI DSS rules are data, not code — add or update controls in `pci_rules.json`
> without touching a line of Python."

---

## 🎬 04:20 – 04:50 · Why LLMs?

**[Screen: back to VS Code, hover over the Rule 10.2.1 finding — "missing audit log call" description visible.]**

> "The LLM isn't decoration — it's doing specific work regex fundamentally cannot do.
>
> Detecting a *missing* audit log call — a line that should exist but doesn't.
> Detecting an MFA bypass hidden behind a generic environment variable name.
> Recognising that `account_digits` is a card number even though the word 'card' never appears.
>
> gpt-4.1-mini was chosen over gpt-4o deliberately — it's accurate enough for
> structured compliance JSON and roughly ten times cheaper per token.
> The RAG step cuts prompt size by around 70%, keeping the per-scan cost
> on a 10,000-line repo under five cents."

---

## 🎬 04:50 – 05:00 · Close

**[Screen: GitHub repo landing page showing the README, the three GIFs, and the Related Repositories section.]**

> "PCI Auditor — open source, fully documented, with a VS Code extension,
> a one-click Bicep deploy, and zero config for the developer.
> It blocks non-compliant code before it ever reaches production.
> Repository and README link in the submission."

---

## Screen Checklist

| Segment | What to have ready before recording |
|---|---|
| Hook | `demo_layer2_ai.py` open, no scan running, obfuscated variable names visible |
| Solution Overview | README open to the *What It Does* table |
| Architecture | README scrolled to the End-to-End Flow Mermaid, then Detection Evolution Mermaid |
| VS Code demo | Extension installed and loaded, `demo_layer2_ai.py` active tab |
| CI/CD — GitHub | Browser open on a PR with a completed (failed) `pci-audit` workflow run |
| CI/CD — blocked merge | PR status checks showing red ✗, merge button greyed out |
| CI/CD — Actions log | `pr-scan` job log with findings output visible |
| CI/CD — SARIF annotations | PR → Files Changed tab with inline red annotations visible |
| Production Readiness | README scrolled to Security Notes section; project structure showing `tests/` |
| Why LLMs | VS Code, hover tooltip on Rule 10.2.1 finding showing description |
| Close | GitHub repo landing page with README GIFs and Related Repositories visible |

---

## Tips — Judging Criteria

| Criterion (25% each) | What to say / show | Key moments |
|---|---|---|
| **Innovation & Problem Fit** | Open with the "$100K/month fine + annual audit gap" framing — compliance shifted left into the PR is the core insight | Hook (00:00) and Solution Overview (00:30) |
| **Technical Architecture** | Name `RuleRetriever`, `LocalRuleIndex`, `AzureSearchRuleIndex`; explain dedup by `(rule_id, file, line)`; show both the End-to-End Flow and Detection Evolution diagrams; mention 76 tests and graceful degradation | Architecture (01:00) and Production Readiness (03:50) |
| **Effective Use of LLMs** | The "missing audit call" and "MFA bypass via env var" examples are the killer moments — completely un-catchable by regex; explain model choice (cost vs accuracy) and the 70% prompt-size saving from RAG | Demo — VS Code (02:00) and Why LLMs (04:20) |
| **Demo & UX** | Keep VS Code on screen as long as possible — inline squiggles are more visceral than terminal output; show the SARIF inline PR annotation as the CI/CD payoff | Demo — VS Code (02:00) and CI/CD (03:00) |
