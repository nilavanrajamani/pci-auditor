"""PCI Auditor CLI entry point."""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional

import click

from pci_auditor import __version__
from pci_auditor.config import AuditorConfig, load_config, should_fail

# Exit codes
EXIT_OK = 0
EXIT_VIOLATIONS = 1
EXIT_ERROR = 2


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )


@click.group()
@click.version_option(version=__version__, prog_name="pci-auditor")
def main() -> None:
    """PCI DSS 4.0 Compliance Auditor.

    Scan pull requests and codebases for PCI DSS violations using
    pattern matching and Azure OpenAI analysis.
    """


# ---------------------------------------------------------------------------
# pci-auditor scan pr
# ---------------------------------------------------------------------------

@main.group()
def scan() -> None:
    """Scan commands (pr / codebase)."""


@scan.command("pr")
@click.option("--repo-path", default=".", show_default=True,
              help="Path to the git repository root.")
@click.option("--base-branch", default="main", show_default=True,
              help="Base branch to diff against (e.g. origin/main).")
@click.option("--head", default="HEAD", show_default=True,
              help="HEAD ref to compare (default: current HEAD).")
@click.option("--no-ai", is_flag=True, default=False,
              help="Disable Azure OpenAI analysis (pattern-only scan).")
@click.option("--fail-on", default=None,
              help="Comma-separated severity levels that fail the build. "
                   "Default from config (critical,high).")
@click.option("--output-format", default=None,
              type=click.Choice(["console", "json", "sarif"], case_sensitive=False),
              help="Output format (default: console).")
@click.option("--output-file", default=None,
              help="Write output to this file (optional).")
@click.option("--verbose", "-v", is_flag=True, default=False)
def scan_pr(
    repo_path: str,
    base_branch: str,
    head: str,
    no_ai: bool,
    fail_on: Optional[str],
    output_format: Optional[str],
    output_file: Optional[str],
    verbose: bool,
) -> None:
    """Scan changed lines in a pull request (git diff)."""
    _setup_logging(verbose)

    repo = Path(repo_path).resolve()
    cfg = load_config(repo)
    _apply_cli_overrides(cfg, no_ai, fail_on, output_format, output_file)

    from pci_auditor.scanner.pr_scanner import get_diff_files
    from pci_auditor.scanner.file_scanner import scan_file
    from pci_auditor.rules.rule_loader import load_rules
    from pci_auditor.models import ScanResult

    try:
        diff_files = get_diff_files(repo, base_branch, head)
    except RuntimeError as exc:
        click.echo(f"ERROR: {exc}", err=True)
        sys.exit(EXIT_ERROR)

    if not diff_files:
        click.echo("No changed files found in diff. Nothing to scan.", err=True)
        sys.exit(EXIT_OK)

    rules = load_rules()
    ai_client = _build_ai_client(cfg)
    rule_retriever = _build_rule_retriever(cfg, rules)
    result = ScanResult()

    for diff_file in diff_files:
        file_path = repo / diff_file.path
        if not file_path.exists():
            continue  # Deleted file

        file_findings = scan_file(
            file_path=file_path,
            rules=rules,
            ai_client=ai_client,
            chunk_lines=cfg.chunk_lines,
            max_file_size_kb=cfg.max_file_size_kb,
            changed_lines=diff_file.added_line_numbers,
            rule_retriever=rule_retriever,
        )
        result.findings.extend(file_findings)
        result.scanned_files += 1
        result.scanned_lines += len(diff_file.added_line_numbers)

    _output_results(result, cfg, repo_root=repo)
    sys.exit(EXIT_VIOLATIONS if should_fail(result.findings, cfg.fail_on) else EXIT_OK)


# ---------------------------------------------------------------------------
# pci-auditor scan codebase
# ---------------------------------------------------------------------------

@scan.command("codebase")
@click.option("--path", default=".", show_default=True,
              help="Root directory of the codebase to scan.")
@click.option("--exclude", default=None,
              help="Comma-separated glob patterns to exclude (merged with defaults).")
@click.option("--no-ai", is_flag=True, default=False)
@click.option("--fail-on", default=None,
              help="Comma-separated severity levels that fail the build.")
@click.option("--output-format", default=None,
              type=click.Choice(["console", "json", "sarif"], case_sensitive=False))
@click.option("--output-file", default=None)
@click.option("--verbose", "-v", is_flag=True, default=False)
def scan_codebase(
    path: str,
    exclude: Optional[str],
    no_ai: bool,
    fail_on: Optional[str],
    output_format: Optional[str],
    output_file: Optional[str],
    verbose: bool,
) -> None:
    """Scan an entire codebase for PCI DSS violations."""
    _setup_logging(verbose)

    root = Path(path).resolve()
    if not root.is_dir():
        click.echo(f"ERROR: '{root}' is not a directory.", err=True)
        sys.exit(EXIT_ERROR)

    cfg = load_config(root)
    _apply_cli_overrides(cfg, no_ai, fail_on, output_format, output_file)
    if exclude:
        cfg.exclude_paths.extend(p.strip() for p in exclude.split(","))

    from pci_auditor.scanner.codebase_scanner import iter_files
    from pci_auditor.scanner.file_scanner import scan_file
    from pci_auditor.rules.rule_loader import load_rules
    from pci_auditor.models import ScanResult

    rules = load_rules()
    ai_client = _build_ai_client(cfg)
    rule_retriever = _build_rule_retriever(cfg, rules)
    result = ScanResult()

    for file_path in iter_files(root, cfg.exclude_paths, cfg.max_file_size_kb):
        file_findings = scan_file(
            file_path=file_path,
            rules=rules,
            ai_client=ai_client,
            chunk_lines=cfg.chunk_lines,
            max_file_size_kb=cfg.max_file_size_kb,
            rule_retriever=rule_retriever,
        )
        result.findings.extend(file_findings)
        result.scanned_files += 1
        try:
            result.scanned_lines += sum(1 for _ in file_path.open(encoding="utf-8", errors="replace"))
        except OSError:
            pass

    _output_results(result, cfg, repo_root=root)
    sys.exit(EXIT_VIOLATIONS if should_fail(result.findings, cfg.fail_on) else EXIT_OK)


# ---------------------------------------------------------------------------
# pci-auditor rules
# ---------------------------------------------------------------------------

@main.group()
def rules() -> None:
    """Manage PCI DSS rules (update / list / info)."""


@rules.command("update")
@click.option("--source", required=True,
              help="URL to fetch latest rules JSON from.")
@click.option("--timeout", default=30, show_default=True,
              help="HTTP timeout in seconds.")
def rules_update(source: Optional[str], timeout: int) -> None:
    """Download and cache the latest PCI DSS rules from a URL.

    Example:

      pci-auditor rules update --source https://example.com/pci_rules.json
    """
    from pci_auditor.rules.rule_manager import update_rules, RuleUpdateError

    try:
        meta = update_rules(source_url=source, timeout=timeout)
        click.echo(
            f"OK Rules updated successfully.\n"
            f"  PCI DSS version : {meta['pci_dss_version']}\n"
            f"  Last updated    : {meta['last_updated']}\n"
            f"  Rules loaded    : {meta['rule_count']}\n"
            f"  Saved to        : {meta['saved_to']}"
        )
    except RuleUpdateError as exc:
        click.echo(f"FAIL Rules update failed: {exc}", err=True)
        sys.exit(EXIT_ERROR)


@rules.command("list")
@click.option("--severity", default=None,
              help="Filter by severity (critical, high, medium, low).")
def rules_list(severity: Optional[str]) -> None:
    """List all available PCI DSS rules."""
    from pci_auditor.rules.rule_loader import load_rules

    severity_filter = [s.strip() for s in severity.split(",")] if severity else None
    rule_list = load_rules(severity_filter)

    click.echo(f"{'ID':<10} {'Severity':<10} {'Category':<35} Requirement")
    click.echo("-" * 100)
    for rule in rule_list:
        req_short = rule.requirement[:60] + "…" if len(rule.requirement) > 60 else rule.requirement
        click.echo(f"{rule.id:<10} {rule.severity:<10} {rule.category:<35} {req_short}")

    click.echo(f"\nTotal: {len(rule_list)} rules")


@rules.command("info")
def rules_info() -> None:
    """Show metadata about the active rules file."""
    from pci_auditor.rules.rule_loader import get_rules_metadata

    meta = get_rules_metadata()
    click.echo(
        f"PCI DSS Version : {meta['pci_dss_version']}\n"
        f"Last Updated    : {meta['last_updated']}\n"
        f"Source          : {meta['source']}\n"
        f"Rule Count      : {meta['rule_count']}\n"
        f"Active File     : {meta['path']}"
    )


@rules.command("reset")
def rules_reset() -> None:
    """Reset to bundled rules (removes any downloaded update)."""
    from pci_auditor.rules.rule_manager import reset_to_bundled

    reset_to_bundled()
    click.echo("OK Rules reset to bundled baseline.")


@rules.command("index-build")
@click.option("--path", default=".", show_default=True,
              help="Repository root (used to locate .pci-auditor.yml).")
@click.option(
    "--backend",
    default="local",
    show_default=True,
    type=click.Choice(["local", "azure-search"], case_sensitive=False),
    help="'local' stores embeddings in ~/.pci-auditor/rule_embeddings.json. "
         "'azure-search' uploads to an Azure AI Search index.",
)
@click.option("--verbose", "-v", is_flag=True, default=False)
@click.option("--force", is_flag=True, default=False,
              help="Force rebuild even if the index is already up-to-date.")
def rules_index_build(path: str, backend: str, verbose: bool, force: bool) -> None:
    """Build the vector index for semantic rule retrieval.

    Generates an embedding for each PCI DSS rule and stores them so that
    during scanning only the most relevant rules are sent to the AI for
    each code chunk (RAG-style).  Run once after installing or after
    'rules update'.

    Requires AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_API_KEY, and
    AZURE_OPENAI_EMBEDDING_DEPLOYMENT to be set.
    """
    _setup_logging(verbose)
    from pci_auditor.rules.rule_loader import load_rules
    from pci_auditor.ai.rule_embedder import EmbeddingClient
    from pci_auditor.ai.rule_index import LocalRuleIndex, AzureSearchRuleIndex

    repo = Path(path).resolve()
    cfg = load_config(repo)

    if not cfg.azure_openai_endpoint or not cfg.azure_openai_api_key:
        click.echo(
            "FAIL Azure OpenAI credentials not configured.\n"
            "  Set AZURE_OPENAI_ENDPOINT and AZURE_OPENAI_API_KEY.",
            err=True,
        )
        sys.exit(EXIT_ERROR)

    if not cfg.azure_openai_embedding_deployment:
        click.echo(
            "FAIL Embedding deployment not configured.\n"
            "  Set AZURE_OPENAI_EMBEDDING_DEPLOYMENT (e.g. text-embedding-3-small).",
            err=True,
        )
        sys.exit(EXIT_ERROR)

    rules = load_rules()
    if not force and backend == "azure-search":
        # Peek at hash before printing or calling the embedding API
        from pci_auditor.ai.rule_index import AzureSearchRuleIndex as _AzIdx
        _peek = _AzIdx(
            search_endpoint=cfg.azure_search_endpoint or "",
            search_api_key=cfg.azure_search_api_key or "",
            index_name=getattr(cfg, "azure_search_index_name", "pci-rules"),
        )
        if _peek.is_up_to_date(rules):
            click.echo("OK Azure AI Search index is already up-to-date — skipping rebuild.")
            return
    click.echo(
        f"Building {backend} index for {len(rules)} rules using "
        f"'{cfg.azure_openai_embedding_deployment}'..."
    )

    try:
        embedder = EmbeddingClient(
            endpoint=cfg.azure_openai_endpoint,
            api_key=cfg.azure_openai_api_key,
            deployment=cfg.azure_openai_embedding_deployment,
            api_version=cfg.azure_openai_api_version,
        )
    except Exception as exc:  # noqa: BLE001
        click.echo(f"FAIL Could not create embedding client: {exc}", err=True)
        sys.exit(EXIT_ERROR)

    if backend == "azure-search":
        if not cfg.azure_search_endpoint or not cfg.azure_search_api_key:
            click.echo(
                "FAIL Azure AI Search credentials not configured.\n"
                "  Set AZURE_SEARCH_ENDPOINT and AZURE_SEARCH_API_KEY.",
                err=True,
            )
            sys.exit(EXIT_ERROR)
        idx: "LocalRuleIndex | AzureSearchRuleIndex" = AzureSearchRuleIndex(
            search_endpoint=cfg.azure_search_endpoint,
            search_api_key=cfg.azure_search_api_key,
            index_name=cfg.azure_search_index_name,
        )
        try:
            idx.build(rules, embedder, force=force)
            click.echo(
                f"OK Azure AI Search index '{cfg.azure_search_index_name}' "
                f"built with {len(rules)} rules."
            )
        except Exception as exc:  # noqa: BLE001
            click.echo(f"FAIL Azure AI Search index build failed: {exc}", err=True)
            sys.exit(EXIT_ERROR)
    else:
        idx = LocalRuleIndex()
        try:
            idx.build(rules, embedder)
            idx.save()
            click.echo(
                f"OK Local rule index built — "
                f"{len(rules)} rules saved to "
                f"~/.pci-auditor/rule_embeddings.json"
            )
        except Exception as exc:  # noqa: BLE001
            click.echo(f"FAIL Local index build failed: {exc}", err=True)
            sys.exit(EXIT_ERROR)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _apply_cli_overrides(
    cfg: AuditorConfig,
    no_ai: bool,
    fail_on: Optional[str],
    output_format: Optional[str],
    output_file: Optional[str],
) -> None:
    if no_ai:
        cfg.use_ai = False
    if fail_on:
        cfg.fail_on = [s.strip().lower() for s in fail_on.split(",")]
    if output_format:
        cfg.output_format = output_format.lower()
    if output_file:
        cfg.output_file = output_file


def _build_rule_retriever(cfg: AuditorConfig, all_rules: list):
    """Build a RuleRetriever for semantic rule selection, or return None.

    Returns None when:
    * AI is disabled (--no-ai)
    * AZURE_OPENAI_EMBEDDING_DEPLOYMENT is not set
    * The local index hasn't been built yet (run 'rules index-build')
    Falls back silently — scanning always works without the retriever.
    """
    if not cfg.use_ai:
        return None
    if not cfg.azure_openai_embedding_deployment:
        return None
    try:
        from pci_auditor.ai.rule_index import build_retriever
        retriever = build_retriever(cfg, all_rules)
        if retriever is None:
            import logging as _logging
            _logging.getLogger(__name__).debug(
                "Semantic search unavailable. Run 'pci-auditor rules index-build'."
            )
        return retriever
    except Exception as exc:  # noqa: BLE001
        import logging as _logging
        _logging.getLogger(__name__).warning(
            "Could not build rule retriever: %s. Using full rule injection.", exc
        )
        return None


def _build_ai_client(cfg: AuditorConfig):
    if not cfg.use_ai:
        return None
    if not cfg.azure_openai_endpoint or not cfg.azure_openai_api_key:
        import logging as _logging
        _logging.getLogger(__name__).warning(
            "Azure OpenAI credentials not set (AZURE_OPENAI_ENDPOINT / AZURE_OPENAI_API_KEY). "
            "Running in pattern-only mode (--no-ai)."
        )
        return None
    try:
        from pci_auditor.ai.openai_client import OpenAIClient
        return OpenAIClient(
            endpoint=cfg.azure_openai_endpoint,
            api_key=cfg.azure_openai_api_key,
            deployment=cfg.azure_openai_deployment,
            api_version=cfg.azure_openai_api_version,
        )
    except Exception as exc:  # noqa: BLE001
        import logging as _logging
        _logging.getLogger(__name__).warning(
            "Could not initialise AI client: %s. Running pattern-only.", exc
        )
        return None


def _output_results(result, cfg: AuditorConfig, repo_root: Optional[Path] = None) -> None:
    from pci_auditor.rules.rule_loader import get_rules_metadata
    fmt = cfg.output_format

    if fmt == "json":
        from pci_auditor.reporter.json_reporter import write_json
        write_json(result, cfg.output_file)
        # Always print console summary so findings are visible in CI logs
        from pci_auditor.reporter.console_reporter import print_results
        print_results(result, cfg.fail_on)
    elif fmt == "sarif":
        from pci_auditor.reporter.sarif_reporter import write_sarif
        meta = get_rules_metadata()
        write_sarif(result, cfg.output_file, meta, repo_root=repo_root)
        # Always print console summary so findings are visible in CI logs
        from pci_auditor.reporter.console_reporter import print_results
        print_results(result, cfg.fail_on)
    else:
        from pci_auditor.reporter.console_reporter import print_results
        print_results(result, cfg.fail_on)
        # Also write JSON/SARIF file if --output-file specified alongside console
        if cfg.output_file:
            from pci_auditor.reporter.sarif_reporter import write_sarif
            meta = get_rules_metadata()
            write_sarif(result, cfg.output_file, meta, repo_root=repo_root)


if __name__ == "__main__":
    main()
