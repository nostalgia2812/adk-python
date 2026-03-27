"""
Ghost AI — ADK-style Security Agent
Built on the Agent Development Kit (ADK) pattern from this repo.

This module wires Ghost AI into the ADK agent framework so it can be
run, tested, and composed with other ADK agents.

Usage:
    from ghost.agent import root_agent          # use directly
    adk web                                      # serve via ADK web UI
    adk run ghost.agent                          # run in CLI
"""
from google.adk.agents import Agent
from google.adk.tools import FunctionTool


# ── Tool functions (thin wrappers Ghost AI backend) ─────────────────────────

def scan_for_secrets(path: str) -> dict:
    """
    Scan a file path for hardcoded secrets using Gitleaks and TruffleHog.

    Args:
        path: Absolute or relative filesystem path to scan.

    Returns:
        dict with keys: gitleaks_count, trufflehog_count, findings_preview.
    """
    import shutil, subprocess, json, tempfile
    results: dict = {"path": path, "gitleaks_count": 0, "trufflehog_count": 0, "findings_preview": []}

    if shutil.which("gitleaks"):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            subprocess.run(
                ["gitleaks", "detect", "--source", path, "--report-format", "json",
                 "--report-path", tmp.name, "--no-git"],
                capture_output=True,
            )
            try:
                data = json.load(open(tmp.name))
                results["gitleaks_count"] = len(data)
                results["findings_preview"] = data[:3]
            except Exception:
                pass

    if shutil.which("trufflehog"):
        proc = subprocess.run(
            ["trufflehog", "filesystem", path, "--json", "--no-update"],
            capture_output=True, text=True,
        )
        lines = [l for l in proc.stdout.splitlines() if l.strip()]
        results["trufflehog_count"] = len(lines)

    return results


def threat_intel_search(query: str) -> dict:
    """
    Search threat intelligence sources for indicators matching the query.

    Args:
        query: Search terms describing the threat, actor, or IOC to look up.

    Returns:
        dict with keys: query, result_count, summary.
    """
    try:
        import sys, os
        # Try to import from the robin OSINT backend if available
        sys.path.insert(0, os.environ.get("GHOST_ROBIN_PATH", ""))
        from search import search_dark_web  # type: ignore
        results = search_dark_web(query)
        return {"query": query, "result_count": len(results), "top_results": results[:5]}
    except ImportError:
        return {"query": query, "result_count": 0, "note": "Robin OSINT backend not available. Set GHOST_ROBIN_PATH."}


def check_web_vulnerabilities(url: str) -> dict:
    """
    Check a web application URL for common vulnerabilities using Commix.
    Only use against targets you own or have authorization to test.

    Args:
        url: Target URL with a potentially injectable parameter.

    Returns:
        dict with keys: url, tool, status, output.
    """
    import shutil, subprocess
    if not shutil.which("commix"):
        return {"url": url, "tool": "commix", "status": "unavailable",
                "output": "commix not installed. See github.com/commixproject/commix"}
    proc = subprocess.run(
        ["commix", "--url", url, "--batch", "--output-dir", "/tmp/ghost_commix"],
        capture_output=True, text=True, timeout=120,
    )
    return {"url": url, "tool": "commix", "status": "complete", "output": proc.stdout[:2000]}


# ── ADK Agent definition ─────────────────────────────────────────────────────

root_agent = Agent(
    name="ghost_ai",
    model="claude-opus-4-6",
    description=(
        "Ghost AI: Autonomous security orchestration agent. Coordinates secret scanning, "
        "vulnerability assessment, and threat intelligence for authorized security operations."
    ),
    instruction="""
You are Ghost AI, an autonomous security operations agent.
You help security professionals by coordinating specialized security tools.

Your available tools:
- scan_for_secrets(path): detect hardcoded secrets and credentials in code
- threat_intel_search(query): search dark web threat intelligence feeds
- check_web_vulnerabilities(url): test web apps for command injection vulnerabilities

Always:
1. Confirm authorization scope before executing any scan
2. Report findings clearly with severity and remediation steps
3. Operate within authorized boundaries only
4. Provide structured, actionable intelligence assessments
""",
    tools=[
        FunctionTool(scan_for_secrets),
        FunctionTool(threat_intel_search),
        FunctionTool(check_web_vulnerabilities),
    ],
)
