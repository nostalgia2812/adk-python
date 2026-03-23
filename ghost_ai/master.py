#!/usr/bin/env python3
"""
Ghost AI - Master Orchestration Script
GitHub API Integration + Security Intelligence Platform

Built on Google ADK Python framework.
NO wallet integration.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

import httpx

try:
    import google.adk
    ADK_AVAILABLE = True
except ImportError:
    ADK_AVAILABLE = False


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

GITHUB_API_BASE = "https://api.github.com"
GITHUB_API_VERSION = "2022-11-28"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ---------------------------------------------------------------------------
# Secret patterns (gitleaks / trufflehog style)
# ---------------------------------------------------------------------------

SECRET_PATTERNS: dict[str, re.Pattern] = {
    "github_token":       re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,255}"),
    "github_fine_grained": re.compile(r"github_pat_[A-Za-z0-9_]{82}"),
    "aws_access_key":     re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret_key":     re.compile(r"(?i)aws.{0,20}secret.{0,20}[=:\s]\s*[A-Za-z0-9/+]{40}"),
    "generic_api_key":    re.compile(r"(?i)(api[_-]?key|apikey)[\s=:]+['\"]?([A-Za-z0-9\-_]{20,})['\"]?"),
    "private_key_header": re.compile(r"-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY-----"),
    "slack_token":        re.compile(r"xox[baprs]-[0-9a-zA-Z\-]{10,48}"),
    "google_api_key":     re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "stripe_secret":      re.compile(r"sk_(live|test)_[0-9a-zA-Z]{24,}"),
    "jwt_token":          re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "password_literal":   re.compile(r"(?i)(password|passwd|pwd)[\s=:]+['\"]([^'\"\n]{8,})['\"]?"),
    "connection_string":  re.compile(r"(?i)(mongodb|postgresql|mysql|redis):\/\/[^\s]+"),
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    type: str
    value: str
    file: str
    line: int
    severity: Severity
    repo_url: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "value": self.value[:20] + "***" if len(self.value) > 20 else "***",
            "file": self.file,
            "line": self.line,
            "severity": self.severity.value,
            "repo_url": self.repo_url,
            "timestamp": self.timestamp,
        }


@dataclass
class ScanResult:
    repo_url: str
    repo_name: str
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    status: str = "pending"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def severity_summary(self) -> dict[str, int]:
        summary: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            summary[f.severity.value] += 1
        return summary

    def to_dict(self) -> dict:
        return {
            "repo_url": self.repo_url,
            "repo_name": self.repo_name,
            "status": self.status,
            "files_scanned": self.files_scanned,
            "total_findings": len(self.findings),
            "severity_summary": self.severity_summary,
            "findings": [f.to_dict() for f in self.findings],
            "timestamp": self.timestamp,
        }


@dataclass
class ThreatFeedEntry:
    title: str
    description: str
    severity: Severity
    category: str
    source: str
    tags: list[str] = field(default_factory=list)
    published_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ---------------------------------------------------------------------------
# GitHub API client
# ---------------------------------------------------------------------------

class GitHubClient:
    """Thin async wrapper around the GitHub REST API."""

    def __init__(self, token: str) -> None:
        self._headers = {
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
            "Accept": "application/vnd.github+json",
        }

    async def get(self, path: str, **params) -> Any:
        url = f"{GITHUB_API_BASE}{path}"
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(url, headers=self._headers, params=params)
            resp.raise_for_status()
            return resp.json()

    async def get_user(self) -> dict:
        return await self.get("/user")

    async def list_repos(self, org: Optional[str] = None, user: Optional[str] = None) -> list[dict]:
        if org:
            return await self.get(f"/orgs/{org}/repos", per_page=100)
        if user:
            return await self.get(f"/users/{user}/repos", per_page=100)
        return await self.get("/user/repos", per_page=100)

    async def get_repo(self, owner: str, repo: str) -> dict:
        return await self.get(f"/repos/{owner}/{repo}")

    async def list_branches(self, owner: str, repo: str) -> list[dict]:
        return await self.get(f"/repos/{owner}/{repo}/branches", per_page=100)

    async def get_tree(self, owner: str, repo: str, sha: str = "HEAD") -> dict:
        return await self.get(
            f"/repos/{owner}/{repo}/git/trees/{sha}",
            recursive=1,
        )

    async def get_file_content(self, owner: str, repo: str, path: str) -> str:
        """Return decoded file content (plain text)."""
        import base64
        data = await self.get(f"/repos/{owner}/{repo}/contents/{path}")
        if isinstance(data, dict) and data.get("encoding") == "base64":
            return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
        return ""

    async def list_commits(self, owner: str, repo: str, sha: str = "HEAD", per_page: int = 30) -> list[dict]:
        return await self.get(f"/repos/{owner}/{repo}/commits", sha=sha, per_page=per_page)

    async def run_secret_scanning(
        self, owner: str, repo: str
    ) -> list[dict]:
        """Return GitHub's own secret-scanning alerts (requires push access)."""
        try:
            return await self.get(f"/repos/{owner}/{repo}/secret-scanning/alerts")
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in (403, 404):
                return []  # not enabled / no access
            raise


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".env", ".yaml", ".yml",
    ".json", ".toml", ".cfg", ".ini", ".sh", ".bash", ".zsh",
    ".rb", ".go", ".java", ".kt", ".swift", ".rs", ".php",
    ".tf", ".tfvars", ".properties", ".conf", ".config",
}

MAX_FILE_SIZE = 500_000  # 500 KB — skip binary blobs


def _severity_for_type(pattern_name: str) -> Severity:
    if pattern_name in ("github_token", "github_fine_grained", "aws_access_key",
                        "aws_secret_key", "private_key_header", "stripe_secret"):
        return Severity.CRITICAL
    if pattern_name in ("google_api_key", "slack_token", "connection_string"):
        return Severity.HIGH
    if pattern_name in ("jwt_token", "generic_api_key"):
        return Severity.MEDIUM
    return Severity.LOW


def scan_text(text: str, file_path: str, repo_url: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()
    for pattern_name, pattern in SECRET_PATTERNS.items():
        for lineno, line in enumerate(lines, start=1):
            for match in pattern.finditer(line):
                findings.append(Finding(
                    type=pattern_name,
                    value=match.group(0),
                    file=file_path,
                    line=lineno,
                    severity=_severity_for_type(pattern_name),
                    repo_url=repo_url,
                ))
    return findings


async def scan_repository(
    client: GitHubClient,
    owner: str,
    repo: str,
    max_files: int = 200,
) -> ScanResult:
    """
    Scan a single repository for secrets.
    Returns a ScanResult with all findings.
    """
    repo_url = f"https://github.com/{owner}/{repo}"
    result = ScanResult(repo_url=repo_url, repo_name=f"{owner}/{repo}")

    try:
        tree_data = await client.get_tree(owner, repo)
        blobs = [
            item for item in tree_data.get("tree", [])
            if item["type"] == "blob"
            and any(item["path"].endswith(ext) for ext in SCANNABLE_EXTENSIONS)
            and item.get("size", 0) < MAX_FILE_SIZE
        ][:max_files]

        for blob in blobs:
            try:
                content = await client.get_file_content(owner, repo, blob["path"])
                result.findings.extend(scan_text(content, blob["path"], repo_url))
                result.files_scanned += 1
            except Exception:
                pass  # skip unreadable files

        # Augment with GitHub's own secret scanning alerts
        gh_alerts = await client.run_secret_scanning(owner, repo)
        for alert in gh_alerts:
            result.findings.append(Finding(
                type=alert.get("secret_type", "github_alert"),
                value=alert.get("secret", "***"),
                file=alert.get("locations", [{}])[0].get("details", {}).get("path", "unknown"),
                line=alert.get("locations", [{}])[0].get("details", {}).get("start_line", 0),
                severity=Severity.CRITICAL,
                repo_url=repo_url,
            ))

        result.status = "complete"
    except Exception as exc:
        result.status = f"error: {exc}"

    return result


async def scan_all_repos(
    client: GitHubClient,
    owner: str,
    is_org: bool = False,
    max_repos: int = 20,
) -> list[ScanResult]:
    """Scan all repos for an owner/org."""
    repos = await client.list_repos(org=owner if is_org else None,
                                    user=None if is_org else owner)
    results = []
    for repo_data in repos[:max_repos]:
        repo_name = repo_data["name"]
        print(f"  [Ghost AI] Scanning {owner}/{repo_name} ...", flush=True)
        result = await scan_repository(client, owner, repo_name)
        results.append(result)
        if result.findings:
            print(f"    Found {len(result.findings)} potential secret(s)", flush=True)
    return results


# ---------------------------------------------------------------------------
# Threat intelligence (local / static seed)
# ---------------------------------------------------------------------------

STATIC_CTI_FEED: list[ThreatFeedEntry] = [
    ThreatFeedEntry(
        title="Mass Credential Stuffing Campaign — GitHub Tokens",
        description="Threat actors scraping public repos for exposed GitHub tokens. Use gitleaks pre-commit hooks.",
        severity=Severity.CRITICAL,
        category="credential_exposure",
        source="Ghost AI Intel",
        tags=["github", "credentials", "scraping"],
    ),
    ThreatFeedEntry(
        title="TruffleHog Bypass via Unicode Homoglyphs",
        description="Attackers using Unicode lookalike characters in secret values to bypass regex-based detectors.",
        severity=Severity.HIGH,
        category="evasion",
        source="Ghost AI Intel",
        tags=["trufflehog", "evasion", "unicode"],
    ),
    ThreatFeedEntry(
        title="Supply Chain Risk: Typosquatted PyPI Packages",
        description="Multiple typosquatted packages containing embedded reverse shells detected on PyPI.",
        severity=Severity.CRITICAL,
        category="supply_chain",
        source="Ghost AI Intel",
        tags=["pypi", "supply-chain", "malware"],
    ),
    ThreatFeedEntry(
        title="BeEF Framework Exploitation via Reflected XSS",
        description="Active campaigns hooking browsers via reflected XSS, pivoting to internal networks.",
        severity=Severity.HIGH,
        category="web_exploitation",
        source="Ghost AI Intel",
        tags=["beef", "xss", "browser"],
    ),
    ThreatFeedEntry(
        title="Commix SSTI in Jinja2 Templates",
        description="Server-side template injection via unsanitized user input in Python web apps.",
        severity=Severity.HIGH,
        category="injection",
        source="Ghost AI Intel",
        tags=["commix", "ssti", "python"],
    ),
]


# ---------------------------------------------------------------------------
# Report generator
# ---------------------------------------------------------------------------

def generate_report(results: list[ScanResult], output_path: str = "ghost_ai_report.json") -> str:
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool": "Ghost AI Security Scanner",
        "version": "1.0.0",
        "summary": {
            "repos_scanned": len(results),
            "total_findings": sum(len(r.findings) for r in results),
            "by_severity": {
                s.value: sum(r.severity_summary.get(s.value, 0) for r in results)
                for s in Severity
            },
        },
        "results": [r.to_dict() for r in results],
        "threat_feed": [
            {
                "title": e.title,
                "description": e.description,
                "severity": e.severity.value,
                "category": e.category,
                "source": e.source,
                "tags": e.tags,
                "published_at": e.published_at,
            }
            for e in STATIC_CTI_FEED
        ],
    }
    with open(output_path, "w") as fh:
        json.dump(report, fh, indent=2)
    return output_path


# ---------------------------------------------------------------------------
# ADK agent tools
# ---------------------------------------------------------------------------

def make_ghost_ai_tools(client: GitHubClient):
    """Return a list of ADK-compatible tool callables."""

    async def scan_repo_tool(owner: str, repo: str) -> dict:
        """Scan a GitHub repository for exposed secrets and credentials."""
        result = await scan_repository(client, owner, repo)
        return result.to_dict()

    async def list_repos_tool(user: str) -> list[dict]:
        """List public repositories for a GitHub user."""
        repos = await client.list_repos(user=user)
        return [
            {"name": r["name"], "url": r["html_url"], "private": r["private"],
             "language": r.get("language"), "stars": r["stargazers_count"]}
            for r in repos
        ]

    async def threat_feed_tool(severity: str = "all") -> list[dict]:
        """Return the current Ghost AI threat intelligence feed."""
        entries = STATIC_CTI_FEED
        if severity != "all":
            entries = [e for e in entries if e.severity.value == severity.lower()]
        return [
            {"title": e.title, "description": e.description,
             "severity": e.severity.value, "category": e.category, "tags": e.tags}
            for e in entries
        ]

    async def get_repo_info_tool(owner: str, repo: str) -> dict:
        """Get detailed info about a GitHub repository."""
        data = await client.get_repo(owner, repo)
        return {
            "name": data["name"],
            "full_name": data["full_name"],
            "description": data.get("description"),
            "url": data["html_url"],
            "language": data.get("language"),
            "stars": data["stargazers_count"],
            "forks": data["forks_count"],
            "open_issues": data["open_issues_count"],
            "default_branch": data["default_branch"],
            "created_at": data["created_at"],
            "updated_at": data["updated_at"],
        }

    return [scan_repo_tool, list_repos_tool, threat_feed_tool, get_repo_info_tool]


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def main() -> None:
    token = os.environ.get("GITHUB_TOKEN") or (
        sys.argv[1] if len(sys.argv) > 1 else ""
    )
    if not token:
        print("ERROR: Set GITHUB_TOKEN env var or pass token as first argument.", file=sys.stderr)
        sys.exit(1)

    client = GitHubClient(token)

    # Identify the authenticated user
    user_info = await client.get_user()
    owner = user_info["login"]
    print(f"\n[Ghost AI] Authenticated as: {owner}")
    print("[Ghost AI] Starting security scan ...\n")

    # Scan all repos
    target_owner = sys.argv[2] if len(sys.argv) > 2 else owner
    results = await scan_all_repos(client, target_owner, max_repos=15)

    # Generate report
    report_path = generate_report(results)
    total = sum(len(r.findings) for r in results)
    critical = sum(r.severity_summary.get("critical", 0) for r in results)

    print(f"\n[Ghost AI] Scan complete.")
    print(f"  Repos scanned : {len(results)}")
    print(f"  Total findings: {total}")
    print(f"  Critical       : {critical}")
    print(f"  Report saved  : {report_path}")
    print(f"\n[Ghost AI] Threat Feed: {len(STATIC_CTI_FEED)} active entries")
    for entry in STATIC_CTI_FEED:
        print(f"  [{entry.severity.value.upper():8}] {entry.title}")


if __name__ == "__main__":
    asyncio.run(main())
