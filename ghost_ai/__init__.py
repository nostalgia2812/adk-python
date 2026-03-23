"""
Ghost AI — Security Intelligence Platform
"""

from .master import (
    GitHubClient,
    ScanResult,
    Finding,
    Severity,
    ThreatFeedEntry,
    scan_repository,
    scan_all_repos,
    generate_report,
    STATIC_CTI_FEED,
    SECRET_PATTERNS,
)

__all__ = [
    "GitHubClient",
    "ScanResult",
    "Finding",
    "Severity",
    "ThreatFeedEntry",
    "scan_repository",
    "scan_all_repos",
    "generate_report",
    "STATIC_CTI_FEED",
    "SECRET_PATTERNS",
]
