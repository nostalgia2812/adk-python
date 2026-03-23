"""
Ghost AI — ADK Agent Definition

Registers Ghost AI as a Google ADK agent with security-focused tools.
Run with: adk run ghost_ai.adk_agent
"""

from __future__ import annotations

import os
from typing import Any

try:
    from google.adk.agents import Agent
    from google.adk.tools import FunctionTool
except ImportError:
    raise ImportError(
        "google-adk is required. Install with: pip install google-adk"
    )

from .master import (
    GitHubClient,
    make_ghost_ai_tools,
)

_SYSTEM_PROMPT = """
You are Ghost AI — a security intelligence assistant specialising in:
- GitHub repository secret scanning and credential exposure detection
- Cyber threat intelligence (CTI) analysis
- Security tool orchestration (Gitleaks, TruffleHog, BeEF, Commix, W3AF, Aircrack-ng, Unblob)
- Vulnerability triage and remediation guidance

Be concise, precise, and security-focused. Always highlight critical findings first.
Never store or log plaintext secrets found during scans.
Do NOT provide guidance on malicious offensive operations against systems the user
does not own or have explicit written authorisation to test.
"""


def create_ghost_agent() -> Agent:
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        raise EnvironmentError("GITHUB_TOKEN environment variable is required.")

    gh_client = GitHubClient(token)
    tool_fns = make_ghost_ai_tools(gh_client)
    tools = [FunctionTool(fn) for fn in tool_fns]

    agent = Agent(
        name="ghost_ai",
        model=os.environ.get("GHOST_AI_MODEL", "gemini-2.0-flash"),
        description="Ghost AI — GitHub security scanner and threat intelligence platform",
        instruction=_SYSTEM_PROMPT,
        tools=tools,
    )
    return agent


# ADK entrypoint
root_agent = create_ghost_agent()
