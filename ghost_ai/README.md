# Ghost AI 👻

**Security Intelligence Platform** — GitHub API Integration  
Built on Google ADK Python · No wallet integration

## Features

- **Secret Scanner** — scans GitHub repos for exposed tokens, API keys, passwords, private keys
- **Threat Intelligence Feed** — CTI entries for active campaigns
- **Security Tool Hub** — integrates with Gitleaks, TruffleHog, BeEF, Commix, W3AF, Aircrack-ng, Unblob
- **ADK Agent** — runnable as a Google ADK agent with tool-use
- **Report Generator** — JSON export of all findings

## Quick Start

```bash
# Install deps
pip install httpx google-adk

# Set your GitHub token
export GITHUB_TOKEN=ghp_your_token_here

# Run the master scanner
python -m ghost_ai.master

# Or scan a specific user
python ghost_ai/master.py $GITHUB_TOKEN nostalgia2812

# Run as ADK agent
adk run ghost_ai.adk_agent
```

## Secret Patterns Detected

| Pattern | Severity |
|---|---|
| GitHub tokens (classic + fine-grained) | Critical |
| AWS Access/Secret Keys | Critical |
| Private key headers (RSA, EC, OpenSSH) | Critical |
| Stripe secret keys | Critical |
| Google API keys | High |
| Slack tokens | High |
| Database connection strings | High |
| JWT tokens | Medium |
| Generic API keys | Medium |
| Password literals | Low |

## Architecture

```
ghost_ai/
  master.py       ← Main scanner + GitHub API client + report generator
  adk_agent.py    ← ADK agent registration (tools + system prompt)
  imagery.py      ← Branding assets (banner, SVG ghost, severity icons)
  __init__.py     ← Public API
  requirements.txt
```

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `GITHUB_TOKEN` | Yes | GitHub personal access token |
| `GHOST_AI_MODEL` | No | ADK model override (default: `gemini-2.0-flash`) |

## Security Notes

- Finding values are **redacted** in all reports (first 20 chars + `***`)
- Never commit your `GITHUB_TOKEN`
- Only scan repos you own or have explicit written authorisation to test
