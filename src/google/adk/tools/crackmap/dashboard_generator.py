# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Dashboard generator for CrackMapExec scan results.

Converts structured scan data into interactive HTML dashboards for use
in Ghost AI security assessment reports.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any


_DASHBOARD_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Ghost AI — Network Assessment Dashboard</title>
  <style>
    :root {{
      --bg: #0d1117;
      --card: #161b22;
      --border: #30363d;
      --accent: #58a6ff;
      --danger: #f85149;
      --warn: #e3b341;
      --ok: #3fb950;
      --muted: #8b949e;
      --text: #c9d1d9;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: var(--bg);
      color: var(--text);
      font-family: 'Segoe UI', system-ui, sans-serif;
      padding: 24px;
    }}
    header {{
      display: flex;
      align-items: center;
      gap: 16px;
      margin-bottom: 32px;
      border-bottom: 1px solid var(--border);
      padding-bottom: 16px;
    }}
    header h1 {{ font-size: 1.6rem; color: var(--accent); }}
    header .meta {{ font-size: 0.85rem; color: var(--muted); }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-bottom: 32px;
    }}
    .stat-card {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 20px;
    }}
    .stat-card .label {{ font-size: 0.8rem; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; }}
    .stat-card .value {{ font-size: 2rem; font-weight: 700; margin-top: 4px; }}
    .stat-card.danger .value {{ color: var(--danger); }}
    .stat-card.warn .value {{ color: var(--warn); }}
    .stat-card.ok .value {{ color: var(--ok); }}
    .stat-card.accent .value {{ color: var(--accent); }}
    section {{ margin-bottom: 32px; }}
    section h2 {{
      font-size: 1rem;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: .08em;
      margin-bottom: 12px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background: var(--card);
      border-radius: 8px;
      overflow: hidden;
      border: 1px solid var(--border);
    }}
    th {{
      background: #21262d;
      padding: 10px 16px;
      text-align: left;
      font-size: 0.8rem;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: .05em;
    }}
    td {{
      padding: 10px 16px;
      border-top: 1px solid var(--border);
      font-size: 0.9rem;
    }}
    tr:hover td {{ background: #1c2128; }}
    .badge {{
      display: inline-block;
      padding: 2px 8px;
      border-radius: 12px;
      font-size: 0.75rem;
      font-weight: 600;
    }}
    .badge-danger {{ background: rgba(248,81,73,.15); color: var(--danger); }}
    .badge-ok {{ background: rgba(63,185,80,.15); color: var(--ok); }}
    .badge-warn {{ background: rgba(227,179,65,.15); color: var(--warn); }}
    .badge-info {{ background: rgba(88,166,255,.15); color: var(--accent); }}
    .ai-insights {{
      background: var(--card);
      border: 1px solid var(--border);
      border-left: 3px solid var(--accent);
      border-radius: 8px;
      padding: 20px;
      white-space: pre-wrap;
      font-size: 0.9rem;
      line-height: 1.6;
    }}
    .protocol-bar {{
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin-bottom: 16px;
    }}
    .timestamp {{ color: var(--muted); font-size: 0.8rem; }}
  </style>
</head>
<body>
  <header>
    <div>
      <h1>&#128123; Ghost AI — Network Assessment Dashboard</h1>
      <div class="meta">
        Target: <strong>{target}</strong> &nbsp;|&nbsp;
        Generated: <span class="timestamp">{generated_at}</span>
      </div>
    </div>
  </header>

  <div class="grid">
    <div class="stat-card accent">
      <div class="label">Hosts Discovered</div>
      <div class="value">{total_hosts}</div>
    </div>
    <div class="stat-card danger">
      <div class="label">Compromised Hosts</div>
      <div class="value">{pwned_hosts}</div>
    </div>
    <div class="stat-card warn">
      <div class="label">Unique Protocols</div>
      <div class="value">{protocol_count}</div>
    </div>
    <div class="stat-card ok">
      <div class="label">Valid Credentials</div>
      <div class="value">{valid_creds}</div>
    </div>
  </div>

  <section>
    <h2>Protocols Detected</h2>
    <div class="protocol-bar">
      {protocol_badges}
    </div>
  </section>

  <section>
    <h2>Host Inventory</h2>
    <table>
      <thead>
        <tr>
          <th>Host</th>
          <th>Hostname</th>
          <th>Protocol</th>
          <th>Port</th>
          <th>Status</th>
          <th>Compromised</th>
        </tr>
      </thead>
      <tbody>
        {host_rows}
      </tbody>
    </table>
  </section>

  {shares_section}

  {hashes_section}

  <section>
    <h2>&#129504; Ghost AI Insights</h2>
    <div class="ai-insights">{ai_insights}</div>
  </section>

  <script>
    // Embed raw scan data for further processing
    window.GHOST_SCAN_DATA = {scan_data_json};
  </script>
</body>
</html>
"""

_HOST_ROW_TEMPLATE = """\
<tr>
  <td><code>{host}</code></td>
  <td>{hostname}</td>
  <td><span class="badge badge-info">{protocol}</span></td>
  <td>{port}</td>
  <td>{status}</td>
  <td>{pwned_badge}</td>
</tr>"""

_SHARE_ROW_TEMPLATE = """\
<tr>
  <td><code>{host}</code></td>
  <td>{name}</td>
  <td><span class="badge {perm_class}">{permissions}</span></td>
  <td>{remark}</td>
</tr>"""

_HASH_ROW_TEMPLATE = """\
<tr>
  <td><code>{host}</code></td>
  <td>{username}</td>
  <td>{rid}</td>
  <td><code>{nt_hash}</code></td>
</tr>"""


def _perm_badge_class(perms: str) -> str:
    if "WRITE" in perms:
        return "badge-danger"
    if "READ" in perms:
        return "badge-warn"
    return "badge-ok"


class DashboardGenerator:
    """Generates interactive HTML dashboards from CrackMapExec scan results."""

    def generate(
        self,
        scan_results: dict[str, Any],
        *,
        target: str = "unknown",
        ai_insights: str = "",
        shares_data: dict[str, Any] | None = None,
        hashes_data: dict[str, Any] | None = None,
    ) -> str:
        """Generate an HTML dashboard from scan results.

        Args:
            scan_results: Structured output from ``parse_scan_results`` or
                ``scan_network``.
            target: Human-readable target identifier.
            ai_insights: AI-generated analysis text to embed in the report.
            shares_data: Optional share enumeration results.
            hashes_data: Optional SAM dump results.

        Returns:
            Full HTML string of the dashboard.
        """
        records = scan_results.get("hosts") or scan_results.get("records", [])
        total_hosts = scan_results.get("hosts_discovered") or scan_results.get("total_hosts", len(records))
        pwned_hosts = scan_results.get("pwned_hosts", sum(1 for r in records if r.get("pwned")))
        protocols = scan_results.get("protocols") or list({r.get("protocol", "") for r in records if r.get("protocol")})
        valid_creds = scan_results.get("valid_count", 0)

        # Protocol badges
        protocol_badges = " ".join(
            f'<span class="badge badge-info">{p}</span>' for p in sorted(protocols)
        ) or '<span class="badge badge-ok">None detected</span>'

        # Host rows
        host_rows = "\n".join(
            _HOST_ROW_TEMPLATE.format(
                host=r.get("host", ""),
                hostname=r.get("hostname", ""),
                protocol=r.get("protocol", ""),
                port=r.get("port", ""),
                status=r.get("status", ""),
                pwned_badge=(
                    '<span class="badge badge-danger">&#10004; Pwned</span>'
                    if r.get("pwned")
                    else '<span class="badge badge-ok">No</span>'
                ),
            )
            for r in records
        ) or "<tr><td colspan='6' style='text-align:center;color:var(--muted)'>No hosts found</td></tr>"

        # Shares section
        shares_section = ""
        if shares_data and shares_data.get("shares_by_host"):
            rows = []
            for host, shares in shares_data["shares_by_host"].items():
                for s in shares:
                    rows.append(_SHARE_ROW_TEMPLATE.format(
                        host=host,
                        name=s.get("name", ""),
                        permissions=s.get("permissions", ""),
                        perm_class=_perm_badge_class(s.get("permissions", "")),
                        remark=s.get("remark", ""),
                    ))
            if rows:
                shares_section = f"""
<section>
  <h2>SMB Shares</h2>
  <table>
    <thead>
      <tr><th>Host</th><th>Share</th><th>Permissions</th><th>Remark</th></tr>
    </thead>
    <tbody>{"".join(rows)}</tbody>
  </table>
</section>"""

        # Hashes section
        hashes_section = ""
        if hashes_data and hashes_data.get("hashes_by_host"):
            rows = []
            for host, hashes in hashes_data["hashes_by_host"].items():
                for h in hashes:
                    rows.append(_HASH_ROW_TEMPLATE.format(
                        host=host,
                        username=h.get("username", ""),
                        rid=h.get("rid", ""),
                        nt_hash=h.get("nt_hash", ""),
                    ))
            if rows:
                hashes_section = f"""
<section>
  <h2>Extracted Hashes (SAM)</h2>
  <table>
    <thead>
      <tr><th>Host</th><th>Username</th><th>RID</th><th>NT Hash</th></tr>
    </thead>
    <tbody>{"".join(rows)}</tbody>
  </table>
</section>"""

        scan_data_json = json.dumps(
            {
                "target": target,
                "records": records,
                "shares": shares_data,
                "hashes": hashes_data,
            },
            indent=2,
        )

        return _DASHBOARD_HTML_TEMPLATE.format(
            target=target,
            generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            total_hosts=total_hosts,
            pwned_hosts=pwned_hosts,
            protocol_count=len(protocols),
            valid_creds=valid_creds,
            protocol_badges=protocol_badges,
            host_rows=host_rows,
            shares_section=shares_section,
            hashes_section=hashes_section,
            ai_insights=ai_insights or "No AI analysis available.",
            scan_data_json=scan_data_json,
        )


def generate_dashboard(
    scan_results: dict[str, Any],
    target: str = "unknown",
    ai_insights: str = "",
    shares_data: dict[str, Any] | None = None,
    hashes_data: dict[str, Any] | None = None,
    output_path: str | None = None,
) -> str:
    """Generate an HTML dashboard and optionally write it to a file.

    Args:
        scan_results: Structured scan data from CrackMapExec tools.
        target: Human-readable target identifier for the report header.
        ai_insights: AI-generated analysis text from the Ghost AI agent.
        shares_data: Optional SMB share enumeration results.
        hashes_data: Optional SAM hash dump results.
        output_path: If provided, write the HTML to this file path.

    Returns:
        HTML string of the generated dashboard.
    """
    html = DashboardGenerator().generate(
        scan_results,
        target=target,
        ai_insights=ai_insights,
        shares_data=shares_data,
        hashes_data=hashes_data,
    )
    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
    return html
