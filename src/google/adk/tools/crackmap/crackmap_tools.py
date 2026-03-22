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

"""CrackMapExec tool functions for the Ghost AI agent.

These tools wrap CrackMapExec (CME) for use in authorized penetration testing
and security assessment workflows orchestrated by the Ghost AI agent.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from typing import Any
from typing import Optional

import logging

logger = logging.getLogger("google_adk.crackmap")

# Regex patterns for parsing CME output lines
_CME_LINE_RE = re.compile(
    r"^(?P<proto>SMB|WINRM|SSH|LDAP|MSSQL|RDP|FTP)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<port>\d+)\s+"
    r"(?P<name>\S+)\s+"
    r"(?P<status>.*)"
)
_CME_CRED_RE = re.compile(
    r"\[(?P<symbol>[+\-!])\]\s+(?P<message>.+)"
)


def _cme_available() -> bool:
    return shutil.which("crackmapexec") is not None or shutil.which("cme") is not None


def _cme_binary() -> str:
    return "crackmapexec" if shutil.which("crackmapexec") else "cme"


def _run_cme(args: list[str], timeout: int = 120) -> dict[str, Any]:
    """Execute a CrackMapExec command and return structured output."""
    if not _cme_available():
        return {
            "error": "CrackMapExec not found. Install via: pip install crackmapexec",
            "available": False,
        }
    cmd = [_cme_binary()] + args
    logger.info("Running CME: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "available": True,
        }
    except subprocess.TimeoutExpired:
        return {"error": f"Command timed out after {timeout}s", "available": True}
    except Exception as e:  # pylint: disable=broad-except
        return {"error": str(e), "available": True}


def _parse_cme_output(raw_output: str) -> list[dict[str, Any]]:
    """Parse raw CME text output into structured records."""
    records = []
    for line in raw_output.splitlines():
        line = line.strip()
        # Strip ANSI color codes
        line = re.sub(r"\x1b\[[0-9;]*m", "", line)
        m = _CME_LINE_RE.match(line)
        if m:
            records.append({
                "protocol": m.group("proto"),
                "host": m.group("host"),
                "port": int(m.group("port")),
                "hostname": m.group("name"),
                "status": m.group("status").strip(),
                "pwned": "(Pwn3d!)" in m.group("status"),
            })
    return records


def scan_network(
    target: str,
    protocol: str = "smb",
    timeout: int = 60,
) -> dict[str, Any]:
    """Scan a network target using CrackMapExec.

    Performs host discovery and service enumeration on the specified target.
    Requires explicit authorization to run against the target network.

    Args:
        target: IP address, CIDR range, or hostname to scan (e.g. "192.168.1.0/24").
        protocol: CME protocol module to use: smb, winrm, ssh, ldap, mssql.
        timeout: Command timeout in seconds.

    Returns:
        Dictionary with scan results including discovered hosts and their status.
    """
    result = _run_cme([protocol, target, "--timeout", "5"], timeout=timeout)
    if "error" in result:
        return result
    hosts = _parse_cme_output(result["stdout"])
    return {
        "target": target,
        "protocol": protocol,
        "hosts_discovered": len(hosts),
        "hosts": hosts,
        "raw": result["stdout"],
    }


def enumerate_shares(
    target: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    domain: Optional[str] = None,
    timeout: int = 60,
) -> dict[str, Any]:
    """Enumerate SMB shares on target hosts.

    Lists accessible SMB shares and their permissions on discovered hosts.
    Requires explicit authorization to run against the target.

    Args:
        target: IP address or CIDR range to enumerate.
        username: Username for authentication (optional for null session).
        password: Password for authentication (optional).
        domain: Active Directory domain name (optional).
        timeout: Command timeout in seconds.

    Returns:
        Dictionary with share enumeration results per host.
    """
    args = ["smb", target, "--shares"]
    if username:
        args += ["-u", username]
    if password:
        args += ["-p", password]
    if domain:
        args += ["-d", domain]

    result = _run_cme(args, timeout=timeout)
    if "error" in result:
        return result

    shares: dict[str, list[dict]] = {}
    share_re = re.compile(
        r"SHARE\s+(?P<name>\S+)\s+(?P<perms>READ|WRITE|READ,WRITE|NO ACCESS|)\s*(?P<remark>.*)"
    )
    current_host = None
    for line in result["stdout"].splitlines():
        line = re.sub(r"\x1b\[[0-9;]*m", "", line)
        m = _CME_LINE_RE.match(line)
        if m:
            current_host = m.group("host")
            shares.setdefault(current_host, [])
        sm = share_re.search(line)
        if sm and current_host:
            shares[current_host].append({
                "name": sm.group("name"),
                "permissions": sm.group("perms").strip(),
                "remark": sm.group("remark").strip(),
            })

    return {
        "target": target,
        "shares_by_host": shares,
        "total_hosts": len(shares),
        "raw": result["stdout"],
    }


def check_credentials(
    target: str,
    username: str,
    password: str,
    protocol: str = "smb",
    domain: Optional[str] = None,
    timeout: int = 60,
) -> dict[str, Any]:
    """Test credentials against target hosts using CrackMapExec.

    Validates whether provided credentials are valid for accessing hosts.
    Must only be used against systems you own or have written authorization to test.

    Args:
        target: IP address or CIDR range to test.
        username: Username to test.
        password: Password to test.
        protocol: CME protocol: smb, winrm, ssh, ldap, mssql.
        domain: Active Directory domain (optional).
        timeout: Command timeout in seconds.

    Returns:
        Dictionary with credential validation results per host.
    """
    args = [protocol, target, "-u", username, "-p", password]
    if domain:
        args += ["-d", domain]

    result = _run_cme(args, timeout=timeout)
    if "error" in result:
        return result

    hosts = _parse_cme_output(result["stdout"])
    valid_hosts = [h for h in hosts if "+" in h.get("status", "") or h.get("pwned")]
    return {
        "target": target,
        "protocol": protocol,
        "username": username,
        "domain": domain,
        "valid_on": valid_hosts,
        "valid_count": len(valid_hosts),
        "total_tested": len(hosts),
        "raw": result["stdout"],
    }


def dump_sam(
    target: str,
    username: str,
    password: str,
    domain: Optional[str] = None,
    timeout: int = 120,
) -> dict[str, Any]:
    """Dump SAM database hashes from target hosts (requires admin privileges).

    Extracts local account hashes from the SAM database on Windows hosts.
    Requires administrator credentials and authorized access to the target.

    Args:
        target: IP address or CIDR range of target hosts.
        username: Administrator username.
        password: Administrator password.
        domain: Active Directory domain (optional).
        timeout: Command timeout in seconds.

    Returns:
        Dictionary with extracted SAM hashes per host.
    """
    args = ["smb", target, "-u", username, "-p", password, "--sam"]
    if domain:
        args += ["-d", domain]

    result = _run_cme(args, timeout=timeout)
    if "error" in result:
        return result

    hash_re = re.compile(r"(?P<user>\S+):(?P<rid>\d+):(?P<lm>[a-fA-F0-9]{32}):(?P<nt>[a-fA-F0-9]{32}):::")
    hashes_by_host: dict[str, list[dict]] = {}
    current_host = None
    for line in result["stdout"].splitlines():
        line = re.sub(r"\x1b\[[0-9;]*m", "", line)
        m = _CME_LINE_RE.match(line)
        if m:
            current_host = m.group("host")
            hashes_by_host.setdefault(current_host, [])
        hm = hash_re.search(line)
        if hm and current_host:
            hashes_by_host[current_host].append({
                "username": hm.group("user"),
                "rid": int(hm.group("rid")),
                "lm_hash": hm.group("lm"),
                "nt_hash": hm.group("nt"),
            })

    return {
        "target": target,
        "hashes_by_host": hashes_by_host,
        "total_hosts": len(hashes_by_host),
        "total_hashes": sum(len(v) for v in hashes_by_host.values()),
        "raw": result["stdout"],
    }


def run_command(
    target: str,
    command: str,
    username: str,
    password: str,
    protocol: str = "smb",
    domain: Optional[str] = None,
    timeout: int = 60,
) -> dict[str, Any]:
    """Execute a command on remote hosts via CrackMapExec.

    Runs an operating system command on target hosts using the specified protocol.
    Requires valid credentials and authorized access to the target systems.

    Args:
        target: IP address or CIDR range of target hosts.
        command: OS command to execute.
        username: Username with execution privileges.
        password: Password for authentication.
        protocol: CME protocol: smb, winrm, ssh.
        domain: Active Directory domain (optional).
        timeout: Command timeout in seconds.

    Returns:
        Dictionary with command output per host.
    """
    args = [protocol, target, "-u", username, "-p", password, "-x", command]
    if domain:
        args += ["-d", domain]

    result = _run_cme(args, timeout=timeout)
    if "error" in result:
        return result

    output_re = re.compile(r"\[(?P<symbol>[+!\-])\]\s+(?P<content>.+)")
    outputs_by_host: dict[str, list[str]] = {}
    current_host = None
    for line in result["stdout"].splitlines():
        line = re.sub(r"\x1b\[[0-9;]*m", "", line)
        m = _CME_LINE_RE.match(line)
        if m:
            current_host = m.group("host")
            outputs_by_host.setdefault(current_host, [])
        om = output_re.search(line)
        if om and current_host:
            outputs_by_host[current_host].append(om.group("content"))

    return {
        "target": target,
        "protocol": protocol,
        "command": command,
        "output_by_host": outputs_by_host,
        "hosts_executed": len(outputs_by_host),
        "raw": result["stdout"],
    }


def parse_scan_results(raw_output: str) -> dict[str, Any]:
    """Parse raw CrackMapExec output into structured JSON data.

    Converts free-text CME output (e.g. from log files) into structured
    records suitable for dashboard generation.

    Args:
        raw_output: Raw text output from a CrackMapExec command.

    Returns:
        Dictionary with parsed host records and summary statistics.
    """
    records = _parse_cme_output(raw_output)
    pwned = [r for r in records if r.get("pwned")]
    protocols = list({r["protocol"] for r in records})
    return {
        "total_hosts": len(records),
        "pwned_hosts": len(pwned),
        "protocols": protocols,
        "records": records,
    }
