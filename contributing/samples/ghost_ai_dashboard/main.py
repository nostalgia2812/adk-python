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

"""Entry point for the Ghost AI dashboard agent demo.

Demonstrates dashboard generation from a mock CrackMapExec scan result,
useful for testing the integration without a live network target.

Run:
    python -m contributing.samples.ghost_ai_dashboard.main
"""

import asyncio
import os

from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types as genai_types

from .agent import root_agent

# Sample CME output used when GHOST_USE_MOCK=1 (default for demos)
_MOCK_CME_OUTPUT = """\
SMB  192.168.1.10  445  DC01   [*] Windows Server 2019 (name:DC01) (domain:CORP) (signing:True) (SMBv1:False)
SMB  192.168.1.10  445  DC01   [+] CORP\\Administrator:P@ssw0rd (Pwn3d!)
SMB  192.168.1.20  445  WEB01  [*] Windows 10.0 Build 19041 (name:WEB01) (domain:CORP) (signing:False) (SMBv1:False)
SMB  192.168.1.20  445  WEB01  [+] CORP\\jsmith:Welcome1
SMB  192.168.1.30  445  FILE01 [*] Windows Server 2016 (name:FILE01) (domain:CORP) (signing:False) (SMBv1:False)
SMB  192.168.1.30  445  FILE01 [-] CORP\\guest: STATUS_LOGON_FAILURE
"""

_MOCK_SHARES = {
    "shares_by_host": {
        "192.168.1.10": [
            {"name": "ADMIN$", "permissions": "READ,WRITE", "remark": "Remote Admin"},
            {"name": "C$", "permissions": "READ,WRITE", "remark": "Default share"},
            {"name": "SYSVOL", "permissions": "READ", "remark": "Logon server share"},
            {"name": "NETLOGON", "permissions": "READ", "remark": "Logon server share"},
        ],
        "192.168.1.30": [
            {"name": "Backups", "permissions": "READ,WRITE", "remark": "IT Backups"},
            {"name": "Finance", "permissions": "READ", "remark": "Finance data"},
            {"name": "IPC$", "permissions": "NO ACCESS", "remark": "IPC"},
        ],
    },
    "total_hosts": 2,
}


async def run_demo() -> None:
    """Run the Ghost AI agent with a mock scan and generate a dashboard."""
    use_mock = os.environ.get("GHOST_USE_MOCK", "1") == "1"

    session_service = InMemorySessionService()
    runner = Runner(
        agent=root_agent,
        app_name="ghost_ai_demo",
        session_service=session_service,
    )
    session = await session_service.create_session(
        app_name="ghost_ai_demo",
        user_id="demo_user",
    )

    if use_mock:
        prompt = (
            "I have the following CrackMapExec output from an authorized assessment "
            "of the 192.168.1.0/24 network. Please parse it, analyze the results, "
            "and generate a full HTML dashboard saved to ghost_ai_report.html.\n\n"
            f"```\n{_MOCK_CME_OUTPUT}\n```\n\n"
            "Also include these share enumeration results in the dashboard:\n"
            f"{_MOCK_SHARES}\n\n"
            "Provide detailed AI insights covering risk findings and remediation steps."
        )
    else:
        target = os.environ.get("GHOST_TARGET", "")
        if not target:
            print("Set GHOST_TARGET=<CIDR> and GHOST_USE_MOCK=0 to run a live scan.")
            return
        prompt = (
            f"Perform a full network assessment of {target}. "
            "Discover hosts, enumerate shares, then generate an HTML dashboard "
            "saved to ghost_ai_report.html."
        )

    print(f"Ghost AI starting {'(mock mode)' if use_mock else '(live mode)'}...")
    print("-" * 60)

    async for event in runner.run_async(
        user_id="demo_user",
        session_id=session.id,
        new_message=genai_types.Content(
            role="user",
            parts=[genai_types.Part.from_text(text=prompt)],
        ),
    ):
        if event.content and event.content.parts:
            for part in event.content.parts:
                if hasattr(part, "text") and part.text:
                    print(part.text, end="", flush=True)

    print("\n" + "-" * 60)
    if os.path.exists("ghost_ai_report.html"):
        print("Dashboard written to: ghost_ai_report.html")
    else:
        print("Dashboard generation complete.")


if __name__ == "__main__":
    asyncio.run(run_demo())
