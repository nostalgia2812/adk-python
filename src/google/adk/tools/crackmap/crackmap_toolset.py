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

"""CrackMapExec toolset for the Ghost AI dashboard agent."""

from __future__ import annotations

from typing import List
from typing import Optional
from typing import Union

from google.adk.agents.readonly_context import ReadonlyContext
from typing_extensions import override

from ..base_tool import BaseTool
from ..base_toolset import BaseToolset
from ..base_toolset import ToolPredicate
from ..function_tool import FunctionTool
from . import crackmap_tools
from .dashboard_generator import generate_dashboard


class CrackMapToolset(BaseToolset):
    """Toolset integrating CrackMapExec with Ghost AI dashboard generation.

    Provides a set of ADK-compatible tools for running authorized network
    assessments via CrackMapExec and generating interactive HTML dashboards
    from the results.

    Example::

        from google.adk.tools.crackmap import CrackMapToolset
        from google.adk.agents import Agent

        agent = Agent(
            model="gemini-2.5-pro",
            name="ghost_ai",
            instruction="You are Ghost AI, a security assessment agent...",
            tools=[CrackMapToolset()],
        )

    Note:
        CrackMapExec must be installed in the execution environment.
        All scans must be performed against systems the operator owns or has
        explicit written authorization to test.
    """

    def __init__(
        self,
        *,
        tool_filter: Optional[Union[ToolPredicate, List[str]]] = None,
    ):
        """Initialize the CrackMapToolset.

        Args:
            tool_filter: Optional list of tool names or a predicate to restrict
                which tools are exposed to the agent.
        """
        super().__init__(tool_filter=tool_filter)
        self._tools: List[BaseTool] = [
            FunctionTool(crackmap_tools.scan_network),
            FunctionTool(crackmap_tools.enumerate_shares),
            FunctionTool(crackmap_tools.check_credentials),
            FunctionTool(crackmap_tools.dump_sam),
            FunctionTool(crackmap_tools.run_command),
            FunctionTool(crackmap_tools.parse_scan_results),
            FunctionTool(generate_dashboard),
        ]

    def _is_tool_selected(
        self, tool: BaseTool, readonly_context: ReadonlyContext
    ) -> bool:
        if self.tool_filter is None:
            return True
        if isinstance(self.tool_filter, ToolPredicate):
            return self.tool_filter(tool, readonly_context)
        if isinstance(self.tool_filter, list):
            return tool.name in self.tool_filter
        return False

    @override
    async def get_tools(
        self, readonly_context: Optional[ReadonlyContext] = None
    ) -> List[BaseTool]:
        """Return the CrackMapExec tools filtered by the configured predicate."""
        if readonly_context is None:
            return list(self._tools)
        return [t for t in self._tools if self._is_tool_selected(t, readonly_context)]

    @override
    async def close(self) -> None:
        pass
