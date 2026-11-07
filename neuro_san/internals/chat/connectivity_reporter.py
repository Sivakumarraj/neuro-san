
# Copyright © 2023-2026 Cognizant Technology Solutions Corp, www.cognizant.com.
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
#
# END COPYRIGHT
from typing import Any
from typing import Dict
from typing import List
from typing import Set

from logging import getLogger
from logging import Logger

from leaf_common.parsers.dictionary_extractor import DictionaryExtractor
from leaf_common.logging.log_once import LogOnce

from neuro_san.internals.interfaces.context_type_toolbox_factory import ContextTypeToolboxFactory
from neuro_san.internals.run_context.factory.master_toolbox_factory import MasterToolboxFactory
from neuro_san.internals.run_context.interfaces.agent_network_inspector import AgentNetworkInspector
from neuro_san.internals.utils.external_agent_parsing import ExternalAgentParsing
from neuro_san.internals.validation.network.abstract_network_validator import AbstractNetworkValidator


class ConnectivityReporter:
    """
    A class that knows how to report the connectivity of an entire AgentNetwork.

    Connectivity information comes as a series of AgentFramework
    messages, each of whose origin field reflects the name of the
    node and the content of the message is a JSON structure
    containing the list of tools that the node is connected to.

    *   The FrontMan is always sent first.
    *   Subsequent tool reporting proceeds in a breadth-first search, as per the
        ordering of the tools laid out in each agent spec.
    *   Cycles in the graph are mentioned in the tool reporting, but any node
        is only ever reported once.
    *   Hocon files can elect to hide the connectivity information from this reporting
        from any level on downstream by adding this block:
            "allow": {
                "connectivity": False
            }
        ...so if a network does not want connectivity reported at all, then this is only
        required in the front man's spec.
        Such a node will itself be reported, but with an empty tool list.
    *   External agents are reported but with an empty tool list.
        No effort to discover their internal connectivity is attempted.
        Maybe someday.
    *   A dictionary-form MCP reference is reported by its url, once per tool in its
        "tools" allow list as "<url>::<tool>", or as the url alone when it has none.
        See expand_tool_reference().
    """

    # Joins an MCP server url and one tool name into a single id. MCP tool names should be
    # ASCII letters, digits, "_", "-" and ".", so "::" cannot be part of a conforming name.
    # An id carries a tool when the text after its last "::" is such a name; a url alone,
    # even one with an IPv6 host such as "http://[::1]:8000/mcp", leaves "/" or "]" there.
    MCP_TOOL_ID_SEPARATOR: str = "::"

    def __init__(self, inspector: AgentNetworkInspector, toolbox_factory: ContextTypeToolboxFactory = None):
        """
        Constructor

        :param inspector: The AgentNetworkInspector to use.
        :param toolbox_factory: An optional ContextTypeToolboxFactory to consult
                        for display_as information about toolbox tools.
                        This should have been built from the same config as the
                        inspector's agent network and may be passed pre-loaded
                        so toolbox info files are not re-read per report.
                        If None, one is created from the inspector's config.
        """

        self.inspector: AgentNetworkInspector = inspector
        self.toolbox_factory: ContextTypeToolboxFactory = toolbox_factory

        if self.inspector is not None and self.toolbox_factory is None:
            wrapped_logger: Logger = getLogger(self.__class__.__name__)
            logger: LogOnce = LogOnce(wrapped_logger)
            logger.info("No toolbox_factory provided. Building one from the agent network config. "
                        "Pass a pre-loaded factory to avoid re-reading toolbox info files per report. "
                        "(Logged once per process.)")
            config: Dict[str, Any] = self.inspector.get_config()
            self.toolbox_factory = MasterToolboxFactory.create_toolbox_factory(config)

    def report_network_connectivity(self) -> List[Dict[str, Any]]:
        """
        Share the connectivity information of the agent network in question
        :return: A list of connectivity information dictionaries each with the following keys:
            * origin  - The agent network node whose connectivity is being described
            * tools   - A list of tool nodes that are possible to reach from the origin

                        This might include references into external agent networks, perhaps hosted
                        on other servers.  Separate calls to those guys will need to be made
                        in order to gain information about their own connectivity, if this is
                        actually desired by the client.

                        Worth noting that server-side agent descriptions are allowed to
                        withhold connectivity info they deem private, or too much of an
                        implementation detail.  That is, connectivity reported is only
                        as much as the server wants a client to know.
        """
        # Load the toolbox factory once
        if self.toolbox_factory is not None:
            self.toolbox_factory.load()

        # Find the name of the front-man as a root node
        front_man: str = self.inspector.find_front_man()

        # Do a breadth-first traversal starting with the front-man
        reported_agents: Set[str] = set()
        connectivity: List[Dict[str, Any]] = self.report_node_connectivity(front_man, reported_agents)
        return connectivity

    def report_node_connectivity(self, agent_name: str, reported_agents: Set[str]) -> List[Dict[str, Any]]:
        """
        Share the connectivity information of a single node in the network.
        :param agent_name: The name of the agent spec dictionary to report on
        :param reported_agents: A list of agents that have been reported already.
                Prevents cycles.
        :return: A list of connectivity information dictionaries.
        """

        connectivity_list: List[Dict[str, Any]] = []
        agent_spec: Dict[str, Any] = None
        display_as: str = None
        metadata: Dict[str, Any] = None

        if not ExternalAgentParsing.is_external_agent(agent_name):

            # This is not an external agent, so get its spec to report on
            agent_spec: Dict[str, Any] = self.inspector.get_agent_tool_spec(agent_name)
            if agent_spec is None:
                # The agent referred to by the caller is not actually in the agent network.
                # As a hint, don't report anything, not even an empty tool list.
                return connectivity_list

            # Check to see if this node in the graph actually wants its connectivity
            # known to the outside world.
            extractor = DictionaryExtractor(agent_spec)
            allow_connectivity = bool(extractor.get("allow.connectivity", True))
            if not bool(allow_connectivity):

                # We are not allowing connectivity reporting from here on down
                agent_spec = None
        else:
            display_as = "external_agent"

        # Compile a tool list of what is referred to by the agent_spec.
        # For many reasons, this list could be empty.
        tool_list: List[str] = self.assemble_tool_list(agent_spec)

        if display_as is None:
            display_as = self.determine_display_as(agent_spec)

        if agent_spec is not None:
            metadata = agent_spec.get("metadata")

        connectivity_dict: Dict[str, Any] = {
            # Report the origin as the agent itself, so any client that receives
            "origin": agent_name,
            # Report the content of the tools list
            "tools": tool_list,
            # Report how the node wishes to be displayed
            "display_as": display_as
        }

        if metadata is not None:
            # Report any metadata about the node but only if we have it
            connectivity_dict["metadata"] = metadata

        # the message has the correct context about the tools listed in the content.
        reported_agents.add(agent_name)
        connectivity_list.append(connectivity_dict)

        # Recurse for a bread-first search.
        for tool in tool_list:
            # Don't report more than once for the same node to avoid cycles.
            if tool not in reported_agents:
                new_list: List[Dict[str, Any]] = self.report_node_connectivity(tool, reported_agents)
                if len(new_list) > 0:
                    connectivity_list.extend(new_list)

        return connectivity_list

    @staticmethod
    def assemble_tool_list(agent_spec: Dict[str, Any]) -> List[str]:
        """
        :param agent_spec: The agent spec to assemble a tool list from.
        :return: A list of tool names referred to by the agent spec.
        """

        # Keep a list of the tools to respect the ordering they were specified.
        tool_list: List[str] = []

        if agent_spec is None:
            # Nothing to report
            return tool_list

        # Combine the traditional `tools` field with `args.tools` (the coded-tool
        # convention). coerce_* keep the result tolerant to malformed shapes.
        # Only `tools` can hold a dictionary-form MCP reference: `args.tools` must hold
        # agent names (ToolsShapeValidator.validate_args_tools), so a dict there is dropped.
        coerced_tools: List[Any] = AbstractNetworkValidator.coerce_tools(agent_spec)
        coerced_args_tools: List[Any] = AbstractNetworkValidator.coerce_args_tools(agent_spec)
        combined: List[Any] = coerced_tools + AbstractNetworkValidator.remove_dictionary_tools(coerced_args_tools)

        # Keep a set of the combined sources of tools,
        # so connectivity only gets reported once.
        tool_set: Set[str] = set()
        tool: Any = None
        # Each reference becomes zero or more string ids, so the dedup set never sees a dict.
        for tool in combined:
            entry: str = None
            # Each id is reported once, in the order it was first seen.
            for entry in ConnectivityReporter.expand_tool_reference(tool):
                if entry not in tool_set:
                    tool_set.add(entry)
                    tool_list.append(entry)

        return tool_list

    @staticmethod
    def expand_tool_reference(tool: Any) -> List[str]:
        """
        Turn one entry of an agent's tools list into the ids the connectivity report lists for it,
        so that the report shows what the agent can reach at run time.

        A string is reported as given. A dictionary-form MCP reference is reported by its url, as
        LangChainMcpAdapter.get_mcp_tools() reads its "tools" allow list:
            *   No allow list, or an empty one: the url alone. The agent gets every tool the server
                lists, or, for a missing list, the tools its MCP servers info entry allows.
            *   A list: "<url>::<tool>" for each entry that is a non-empty string, the entries the
                adapter can use. A list with none of those gives the agent no tools, so nothing.
            *   Any other shape, such as a bare string: nothing. The adapter would treat it as a
                list of its characters, which grants practically no tools.
        Anything else, such as a dictionary with no url, is not reported.

        :param tool: One entry of an agent's tools list
        :return: The ids to report for the entry, possibly none
        """
        if isinstance(tool, str):
            return [tool]

        expanded: List[str] = []
        if not isinstance(tool, dict) or not isinstance(tool.get("url"), str):
            # Not a reference that can be reported, such as a dict with no url.
            return expanded

        url: str = tool.get("url")
        allowed: Any = tool.get("tools")
        if not allowed:
            # No allow list: the whole server is one node.
            expanded.append(url)
            return expanded

        if not isinstance(allowed, list):
            # A malformed allow list grants practically nothing at run time.
            return expanded

        name: Any = None
        # Each usable tool name in the allow list is its own node for the client to draw.
        for name in allowed:
            if isinstance(name, str) and len(name) > 0:
                expanded.append(f"{url}{ConnectivityReporter.MCP_TOOL_ID_SEPARATOR}{name}")

        return expanded

    def determine_display_as(self, agent_spec: Dict[str, Any]) -> str:
        """
        :param agent_spec: The agent spec to determine display_as from.
        :return: A string describing how the node wants to be seen.
        """
        # Attempt to get something node-specific from the spec.
        display_as: str = agent_spec.get("display_as")
        if display_as is not None:
            display_as = str(display_as)
            return display_as

        tool_name: str = agent_spec.get("toolbox")
        if tool_name is not None:
            # As a default, assume something from the toolbox is a lanchain_tool.
            display_as = "langchain_tool"

            tool_info: Dict[str, Any] = None
            if self.toolbox_factory is not None:
                tool_info = self.toolbox_factory.get_tool_info(tool_name)

            if tool_info is not None:
                if tool_info.get("display_as") is not None:
                    # Tool infos in a toolbox hocon can have their own display_as for potential branding
                    display_as = tool_info.get("display_as")
                elif tool_info.get("description") is not None:
                    # Shared coded tools need to at least specify their description,
                    # whereas langchain_tools get the description from their @tool annotation
                    display_as = "coded_tool"

        elif agent_spec.get("function") is not None:
            # If we have a function in the spec, the agent has arguments
            # it wants to be called with.
            if agent_spec.get("class") is not None:
                display_as = "coded_tool"
            else:
                display_as = "llm_agent"
        else:
            # Front-man
            display_as = "llm_agent"

        return display_as
