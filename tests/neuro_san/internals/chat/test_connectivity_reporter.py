
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

import os

from unittest import TestCase
from unittest.mock import patch

from neuro_san import REGISTRIES_DIR
from neuro_san.internals.chat.connectivity_reporter import ConnectivityReporter
from neuro_san.internals.graph.registry.agent_network import AgentNetwork
from neuro_san.internals.graph.persistence.agent_network_restorer import AgentNetworkRestorer
from neuro_san.internals.run_context.langchain.toolbox.toolbox_factory import ToolboxFactory


class TestConnectivityReporter(TestCase):
    """
    Unit tests for ConnectivityReporter class.
    """

    def test_assumptions(self):
        """
        Can we construct?
        """
        agent_network: AgentNetwork = None
        reporter = ConnectivityReporter(agent_network)
        self.assertIsNotNone(reporter)

    def get_sample_registry(self, hocon_file: str) -> AgentNetwork:
        """
        :param hocon_file: A hocon file reference within this repo
        """
        file_reference = REGISTRIES_DIR.get_file_in_basis(hocon_file)
        restorer = AgentNetworkRestorer()
        agent_network: AgentNetwork = restorer.restore(file_reference=file_reference)
        return agent_network

    def test_hello_world(self):
        """
        Tests the connectivity of the hello world hocon
        """
        agent_network: AgentNetwork = self.get_sample_registry("hello_world.hocon")

        # The reporter's self-built factory reads AGENT_TOOLBOX_INFO_FILE at
        # construction. Keep the test hermetic against the environment.
        with patch.dict(os.environ):
            os.environ.pop("AGENT_TOOLBOX_INFO_FILE", None)
            reporter = ConnectivityReporter(agent_network)
            messages: List[Dict[str, Any]] = reporter.report_network_connectivity()
        self.assertEqual(len(messages), 2)

        # First guy is the front-man and he only has a single tool
        connectivity: Dict[str, Any] = messages[0]
        self.assertIsNotNone(connectivity)
        self.assertEqual(connectivity.get("display_as"), "llm_agent")

        tools: List[str] = connectivity.get("tools")
        self.assertIsNotNone(tools)
        self.assertEqual(len(tools), 1)
        self.assertEqual(tools[0], "synonymizer")

        # Next guy is the synonymizer and has no tools
        connectivity: Dict[str, Any] = messages[1]
        self.assertIsNotNone(connectivity)
        self.assertEqual(connectivity.get("display_as"), "llm_agent")

        tools: List[str] = connectivity.get("tools")
        self.assertIsNotNone(tools)
        self.assertEqual(len(tools), 0)

    def test_injected_toolbox_factory_is_used(self):
        """
        Tests that a toolbox factory passed to the constructor is used as-is
        rather than being replaced by one built from the inspector's config,
        and that reporting loads it.
        """
        agent_network: AgentNetwork = self.get_sample_registry("hello_world.hocon")
        toolbox_factory = ToolboxFactory()
        # Keep the test hermetic: no user toolbox info file on the injected
        # factory, nor from the environment should a self-built factory
        # ever be constructed (the regression this test guards against).
        toolbox_factory.toolbox_info_file = None
        with patch.dict(os.environ):
            os.environ.pop("AGENT_TOOLBOX_INFO_FILE", None)
            reporter = ConnectivityReporter(agent_network, toolbox_factory)
            self.assertIs(reporter.toolbox_factory, toolbox_factory)

            messages: List[Dict[str, Any]] = reporter.report_network_connectivity()
        self.assertEqual(len(messages), 2)
        self.assertTrue(toolbox_factory.loaded)

    def test_injected_toolbox_factory_data_is_consulted(self):
        """
        Tests that display_as information comes from the injected factory's
        toolbox infos, not from a factory built behind the scenes.
        """
        agent_network: AgentNetwork = self.get_sample_registry("date_time_timezone.hocon")
        toolbox_factory = ToolboxFactory()
        # Keep the test hermetic: no user toolbox info file on the injected
        # factory, nor from the environment should a self-built factory
        # ever be constructed (the regression this test guards against).
        toolbox_factory.toolbox_info_file = None
        # Seed distinctive tool info and mark loaded so load() keeps it as-is.
        # A self-built or bundled factory would report "coded_tool" instead.
        toolbox_factory.toolbox_infos = {
            "get_current_date_time": {
                "class": "mock_package.mock_module.MockTool",
                "display_as": "injected_tool",
            }
        }
        toolbox_factory.loaded = True

        with patch.dict(os.environ):
            os.environ.pop("AGENT_TOOLBOX_INFO_FILE", None)
            reporter = ConnectivityReporter(agent_network, toolbox_factory)
            messages: List[Dict[str, Any]] = reporter.report_network_connectivity()

        display_as_by_origin: Dict[str, str] = {
            message.get("origin"): message.get("display_as") for message in messages
        }
        self.assertEqual(display_as_by_origin.get("current_date_time"), "injected_tool")

    def test_assemble_tool_list_args_tools_dict(self):
        """
        Tests that an agent referencing downstream agents via `args.tools`
        as a dict (the coded-tool convention) has those references included
        in the assembled tool list. Previously the dict.values() result was
        a dict_values view that failed the isinstance(args_tools, List)
        check, silently dropping all coded-tool down-chains.
        """
        agent_spec: Dict[str, Any] = {
            "args": {"tools": {"helper": "agent_a", "fallback": "agent_b"}},
        }
        tools: List[str] = ConnectivityReporter.assemble_tool_list(agent_spec)
        self.assertEqual(sorted(tools), ["agent_a", "agent_b"])

    def test_assemble_tool_list_tools_as_string_does_not_iterate_chars(self):
        """
        Tests that a malformed `tools` field (string instead of list) does
        not silently iterate the string character-by-character. coerce_tools
        treats it as empty.
        """
        agent_spec: Dict[str, Any] = {"tools": "agent_a"}
        tools: List[str] = ConnectivityReporter.assemble_tool_list(agent_spec)
        self.assertEqual([], tools)

    def test_assemble_tool_list_dict_element_does_not_crash(self):
        """
        Tests that a dict element in `tools` with no url is filtered out
        instead of raising TypeError: unhashable type: 'dict' when added to
        the dedup set. Other string entries are retained.
        """
        agent_spec: Dict[str, Any] = {
            "tools": ["agent_a", {"server": "mcp_server"}, "agent_b"],
        }
        tools: List[str] = ConnectivityReporter.assemble_tool_list(agent_spec)
        self.assertEqual(tools, ["agent_a", "agent_b"])

    def test_assemble_tool_list_expands_filtered_dict_mcp_reference(self) -> None:
        """
        Tests that a dict-form MCP reference with a tools allow list is reported once per
        tool, as "<url>::<tool>", next to the string references.
        """
        agent_spec: Dict[str, Any] = {
            "name": "front_man",
            "tools": [
                "helper",
                "https://example.com/mcp",
                {"url": "https://example.com/other/mcp", "tools": ["tool_1", "tool_2"]},
            ],
        }
        tools: List[str] = ConnectivityReporter.assemble_tool_list(agent_spec)
        self.assertEqual(tools, [
            "helper",
            "https://example.com/mcp",
            "https://example.com/other/mcp::tool_1",
            "https://example.com/other/mcp::tool_2",
        ])

    def test_assemble_tool_list_reports_dict_mcp_reference_without_allow_list_as_its_url(self) -> None:
        """
        Tests that a dict-form MCP reference with no allow list, or an empty one, is reported
        as its url, because at run time the agent then gets the whole server.
        """
        agent_spec: Dict[str, Any] = {
            "tools": [
                {"url": "https://example.com/a/mcp"},
                {"url": "https://example.com/b/mcp", "tools": []},
                {"url": "https://example.com/c/mcp", "tools": ""},
            ],
        }
        tools: List[str] = ConnectivityReporter.assemble_tool_list(agent_spec)
        self.assertEqual(tools, ["https://example.com/a/mcp", "https://example.com/b/mcp", "https://example.com/c/mcp"])

    def test_assemble_tool_list_dedups_string_and_dict_references_to_one_server(self) -> None:
        """
        Tests that a string reference and a dict reference with no allow list to the same
        server, or the same tool allowed twice, are each reported once.
        """
        agent_spec: Dict[str, Any] = {
            "tools": [
                "https://example.com/mcp",
                {"url": "https://example.com/mcp"},
                {"url": "https://example.com/other/mcp", "tools": ["tool_1"]},
                {"url": "https://example.com/other/mcp", "tools": ["tool_1"]},
            ],
        }
        tools: List[str] = ConnectivityReporter.assemble_tool_list(agent_spec)
        self.assertEqual(tools, ["https://example.com/mcp", "https://example.com/other/mcp::tool_1"])

    def test_assemble_tool_list_drops_dict_entries_in_args_tools(self) -> None:
        """
        Tests that a dict in `args.tools` is not reported: `args.tools` holds agent names,
        so a coded tool can never call such an entry.
        """
        agent_spec: Dict[str, Any] = {
            "args": {"tools": ["agent_a", {"url": "https://example.com/mcp", "tools": ["tool_1"]}]},
        }
        tools: List[str] = ConnectivityReporter.assemble_tool_list(agent_spec)
        self.assertEqual(tools, ["agent_a"])

    def test_assemble_tool_list_reports_what_a_malformed_allow_list_grants(self) -> None:
        """
        Tests that only the allow-list entries the MCP adapter can use, non-empty strings, are
        reported, and that an allow list that grants nothing, such as a bare string or a list
        with no usable entry, reports nothing rather than the whole server.
        """
        agent_spec: Dict[str, Any] = {
            "tools": [
                {"url": "https://example.com/a/mcp", "tools": "tool_1"},
                {"url": "https://example.com/b/mcp", "tools": [3, "tool_1", None, ""]},
                {"url": "https://example.com/c/mcp", "tools": [3]},
            ],
        }
        tools: List[str] = ConnectivityReporter.assemble_tool_list(agent_spec)
        self.assertEqual(tools, ["https://example.com/b/mcp::tool_1"])

    def test_dict_mcp_references_appear_in_network_connectivity(self) -> None:
        """
        Tests that the front man's reported tools include its dict-form MCP references.
        A path-form id is reported as its own external agent node, as a string MCP url is;
        a host-only url has no path, so it gets no node of its own.
        """
        config: Dict[str, Any] = {
            "tools": [
                {
                    "name": "front_man",
                    "instructions": "test",
                    "tools": [
                        "helper",
                        {"url": "https://example.com/other/mcp", "tools": ["tool_1"]},
                        {"url": "https://mcp.example.com"},
                    ],
                },
                {"name": "helper", "function": {"description": "helps"}, "instructions": "help"},
            ]
        }
        agent_network: AgentNetwork = AgentNetwork(config, "dict_mcp_network")

        # The reporter's self-built factory reads AGENT_TOOLBOX_INFO_FILE at
        # construction. Keep the test hermetic against the environment.
        with patch.dict(os.environ):
            os.environ.pop("AGENT_TOOLBOX_INFO_FILE", None)
            reporter = ConnectivityReporter(agent_network)
            messages: List[Dict[str, Any]] = reporter.report_network_connectivity()

        front_man: Dict[str, Any] = messages[0]
        self.assertEqual(front_man.get("origin"), "front_man")
        self.assertEqual(front_man.get("tools"), [
            "helper",
            "https://example.com/other/mcp::tool_1",
            "https://mcp.example.com",
        ])

        display_as_by_origin: Dict[str, str] = {}
        message: Dict[str, Any] = None
        # Index the reported nodes by name
        for message in messages:
            display_as_by_origin[message.get("origin")] = message.get("display_as")
        self.assertEqual(display_as_by_origin.get("https://example.com/other/mcp::tool_1"), "external_agent")
        self.assertNotIn("https://mcp.example.com", display_as_by_origin)

    def test_malformed_url_does_not_crash_network_connectivity(self) -> None:
        """
        Tests that a string tool reference whose url cannot be parsed
        (mismatched bracket read as an invalid IPv6 netloc) does not crash
        the whole connectivity report. UrlNetworkValidator accepts any
        http(s)-prefixed string, so such a url can reach the reporter, where
        the recursion used to die with ValueError inside urlparse via
        is_external_agent.
        """
        config: Dict[str, Any] = {
            "tools": [
                {
                    "name": "front_man",
                    "instructions": "test",
                    "tools": ["http://[oops/mcp"],
                }
            ]
        }
        agent_network: AgentNetwork = AgentNetwork(config, "malformed_url_network")

        # The reporter's self-built factory reads AGENT_TOOLBOX_INFO_FILE at
        # construction. Keep the test hermetic against the environment.
        with patch.dict(os.environ):
            os.environ.pop("AGENT_TOOLBOX_INFO_FILE", None)
            reporter = ConnectivityReporter(agent_network)
            messages: List[Dict[str, Any]] = reporter.report_network_connectivity()

        # The unparseable reference is still advertised on the front man, but
        # it resolves to no known agent, so no node of its own is reported.
        self.assertEqual(len(messages), 1)
        connectivity: Dict[str, Any] = messages[0]
        self.assertEqual(connectivity.get("origin"), "front_man")
        self.assertEqual(connectivity.get("tools"), ["http://[oops/mcp"])
