
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
from typing import Tuple
from typing import Type
from typing import Union

from logging import Logger
from logging import getLogger

from neuro_san.internals.validation.network.abstract_network_validator import AbstractNetworkValidator


class ToolsShapeValidator(AbstractNetworkValidator):
    """
    AbstractNetworkValidator that checks the shape of fields that downstream
    structural validators traverse:
      - `tools` must be a list whose elements are each a str or dict. A dict is an MCP
        server entry: it needs a string `url`, may have a `tools` list of tool names,
        and any other key is warned about, since neuro-san ignores it.
      - `args.tools`, when present, must be either a dict (label -> agent name,
        the coded-tool convention) or a list of names.

    Other validators (UnreachableNodesNetworkValidator, MissingNodesNetworkValidator,
    etc.) iterate or concatenate these fields and would crash or produce nonsense
    results on a malformed value. This validator surfaces those shape errors so
    callers see a readable message instead of a downstream TypeError/AttributeError.

    The matching defensive readers `AbstractNetworkValidator.coerce_tools` and
    `coerce_args_tools` enforce the same shape contract in a tolerant form
    (returning an empty list when the value is malformed) for use by validators
    that traverse the connectivity graph.
    """

    # The keys neuro-san reads from an MCP server entry in an agent's tools list.
    # See BaseToolFactory.create_external_tool() and McpToolCreator.split_reference().
    MCP_ENTRY_KEYS: Tuple[str, ...] = ("url", "tools")

    def __init__(self, network_name: str = None):
        """
        Constructor

        :param network_name: The agent network name for diagnostic log lines
        """
        self.logger: Logger = getLogger(self.__class__.__name__)
        self.network_name: str = network_name

    def validate_name_to_spec_dict(self, name_to_spec: Dict[str, Any]) -> List[str]:
        """
        Validate the agent network, specifically in the form of a name -> agent spec dictionary.

        :param name_to_spec: The name -> agent spec dictionary to validate
        :return: A list of error messages
        """
        errors: List[str] = []

        self.logger.debug("Validating %s tools shape...", self.network_name)

        for agent_name, agent in name_to_spec.items():
            errors.extend(self.validate_tools(agent_name, agent))
            errors.extend(self.validate_args_tools(agent_name, agent))
            self.warn_about_unknown_mcp_keys(agent_name, agent)

        if len(errors) > 0:
            # Only warn if there is a problem
            self.logger.warning(str(errors))

        return errors

    @staticmethod
    def validate_tools(agent_name: str, agent: Dict[str, Any]) -> List[str]:
        """
        Validate that 'tools' is a list where each element is a str or dict.

        :param agent_name: The name of the agent being validated
        :param agent: The agent spec dictionary
        :return: A list of error messages
        """
        tools: Any = agent.get("tools")
        if tools is None:
            return []
        if not isinstance(tools, list):
            return [f"{agent_name} 'tools' must be a list, got {type(tools).__name__}."]
        # Each element of tools must be a str (agent name) or dict (MCP server).
        errors: List[str] = ToolsShapeValidator.check_element_types(
            tools, (str, dict), "str or dict", agent_name, "tools",
        )
        index: int = 0
        entry: Any = None
        # Each dict element is an MCP server entry, with a shape of its own
        for index, entry in enumerate(tools):
            if isinstance(entry, dict):
                errors.extend(ToolsShapeValidator.validate_mcp_entry(agent_name, index, entry))
        return errors

    @staticmethod
    def validate_mcp_entry(agent_name: str, index: int, entry: Dict[str, Any]) -> List[str]:
        """
        Validate one MCP server entry of an agent's tools list: a string `url`, and,
        if present, a `tools` allow list of tool names.

        :param agent_name: The name of the agent being validated
        :param index: The position of the entry in the agent's tools list
        :param entry: The MCP server entry
        :return: A list of error messages
        """
        errors: List[str] = []
        url: Any = entry.get("url")
        if not isinstance(url, str):
            errors.append(f"{agent_name} 'tools[{index}]' is an MCP server entry, so it needs a 'url' string,"
                          f" got {type(url).__name__}.")
        elif len(url) == 0:
            errors.append(f"{agent_name} 'tools[{index}]' is an MCP server entry, so its 'url' must not be empty.")

        allowed: Any = entry.get("tools")
        if allowed is None:
            return errors
        if not isinstance(allowed, list):
            errors.append(f"{agent_name} 'tools[{index}].tools' must be a list of tool names,"
                          f" got {type(allowed).__name__}.")
            return errors
        errors.extend(ToolsShapeValidator.check_element_types(
            allowed, str, "str (tool name)", agent_name, f"tools[{index}].tools",
        ))
        position: int = 0
        name: Any = None
        # The MCP adapter sets an empty name aside, so it can never select a tool
        for position, name in enumerate(allowed):
            if name == "":
                errors.append(f"{agent_name} 'tools[{index}].tools[{position}]' must not be an empty tool name.")
        return errors

    def warn_about_unknown_mcp_keys(self, agent_name: str, agent: Dict[str, Any]) -> None:
        """
        Warn about keys in an agent's MCP server entries that neuro-san ignores. They are
        usually typos, and a misspelled "tools" drops the allow list, exposing every tool
        on the server.

        :param agent_name: The name of the agent being validated
        :param agent: The agent spec dictionary
        """
        index: int = 0
        entry: Any = None
        # Only dict elements are MCP server entries
        for index, entry in enumerate(self.coerce_tools(agent)):
            if not isinstance(entry, dict):
                continue
            unknown_keys: List[str] = []
            key: Any = None
            # Collect the keys neuro-san does not read
            for key in entry.keys():
                if key not in self.MCP_ENTRY_KEYS:
                    unknown_keys.append(str(key))
            if len(unknown_keys) > 0:
                self.logger.warning("Agent network %s: %s 'tools[%d]' has %s, which neuro-san ignores: an MCP server"
                                    " entry takes only 'url' and 'tools'.", self.network_name, agent_name, index,
                                    sorted(unknown_keys))

    @staticmethod
    def validate_args_tools(agent_name: str, agent: Dict[str, Any]) -> List[str]:
        """
        Validate that 'args.tools', if present, is either a dict of str values or a
        list of str values. This is the coded-tool convention for declaring
        downstream agents: a dict of label -> agent name, or a list of agent names.

        :param agent_name: The name of the agent being validated
        :param agent: The agent spec dictionary
        :return: A list of error messages
        """
        args: Any = agent.get("args")
        if not isinstance(args, dict):
            return []

        args_dict: Dict[str, Any] = args
        if "tools" not in args_dict.keys():
            return []
        args_tools: Any = args_dict.get("tools")
        if not isinstance(args_tools, (dict, list)):
            return [
                f"{agent_name} 'args.tools' must be a dict or list,"
                f" got {type(args_tools).__name__}."
            ]
        # Tools in args.tools must be agent names (str).
        return ToolsShapeValidator.check_element_types(
            args_tools, str, "str (agent name)", agent_name, "args.tools",
        )

    @staticmethod
    def check_element_types(items: Union[Dict[Any, Any], List[Any]],
                            allowed_types: Union[Type, Tuple[Type, ...]],
                            type_label: str,
                            agent_name: str,
                            field_prefix: str) -> List[str]:
        """
        Validate that each value in `items` is an instance of `allowed_types`.

        `items` can be a list (indexed by position, error label uses [i]) or a
        dict (keyed by label, error label uses [key!r]). Used by both
        `validate_tools` (tools list) and `validate_args_tools` (args.tools as
        dict or list) to keep the iteration + error format consistent.

        :param items: The list or dict whose entries to check
        :param allowed_types: A type or tuple of types each value must match
        :param type_label: Human-readable description of allowed types for the
                error message (e.g., "str or dict", "str (agent name)")
        :param agent_name: The name of the agent being validated
        :param field_prefix: The field path prefix used in error messages
                (e.g., "tools" or "args.tools")
        :return: A list of error messages, one per element that fails the check
        """
        errors: List[str] = []
        if isinstance(items, dict):
            for key, value in items.items():
                if not isinstance(value, allowed_types):
                    errors.append(
                        f"{agent_name} '{field_prefix}[{key!r}]' must be a {type_label},"
                        f" got {type(value).__name__}."
                    )
        elif isinstance(items, list):
            for i, value in enumerate(items):
                if not isinstance(value, allowed_types):
                    errors.append(
                        f"{agent_name} '{field_prefix}[{i}]' must be a {type_label},"
                        f" got {type(value).__name__}."
                    )
        return errors
