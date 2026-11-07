
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

from logging import INFO
from os import environ
from unittest import TestCase
from unittest.mock import patch

from neuro_san.service.generic.agent_server_logging import AgentServerLogging


class TestAgentServerLogging(TestCase):
    """
    Unit tests for how AgentServerLogging prepares user input for the request log.
    """

    SLICE_ENV_VAR: str = "AGENT_REQUEST_LOGGING_INPUT_SLICE"

    # Assembled from parts so that secret scanners do not report this file
    FAKE_KEY: str = "sk-" + "proj-" + "ABCDEFGHIJKLMNOP"

    def test_masks_secret_without_slice(self) -> None:
        """
        Test that with no slice set, the whole input is logged with its secret masked.
        """
        with patch.dict(environ, clear=True):
            server_logging: AgentServerLogging = AgentServerLogging("test", "")
            value: str = server_logging.redact_per_env_var(f"my key is {self.FAKE_KEY}", self.SLICE_ENV_VAR)
        self.assertEqual(value, "'my key is <redacted>'")

    def test_masks_before_slicing_from_end(self) -> None:
        """
        Test that the secret is masked before the last characters are sliced off,
        so that no tail of the key reaches the log.
        """
        with patch.dict(environ, {self.SLICE_ENV_VAR: "-10"}, clear=True):
            server_logging: AgentServerLogging = AgentServerLogging("test", "")
            value: str = server_logging.redact_per_env_var(f"my key is {self.FAKE_KEY}", self.SLICE_ENV_VAR)
        self.assertEqual(value, "'...<redacted>'")

    def test_masks_before_slicing_from_start(self) -> None:
        """
        Test that slicing from the start counts the characters of the masked input.
        """
        with patch.dict(environ, {self.SLICE_ENV_VAR: "20"}, clear=True):
            server_logging: AgentServerLogging = AgentServerLogging("test", "")
            value: str = server_logging.redact_per_env_var(f"my key is {self.FAKE_KEY}", self.SLICE_ENV_VAR)
        self.assertEqual(value, "'my key is <redacted>'")

    def test_zero_slice_still_hides_input(self) -> None:
        """
        Test that a zero slice still hides the whole input.
        """
        with patch.dict(environ, {self.SLICE_ENV_VAR: "0"}, clear=True):
            server_logging: AgentServerLogging = AgentServerLogging("test", "")
            value: str = server_logging.redact_per_env_var(f"my key is {self.FAKE_KEY}", self.SLICE_ENV_VAR)
        self.assertEqual(value, "<redacted>")

    def test_zero_slice_does_not_scan_the_input(self) -> None:
        """
        Test that a zero slice returns without masking, since none of the input is logged.
        """
        with patch.dict(environ, {self.SLICE_ENV_VAR: "0"}, clear=True):
            server_logging: AgentServerLogging = AgentServerLogging("test", "")
            with patch.object(server_logging.secret_masker, "mask") as mock_mask:
                value: str = server_logging.redact_per_env_var(f"my key is {self.FAKE_KEY}", self.SLICE_ENV_VAR)
        self.assertEqual(value, "<redacted>")
        mock_mask.assert_not_called()

    def test_non_integer_slice_logs_the_whole_masked_input(self) -> None:
        """
        Test that a slice that is not an integer is reported and ignored, and the whole input
        is logged with its secret masked.
        """
        with patch.dict(environ, {self.SLICE_ENV_VAR: "lots"}, clear=True):
            server_logging: AgentServerLogging = AgentServerLogging("test", "")
            with self.assertLogs("AgentServerLogging", level=INFO):
                value: str = server_logging.redact_per_env_var(f"my key is {self.FAKE_KEY}", self.SLICE_ENV_VAR)
        self.assertEqual(value, "'my key is <redacted>'")

    def test_masks_extra_patterns_from_env_var(self) -> None:
        """
        Test that the space-delimited patterns in AGENT_REQUEST_LOGGING_SECRET_PATTERNS are masked too.
        """
        extra_patterns: str = r"acme_[0-9a-f]{8}  corp_\d{4}"
        with patch.dict(environ, {AgentServerLogging.SECRET_PATTERNS_ENV_VAR: extra_patterns}, clear=True):
            server_logging: AgentServerLogging = AgentServerLogging("test", "")
            value: str = server_logging.redact_per_env_var("acme_deadbeef corp_1234", self.SLICE_ENV_VAR)
        self.assertEqual(value, "'<redacted> <redacted>'")
