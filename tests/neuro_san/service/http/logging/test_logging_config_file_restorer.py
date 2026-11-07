
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

import os

from shutil import rmtree
from tempfile import mkdtemp
from typing import Any
from typing import Dict
from unittest import TestCase

from typing_extensions import override

from neuro_san.service.http.logging.logging_config_file_restorer import LoggingConfigFileRestorer


class TestLoggingConfigFileRestorer(TestCase):
    """
    Unit tests for LoggingConfigFileRestorer, the HOCON and JSON reader behind LoggingConfigRestorer.
    """

    @override
    def setUp(self) -> None:
        """
        Create a temporary directory for the config files under test, removed after each test.
        """
        self.temp_dir_name: str = mkdtemp()
        self.addCleanup(rmtree, self.temp_dir_name)

    def write_file(self, file_name: str, contents: str) -> str:
        """
        Write a file into the temporary directory.

        :param file_name: The name of the file to write
        :param contents: The text to write into it
        :return: The path to the file written
        """
        file_path: str = os.path.join(self.temp_dir_name, file_name)
        with open(file_path, "w", encoding="utf-8") as file_obj:
            file_obj.write(contents)
        return file_path

    def test_quoted_keys_lose_their_quotes_at_every_level(self) -> None:
        """
        Test that quoted keys come back without their quotes, at the top level and nested.
        """
        file_path: str = self.write_file("logging.hocon", '"a.b" { "c.d" { level = "INFO" } }\n')

        config: Dict[str, Any] = LoggingConfigFileRestorer().restore(file_path)

        self.assertEqual(config, {"a.b": {"c.d": {"level": "INFO"}}})

    def test_missing_file_names_the_environment_variable(self) -> None:
        """
        Test that the error for a missing file names AGENT_SERVICE_LOG_JSON, so the reader knows where
        the path came from.
        """
        file_path: str = os.path.join(self.temp_dir_name, "missing.hocon")

        with self.assertRaises(FileNotFoundError) as raised_error:
            LoggingConfigFileRestorer().restore(file_path)

        self.assertIn(file_path, str(raised_error.exception))
        self.assertIn("AGENT_SERVICE_LOG_JSON", str(raised_error.exception))
