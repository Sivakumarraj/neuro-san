
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

import logging
import logging.config
import os

from shutil import rmtree
from tempfile import mkdtemp
from typing import Any
from typing import Dict
from unittest import TestCase

from typing_extensions import override

from leaf_common.persistence.easy.easy_hocon_persistence import EasyHoconPersistence

from neuro_san import DEPLOY_DIR
from neuro_san.service.http.logging.logging_config_restorer import LoggingConfigRestorer


class TestLoggingConfigRestorer(TestCase):
    """
    Unit tests for LoggingConfigRestorer.
    """

    # A logger name no other test uses, so that configuring it changes nothing else
    DOTTED_LOGGER_NAME: str = "neuro_san_test_logging_config_restorer.dotted"

    # Dotted logger names must be quoted in HOCON, which is what issue #1205 is about
    DOTTED_LOGGER_HOCON: str = f"""
version = 1
disable_existing_loggers = false
loggers {{
    "{DOTTED_LOGGER_NAME}" {{
        level = "DEBUG"
    }}
}}
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

    def test_quoted_dotted_logger_name_loses_its_quotes(self) -> None:
        """
        Test that a dotted logger name quoted in HOCON comes back as the plain logger name.
        """
        file_path: str = self.write_file("logging.hocon", self.DOTTED_LOGGER_HOCON)

        config: Dict[str, Any] = LoggingConfigRestorer().restore(file_path)

        self.assertEqual(list(config.get("loggers").keys()), [self.DOTTED_LOGGER_NAME])

    def test_quoted_dotted_logger_level_applies(self) -> None:
        """
        Test that dictConfig() with the restored config sets the level of the dotted logger itself.
        """
        file_path: str = self.write_file("logging.hocon", self.DOTTED_LOGGER_HOCON)
        dotted_logger: logging.Logger = logging.getLogger(self.DOTTED_LOGGER_NAME)
        self.addCleanup(dotted_logger.setLevel, logging.NOTSET)

        logging.config.dictConfig(LoggingConfigRestorer().restore(file_path))

        self.assertEqual(dotted_logger.level, logging.DEBUG)

    def test_shipped_logging_hocon_restores_as_before(self) -> None:
        """
        Test that the logging.hocon shipped in the deploy directory gives the same config as a plain parse,
        since none of its keys needed quotes.
        """
        file_path: str = DEPLOY_DIR.get_file_in_basis("logging.hocon")

        config: Dict[str, Any] = LoggingConfigRestorer().restore(file_path)

        self.assertEqual(config, EasyHoconPersistence().restore(file_reference=file_path))

    def test_json_config_restores(self) -> None:
        """
        Test that a JSON logging config still restores.
        """
        file_path: str = self.write_file("logging.json", '{"version": 1, "loggers": {"a.b": {"level": "INFO"}}}')

        config: Dict[str, Any] = LoggingConfigRestorer().restore(file_path)

        self.assertEqual(config, {"version": 1, "loggers": {"a.b": {"level": "INFO"}}})

    def test_missing_hocon_file_is_reported(self) -> None:
        """
        Test that a HOCON logging config that does not exist raises an error naming the path.
        """
        file_path: str = os.path.join(self.temp_dir_name, "missing.hocon")

        with self.assertRaises(FileNotFoundError) as raised_error:
            LoggingConfigRestorer().restore(file_path)

        self.assertIn(file_path, str(raised_error.exception))

    def test_malformed_hocon_file_is_reported(self) -> None:
        """
        Test that a HOCON logging config that does not parse raises a ValueError naming the file.
        """
        file_path: str = self.write_file("broken.hocon", "loggers { level = ")

        with self.assertRaises(ValueError) as raised_error:
            LoggingConfigRestorer().restore(file_path)

        self.assertIn(file_path, str(raised_error.exception))

    def test_unsupported_file_type_is_reported(self) -> None:
        """
        Test that a logging config with an unsupported extension still raises a ValueError.
        """
        with self.assertRaises(ValueError) as raised_error:
            LoggingConfigRestorer().restore(os.path.join(self.temp_dir_name, "logging.ini"))

        self.assertIn("Unsupported logging config file type", str(raised_error.exception))
