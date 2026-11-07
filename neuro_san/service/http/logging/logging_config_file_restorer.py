
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

from neuro_san.internals.persistence.abstract_async_config_restorer import AbstractAsyncConfigRestorer


class LoggingConfigFileRestorer(AbstractAsyncConfigRestorer):
    """
    Restores a HOCON or JSON logging config file the same way as the other neuro-san config files.

    HOCON is parsed with sanitize_keys=True, so a logger name that has to be quoted in HOCON,
    such as "neuro_san.internals", comes back without the quotes and matches the logger.
    A missing file raises FileNotFoundError.
    LoggingConfigRestorer uses this class for its HOCON and JSON files.
    """

    def __init__(self):
        """
        Constructor
        """
        super().__init__(file_purpose="logging config")
