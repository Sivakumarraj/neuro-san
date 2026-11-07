
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

from typing import List

import logging
import re

from re import Pattern


class SecretMasker:
    """
    Replaces secret-shaped text, such as API keys and access tokens, with a placeholder,
    so that the text can be logged without the secrets in it.

    The default patterns cover common key formats. Callers can add their own patterns,
    for example the ones AgentServerLogging reads from AGENT_REQUEST_LOGGING_SECRET_PATTERNS.
    """

    REPLACEMENT: str = "<redacted>"

    # Each pattern matches a whole secret, so that no part of it is left in the text.
    DEFAULT_PATTERNS: List[str] = [
        # OpenAI project, service account and admin keys, Anthropic keys and OpenRouter keys.
        # Their prefixes are distinctive enough to match a key of any length.
        r"\bsk-(?:proj|svcacct|admin|ant|or)-[A-Za-z0-9_\-]+",
        # Other keys that start with sk-, such as older OpenAI keys
        r"\bsk-[A-Za-z0-9_\-]{20,}",
        # AWS access key IDs, long-term (AKIA) and temporary (ASIA)
        r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        # Google API keys, which include Gemini keys
        r"\bAIza[0-9A-Za-z_\-]{35}",
        # GitHub personal, OAuth, user-to-server, server-to-server and refresh tokens
        r"\bgh[pousr]_[A-Za-z0-9]{36,}",
        # GitHub fine-grained personal access tokens
        r"\bgithub_pat_[A-Za-z0-9_]{22,}",
        # Slack tokens
        r"\bxox[abposr]-[A-Za-z0-9\-]{10,}",
        # Hugging Face tokens
        r"\bhf_[A-Za-z0-9]{30,}",
        # JSON Web Tokens: header, payload and signature
        r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
        # PEM private key blocks, up to the end marker or, if it is missing, the end of the text
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)",
    ]

    def __init__(self, extra_patterns: List[str] = None, extra_patterns_source: str = "the extra patterns"):
        """
        Constructor

        :param extra_patterns: Regular expressions to mask in addition to DEFAULT_PATTERNS.
                    A pattern that is not a valid regular expression is logged as an error and skipped,
                    so that the default patterns still apply.
        :param extra_patterns_source: Where the extra patterns come from, such as the name of an
                    environment variable, so that an error about one says where to fix it.
        """
        self.logger: logging.Logger = logging.getLogger(self.__class__.__name__)
        self.patterns: List[Pattern] = []

        # The default patterns are known to compile
        one_pattern: str = None
        for one_pattern in self.DEFAULT_PATTERNS:
            self.patterns.append(re.compile(one_pattern))

        if extra_patterns is None:
            return

        # Extra patterns come from configuration, so each one is checked
        for one_pattern in extra_patterns:
            try:
                self.patterns.append(re.compile(one_pattern))
            except re.error as exception:
                self.logger.error("Ignoring the secret pattern '%s' from %s. It is not a valid regular expression: %s",
                                  one_pattern, extra_patterns_source, exception)

    def mask(self, text: str) -> str:
        """
        Replace every match of every pattern with REPLACEMENT.

        :param text: The text to mask. Can be None or empty.
        :return: The text with each secret replaced, or the text as given if it is None or empty
        """
        if not text:
            return text

        masked_text: str = text
        # Each pattern is applied to what the patterns before it left
        one_pattern: Pattern = None
        for one_pattern in self.patterns:
            masked_text = one_pattern.sub(self.REPLACEMENT, masked_text)

        return masked_text
