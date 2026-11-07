
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
from typing import Optional

import logging
import re

from re import Pattern

from leaf_common.logging.log_once import LogOnce


class SecretMasker:
    """
    Replaces secret-shaped text, such as API keys and access tokens, with a placeholder,
    so that the text can be logged without the secrets in it.

    The default patterns cover keys with a recognizable prefix. Keys without one, such as
    Azure OpenAI keys and AWS secret access keys, cannot be told apart from other text, so
    callers add patterns for them, for example the ones AgentServerLogging reads from
    AGENT_REQUEST_LOGGING_SECRET_PATTERNS.
    """

    REPLACEMENT: str = "<redacted>"

    # A secret starts where no letter or digit comes before it. Unlike \b, this also
    # catches a key right after "_" or "=", as in "KEY_sk-proj-..." or "key=sk-proj-...",
    # while ordinary words like "risk-or-reward" are left alone.
    START: str = r"(?<![A-Za-z0-9])"

    # Each pattern matches a whole secret, so that no part of it is left in the text.
    DEFAULT_PATTERNS: List[str] = [
        # OpenAI project, service account and admin keys, Anthropic keys and OpenRouter keys.
        # Their prefixes are distinctive enough to match a key of any length.
        START + r"sk-(?:proj|svcacct|admin|ant|or)-[A-Za-z0-9_\-]+",
        # Other keys that start with sk-, such as older OpenAI keys
        START + r"sk-[A-Za-z0-9_\-]{20,}",
        # NVIDIA API keys
        START + r"nvapi-[A-Za-z0-9_\-]{20,}",
        # AWS access key IDs, long-term (AKIA) and temporary (ASIA)
        START + r"(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        # Google API keys, which include Gemini keys
        START + r"AIza[0-9A-Za-z_\-]{35}",
        # GitHub personal, OAuth, user-to-server, server-to-server and refresh tokens
        START + r"gh[pousr]_[A-Za-z0-9]{36,}",
        # GitHub fine-grained personal access tokens
        START + r"github_pat_[A-Za-z0-9_]{22,}",
        # Slack tokens
        START + r"xox[abposr]-[A-Za-z0-9\-]{10,}",
        # Hugging Face tokens
        START + r"hf_[A-Za-z0-9]{30,}",
        # JSON Web Tokens: header, payload and a signature that is empty for an unsigned token
        START + r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]*",
        # PEM private key blocks, up to the end marker or, if it is missing, the end of the text
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)",
    ]

    def __init__(self, extra_patterns: Optional[List[str]] = None,
                 extra_patterns_source: str = "the extra patterns") -> None:
        """
        Constructor

        :param extra_patterns: Regular expressions to mask in addition to DEFAULT_PATTERNS.
                    A pattern that is not a valid regular expression, or that matches empty text
                    and so would put REPLACEMENT between every character, is logged as an error
                    once per process and skipped, so that the other patterns still apply.
        :param extra_patterns_source: Where the extra patterns come from, such as the name of an
                    environment variable, so that an error about one says where to fix it.
        """
        self.logger: logging.Logger = logging.getLogger(self.__class__.__name__)

        # The default patterns are known to be valid
        usable_patterns: List[str] = list(self.DEFAULT_PATTERNS)

        one_pattern: str = None
        # Extra patterns come from configuration, so each one is checked on its own
        for one_pattern in extra_patterns or []:
            if self.is_usable_extra_pattern(one_pattern, extra_patterns_source):
                usable_patterns.append(one_pattern)

        # One alternation, so mask() reads the text once however many patterns there are.
        # Where two patterns could match at the same place, the one listed first wins.
        alternatives: List[str] = []
        # Each pattern is grouped so that its own alternatives stay inside it
        for one_pattern in usable_patterns:
            alternatives.append(f"(?:{one_pattern})")
        self.combined_pattern: Pattern = re.compile("|".join(alternatives))

    def is_usable_extra_pattern(self, pattern: str, source: str) -> bool:
        """
        Check one extra pattern, logging why it is skipped if it cannot be used.

        :param pattern: The regular expression to check
        :param source: Where the pattern comes from, for the error message
        :return: True if the pattern compiles and does not match empty text
        """
        # The same configuration is checked for every agent a server adds, so say it once.
        log_once: LogOnce = LogOnce(self.logger)
        try:
            compiled: Pattern = re.compile(pattern)
        except re.error as exception:
            log_once.error("Ignoring the secret pattern '%s' from %s. It is not a valid regular expression: %s",
                           pattern, source, exception)
            return False

        if compiled.match("") is not None:
            log_once.error("Ignoring the secret pattern '%s' from %s. It matches empty text, so it would "
                           "put %s between every character.", pattern, source, self.REPLACEMENT)
            return False

        return True

    def mask(self, text: str) -> str:
        """
        Replace every match of every pattern with REPLACEMENT.

        :param text: The text to mask. Can be None or empty.
        :return: The text with each secret replaced, or the text as given if it is None or empty
        """
        if not text:
            return text

        masked_text: str = self.combined_pattern.sub(self.REPLACEMENT, text)
        return masked_text
