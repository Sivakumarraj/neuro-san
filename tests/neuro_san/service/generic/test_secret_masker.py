
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

from logging import ERROR
from typing import Dict
from typing import List
from unittest import TestCase

from neuro_san.service.generic.secret_masker import SecretMasker


class TestSecretMasker(TestCase):
    """
    Unit tests for SecretMasker.
    """

    # Fake secrets, one per default pattern. Each is assembled from parts so that
    # secret scanners do not report this file.
    FAKE_SECRETS: Dict[str, str] = {
        "openai project key": "sk-" + "proj-" + "AbC123",
        "openai service account key": "sk-" + "svcacct-" + "Zx9_Yw8-Vu7Ts6",
        "anthropic key": "sk-" + "ant-" + "api03-" + "q" * 40,
        "openrouter key": "sk-" + "or-" + "v1-" + "0123456789abcdef" * 4,
        "older openai key": "sk-" + "T3BlbkFJ" * 6,
        "aws access key id": "AKIA" + "IOSFODNN7EXAMPLE",
        "aws temporary access key id": "ASIA" + "Q3EGUXZ6EXAMPLE7",
        "google api key": "AIza" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q",
        "github personal token": "ghp" + "_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
        "github fine-grained token": "github" + "_pat_" + "11ABCDEFG0123456789_abcdefghijklmnop",
        "slack bot token": "xox" + "b-" + "1234567890-0987654321-AbCdEfGhIjKlMnOp",
        "hugging face token": "hf" + "_" + "AbCdEfGhIjKlMnOpQrStUvWxYz012345",
        "json web token": "eyJ" + "hbGciOiJIUzI1NiJ9" + ".eyJzdWIiOiIxMjM0NTY3ODkwIn0" + ".SflKxwRJSMeKKF2QT4fwpM",
        "pem private key": "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEow\nIBAAK\n-----END " + "RSA PRIVATE KEY-----",
    }

    def test_masks_example_from_issue(self) -> None:
        """
        Test that the example from issue #1607 is masked as the issue describes.
        """
        masker: SecretMasker = SecretMasker()
        masked: str = masker.mask("my key is " + self.FAKE_SECRETS.get("openai project key"))
        self.assertEqual(masked, "my key is <redacted>")

    def test_masks_each_default_format(self) -> None:
        """
        Test that a secret in each of the default formats is masked whole, with the text around it kept.
        """
        masker: SecretMasker = SecretMasker()
        # Each label is a string, so the subTest parameters stay picklable under pytest-xdist.
        label: str = None
        for label in self.FAKE_SECRETS:
            with self.subTest(case=label):
                secret: str = self.FAKE_SECRETS.get(label)
                masked: str = masker.mask(f"use {secret} for this")
                self.assertEqual(masked, "use <redacted> for this")

    def test_masks_unterminated_private_key_to_end_of_text(self) -> None:
        """
        Test that a private key block with no end marker is masked to the end of the text.
        """
        masker: SecretMasker = SecretMasker()
        masked: str = masker.mask("here: -----BEGIN " + "PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0B")
        self.assertEqual(masked, "here: <redacted>")

    def test_masks_every_secret_in_text(self) -> None:
        """
        Test that several secrets in one text are all masked.
        """
        masker: SecretMasker = SecretMasker()
        text: str = (f"openai {self.FAKE_SECRETS.get('openai project key')}, "
                     f"aws {self.FAKE_SECRETS.get('aws access key id')}")
        self.assertEqual(masker.mask(text), "openai <redacted>, aws <redacted>")

    def test_leaves_ordinary_text_alone(self) -> None:
        """
        Test that text with no secret in it is not changed, including words that start like a key prefix.
        """
        masker: SecretMasker = SecretMasker()
        ordinary_texts: List[str] = [
            "What is 2 + 2?",
            "Ask the task-force about sk-8 skis and the AKIA tribe.",
            "Use the hf_hub library and the gh_pages branch.",
            "The token eyJ alone is not a JWT.",
        ]
        # Each text is compared with itself after masking
        one_text: str = None
        for one_text in ordinary_texts:
            with self.subTest(case=one_text):
                self.assertEqual(masker.mask(one_text), one_text)

    def test_keeps_empty_and_none_text(self) -> None:
        """
        Test that empty and None text come back as given.
        """
        masker: SecretMasker = SecretMasker()
        self.assertEqual(masker.mask(""), "")
        self.assertIsNone(masker.mask(None))

    def test_masks_extra_pattern(self) -> None:
        """
        Test that an extra pattern is masked along with the default ones.
        """
        masker: SecretMasker = SecretMasker([r"acme_[0-9a-f]{8}"])
        text: str = f"internal acme_deadbeef and {self.FAKE_SECRETS.get('openai project key')}"
        self.assertEqual(masker.mask(text), "internal <redacted> and <redacted>")

    def test_skips_and_logs_invalid_extra_pattern(self) -> None:
        """
        Test that an extra pattern that does not compile is logged with where it came from,
        and that the other patterns still apply.
        """
        with self.assertLogs("SecretMasker", level=ERROR) as captured:
            masker: SecretMasker = SecretMasker(["acme_[0-9", r"corp_\d{4}"], "TEST_PATTERNS_ENV_VAR")

        log_text: str = "\n".join(captured.output)
        self.assertIn("acme_[0-9", log_text)
        self.assertIn("TEST_PATTERNS_ENV_VAR", log_text)

        text: str = f"corp_1234 and {self.FAKE_SECRETS.get('openai project key')}"
        self.assertEqual(masker.mask(text), "<redacted> and <redacted>")
