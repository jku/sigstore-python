# Copyright 2022 The Sigstore Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Functionality for interacting with a generic keyring.
"""

from __future__ import annotations

from collections.abc import Iterable

import cryptography.hazmat.primitives.asymmetric.padding as padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from sigstore._utils import (
    KeyID,
    LogInstance,
    key_id,
)


class KeyringError(Exception):
    """
    Raised on failure by `Keyring.verify()`.
    """

    pass


class KeyringLookupError(KeyringError):
    """
    A specialization of `KeyringError`, indicating that the specified
    key ID wasn't found in the keyring.
    """

    pass


class KeyringSignatureError(KeyringError):
    """
    Raised when `Keyring.verify()` is passed an invalid signature.
    """


class Keyring:
    """
    A set of transparency logs, in practice pairs of URL and public key.

    This structure exists to facilitate key rotation in a CT log.
    """

    def __init__(self, logs: Iterable[LogInstance] = []):
        """
        Create a new `Keyring`, with `logs` as the initial content. These `logs`
        consist of a URL and a public key.
        """
        self._keyring = {key_id(log.key): log for log in logs}

    def verify(self, *, key_id: KeyID, signature: bytes, data: bytes) -> None:
        """
        Verify that `signature` is a valid signature for `data`, using the
        key identified by `key_id`.

        Raises if `key_id` does not match a key in the `Keyring`, or if
        the signature is invalid.
        """
        log = self._keyring.get(key_id)
        if log is None:
            # If we don't have a key corresponding to this key ID, we can't
            # possibly verify the signature.
            raise KeyringLookupError(f"no known key for key ID {key_id.hex()}")

        try:
            if isinstance(log.key, rsa.RSAPublicKey):
                log.key.verify(
                    signature=signature,
                    data=data,
                    padding=padding.PKCS1v15(),
                    algorithm=hashes.SHA256(),
                )
            elif isinstance(log.key, ec.EllipticCurvePublicKey):
                log.key.verify(
                    signature=signature,
                    data=data,
                    signature_algorithm=ec.ECDSA(hashes.SHA256()),
                )
            else:
                # NOTE(ww): Unreachable without API misuse.
                raise KeyringError(f"unsupported key type: {log.key}")
        except InvalidSignature as exc:
            raise KeyringSignatureError("invalid signature") from exc
