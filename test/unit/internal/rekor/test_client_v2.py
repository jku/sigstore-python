# Copyright 2025 The Sigstore Authors
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

import hashlib

import pytest

from sigstore import dsse
from sigstore.models import TransparencyLogEntry


@pytest.mark.staging
@pytest.mark.ambient_oidc
def test_rekor_v2_create_entry_dsse(staging):
    # This is not a real unit test: it requires not only staging rekor but also TUF
    # fulcio and oidc -- maybe useful only until we have real integration tests in place
    sign_ctx_cls, _, identity = staging
    sign_ctx = sign_ctx_cls()

    stmt = (
        dsse.StatementBuilder()
        .subjects(
            [
                dsse.Subject(
                    name="null", digest={"sha256": hashlib.sha256(b"").hexdigest()}
                )
            ]
        )
        .predicate_type("https://cosign.sigstore.dev/attestation/v1")
        .predicate(
            {
                "Data": "",
                "Timestamp": "2023-12-07T00:37:58Z",
            }
        )
    ).build()

    with sign_ctx.signer(identity) as signer:
        bundle = signer.sign_dsse(stmt)

    assert isinstance(bundle.log_entry, TransparencyLogEntry)


@pytest.mark.staging
@pytest.mark.ambient_oidc
def test_rekor_v2_create_entry_hashed_rekord(staging):
    # This is not a real unit test: it requires not only staging rekor but also TUF
    # fulcio and oidc -- maybe useful only until we have real integration tests in place
    sign_ctx_cls, _, identity = staging
    sign_ctx = sign_ctx_cls()

    with sign_ctx.signer(identity) as signer:
        bundle = signer.sign_artifact(b"")

    assert isinstance(bundle.log_entry, TransparencyLogEntry)


def test_rekor_v2_build_dsse_request_returns_hashed_rekord():
    import base64
    import hashlib
    from unittest.mock import Mock

    from sigstore._internal.rekor.client_v2 import RekorV2Client
    from sigstore.dsse import Envelope

    mock_envelope = Mock(spec=Envelope)
    mock_envelope._inner = Mock()
    mock_envelope._inner.payload_type = "application/vnd.in-toto+json"
    mock_envelope._inner.payload = b"some payload"
    mock_envelope.signature = b"some signature"

    from sigstore_models.common.v1 import HashAlgorithm

    from sigstore.hashes import Hashed

    pae = b"DSSEv1 28 application/vnd.in-toto+json 12 some payload"
    digest = hashlib.sha256(pae).digest()
    mock_envelope.pae_hash.return_value = Hashed(
        algorithm=HashAlgorithm.SHA2_256,
        digest=digest,
    )

    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509 import Certificate

    mock_cert = Mock(spec=Certificate)
    mock_key = Mock(spec=ec.EllipticCurvePublicKey)
    mock_key.curve = ec.SECP256R1()
    mock_cert.public_key.return_value = mock_key
    mock_cert.public_bytes.return_value = b"some cert bytes"

    req_body = RekorV2Client._build_dsse_request(mock_envelope, mock_cert)

    assert "hashedRekordRequestV002" in req_body
    assert "dsseRequestV002" not in req_body

    hr_req = req_body["hashedRekordRequestV002"]

    # Verify digest
    pae = b"DSSEv1 28 application/vnd.in-toto+json 12 some payload"
    expected_digest = base64.b64encode(hashlib.sha256(pae).digest()).decode()
    assert hr_req["digest"] == expected_digest

    # Verify signature
    assert (
        hr_req["signature"]["content"] == base64.b64encode(b"some signature").decode()
    )
