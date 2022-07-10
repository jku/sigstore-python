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

from importlib import resources
from sigstore._verify import (
    CertificateVerificationFailure,
    VerificationFailure,
    VerificationSuccess,
    Verifier,
    load_pem_x509_certificate,
)


def test_verifier_production():
    verifier = Verifier.production()
    assert verifier is not None


def test_verifier_staging():
    verifier = Verifier.staging()
    assert verifier is not None


def test_verify_result_boolish():
    pem_bytes = resources.read_binary("sigstore._store", "fulcio.crt.pem")
    cert = load_pem_x509_certificate(pem_bytes)

    assert not VerificationFailure(reason="foo")
    assert not CertificateVerificationFailure(reason="foo", exception=ValueError("bar"))
    assert VerificationSuccess(cert=cert)
