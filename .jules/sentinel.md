## 2026-01-06 - Missing Timeouts in Network Requests
**Vulnerability:** Several network requests using the `requests` library were made without a `timeout` argument.
**Learning:** This can lead to the application hanging indefinitely if the server does not respond, potentially causing denial of service (DoS) by resource exhaustion.
**Prevention:** Always specify a `timeout` when making network requests. A `DEFAULT_TIMEOUT` constant has been added to `sigstore/_utils.py` and should be used for all new requests.
