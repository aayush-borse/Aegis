"""Tests for robust OSV client error handling."""

import urllib.error
from unittest.mock import patch

import pytest

from aegis.models import Dependency
from aegis.vulnerability import osv as osv_module
from aegis.vulnerability.osv import OSVError, query_vulnerabilities


def test_osv_rate_limit_error() -> None:
    dep = Dependency(name="requests", specifier="==2.31.0")

    with patch("urllib.request.urlopen") as mock_urlopen, patch(
        "aegis.vulnerability.osv.time.sleep"
    ) as mock_sleep:
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://api.osv.dev/v1/query",
            code=429,
            msg="Too Many Requests",
            hdrs=None,
            fp=None,
        )

        with pytest.raises(OSVError, match="Rate limit exceeded"):
            query_vulnerabilities(dep)

        # Verify the retry policy actually fired: one initial attempt plus
        # three retries on HTTP 429, with exponential backoff sleeps.
        assert mock_urlopen.call_count == len(osv_module._RATE_LIMIT_BACKOFF_SECONDS) + 1
        assert mock_sleep.call_count == len(osv_module._RATE_LIMIT_BACKOFF_SECONDS)
        actual_backoffs = [call.args[0] for call in mock_sleep.call_args_list]
        assert actual_backoffs == list(osv_module._RATE_LIMIT_BACKOFF_SECONDS)


def test_osv_timeout_error() -> None:
    dep = Dependency(name="requests", specifier="==2.31.0")

    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.side_effect = TimeoutError()

        with pytest.raises(OSVError, match="Request timed out"):
            query_vulnerabilities(dep, timeout=1.0)