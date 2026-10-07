"""Origin permission checks follow browser serialization without relaxing URI identifiers."""

from http import HTTPStatus

import pytest
from starlette.requests import Request

from federated_identity.common.security.browser import BrowserInputError, require_form_origin
from federated_identity.common.settings.runtime import RuntimeSettings, ServiceId


def login_request(origin: str) -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "scheme": "https",
            "server": ("idp.localhost", 443),
            "path": "/login",
            "query_string": b"",
            "headers": [(b"origin", origin.encode("ascii"))],
        }
    )


@pytest.mark.parametrize("public_url", ["https://idp.localhost:443", "https://IDP.LOCALHOST:443"])
def test_browser_serialized_origin_works_with_default_port_and_configured_host_case(
    public_url: str,
) -> None:
    settings = RuntimeSettings(
        service_id=ServiceId.IDP, public_url=public_url, issuer=public_url, listen_port=443
    )
    require_form_origin(login_request("https://idp.localhost"), settings)
    assert settings.issuer == public_url


@pytest.mark.parametrize(
    "origin",
    [
        "null",
        "http://idp.localhost",
        "https://sp-a.localhost",
        "https://idp.localhost:8443",
        "https://idp.localhost/",
        "https://idp.localhost https://sp-b.localhost",
    ],
)
def test_default_port_configuration_does_not_accept_opaque_foreign_or_ambiguous_origins(
    origin: str,
) -> None:
    settings = RuntimeSettings(
        service_id=ServiceId.IDP,
        public_url="https://IDP.LOCALHOST:443",
        issuer="https://IDP.LOCALHOST:443",
        listen_port=443,
    )
    with pytest.raises(BrowserInputError) as denied:
        require_form_origin(login_request(origin), settings)
    assert denied.value.status == HTTPStatus.FORBIDDEN
