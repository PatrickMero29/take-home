"""Operator-only signing lifecycle with public-only responses and bound browser intentions."""

import html
from http import HTTPStatus

from fastapi import FastAPI, Request
from pydantic import TypeAdapter, ValidationError
from starlette.responses import JSONResponse, Response

from federated_identity.common.security.actions import BrowserActionPurpose
from federated_identity.common.security.browser import (
    BROWSER_HEADERS,
    browser_parameters,
    redirect,
    require_form_origin,
)
from federated_identity.common.security.model import KeyState
from federated_identity.idp.api.operator import (
    api_authorization,
    browser_authorization,
    json_input,
    operator_page,
)
from federated_identity.idp.schemas.clients import KeyId
from federated_identity.idp.schemas.components import IdpComponents
from federated_identity.idp.schemas.operator import OperatorPermission
from federated_identity.idp.schemas.signing import (
    SigningKeyActivation,
    SigningKeyContainment,
    SigningKeyPrepare,
    SigningKeyRetirement,
)
from federated_identity.idp.services.operator import OperatorError


def signing_identity(value: str) -> str:
    try:
        return TypeAdapter(KeyId).validate_python(value)
    except ValidationError:
        raise OperatorError("Invalid signing key identity", HTTPStatus.BAD_REQUEST) from None


def install_signing_routes(app: FastAPI, components: IdpComponents) -> None:
    administration = components.signing
    operators = components.operators

    @app.get("/admin/api/signing-keys")
    async def inspect(request: Request) -> Response:
        await browser_parameters(
            request, frozenset(), limit=components.settings.policy.max_form_bytes
        )
        records = await administration.inspect(api_authorization(request, components))
        return JSONResponse(
            {"keys": [record.model_dump(mode="json") for record in records]},
            headers=BROWSER_HEADERS,
        )

    @app.post("/admin/api/signing-keys/prepare")
    async def prepare(request: Request) -> Response:
        authorization = api_authorization(request, components, mutation=True)
        await operators.principal(authorization, OperatorPermission.KEYS_WRITE)
        await json_input(request, components, SigningKeyPrepare)
        record = await administration.prepare(authorization)
        return JSONResponse(
            record.model_dump(mode="json"), status_code=HTTPStatus.CREATED, headers=BROWSER_HEADERS
        )

    @app.post("/admin/api/signing-keys/{key_id}/activate")
    async def activate(request: Request, key_id: str) -> Response:
        authorization = api_authorization(request, components, mutation=True)
        await operators.principal(authorization, OperatorPermission.KEYS_WRITE)
        record = await administration.activate(
            authorization,
            signing_identity(key_id),
            await json_input(request, components, SigningKeyActivation),
        )
        return JSONResponse(record.model_dump(mode="json"), headers=BROWSER_HEADERS)

    @app.post("/admin/api/signing-keys/{key_id}/retire")
    async def retire(request: Request, key_id: str) -> Response:
        authorization = api_authorization(request, components, mutation=True)
        await operators.principal(authorization, OperatorPermission.KEYS_WRITE)
        record = await administration.retire(
            authorization,
            signing_identity(key_id),
            await json_input(request, components, SigningKeyRetirement),
        )
        return JSONResponse(record.model_dump(mode="json"), headers=BROWSER_HEADERS)

    @app.get("/admin/signing-keys")
    async def key_page(request: Request) -> Response:
        await browser_parameters(
            request, frozenset(), limit=components.settings.policy.max_form_bytes
        )
        authorization = browser_authorization(request, components)
        records = await administration.inspect(authorization)
        principal = await operators.principal(authorization)
        writable = OperatorPermission.KEYS_WRITE in principal.permissions
        active = next((record for record in records if record.state == KeyState.ACTIVE), None)
        content = (
            "<h2>Issuer signing keys</h2>"
            "<p>Prepare, publish public keys, then activate. "
            "Existing sessions survive routine rotation.</p>"
            "<p><a href='/jwks.json' target='_blank' rel='noopener'>Publish public JWKS</a></p>"
            "<p><a href='/admin/signing-keys'>Reload key state</a></p>"
        )
        if writable:
            challenge = await operators.action(
                authorization, BrowserActionPurpose.SIGNING_PREPARE, "signing:new"
            )
            content += (
                "<form method='post' action='/admin/signing-keys/prepare'>"
                "<input type='hidden' name='csrf' "
                f"value='{html.escape(challenge.get_secret_value())}'>"
                "<button type='submit'>Prepare signing key</button></form>"
            )
        for record in records:
            kid = html.escape(record.key_id, quote=True)
            content += (
                f"<section data-key-id='{kid}'><h3>{kid}</h3>"
                f"<p>State: {record.state.value}; published: {record.published_at}; "
                f"verification deadline: {record.verification_deadline}.</p>"
            )
            if (
                writable
                and record.state == KeyState.PREPARED
                and record.published_at is not None
                and active is not None
            ):
                challenge = await operators.action(
                    authorization, BrowserActionPurpose.SIGNING_ACTIVATE, record.key_id
                )
                content += (
                    f"<form method='post' action='/admin/signing-keys/{kid}/activate'>"
                    "<input type='hidden' name='csrf' "
                    f"value='{html.escape(challenge.get_secret_value())}'>"
                    "<input type='hidden' name='expected_active_key_id' "
                    f"value='{html.escape(active.key_id, quote=True)}'>"
                    "<button type='submit'>Activate signing key</button></form>"
                )
            elif writable and record.state == KeyState.DRAINING:
                challenge = await operators.action(
                    authorization, BrowserActionPurpose.SIGNING_RETIRE, record.key_id
                )
                eligible = (
                    record.verification_deadline + components.settings.policy.clock_skew_seconds
                )
                content += (
                    f"<p>Retirement requires server time at least {eligible}.</p>"
                    f"<form method='post' action='/admin/signing-keys/{kid}/retire'>"
                    "<input type='hidden' name='csrf' "
                    f"value='{html.escape(challenge.get_secret_value())}'>"
                    "<input type='hidden' name='expected_verification_deadline' "
                    f"value='{record.verification_deadline}'>"
                    "<button type='submit'>Retire signing key</button></form>"
                )
            candidates = [
                key
                for key in records
                if key.key_id != record.key_id
                and (
                    key.state == KeyState.ACTIVE
                    or (key.state == KeyState.PREPARED and key.published_at is not None)
                )
            ]
            if writable and active is not None and record.state != KeyState.REVOKED and candidates:
                challenge = await operators.action(
                    authorization, BrowserActionPurpose.SIGNING_CONTAIN, record.key_id
                )
                options = "".join(
                    f"<option value='{html.escape(key.key_id, quote=True)}'>"
                    f"{html.escape(key.key_id)} ({key.state.value})</option>"
                    for key in candidates
                )
                content += (
                    f"<form method='post' action='/admin/signing-keys/{kid}/contain'>"
                    "<input type='hidden' name='csrf' "
                    f"value='{html.escape(challenge.get_secret_value())}'>"
                    "<input type='hidden' name='expected_active_key_id' "
                    f"value='{html.escape(active.key_id, quote=True)}'>"
                    "<p><label>Replacement signing key <select name='replacement_key_id' required>"
                    f"{options}</select></label></p>"
                    "<button type='submit'>Contain compromised signing key</button></form>"
                )
            content += "</section>"
        return operator_page(
            "Issuer signing keys", content + "<a href='/admin'>Operator control plane</a>"
        )

    @app.post("/admin/signing-keys/prepare")
    async def browser_prepare(request: Request) -> Response:
        require_form_origin(request, components.settings)
        fields = await browser_parameters(
            request, frozenset({"csrf"}), limit=components.settings.policy.max_form_bytes
        )
        if set(fields) != {"csrf"}:
            raise OperatorError("A signing preparation intention is required", HTTPStatus.FORBIDDEN)
        await administration.prepare(browser_authorization(request, components, fields["csrf"]))
        return redirect("/admin/signing-keys")

    @app.post("/admin/api/signing-keys/{key_id}/contain")
    async def contain(request: Request, key_id: str) -> Response:
        authorization = api_authorization(request, components, mutation=True)
        await operators.principal(authorization, OperatorPermission.KEYS_WRITE)
        result = await administration.contain(
            authorization,
            signing_identity(key_id),
            await json_input(request, components, SigningKeyContainment),
        )
        return JSONResponse(result.model_dump(mode="json"), headers=BROWSER_HEADERS)

    @app.post("/admin/signing-keys/{key_id}/contain")
    async def browser_contain(request: Request, key_id: str) -> Response:
        require_form_origin(request, components.settings)
        fields = await browser_parameters(
            request,
            frozenset({"csrf", "replacement_key_id", "expected_active_key_id"}),
            limit=components.settings.policy.max_form_bytes,
        )
        if set(fields) != {"csrf", "replacement_key_id", "expected_active_key_id"}:
            raise OperatorError("A signing containment intention is required", HTTPStatus.FORBIDDEN)
        await administration.contain(
            browser_authorization(request, components, fields["csrf"]),
            signing_identity(key_id),
            SigningKeyContainment(
                replacement_key_id=signing_identity(fields["replacement_key_id"]),
                expected_active_key_id=signing_identity(fields["expected_active_key_id"]),
            ),
        )
        return redirect("/admin/signing-keys")

    @app.post("/admin/signing-keys/{key_id}/activate")
    async def browser_activate(request: Request, key_id: str) -> Response:
        require_form_origin(request, components.settings)
        fields = await browser_parameters(
            request,
            frozenset({"csrf", "expected_active_key_id"}),
            limit=components.settings.policy.max_form_bytes,
        )
        if set(fields) != {"csrf", "expected_active_key_id"}:
            raise OperatorError("A signing activation intention is required", HTTPStatus.FORBIDDEN)
        await administration.activate(
            browser_authorization(request, components, fields["csrf"]),
            signing_identity(key_id),
            SigningKeyActivation(
                expected_active_key_id=signing_identity(fields["expected_active_key_id"])
            ),
        )
        return redirect("/admin/signing-keys")

    @app.post("/admin/signing-keys/{key_id}/retire")
    async def browser_retire(request: Request, key_id: str) -> Response:
        require_form_origin(request, components.settings)
        fields = await browser_parameters(
            request,
            frozenset({"csrf", "expected_verification_deadline"}),
            limit=components.settings.policy.max_form_bytes,
        )
        value = fields.get("expected_verification_deadline", "")
        if (
            set(fields) != {"csrf", "expected_verification_deadline"}
            or not value.isascii()
            or not value.isdecimal()
        ):
            raise OperatorError("A signing retirement intention is required", HTTPStatus.FORBIDDEN)
        await administration.retire(
            browser_authorization(request, components, fields["csrf"]),
            signing_identity(key_id),
            SigningKeyRetirement(expected_verification_deadline=int(value)),
        )
        return redirect("/admin/signing-keys")
