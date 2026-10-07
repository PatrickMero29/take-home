"""Separate operator API and script-free, purpose/CSRF-bound control plane pages."""

import html
import json
from http import HTTPStatus

from fastapi import FastAPI, Request
from pydantic import BaseModel, SecretStr, TypeAdapter, ValidationError
from starlette.responses import JSONResponse, Response

from federated_identity.common.security.actions import BrowserActionPurpose
from federated_identity.common.security.browser import (
    BROWSER_HEADERS,
    OPAQUE_COOKIE,
    action_form,
    browser_parameters,
    page,
    redirect,
    require_form_origin,
    require_https,
)
from federated_identity.idp.schemas.clients import (
    ClientCreate,
    ClientCredentialReplacement,
    ClientDestinations,
    ClientId,
    ClientStateChange,
    ClientUpdate,
)
from federated_identity.idp.schemas.components import IdpComponents
from federated_identity.idp.schemas.operator import (
    OperatorAuthorization,
    OperatorChannel,
    OperatorLogin,
    OperatorPermission,
)
from federated_identity.idp.services.operator import OperatorError

CLIENT_ACTIONS = {
    "register": BrowserActionPurpose.CLIENT_REGISTER,
    "update": BrowserActionPurpose.CLIENT_UPDATE,
    "disable": BrowserActionPurpose.CLIENT_DISABLE,
    "enable": BrowserActionPurpose.CLIENT_ENABLE,
    "credential": BrowserActionPurpose.CLIENT_REPLACE,
    "contain": BrowserActionPurpose.CLIENT_CONTAIN,
}


def operator_cookie(request: Request, components: IdpComponents) -> SecretStr | None:
    value = request.cookies.get(components.settings.operator_cookie_name, "")
    return SecretStr(value) if OPAQUE_COOKIE.fullmatch(value) else None


def set_operator_cookie(
    response: Response, components: IdpComponents, token: SecretStr, ttl: int
) -> None:
    response.set_cookie(
        components.settings.operator_cookie_name,
        token.get_secret_value(),
        secure=True,
        httponly=True,
        samesite="lax",
        path="/",
        max_age=ttl,
    )


def browser_authorization(
    request: Request, components: IdpComponents, challenge: str | None = None
) -> OperatorAuthorization:
    token = operator_cookie(request, components)
    if token is None:
        raise OperatorError("Operator authentication is required", HTTPStatus.UNAUTHORIZED)
    if challenge is not None and not OPAQUE_COOKIE.fullmatch(challenge):
        raise OperatorError("A valid operator intention is required", HTTPStatus.FORBIDDEN)
    return OperatorAuthorization(
        token, OperatorChannel.BROWSER, SecretStr(challenge) if challenge else None
    )


def api_authorization(
    request: Request, components: IdpComponents, *, mutation: bool = False
) -> OperatorAuthorization:
    require_https(request)
    header = request.headers.get("authorization")
    cookie = operator_cookie(request, components)
    if header is not None:
        scheme, separator, value = header.partition(" ")
        if (
            cookie is not None
            or scheme != "Bearer"
            or not separator
            or not OPAQUE_COOKIE.fullmatch(value)
        ):
            raise OperatorError(
                "An unambiguous operator API session is required", HTTPStatus.UNAUTHORIZED
            )
        return OperatorAuthorization(SecretStr(value), OperatorChannel.API)
    authorization = browser_authorization(request, components)
    if mutation:
        require_form_origin(request, components.settings)
        challenge = request.headers.get("x-csrf-token", "")
        if not OPAQUE_COOKIE.fullmatch(challenge):
            raise OperatorError("An operator browser intention is required", HTTPStatus.FORBIDDEN)
        authorization = OperatorAuthorization(
            authorization.token, authorization.channel, SecretStr(challenge)
        )
    return authorization


async def json_input[T: BaseModel](
    request: Request, components: IdpComponents, model: type[T]
) -> T:
    require_https(request)
    if (
        request.query_params
        or request.headers.get("content-type", "").partition(";")[0].lower() != "application/json"
    ):
        raise OperatorError(
            "A JSON body without query parameters is required", HTTPStatus.BAD_REQUEST
        )
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > components.settings.policy.max_form_bytes:
            raise OperatorError(
                "Operator request exceeds the body limit", HTTPStatus.REQUEST_ENTITY_TOO_LARGE
            )
        body.extend(chunk)
    try:
        # Reject duplicate JSON members before Pydantic's model parser flattens them.
        def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for name, value in pairs:
                if name in result:
                    raise ValueError("Duplicate JSON members")
                result[name] = value
            return result

        json.loads(body, object_pairs_hook=unique_pairs)
        return model.model_validate_json(body)
    except (ValueError, ValidationError) as error:
        raise OperatorError("Invalid operator request metadata", HTTPStatus.BAD_REQUEST) from error


def metadata_input[T: BaseModel](raw: str, model: type[T]) -> T:
    try:
        return model.model_validate_json(raw)
    except (ValueError, ValidationError) as error:
        raise OperatorError("Invalid client metadata", HTTPStatus.BAD_REQUEST) from error


def client_identity(value: str) -> str:
    try:
        return TypeAdapter(ClientId).validate_python(value)
    except ValidationError:
        raise OperatorError("Invalid client identity", HTTPStatus.BAD_REQUEST) from None


def operator_page(title: str, content: str, *, status: HTTPStatus = HTTPStatus.OK) -> Response:
    response = page("idp operator", title, content, status=status)
    response.headers["Referrer-Policy"] = "same-origin"
    return response


def install_operator_routes(app: FastAPI, components: IdpComponents) -> None:
    operators, clients = components.operators, components.clients

    @app.exception_handler(OperatorError)
    async def rejected(request: Request, error: OperatorError) -> Response:
        if request.url.path.startswith("/admin/api/"):
            return JSONResponse(
                {"error": error.description}, status_code=error.status, headers=BROWSER_HEADERS
            )
        return operator_page(
            "Operator request rejected",
            f"<p>{html.escape(error.description)}</p><a href='/admin'>Operator control plane</a>",
            status=error.status,
        )

    @app.post("/admin/api/session")
    async def api_login(request: Request) -> Response:
        if "origin" in request.headers:
            require_form_origin(request, components.settings)
        login = await json_input(request, components, OperatorLogin)
        session = await operators.login(login.username, login.password, channel=OperatorChannel.API)
        return JSONResponse(
            {
                "token_type": "Bearer",
                "access_token": session.token.get_secret_value(),
                "expires_in": session.ttl,
            },
            headers=BROWSER_HEADERS,
        )

    @app.delete("/admin/api/session")
    async def api_logout(request: Request) -> Response:
        await operators.logout(api_authorization(request, components, mutation=True))
        return Response(status_code=HTTPStatus.NO_CONTENT, headers=BROWSER_HEADERS)

    @app.get("/admin/api/clients")
    async def list_clients(request: Request) -> Response:
        await browser_parameters(
            request, frozenset(), limit=components.settings.policy.max_form_bytes
        )
        records = await clients.inspect(api_authorization(request, components))
        return JSONResponse(
            {"clients": [record.model_dump(mode="json") for record in records]},
            headers=BROWSER_HEADERS,
        )

    @app.get("/admin/api/clients/{client_id}")
    async def inspect_client(request: Request, client_id: str) -> Response:
        await browser_parameters(
            request, frozenset(), limit=components.settings.policy.max_form_bytes
        )
        records = await clients.inspect(
            api_authorization(request, components), client_identity(client_id)
        )
        return JSONResponse(records[0].model_dump(mode="json"), headers=BROWSER_HEADERS)

    @app.post("/admin/api/clients")
    async def register_client(request: Request) -> Response:
        authorization = api_authorization(request, components, mutation=True)
        await operators.principal(authorization, OperatorPermission.CLIENTS_WRITE)
        record = await clients.register(
            authorization, await json_input(request, components, ClientCreate)
        )
        return JSONResponse(
            record.model_dump(mode="json"), status_code=HTTPStatus.CREATED, headers=BROWSER_HEADERS
        )

    @app.put("/admin/api/clients/{client_id}")
    async def update_client(request: Request, client_id: str) -> Response:
        authorization = api_authorization(request, components, mutation=True)
        await operators.principal(authorization, OperatorPermission.CLIENTS_WRITE)
        record = await clients.update(
            authorization,
            client_identity(client_id),
            await json_input(request, components, ClientUpdate),
        )
        return JSONResponse(record.model_dump(mode="json"), headers=BROWSER_HEADERS)

    @app.post("/admin/api/clients/{client_id}/disable")
    async def disable_client(request: Request, client_id: str) -> Response:
        authorization = api_authorization(request, components, mutation=True)
        await operators.principal(authorization, OperatorPermission.CLIENTS_WRITE)
        record = await clients.set_enabled(
            authorization,
            client_identity(client_id),
            await json_input(request, components, ClientStateChange),
            enabled=False,
        )
        return JSONResponse(record.model_dump(mode="json"), headers=BROWSER_HEADERS)

    @app.post("/admin/api/clients/{client_id}/enable")
    async def enable_client(request: Request, client_id: str) -> Response:
        authorization = api_authorization(request, components, mutation=True)
        await operators.principal(authorization, OperatorPermission.CLIENTS_WRITE)
        record = await clients.set_enabled(
            authorization,
            client_identity(client_id),
            await json_input(request, components, ClientStateChange),
            enabled=True,
        )
        return JSONResponse(record.model_dump(mode="json"), headers=BROWSER_HEADERS)

    @app.post("/admin/api/clients/{client_id}/credential")
    async def replace_credential(request: Request, client_id: str) -> Response:
        authorization = api_authorization(request, components, mutation=True)
        await operators.principal(authorization, OperatorPermission.CLIENTS_WRITE)
        record = await clients.replace_credential(
            authorization,
            client_identity(client_id),
            await json_input(request, components, ClientCredentialReplacement),
        )
        return JSONResponse(record.model_dump(mode="json"), headers=BROWSER_HEADERS)

    @app.post("/admin/api/clients/{client_id}/contain")
    async def contain_client(request: Request, client_id: str) -> Response:
        authorization = api_authorization(request, components, mutation=True)
        await operators.principal(authorization, OperatorPermission.CLIENTS_WRITE)
        record = await clients.contain(
            authorization,
            client_identity(client_id),
            await json_input(request, components, ClientStateChange),
        )
        return JSONResponse(record.model_dump(mode="json"), headers=BROWSER_HEADERS)

    @app.get("/admin/api/intent")
    async def browser_intent(request: Request) -> Response:
        fields = await browser_parameters(
            request,
            frozenset({"action", "client_id"}),
            limit=components.settings.policy.max_form_bytes,
        )
        purpose = CLIENT_ACTIONS.get(fields.get("action", ""))
        if purpose is None:
            raise OperatorError("Unknown operator intention", HTTPStatus.BAD_REQUEST)
        target = (
            "clients:new"
            if purpose == BrowserActionPurpose.CLIENT_REGISTER
            else client_identity(fields.get("client_id", ""))
        )
        authorization = browser_authorization(request, components)
        if target != "clients:new":
            await clients.inspect(authorization, target)
        challenge = await operators.action(authorization, purpose, target)
        return JSONResponse({"csrf": challenge.get_secret_value()}, headers=BROWSER_HEADERS)

    async def login_form(request: Request, *, rejected_credentials: bool = False) -> Response:
        cookie, challenge = await operators.login_form(operator_cookie(request, components))
        error = "<p role='alert'>Invalid operator credentials.</p>" if rejected_credentials else ""
        response = operator_page(
            "Operator sign in",
            "<h2>Operator sign in</h2>" + error + "<form method='post' action='/admin/login'>"
            f"<input type='hidden' name='csrf' value='{html.escape(challenge.get_secret_value())}'>"
            "<p><label>Operator username <input name='username' "
            "autocomplete='username' required></label></p>"
            "<p><label>Operator password <input name='password' type='password' "
            "autocomplete='current-password' required></label></p>"
            "<button type='submit'>Operator sign in</button></form>",
            status=HTTPStatus.UNAUTHORIZED if rejected_credentials else HTTPStatus.OK,
        )
        set_operator_cookie(
            response, components, cookie, components.settings.browser_action_ttl_seconds
        )
        return response

    @app.get("/admin/login")
    async def login_page(request: Request) -> Response:
        await browser_parameters(
            request, frozenset(), limit=components.settings.policy.max_form_bytes
        )
        if operator_cookie(request, components) is not None:
            try:
                await operators.principal(browser_authorization(request, components))
                return redirect("/admin")
            except OperatorError:
                pass
        return await login_form(request)

    @app.post("/admin/login")
    async def browser_login(request: Request) -> Response:
        require_form_origin(request, components.settings)
        fields = await browser_parameters(
            request,
            frozenset({"csrf", "username", "password"}),
            limit=components.settings.policy.max_form_bytes,
        )
        if set(fields) != {"csrf", "username", "password"}:
            raise OperatorError("An operator credential form is required", HTTPStatus.BAD_REQUEST)
        cookie = operator_cookie(request, components)
        if cookie is None or not OPAQUE_COOKIE.fullmatch(fields["csrf"]):
            raise OperatorError("An operator browser binding is required", HTTPStatus.FORBIDDEN)
        login = metadata_input(
            json.dumps({"username": fields["username"], "password": fields["password"]}),
            OperatorLogin,
        )
        try:
            session = await operators.login(
                login.username,
                login.password,
                channel=OperatorChannel.BROWSER,
                browser=cookie,
                challenge=SecretStr(fields["csrf"]),
            )
        except OperatorError as error:
            if error.status == HTTPStatus.UNAUTHORIZED:
                return await login_form(request, rejected_credentials=True)
            raise
        response = redirect("/admin")
        set_operator_cookie(response, components, session.token, session.ttl)
        return response

    @app.get("/admin")
    async def home(request: Request) -> Response:
        require_https(request)
        try:
            authorization = browser_authorization(request, components)
            records = await clients.inspect(authorization)
        except OperatorError as error:
            if error.status == HTTPStatus.UNAUTHORIZED:
                return redirect("/admin/login")
            raise
        content = (
            "<h2>Operator control plane</h2><a href='/admin/clients/new'>Register a client</a><ul>"
        )
        for record in records:
            content += (
                f"<li><a href='/admin/clients/{html.escape(record.client_id)}'>"
                f"{html.escape(record.client_id)}</a>: "
                f"{'enabled' if record.enabled else 'disabled'}, "
                f"version {record.registration_version}</li>"
            )
        content += "</ul>"
        if OperatorPermission.KEYS_READ in (await operators.principal(authorization)).permissions:
            content += "<p><a href='/admin/signing-keys'>Manage signing keys</a></p>"
        challenge = await operators.action(
            authorization, BrowserActionPurpose.OPERATOR_LOGOUT, "operator"
        )
        return operator_page(
            "Operator control plane",
            content + action_form("/admin/logout", "Operator sign out", challenge),
        )

    @app.post("/admin/logout")
    async def browser_logout(request: Request) -> Response:
        require_form_origin(request, components.settings)
        fields = await browser_parameters(
            request, frozenset({"csrf"}), limit=components.settings.policy.max_form_bytes
        )
        if set(fields) != {"csrf"}:
            raise OperatorError("An operator intention is required", HTTPStatus.FORBIDDEN)
        await operators.logout(browser_authorization(request, components, fields["csrf"]))
        response = redirect("/admin/login")
        response.delete_cookie(
            components.settings.operator_cookie_name,
            path="/",
            secure=True,
            httponly=True,
            samesite="lax",
        )
        return response

    @app.get("/admin/clients/new")
    async def new_client(request: Request) -> Response:
        require_https(request)
        authorization = browser_authorization(request, components)
        challenge = await operators.action(
            authorization, BrowserActionPurpose.CLIENT_REGISTER, "clients:new"
        )
        return operator_page(
            "Register client",
            "<h2>Register client</h2><p>Paste public client metadata "
            "from federationctl client-metadata.</p>"
            "<form method='post' action='/admin/clients/new'>"
            f"<input type='hidden' name='csrf' value='{html.escape(challenge.get_secret_value())}'>"
            "<p><label>Client metadata JSON <textarea name='metadata' rows='16' "
            "cols='90' required></textarea></label></p>"
            "<button type='submit'>Register client</button></form>",
        )

    @app.post("/admin/clients/new")
    async def create_client(request: Request) -> Response:
        require_form_origin(request, components.settings)
        fields = await browser_parameters(
            request,
            frozenset({"csrf", "metadata"}),
            limit=components.settings.policy.max_form_bytes,
        )
        if set(fields) != {"csrf", "metadata"}:
            raise OperatorError("A client metadata form is required", HTTPStatus.BAD_REQUEST)
        record = await clients.register(
            browser_authorization(request, components, fields["csrf"]),
            metadata_input(fields["metadata"], ClientCreate),
        )
        return redirect(f"/admin/clients/{record.client_id}")

    @app.get("/admin/clients/{client_id}")
    async def client_page(request: Request, client_id: str) -> Response:
        require_https(request)
        authorization = browser_authorization(request, components)
        record = (await clients.inspect(authorization, client_identity(client_id)))[0]
        content = (
            f"<h2>{html.escape(record.client_id)}</h2>"
            f"<pre>{html.escape(record.model_dump_json(indent=2))}</pre>"
        )
        if record.compromised_key_id == record.key_id:
            content += (
                "<p>Compromised credentials require replacement before explicit re-enable.</p>"
            )
        if (
            OperatorPermission.CLIENTS_WRITE
            in (await operators.principal(authorization)).permissions
        ):
            update = {
                name: value
                for name, value in record.model_dump(mode="json").items()
                if name in ClientDestinations.model_fields
            }
            update["expected_version"] = record.registration_version
            for action, label, payload in (
                ("update", "Update client metadata", update),
                (
                    "credential",
                    "Replace client credentials",
                    {
                        "expected_version": record.registration_version,
                        "public_key_pem": "",
                        "key_id": "",
                    },
                ),
            ):
                challenge = await operators.action(
                    authorization, CLIENT_ACTIONS[action], record.client_id
                )
                content += (
                    f"<form method='post' action='/admin/clients/{record.client_id}/{action}'>"
                    "<input type='hidden' name='csrf' "
                    f"value='{html.escape(challenge.get_secret_value())}'>"
                    f"<p><label>{label} JSON <textarea name='metadata' rows='12' "
                    f"cols='90' required>{html.escape(json.dumps(payload, indent=2))}"
                    "</textarea></label></p>"
                    f"<button type='submit'>{label}</button></form>"
                )
            action = "disable" if record.enabled else "enable"
            challenge = await operators.action(
                authorization, CLIENT_ACTIONS[action], record.client_id
            )
            content += action_form(
                f"/admin/clients/{record.client_id}/{action}", f"{action.title()} client", challenge
            )
            challenge = await operators.action(
                authorization, BrowserActionPurpose.CLIENT_CONTAIN, record.client_id
            )
            content += (
                f"<form method='post' action='/admin/clients/{record.client_id}/contain'>"
                "<input type='hidden' name='csrf' "
                f"value='{html.escape(challenge.get_secret_value())}'>"
                "<input type='hidden' name='expected_version' "
                f"value='{record.registration_version}'>"
                "<button type='submit'>Contain compromised client</button></form>"
            )
        return operator_page("Client registration", content + "<a href='/admin'>Client list</a>")

    @app.post("/admin/clients/{client_id}/{action}")
    async def mutate_client(request: Request, client_id: str, action: str) -> Response:
        require_form_origin(request, components.settings)
        fields = await browser_parameters(
            request,
            frozenset({"csrf", "metadata", "expected_version"}),
            limit=components.settings.policy.max_form_bytes,
        )
        authorization = browser_authorization(request, components, fields.get("csrf", ""))
        client_id = client_identity(client_id)
        if action == "contain" and set(fields) == {"csrf", "expected_version"}:
            value = fields["expected_version"]
            if not value.isascii() or not value.isdecimal() or not 1 <= len(value) <= 18:
                raise OperatorError("A current client version is required", HTTPStatus.BAD_REQUEST)
            if int(value) < 1:
                raise OperatorError("A current client version is required", HTTPStatus.BAD_REQUEST)
            await clients.contain(
                authorization, client_id, ClientStateChange(expected_version=int(value))
            )
        elif action == "update" and set(fields) == {"csrf", "metadata"}:
            await clients.update(
                authorization, client_id, metadata_input(fields["metadata"], ClientUpdate)
            )
        elif action == "credential" and set(fields) == {"csrf", "metadata"}:
            await clients.replace_credential(
                authorization,
                client_id,
                metadata_input(fields["metadata"], ClientCredentialReplacement),
            )
        elif action in {"disable", "enable"} and set(fields) == {"csrf"}:
            # Current version is read under authorization; the service still
            # rejects a concurrent metadata update before publishing success.
            record = (await clients.inspect(authorization, client_id))[0]
            await clients.set_enabled(
                authorization,
                client_id,
                ClientStateChange(expected_version=record.registration_version),
                enabled=action == "enable",
            )
        else:
            raise OperatorError("Invalid client-management action", HTTPStatus.BAD_REQUEST)
        return redirect(f"/admin/clients/{client_id}")
