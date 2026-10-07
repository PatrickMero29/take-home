"""Typed, server-selected browser intent; a challenge is not authentication evidence."""

from enum import StrEnum

from pydantic import Field

from federated_identity.common.settings.policy import FrozenModel, HttpsUrl, Identifier


class BrowserActionPurpose(StrEnum):
    SP_LOGOUT = "sp_logout"
    SP_GLOBAL_LOGOUT = "sp_global_logout"
    SP_REVOKE = "sp_revoke"
    SP_REAUTHENTICATE = "sp_reauthenticate"
    SP_STEP_UP = "sp_step_up"
    SP_SENSITIVE = "sp_sensitive"
    IDP_LOGOUT = "idp_logout"
    RP_LOGOUT = "rp_logout"
    IDP_REVOKE = "idp_revoke"
    OPERATOR_LOGIN = "operator_login"
    OPERATOR_LOGOUT = "operator_logout"
    CLIENT_REGISTER = "client_register"
    CLIENT_UPDATE = "client_update"
    CLIENT_DISABLE = "client_disable"
    CLIENT_ENABLE = "client_enable"
    CLIENT_REPLACE = "client_replace"
    CLIENT_CONTAIN = "client_contain"
    SIGNING_PREPARE = "signing_prepare"
    SIGNING_ACTIVATE = "signing_activate"
    SIGNING_RETIRE = "signing_retire"
    SIGNING_CONTAIN = "signing_contain"


class LogoutReturn(FrozenModel):
    client_id: Identifier
    registration_version: int = Field(ge=1)
    post_logout_redirect_uri: HttpsUrl | None = None
    state: str | None = Field(default=None, min_length=1, max_length=256)


class BrowserAction(FrozenModel):
    purpose: BrowserActionPurpose
    target: Identifier
    logout_return: LogoutReturn | None = None
