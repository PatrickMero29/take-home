"""Public-only snapshots of the live client registry."""

import json

from federated_identity.idp.repositories.tables import ClientRow
from federated_identity.idp.schemas.clients import ClientRegistration


def client_snapshot(row: ClientRow) -> ClientRegistration:
    return ClientRegistration.model_validate_json(
        json.dumps(
            {
                "client_id": row.client_id,
                "redirect_uris": row.redirect_uris,
                "public_key_pem": row.public_key_pem,
                "key_id": row.key_id,
                "enabled": row.enabled,
                "backchannel_logout_uri": row.backchannel_logout_uri,
                "allowed_grants": row.allowed_grants,
                "allowed_scopes": row.allowed_scopes,
                "post_logout_redirect_uris": row.post_logout_redirect_uris,
                "token_endpoint_auth_method": row.token_endpoint_auth_method,
                "token_endpoint_auth_signing_alg": row.token_endpoint_auth_signing_alg,
                "registration_version": row.registration_version,
                "compromised_key_id": row.compromised_key_id,
            }
        )
    )
