"""A separate pool/database instance for every relying application."""

from federated_identity.common.persistence.database import AsyncDatabase


class SpDatabase(AsyncDatabase):
    pass
