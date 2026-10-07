"""Each SP migration runs against its independently authenticated database."""

from alembic import context

connection = context.config.attributes.get("connection")
if connection is None:
    raise RuntimeError("Use federationctl to supply the verified database connection")

context.configure(connection=connection)
with context.begin_transaction():
    context.run_migrations()
