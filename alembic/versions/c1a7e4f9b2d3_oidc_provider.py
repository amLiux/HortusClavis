"""oidc_provider

Revision ID: c1a7e4f9b2d3
Revises: 8c5e2f1a3b4d
Create Date: 2026-11-15 22:45:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c1a7e4f9b2d3"
down_revision: str | Sequence[str] | None = "8c5e2f1a3b4d"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "signing_keys",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("kid", sa.String(length=64), nullable=False),
        sa.Column("alg", sa.String(length=8), nullable=False, server_default=sa.text("'RS256'")),
        sa.Column("private_key_pem", sa.Text(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("kid"),
    )
    op.create_index(op.f("ix_signing_keys_kid"), "signing_keys", ["kid"])

    op.create_table(
        "oauth_clients",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("client_id", sa.String(length=64), nullable=False),
        sa.Column("client_secret_hash", sa.String(length=255), nullable=True),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("service_id", sa.UUID(), nullable=False),
        sa.Column("redirect_uris", sa.JSON(), nullable=False),
        sa.Column("scopes", sa.String(length=256), nullable=False),
        sa.Column("is_confidential", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["service_id"], ["services.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("client_id"),
    )
    op.create_index(op.f("ix_oauth_clients_client_id"), "oauth_clients", ["client_id"])
    op.create_index(op.f("ix_oauth_clients_service_id"), "oauth_clients", ["service_id"])

    op.create_table(
        "oidc_authorization_codes",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("code_hash", sa.String(length=64), nullable=False),
        sa.Column("client_id", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("redirect_uri", sa.Text(), nullable=False),
        sa.Column("scope", sa.String(length=256), nullable=False),
        sa.Column("nonce", sa.String(length=255), nullable=True),
        sa.Column("code_challenge", sa.String(length=128), nullable=True),
        sa.Column("code_challenge_method", sa.String(length=10), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["client_id"], ["oauth_clients.client_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("code_hash"),
    )
    op.create_index(
        op.f("ix_oidc_authorization_codes_code_hash"), "oidc_authorization_codes", ["code_hash"]
    )
    op.create_index(
        op.f("ix_oidc_authorization_codes_client_id"), "oidc_authorization_codes", ["client_id"]
    )
    op.create_index(
        op.f("ix_oidc_authorization_codes_user_id"), "oidc_authorization_codes", ["user_id"]
    )

    op.create_table(
        "oidc_refresh_tokens",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("client_id", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("scope", sa.String(length=256), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rotated_from", sa.UUID(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["client_id"], ["oauth_clients.client_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index(
        op.f("ix_oidc_refresh_tokens_token_hash"), "oidc_refresh_tokens", ["token_hash"]
    )
    op.create_index(op.f("ix_oidc_refresh_tokens_client_id"), "oidc_refresh_tokens", ["client_id"])
    op.create_index(op.f("ix_oidc_refresh_tokens_user_id"), "oidc_refresh_tokens", ["user_id"])


def downgrade() -> None:
    op.drop_index(op.f("ix_oidc_refresh_tokens_user_id"), table_name="oidc_refresh_tokens")
    op.drop_index(op.f("ix_oidc_refresh_tokens_client_id"), table_name="oidc_refresh_tokens")
    op.drop_index(op.f("ix_oidc_refresh_tokens_token_hash"), table_name="oidc_refresh_tokens")
    op.drop_table("oidc_refresh_tokens")

    op.drop_index(
        op.f("ix_oidc_authorization_codes_user_id"), table_name="oidc_authorization_codes"
    )
    op.drop_index(
        op.f("ix_oidc_authorization_codes_client_id"), table_name="oidc_authorization_codes"
    )
    op.drop_index(
        op.f("ix_oidc_authorization_codes_code_hash"), table_name="oidc_authorization_codes"
    )
    op.drop_table("oidc_authorization_codes")

    op.drop_index(op.f("ix_oauth_clients_service_id"), table_name="oauth_clients")
    op.drop_index(op.f("ix_oauth_clients_client_id"), table_name="oauth_clients")
    op.drop_table("oauth_clients")

    op.drop_index(op.f("ix_signing_keys_kid"), table_name="signing_keys")
    op.drop_table("signing_keys")
