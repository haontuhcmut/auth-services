"""add email verification

Revision ID: 4e935de55b45
Revises: e62b713a385a
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "4e935de55b45"
down_revision: str | Sequence[str] | None = "e62b713a385a"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "email_verified",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade() -> None:
    op.drop_column("users", "email_verified")
