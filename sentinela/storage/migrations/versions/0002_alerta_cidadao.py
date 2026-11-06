"""alerta ao cidadão escrito pela IA (Global Solution 2026.2)

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-07 10:00:00
"""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.add_column(sa.Column("ai_alerta_cidadao", sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.drop_column("ai_alerta_cidadao")
