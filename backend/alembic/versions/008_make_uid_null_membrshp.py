"""Make user_id nullable in memberships for invitation flow

Revision ID: 008_make_user_id_nullable_in_memberships
Revises: 007_add_invited_email_to_memberships
Create Date: 2025-01-22 12:00:00.000000
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '008_make_uid_null_in_membrship'
down_revision = '007_invited_email_to_membrshp'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Make user_id nullable to support invitation-only memberships
    op.alter_column('memberships', 'user_id',
                    existing_type=sa.VARCHAR(),
                    nullable=True)


def downgrade() -> None:
    # Make user_id non-nullable again (will fail if there are null values)
    op.alter_column('memberships', 'user_id',
                    existing_type=sa.VARCHAR(),
                    nullable=False)