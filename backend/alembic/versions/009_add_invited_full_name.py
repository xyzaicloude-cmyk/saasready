"""add invited_full_name to memberships

Revision ID: 009_add_invited_full_name
Revises: 008_make_uid_null_in_membrship
Create Date: 2024-01-XX XX:XX:XX.XXXXXX

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '009_add_invited_full_name'
down_revision = '008_make_uid_null_in_membrship'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add invited_full_name column to memberships table
    op.add_column('memberships', sa.Column('invited_full_name', sa.String(), nullable=True))


def downgrade() -> None:
    # Remove invited_full_name column from memberships table
    op.drop_column('memberships', 'invited_full_name')