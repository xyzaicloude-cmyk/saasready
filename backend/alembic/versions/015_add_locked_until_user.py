
"""Add security fields to users table

Revision ID: 010_add_security_fields
Revises: 009_add_invited_full_name
Create Date: 2025-01-XX XX:XX:XX.XXXXXX

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = '014_add_locked_untill_user'
down_revision = '014_add_user_columns'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Password security tracking
    op.add_column('users', sa.Column('locked_until', sa.DateTime(), nullable=True))



def downgrade() -> None:

    # Drop columns

    op.drop_column('users', 'locked_until')
