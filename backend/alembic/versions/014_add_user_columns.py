
"""Add security fields to users table

Revision ID: 010_add_security_fields
Revises: 009_add_invited_full_name
Create Date: 2025-01-XX XX:XX:XX.XXXXXX

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = '014_add_user_columns'
down_revision = '013_enhance_account_lockouts'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Password security tracking
    op.add_column('users', sa.Column('totp_enabled_at', sa.DateTime(), nullable=True))
    op.add_column('users', sa.Column('last_device_fingerprint', sa.String(), nullable=True))
    op.add_column('users', sa.Column('locked_until', sa.DateTime(), nullable=True))



def downgrade() -> None:

    # Drop columns
    op.drop_column('users', 'totp_enabled_at')
    op.drop_column('users', 'last_device_fingerprint')
    op.drop_column('users', 'locked_until')
