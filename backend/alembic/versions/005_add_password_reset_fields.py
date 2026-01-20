"""Add password reset fields to users

Revision ID: 005_add_password_reset_fields
Revises: 004_add_invitation_tokens
Create Date: 2025-01-20 11:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from datetime import datetime, timedelta


# revision identifiers, used by Alembic.
revision = '005_add_password_reset_fields'
down_revision = '004_add_invitation_tokens'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add reset_token column
    op.add_column('users', sa.Column('reset_token', sa.String(), nullable=True))

    # Add reset_token_expires_at column
    op.add_column('users', sa.Column('reset_token_expires_at', sa.DateTime(), nullable=True))

    # Create unique index on reset_token
    op.create_index('ix_users_reset_token', 'users', ['reset_token'], unique=True)


def downgrade() -> None:
    # Drop index
    op.drop_index('ix_users_reset_token', table_name='users')

    # Drop columns
    op.drop_column('users', 'reset_token_expires_at')
    op.drop_column('users', 'reset_token')