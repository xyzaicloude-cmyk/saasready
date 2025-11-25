"""Add email verification fields to users

Revision ID: 006_add_email_verification_fields
Revises: 005_add_password_reset_fields
Create Date: 2025-01-20 12:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
from datetime import datetime, timedelta


# revision identifiers, used by Alembic.
revision = '006_add_email_verif_fields'
down_revision = '005_add_password_reset_fields'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add is_email_verified column with default False
    op.add_column('users', sa.Column('is_email_verified', sa.Boolean(), nullable=False, server_default='false'))

    # Add email_verification_token column
    op.add_column('users', sa.Column('email_verification_token', sa.String(), nullable=True))

    # Add email_verification_sent_at column
    op.add_column('users', sa.Column('email_verification_sent_at', sa.DateTime(), nullable=True))

    # Create unique index on email_verification_token
    op.create_index('ix_users_email_verification_token', 'users', ['email_verification_token'], unique=True)

    # Update existing users to have is_email_verified = true (for backward compatibility)
    op.execute("UPDATE users SET is_email_verified = true WHERE is_email_verified IS NULL")


def downgrade() -> None:
    # Drop index
    op.drop_index('ix_users_email_verification_token', table_name='users')

    # Drop columns
    op.drop_column('users', 'email_verification_sent_at')
    op.drop_column('users', 'email_verification_token')
    op.drop_column('users', 'is_email_verified')