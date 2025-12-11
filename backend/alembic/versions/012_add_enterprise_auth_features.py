
"""Add security fields to users table

Revision ID: 010_add_security_fields
Revises: 009_add_invited_full_name
Create Date: 2025-01-XX XX:XX:XX.XXXXXX

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = '012_add_enterprise_auth_features'
down_revision = '011_rename_email_queue_metadata'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Password security tracking
    op.add_column('users', sa.Column('password_history', postgresql.JSON(astext_type=sa.Text()), nullable=True))
    op.add_column('users', sa.Column('failed_login_attempts', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('users', sa.Column('account_locked_until', sa.DateTime(), nullable=True))

    # Login tracking
    op.add_column('users', sa.Column('previous_login_at', sa.DateTime(), nullable=True))
    op.add_column('users', sa.Column('previous_login_ip', sa.String(), nullable=True))

    # 2FA fields
    op.add_column('users', sa.Column('totp_secret', sa.String(), nullable=True))
    op.add_column('users', sa.Column('totp_secret_pending', sa.String(), nullable=True))
    op.add_column('users', sa.Column('totp_enabled', sa.Boolean(), nullable=False, server_default='false'))
    op.add_column('users', sa.Column('backup_codes', postgresql.JSON(astext_type=sa.Text()), nullable=True))

    # Security preferences
    op.add_column('users', sa.Column('security_alerts_enabled', sa.Boolean(), nullable=False, server_default='true'))
    op.add_column('users', sa.Column('suspicious_activity_notified_at', sa.DateTime(), nullable=True))

    # Compliance fields
    op.add_column('users', sa.Column('terms_accepted_at', sa.DateTime(), nullable=True))
    op.add_column('users', sa.Column('privacy_policy_accepted_at', sa.DateTime(), nullable=True))
    op.add_column('users', sa.Column('gdpr_consent_given', sa.Boolean(), nullable=False, server_default='false'))

    # Soft delete
    op.add_column('users', sa.Column('deleted_at', sa.DateTime(), nullable=True))

    # Create indexes for performance
    op.create_index('ix_users_last_login_at', 'users', ['last_login_at'])
    op.create_index('ix_users_deleted_at', 'users', ['deleted_at'])


def downgrade() -> None:
    # Drop indexes
    op.drop_index('ix_users_deleted_at', table_name='users')
    op.drop_index('ix_users_last_login_at', table_name='users')

    # Drop columns
    op.drop_column('users', 'deleted_at')
    op.drop_column('users', 'gdpr_consent_given')
    op.drop_column('users', 'privacy_policy_accepted_at')
    op.drop_column('users', 'terms_accepted_at')
    op.drop_column('users', 'suspicious_activity_notified_at')
    op.drop_column('users', 'security_alerts_enabled')
    op.drop_column('users', 'backup_codes')
    op.drop_column('users', 'totp_enabled')
    op.drop_column('users', 'totp_secret_pending')
    op.drop_column('users', 'totp_secret')
    op.drop_column('users', 'previous_login_ip')
    op.drop_column('users', 'previous_login_at')
    op.drop_column('users', 'account_locked_until')
    op.drop_column('users', 'failed_login_attempts')
