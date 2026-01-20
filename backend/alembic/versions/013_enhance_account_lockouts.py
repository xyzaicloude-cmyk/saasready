# backend/alembic/versions/013_enhance_account_lockouts.py
"""Add enhanced columns to account_lockouts table

Revision ID: 013_enhance_account_lockouts
Revises: 012_add_enterprise_auth_features
Create Date: 2025-12-09 18:30:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = '013_enhance_account_lockouts'
down_revision = '012_add_enterprise_auth_features'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add enhanced columns to account_lockouts
    op.add_column('account_lockouts', sa.Column('lockout_type', sa.String(), default='account', nullable=False))
    op.add_column('account_lockouts', sa.Column('device_id', sa.String(), nullable=True))
    op.add_column('account_lockouts', sa.Column('ip_address', sa.String(), nullable=True))

    # Add indexes for performance
    op.create_index('ix_account_lockouts_device_id', 'account_lockouts', ['device_id'])
    op.create_index('ix_account_lockouts_ip_address', 'account_lockouts', ['ip_address'])

    # Also add device tracking to login_attempts (since you reference it)
    op.add_column('login_attempts', sa.Column('device_id', sa.String(), nullable=True))
    op.add_column('login_attempts', sa.Column('device_type', sa.String(), nullable=True))
    op.add_column('login_attempts', sa.Column('two_factor_success', sa.Boolean(), nullable=True))
    op.add_column('login_attempts', sa.Column('location_data', sa.JSON(), nullable=True)),
    op.add_column('login_attempts', sa.Column('two_factor_attempted', sa.Boolean, nullable=True)),

    op.create_index('ix_login_attempts_device_id', 'login_attempts', ['device_id'])


def downgrade() -> None:
    # Remove login_attempts enhancements
    op.drop_index('ix_login_attempts_device_id', table_name='login_attempts')
    op.drop_column('login_attempts', 'two_factor_success')
    op.drop_column('login_attempts', 'device_type')
    op.drop_column('login_attempts', 'device_id')
    op.drop_column('login_attempts', 'location_data')
    op.drop_column('login_attempts', 'two_factor_attempted')


    # Remove account_lockouts enhancements
    op.drop_index('ix_account_lockouts_ip_address', table_name='account_lockouts')
    op.drop_index('ix_account_lockouts_device_id', table_name='account_lockouts')
    op.drop_column('account_lockouts', 'ip_address')
    op.drop_column('account_lockouts', 'device_id')
    op.drop_column('account_lockouts', 'lockout_type')