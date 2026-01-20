# backend/alembic/versions/010_add_token_revocation_tables.py
"""Add token revocation and session management tables

Revision ID: 010_add_token_revocation
Revises: 009_add_invited_full_name
Create Date: 2025-01-25 10:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
from datetime import datetime


revision = '010_add_token_revocation'
down_revision = '009_add_invited_full_name'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create token_blacklist table
    op.create_table(
        'token_blacklist',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('jti', sa.String(), nullable=False, unique=True),
        sa.Column('user_id', sa.String(), nullable=False),
        sa.Column('revoked_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('reason', sa.String(), nullable=True)
    )

    op.create_index('ix_token_blacklist_jti', 'token_blacklist', ['jti'])
    op.create_index('ix_token_blacklist_user_id', 'token_blacklist', ['user_id'])
    op.create_index('ix_token_blacklist_expires_at', 'token_blacklist', ['expires_at'])

    # Create user_sessions table
    op.create_table(
        'user_sessions',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('user_id', sa.String(), nullable=False),
        sa.Column('jti', sa.String(), nullable=False, unique=True),
        sa.Column('device_info', sa.String(), nullable=True),
        sa.Column('ip_address', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.Column('last_activity', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True)
    )

    op.create_index('ix_user_sessions_jti', 'user_sessions', ['jti'])
    op.create_index('ix_user_sessions_user_id', 'user_sessions', ['user_id'])
    op.create_index('ix_user_sessions_user_id_active', 'user_sessions', ['user_id', 'is_active'])

    # Create login_attempts table for brute force protection
    op.create_table(
        'login_attempts',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('identifier', sa.String(), nullable=False),
        sa.Column('attempt_type', sa.String(), nullable=False),
        sa.Column('success', sa.Boolean(), default=False, nullable=False),
        sa.Column('attempted_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.Column('ip_address', sa.String(), nullable=True),
        sa.Column('user_agent', sa.String(), nullable=True)
    )

    op.create_index('ix_login_attempts_identifier', 'login_attempts', ['identifier'])
    op.create_index('ix_login_attempts_attempted_at', 'login_attempts', ['attempted_at'])

    # Create account_lockouts table
    op.create_table(
        'account_lockouts',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('user_email', sa.String(), nullable=False),
        sa.Column('locked_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.Column('unlock_at', sa.DateTime(), nullable=False),
        sa.Column('reason', sa.String(), nullable=False),
        sa.Column('failed_attempts', sa.Integer(), default=0, nullable=False),
        sa.Column('is_active', sa.Boolean(), default=True, nullable=False)
    )

    op.create_index('ix_account_lockouts_user_email', 'account_lockouts', ['user_email'])
    op.create_index('ix_account_lockouts_unlock_at', 'account_lockouts', ['unlock_at'])

    # Create email_queue table for async email processing
    op.create_table(
        'email_queue',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('to_email', sa.String(), nullable=False),
        sa.Column('subject', sa.String(), nullable=False),
        sa.Column('html_content', sa.Text(), nullable=False),
        sa.Column('text_content', sa.Text(), nullable=True),
        sa.Column('status', sa.String(), nullable=False, default='pending'),
        sa.Column('attempts', sa.Integer(), default=0, nullable=False),
        sa.Column('max_attempts', sa.Integer(), default=3, nullable=False),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('metadata', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.Column('sent_at', sa.DateTime(), nullable=True),
        sa.Column('next_retry_at', sa.DateTime(), nullable=True)
    )

    op.create_index('ix_email_queue_status', 'email_queue', ['status'])
    op.create_index('ix_email_queue_next_retry_at', 'email_queue', ['next_retry_at'])

    # Add password_changed_at to users table for security tracking
    op.add_column('users', sa.Column('password_changed_at', sa.DateTime(), nullable=True))
    op.add_column('users', sa.Column('last_login_at', sa.DateTime(), nullable=True))
    op.add_column('users', sa.Column('last_login_ip', sa.String(), nullable=True))


def downgrade() -> None:
    # Drop tables in reverse order
    op.drop_table('email_queue')
    op.drop_table('account_lockouts')
    op.drop_table('login_attempts')
    op.drop_table('user_sessions')
    op.drop_table('token_blacklist')

    # Drop columns from users
    op.drop_column('users', 'last_login_ip')
    op.drop_column('users', 'last_login_at')
    op.drop_column('users', 'password_changed_at')