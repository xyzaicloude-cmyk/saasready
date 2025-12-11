# backend/alembic/versions/011_rename_email_queue_metadata.py
"""Rename email_queue metadata column to metadata_email

Revision ID: 011_rename_email_queue_metadata
Revises: 010_add_token_revocation
Create Date: 2025-01-25 11:00:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = '011_rename_email_queue_metadata'
down_revision = '010_add_token_revocation'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Rename the column from 'metadata' to 'metadata_email'
    op.alter_column(
        'email_queue',
        'metadata',
        new_column_name='metadata_email',
        existing_type=sa.JSON(),
        existing_nullable=True
    )


def downgrade() -> None:
    # Rename the column back from 'metadata_email' to 'metadata'
    op.alter_column(
        'email_queue',
        'metadata_email',
        new_column_name='metadata',
        existing_type=sa.JSON(),
        existing_nullable=True
    )