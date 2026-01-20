"""Add invited_email to memberships table

Revision ID: 007_add_invited_email_to_memberships
Revises: 006_add_email_verif_fields
Create Date: 2025-01-21 12:00:00.000000
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '007_invited_email_to_membrshp'
down_revision = '006_add_email_verif_fields'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add invited_email column to memberships table
    op.add_column('memberships', sa.Column('invited_email', sa.String(), nullable=True))

    # Optional: Create index for better performance when querying by invited_email
    op.create_index('ix_memberships_invited_email', 'memberships', ['invited_email'])


def downgrade() -> None:
    # Drop index
    op.drop_index('ix_memberships_invited_email', table_name='memberships')

    # Drop invited_email column
    op.drop_column('memberships', 'invited_email')