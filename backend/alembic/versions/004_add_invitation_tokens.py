"""Add invitation tokens to memberships

Revision ID: 004_add_invitation_tokens
Revises: 003_feature_flags
Create Date: 2025-01-20 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from datetime import datetime, timedelta
import uuid


# revision identifiers, used by Alembic.
revision = '004_add_invitation_tokens'
down_revision = '003_feature_flags'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add invitation_token column
    op.add_column('memberships', sa.Column('invitation_token', sa.String(), nullable=True))

    # Add invitation_expires_at column
    op.add_column('memberships', sa.Column('invitation_expires_at', sa.DateTime(), nullable=True))

    # Create unique index on invitation_token
    op.create_index('ix_memberships_invitation_token', 'memberships', ['invitation_token'], unique=True)

    # Update existing invited memberships to have tokens using uuid instead of gen_random_bytes
    op.execute("""
        UPDATE memberships 
        SET invitation_token = encode(sha256(random()::text::bytea), 'hex')
        WHERE status = 'invited' AND invitation_token IS NULL
    """)


def downgrade() -> None:
    # Drop index
    op.drop_index('ix_memberships_invitation_token', table_name='memberships')

    # Drop columns
    op.drop_column('memberships', 'invitation_expires_at')
    op.drop_column('memberships', 'invitation_token')