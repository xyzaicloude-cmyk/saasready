"""Add feature flags tables

Revision ID: 002_feature_flags
Revises: 001_initial_schema
Create Date: 2025-01-15 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
import uuid

# revision identifiers, used by Alembic.
revision = '003_feature_flags'
down_revision = '002_feature_flags'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add key column
    #op.add_column('permissions', sa.Column('key', sa.String(), nullable=True))

    # Populate key from existing name (or leave null for manual population)
    # If you have existing permissions, you may want to generate keys from name
    op.execute("""
        UPDATE permissions 
        SET key = LOWER(REPLACE(name, ' ', '.'))
        WHERE key IS NULL
    """)

    # Make key NOT NULL and unique after populating
    op.alter_column('permissions', 'key', nullable=False)
   # op.create_unique_constraint('uq_permissions_key', 'permissions', ['key'])

def downgrade():
    #op.drop_constraint('uq_permissions_key', 'permissions', type_='unique')
    op.drop_column('permissions', 'key')
