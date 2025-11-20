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
revision = '002_feature_flags'
down_revision = '001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create feature_flags table
    op.create_table(
        'feature_flags',
        sa.Column('id', sa.String(), primary_key=True),  # Changed to String
        sa.Column('key', sa.String(length=100), nullable=False),
        sa.Column('name', sa.String(length=200), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('default_enabled', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )
    op.create_index('ix_feature_flags_key', 'feature_flags', ['key'], unique=True)

    # Create org_feature_flags table
    op.create_table(
        'org_feature_flags',
        sa.Column('id', sa.String(), primary_key=True),  # Changed to String
        sa.Column('org_id', sa.String(), nullable=False),  # Changed to String
        sa.Column('feature_flag_id', sa.String(), nullable=False),  # Changed to String
        sa.Column('enabled', sa.Boolean(), nullable=False),
        sa.Column('rollout_percent', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['feature_flag_id'], ['feature_flags.id'], ondelete='CASCADE'),
        sa.UniqueConstraint('org_id', 'feature_flag_id', name='uq_org_feature_flag')
    )
    op.create_index('ix_org_feature_flags_org_id', 'org_feature_flags', ['org_id'])
    op.create_index('ix_org_feature_flags_feature_flag_id', 'org_feature_flags', ['feature_flag_id'])

    # Insert some default feature flags
    op.execute("""
        INSERT INTO feature_flags (id, key, name, description, default_enabled)
        VALUES 
            (gen_random_uuid()::text, 'beta-new-ui', 'Beta New UI', 'Enable the new redesigned user interface', false),
            (gen_random_uuid()::text, 'ai-insights', 'AI Insights', 'Enable AI-powered analytics and insights', false),
            (gen_random_uuid()::text, 'advanced-reporting', 'Advanced Reporting', 'Enable advanced reporting features', false),
            (gen_random_uuid()::text, 'api-v2', 'API v2', 'Enable access to API version 2', false)
    """)

    op.add_column('permissions', sa.Column('key', sa.String(), nullable=True))
    op.execute("""
        UPDATE permissions 
        SET key = LOWER(REPLACE(name, ' ', '.'))
        WHERE key IS NULL
    """)

    op.alter_column('permissions', 'key', nullable=False)
    op.create_unique_constraint('uq_permissions_key', 'permissions', ['key'])


def downgrade() -> None:
    op.drop_index('ix_org_feature_flags_feature_flag_id', table_name='org_feature_flags')
    op.drop_index('ix_org_feature_flags_org_id', table_name='org_feature_flags')
    op.drop_table('org_feature_flags')
    op.drop_index('ix_feature_flags_key', table_name='feature_flags')
    op.drop_table('feature_flags')
    op.drop_constraint('uq_permissions_key', 'permissions', type_='unique')
    op.drop_column('permissions', 'key')