"""Initial migration - create all tables

Revision ID: 001_initial
Revises: 
Create Date: 2026-02-15

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '001_initial'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create organizations table
    op.create_table('organizations',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('industry', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_organizations_id'), 'organizations', ['id'], unique=False)
    op.create_index(op.f('ix_organizations_name'), 'organizations', ['name'], unique=False)

    # Create users table
    op.create_table('users',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('hashed_password', sa.String(length=255), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=True),
        sa.Column('org_id', sa.Integer(), nullable=True),
        sa.Column('role', sa.String(length=50), nullable=True),
        sa.Column('department', sa.String(length=100), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email')
    )
    op.create_index(op.f('ix_users_id'), 'users', ['id'], unique=False)
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
    op.create_index(op.f('ix_users_org_id'), 'users', ['org_id'], unique=False)

    # Create ai_tools table
    op.create_table('ai_tools',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('tool_type', sa.String(length=100), nullable=False),
        sa.Column('provider', sa.String(length=100), nullable=True),
        sa.Column('risk_level', sa.String(length=20), nullable=True),
        sa.Column('category', sa.String(length=100), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_ai_tools_id'), 'ai_tools', ['id'], unique=False)
    op.create_index(op.f('ix_ai_tools_name'), 'ai_tools', ['name'], unique=False)

    # Create policies table
    op.create_table('policies',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.String(), nullable=True),
        sa.Column('rules', sa.JSON(), nullable=True),
        sa.Column('org_id', sa.Integer(), nullable=True),
        sa.Column('enforcement_mode', sa.String(length=20), nullable=True),
        sa.Column('allowed_tools', sa.JSON(), nullable=True),
        sa.Column('restricted_data_types', sa.JSON(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_policies_id'), 'policies', ['id'], unique=False)
    op.create_index(op.f('ix_policies_name'), 'policies', ['name'], unique=False)
    op.create_index(op.f('ix_policies_org_id'), 'policies', ['org_id'], unique=False)

    # Create prompts table
    op.create_table('prompts',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('category', sa.String(length=100), nullable=True),
        sa.Column('org_id', sa.Integer(), nullable=True),
        sa.Column('allowed_roles', sa.JSON(), nullable=True),
        sa.Column('sensitivity_level', sa.String(length=20), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_prompts_id'), 'prompts', ['id'], unique=False)
    op.create_index(op.f('ix_prompts_name'), 'prompts', ['name'], unique=False)
    op.create_index(op.f('ix_prompts_org_id'), 'prompts', ['org_id'], unique=False)
    op.create_index(op.f('ix_prompts_category'), 'prompts', ['category'], unique=False)

    # Create ai_usage_logs table
    op.create_table('ai_usage_logs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('request_id', sa.String(length=36), nullable=False),
        sa.Column('org_id', sa.Integer(), nullable=True),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('tool_id', sa.Integer(), nullable=True),
        sa.Column('prompt', sa.Text(), nullable=True),
        sa.Column('output_summary', sa.Text(), nullable=True),
        sa.Column('ai_model', sa.String(length=255), nullable=True),
        sa.Column('usage_type', sa.String(length=50), nullable=False),
        sa.Column('data_type', sa.String(length=50), nullable=False),
        sa.Column('policy_result', sa.String(length=20), nullable=True),
        sa.Column('policy_message', sa.String(), nullable=True),
        sa.Column('input_tokens', sa.Integer(), nullable=True),
        sa.Column('output_tokens', sa.Integer(), nullable=True),
        sa.Column('total_tokens', sa.Integer(), nullable=True),
        sa.Column('cost_usd', sa.Numeric(precision=10, scale=6), nullable=True),
        sa.Column('endpoint', sa.String(length=255), nullable=True),
        sa.Column('client_ip', sa.String(length=45), nullable=True),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.ForeignKeyConstraint(['tool_id'], ['ai_tools.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('request_id')
    )
    op.create_index(op.f('ix_ai_usage_logs_id'), 'ai_usage_logs', ['id'], unique=False)
    op.create_index(op.f('ix_ai_usage_logs_org_id'), 'ai_usage_logs', ['org_id'], unique=False)
    op.create_index(op.f('ix_ai_usage_logs_user_id'), 'ai_usage_logs', ['user_id'], unique=False)
    op.create_index(op.f('ix_ai_usage_logs_policy_result'), 'ai_usage_logs', ['policy_result'], unique=False)
    op.create_index(op.f('ix_ai_usage_logs_timestamp'), 'ai_usage_logs', ['timestamp'], unique=False)
    op.create_index(op.f('ix_ai_usage_logs_request_id'), 'ai_usage_logs', ['request_id'], unique=True)

    # Create policy_violations table
    op.create_table('policy_violations',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('org_id', sa.Integer(), nullable=True),
        sa.Column('usage_id', sa.Integer(), nullable=True),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('policy_id', sa.Integer(), nullable=True),
        sa.Column('violation_type', sa.String(length=100), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('details', sa.Text(), nullable=True),
        sa.Column('resolved', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
        sa.ForeignKeyConstraint(['usage_id'], ['ai_usage_logs.id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.ForeignKeyConstraint(['policy_id'], ['policies.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_policy_violations_id'), 'policy_violations', ['id'], unique=False)
    op.create_index(op.f('ix_policy_violations_org_id'), 'policy_violations', ['org_id'], unique=False)
    op.create_index(op.f('ix_policy_violations_usage_id'), 'policy_violations', ['usage_id'], unique=False)
    op.create_index(op.f('ix_policy_violations_severity'), 'policy_violations', ['severity'], unique=False)
    op.create_index(op.f('ix_policy_violations_resolved'), 'policy_violations', ['resolved'], unique=False)

    # Create reports table
    op.create_table('reports',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('report_type', sa.String(length=100), nullable=True),
        sa.Column('data', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_reports_id'), 'reports', ['id'], unique=False)
    op.create_index(op.f('ix_reports_title'), 'reports', ['title'], unique=False)

    # Create audit_exports table
    op.create_table('audit_exports',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('org_id', sa.Integer(), nullable=True),
        sa.Column('export_type', sa.String(length=50), nullable=False),
        sa.Column('generated_by', sa.Integer(), nullable=True),
        sa.Column('file_path', sa.String(length=500), nullable=True),
        sa.Column('filters', sa.JSON(), nullable=True),
        sa.Column('record_count', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
        sa.ForeignKeyConstraint(['generated_by'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_audit_exports_id'), 'audit_exports', ['id'], unique=False)
    op.create_index(op.f('ix_audit_exports_org_id'), 'audit_exports', ['org_id'], unique=False)
    op.create_index(op.f('ix_audit_exports_created_at'), 'audit_exports', ['created_at'], unique=False)

    # Create usage_logs table (legacy)
    op.create_table('usage_logs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('endpoint', sa.String(length=255), nullable=True),
        sa.Column('tokens_used', sa.Integer(), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_usage_logs_id'), 'usage_logs', ['id'], unique=False)
    op.create_index(op.f('ix_usage_logs_user_id'), 'usage_logs', ['user_id'], unique=False)


def downgrade() -> None:
    op.drop_table('usage_logs')
    op.drop_table('audit_exports')
    op.drop_table('reports')
    op.drop_table('policy_violations')
    op.drop_table('ai_usage_logs')
    op.drop_table('prompts')
    op.drop_table('policies')
    op.drop_table('ai_tools')
    op.drop_table('users')
    op.drop_table('organizations')
