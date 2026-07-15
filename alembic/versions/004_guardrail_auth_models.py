"""Add guardrail, auth security, webhook, and cybersecurity models

Revision ID: 004_guardrail_auth_models
Revises: 003_api_key_hashing
Create Date: 2026-07-15

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '004_guardrail_auth_models'
down_revision: Union[str, None] = '003_api_key_hashing'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Users: add token_version for session invalidation
    op.add_column('users', sa.Column('token_version', sa.Integer(), server_default='0', nullable=False))

    # Webhooks
    op.create_table('webhooks',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('url', sa.String(2048), nullable=False),
        sa.Column('secret', sa.String(64), nullable=True),
        sa.Column('events', sa.JSON(), nullable=False),
        sa.Column('status', sa.String(20), server_default='active', nullable=False),
        sa.Column('timeout', sa.Integer(), server_default='30', nullable=False),
        sa.Column('retry_count', sa.Integer(), server_default='3', nullable=False),
        sa.Column('retry_delay', sa.Integer(), server_default='5', nullable=False),
        sa.Column('last_triggered_at', sa.DateTime(), nullable=True),
        sa.Column('last_status_code', sa.Integer(), nullable=True),
        sa.Column('failure_count', sa.Integer(), server_default='0', nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_webhooks_id'), 'webhooks', ['id'], unique=False)
    op.create_index(op.f('ix_webhooks_user_id'), 'webhooks', ['user_id'], unique=False)

    # Guardrail logs
    op.create_table('guardrail_logs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('org_id', sa.Integer(), nullable=True),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('tool_id', sa.Integer(), nullable=True),
        sa.Column('prompt_hash', sa.String(64), nullable=True),
        sa.Column('prompt_preview', sa.String(200), nullable=True),
        sa.Column('evaluation_type', sa.String(20), nullable=False),
        sa.Column('risk_score', sa.Float(), server_default='0.0', nullable=False),
        sa.Column('action_taken', sa.String(20), nullable=True),
        sa.Column('injection_score', sa.Float(), server_default='0.0', nullable=False),
        sa.Column('pii_detected', sa.Boolean(), server_default='false', nullable=False),
        sa.Column('pii_types', sa.JSON(), nullable=True),
        sa.Column('policy_violations', sa.JSON(), nullable=True),
        sa.Column('latency_ms', sa.Float(), server_default='0.0', nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.ForeignKeyConstraint(['tool_id'], ['ai_tools.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_guardrail_logs_id'), 'guardrail_logs', ['id'], unique=False)
    op.create_index(op.f('ix_guardrail_logs_user_id'), 'guardrail_logs', ['user_id'], unique=False)
    op.create_index(op.f('ix_guardrail_logs_prompt_hash'), 'guardrail_logs', ['prompt_hash'], unique=False)

    # Guardrail rules
    op.create_table('guardrail_rules',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('org_id', sa.Integer(), nullable=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('description', sa.String(), nullable=True),
        sa.Column('category', sa.String(50), nullable=False),
        sa.Column('pattern', sa.String(), nullable=False),
        sa.Column('action', sa.String(20), server_default='warn', nullable=False),
        sa.Column('severity', sa.String(20), server_default='medium', nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default='true', nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_guardrail_rules_id'), 'guardrail_rules', ['id'], unique=False)

    # Password reset tokens
    op.create_table('password_reset_tokens',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('token_hash', sa.String(64), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('used', sa.Boolean(), server_default='false', nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('token_hash')
    )
    op.create_index(op.f('ix_password_reset_tokens_id'), 'password_reset_tokens', ['id'], unique=False)
    op.create_index(op.f('ix_password_reset_tokens_token_hash'), 'password_reset_tokens', ['token_hash'], unique=True)

    # User MFA settings
    op.create_table('user_mfa_settings',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('totp_secret', sa.String(), nullable=True),
        sa.Column('is_enabled', sa.Boolean(), server_default='false', nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id')
    )
    op.create_index(op.f('ix_user_mfa_settings_id'), 'user_mfa_settings', ['id'], unique=False)

    # Cybersecurity: assets
    op.create_table('assets',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('org_id', sa.Integer(), nullable=True),
        sa.Column('hostname', sa.String(255), nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=False),
        sa.Column('service', sa.String(100), nullable=True),
        sa.Column('version', sa.String(100), nullable=True),
        sa.Column('exposure_level', sa.String(20), server_default='internal', nullable=False),
        sa.Column('asset_type', sa.String(50), nullable=True),
        sa.Column('cloud_provider', sa.String(50), nullable=True),
        sa.Column('cloud_resource_id', sa.String(255), nullable=True),
        sa.Column('is_active', sa.Boolean(), server_default='true', nullable=False),
        sa.Column('discovered_at', sa.DateTime(), nullable=True),
        sa.Column('last_scanned', sa.DateTime(), nullable=True),
        sa.Column('meta_data', sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_assets_id'), 'assets', ['id'], unique=False)
    op.create_index(op.f('ix_assets_hostname'), 'assets', ['hostname'], unique=False)
    op.create_index(op.f('ix_assets_ip_address'), 'assets', ['ip_address'], unique=False)

    # Cybersecurity: vulnerabilities
    op.create_table('vulnerabilities',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('org_id', sa.Integer(), nullable=True),
        sa.Column('asset_id', sa.Integer(), nullable=False),
        sa.Column('cve_id', sa.String(50), nullable=True),
        sa.Column('vulnerability_type', sa.String(100), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('severity', sa.String(20), nullable=False),
        sa.Column('cvss_score', sa.Float(), nullable=True),
        sa.Column('exploit_probability', sa.Float(), server_default='0.0', nullable=False),
        sa.Column('risk_score', sa.Float(), server_default='0.0', nullable=False),
        sa.Column('is_exploitable', sa.Boolean(), server_default='false', nullable=False),
        sa.Column('is_patched', sa.Boolean(), server_default='false', nullable=False),
        sa.Column('discovered_at', sa.DateTime(), nullable=True),
        sa.Column('remediation', sa.Text(), nullable=True),
        sa.Column('references', sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_vulnerabilities_id'), 'vulnerabilities', ['id'], unique=False)
    op.create_index(op.f('ix_vulnerabilities_cve_id'), 'vulnerabilities', ['cve_id'], unique=False)

    # Cybersecurity: attack paths
    op.create_table('attack_paths',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('org_id', sa.Integer(), nullable=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('entry_asset_id', sa.Integer(), nullable=False),
        sa.Column('critical_asset_id', sa.Integer(), nullable=False),
        sa.Column('path_data', sa.JSON(), nullable=False),
        sa.Column('attack_vector', sa.String(100), nullable=True),
        sa.Column('likelihood', sa.Float(), server_default='0.0', nullable=False),
        sa.Column('impact_score', sa.Float(), server_default='0.0', nullable=False),
        sa.Column('is_simulated', sa.Boolean(), server_default='true', nullable=False),
        sa.Column('executed_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
        sa.ForeignKeyConstraint(['entry_asset_id'], ['assets.id'], ),
        sa.ForeignKeyConstraint(['critical_asset_id'], ['assets.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_attack_paths_id'), 'attack_paths', ['id'], unique=False)

    # Cybersecurity: alerts
    op.create_table('alerts',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('org_id', sa.Integer(), nullable=True),
        sa.Column('asset_id', sa.Integer(), nullable=True),
        sa.Column('alert_type', sa.String(50), nullable=False),
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('severity', sa.String(20), nullable=False),
        sa.Column('status', sa.String(20), server_default='open', nullable=False),
        sa.Column('source', sa.String(50), nullable=True),
        sa.Column('mitre_tactic', sa.String(100), nullable=True),
        sa.Column('mitre_technique', sa.String(100), nullable=True),
        sa.Column('indicators', sa.JSON(), nullable=True),
        sa.Column('response_action', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('resolved_at', sa.DateTime(), nullable=True),
        sa.Column('resolved_by', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ),
        sa.ForeignKeyConstraint(['resolved_by'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_alerts_id'), 'alerts', ['id'], unique=False)

    # Cybersecurity: threat intel
    op.create_table('threat_intel',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('indicator_type', sa.String(20), nullable=False),
        sa.Column('indicator_value', sa.String(255), nullable=False),
        sa.Column('threat_type', sa.String(50), nullable=False),
        sa.Column('source', sa.String(100), nullable=True),
        sa.Column('confidence', sa.Float(), server_default='0.0', nullable=False),
        sa.Column('first_seen', sa.DateTime(), nullable=True),
        sa.Column('last_seen', sa.DateTime(), nullable=True),
        sa.Column('is_active', sa.Boolean(), server_default='true', nullable=False),
        sa.Column('meta_data', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_threat_intel_id'), 'threat_intel', ['id'], unique=False)
    op.create_index(op.f('ix_threat_intel_indicator_value'), 'threat_intel', ['indicator_value'], unique=False)

    # Cybersecurity: scan jobs
    op.create_table('scan_jobs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('org_id', sa.Integer(), nullable=True),
        sa.Column('scan_type', sa.String(50), nullable=False),
        sa.Column('target', sa.String(255), nullable=False),
        sa.Column('status', sa.String(20), server_default='pending', nullable=False),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('results', sa.JSON(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_by', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_scan_jobs_id'), 'scan_jobs', ['id'], unique=False)


def downgrade() -> None:
    op.drop_table('scan_jobs')
    op.drop_table('threat_intel')
    op.drop_table('alerts')
    op.drop_table('attack_paths')
    op.drop_table('vulnerabilities')
    op.drop_table('assets')
    op.drop_table('user_mfa_settings')
    op.drop_table('password_reset_tokens')
    op.drop_table('guardrail_rules')
    op.drop_table('guardrail_logs')
    op.drop_table('webhooks')
    op.drop_column('users', 'token_version')
