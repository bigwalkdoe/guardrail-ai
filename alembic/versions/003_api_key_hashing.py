"""Hash API keys and add key prefix

Revision ID: 003_api_key_hashing
Revises: 002_saas_models
Create Date: 2026-03-14

"""
from typing import Sequence, Union
import hashlib
import string

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '003_api_key_hashing'
down_revision: Union[str, None] = '002_saas_models'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _is_probably_hash(value: str) -> bool:
    if not value or len(value) != 64:
        return False
    return all(ch in string.hexdigits for ch in value)


def upgrade() -> None:
    op.add_column('api_keys', sa.Column('key_prefix', sa.String(length=16), nullable=True))

    conn = op.get_bind()
    result = conn.execute(sa.text("SELECT id, key FROM api_keys"))

    for row in result.mappings():
        raw_key = row.get("key")
        if not raw_key:
            continue

        if _is_probably_hash(raw_key):
            key_hash = raw_key
            key_prefix = None
        else:
            key_prefix = raw_key[:8]
            key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

        conn.execute(
            sa.text(
                "UPDATE api_keys SET key = :key_hash, key_prefix = :key_prefix WHERE id = :id"
            ),
            {
                "key_hash": key_hash,
                "key_prefix": key_prefix,
                "id": row["id"],
            },
        )


def downgrade() -> None:
    op.drop_column('api_keys', 'key_prefix')
