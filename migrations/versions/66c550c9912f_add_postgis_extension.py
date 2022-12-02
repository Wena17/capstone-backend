"""Add PostGIS extension

Revision ID: 66c550c9912f
Revises: 7f896a5b4f9a
Create Date: 2022-12-02 23:03:54.385012

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '66c550c9912f'
down_revision = '7f896a5b4f9a'
branch_labels = None
depends_on = None


def upgrade():
    op.execute("CREATE EXTENSION IF NOT EXISTS postgis")


def downgrade():
    op.execute("DROP EXTENSION postgis")
