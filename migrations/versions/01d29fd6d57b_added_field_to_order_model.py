"""added field to order model

Revision ID: 01d29fd6d57b
Revises: 91b5f0dee6d2
Create Date: 2023-01-12 00:54:45.067866

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '01d29fd6d57b'
down_revision = '91b5f0dee6d2'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('order', sa.Column('status', sa.Integer(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('order', 'status')
    # ### end Alembic commands ###
