"""Add device model with geo location

Revision ID: d752ff24cce2
Revises: f92a150b417f
Create Date: 2022-10-10 20:54:38.467801

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd752ff24cce2'
down_revision = 'f92a150b417f'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('device',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('dev_id', sa.String(length=32), nullable=False),
    sa.Column('lat', sa.Float(), nullable=True),
    sa.Column('long', sa.Float(), nullable=True),
    sa.Column('ts', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_device_dev_id'), 'device', ['dev_id'], unique=True)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_device_dev_id'), table_name='device')
    op.drop_table('device')
    # ### end Alembic commands ###
