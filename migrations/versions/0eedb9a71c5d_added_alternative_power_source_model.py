"""Added alternative power source model

Revision ID: 0eedb9a71c5d
Revises: 703bccc2ef6c
Create Date: 2022-11-17 00:09:25.549648

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0eedb9a71c5d'
down_revision = '703bccc2ef6c'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('alternative_power_source',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=100), nullable=True),
    sa.Column('address', sa.String(length=255), nullable=True),
    sa.Column('payment', sa.String(length=50), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('alternative_power_source')
    # ### end Alembic commands ###