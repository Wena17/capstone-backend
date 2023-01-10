"""Order and price model created

Revision ID: fc890e2cd22c
Revises: 69dbe8bcf437
Create Date: 2023-01-11 00:08:54.739631

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'fc890e2cd22c'
down_revision = '69dbe8bcf437'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('order',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('quantity', sa.Integer(), nullable=True),
    sa.Column('price', sa.Integer(), nullable=True),
    sa.Column('ts', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('price',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('price', sa.Integer(), nullable=True),
    sa.Column('ts', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('price')
    op.drop_table('order')
    # ### end Alembic commands ###
