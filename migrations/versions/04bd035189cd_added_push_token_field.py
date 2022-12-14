"""Added push token field

Revision ID: 04bd035189cd
Revises: d5d92c2a6ddc
Create Date: 2022-12-20 01:45:23.939079

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '04bd035189cd'
down_revision = 'd5d92c2a6ddc'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('user', sa.Column('pushToken', sa.String(length=100), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('user', 'pushToken')
    # ### end Alembic commands ###
