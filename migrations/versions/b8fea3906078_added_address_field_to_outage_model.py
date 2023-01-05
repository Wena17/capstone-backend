"""Added address field to outage model

Revision ID: b8fea3906078
Revises: e2757e5705bd
Create Date: 2023-01-05 06:16:51.063322

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b8fea3906078'
down_revision = 'e2757e5705bd'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('outage', sa.Column('address', sa.String(length=255), nullable=True))
    op.add_column('outage', sa.Column('user_id', sa.Integer(), nullable=True))
    op.execute('UPDATE "outage" SET user_id = 1')
    op.alter_column('outage', 'user_id', nullable=False)
    op.create_foreign_key(None, 'outage', 'user', ['user_id'], ['id'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'outage', type_='foreignkey')
    op.drop_column('outage', 'user_id')
    op.drop_column('outage', 'address')
    # ### end Alembic commands ###
