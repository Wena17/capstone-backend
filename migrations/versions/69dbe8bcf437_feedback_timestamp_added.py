"""Feedback timestamp added

Revision ID: 69dbe8bcf437
Revises: b8fea3906078
Create Date: 2023-01-05 14:36:06.839616

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '69dbe8bcf437'
down_revision = 'b8fea3906078'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('feedback', sa.Column('ts', sa.DateTime(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('feedback', 'ts')
    # ### end Alembic commands ###
