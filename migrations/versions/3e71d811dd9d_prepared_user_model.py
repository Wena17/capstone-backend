"""Prepared user model

Revision ID: 3e71d811dd9d
Revises: b55a767559ac
Create Date: 2022-11-13 21:37:53.128648

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '3e71d811dd9d'
down_revision = 'b55a767559ac'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('user', sa.Column('registered_on', sa.DateTime(), nullable=True))
    op.execute('UPDATE "user" SET registered_on = NOW()')
    op.alter_column('user', 'registered_on', nullable=False)
    op.add_column('user', sa.Column('admin', sa.Boolean(), nullable=True))
    op.execute('UPDATE "user" SET admin = false')
    op.alter_column('user', 'admin', nullable=False)
    op.alter_column('user', 'accountId',
               existing_type=sa.INTEGER(),
               nullable=True)
    op.alter_column('user', 'firstname',
               existing_type=sa.VARCHAR(length=100),
               nullable=True)
    op.alter_column('user', 'lastname',
               existing_type=sa.VARCHAR(length=100),
               nullable=True)
    op.alter_column('user', 'phoneNo',
               existing_type=sa.VARCHAR(length=15),
               nullable=True)
    op.alter_column('user', 'password',
               existing_type=sa.VARCHAR(length=100),
               type_=sa.String(length=255),
               existing_nullable=False)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('user', 'password',
               existing_type=sa.String(length=255),
               type_=sa.VARCHAR(length=100),
               existing_nullable=False)
    op.alter_column('user', 'phoneNo',
               existing_type=sa.VARCHAR(length=15),
               nullable=False)
    op.alter_column('user', 'lastname',
               existing_type=sa.VARCHAR(length=100),
               nullable=False)
    op.alter_column('user', 'firstname',
               existing_type=sa.VARCHAR(length=100),
               nullable=False)
    op.alter_column('user', 'accountId',
               existing_type=sa.INTEGER(),
               nullable=False)
    op.drop_column('user', 'admin')
    op.drop_column('user', 'registered_on')
    # ### end Alembic commands ###
