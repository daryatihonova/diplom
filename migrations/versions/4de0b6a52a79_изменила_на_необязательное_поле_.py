"""изменила на необязательное поле описание мероприятия

Revision ID: 4de0b6a52a79
Revises: 55277c212d46
Create Date: 2025-03-04 00:57:52.745930

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '4de0b6a52a79'
down_revision = '55277c212d46'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('event', schema=None) as batch_op:
        batch_op.alter_column('description',
               existing_type=sa.TEXT(),
               nullable=True)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('event', schema=None) as batch_op:
        batch_op.alter_column('description',
               existing_type=sa.TEXT(),
               nullable=False)

    # ### end Alembic commands ###
