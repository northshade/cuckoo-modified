"""add notification_deleted

Revision ID: 160d3ee4fafd
Revises:
Create Date: 2017-11-27 14:52:13.452881

"""

# revision identifiers, used by Alembic.
revision = '160d3ee4fafd'
down_revision = None
branch_labels = None
depends_on = None

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('task', sa.Column('notificated', sa.Boolean()))
    op.add_column('task', sa.Column('deleted', sa.Boolean()))

def downgrade():
    pass
