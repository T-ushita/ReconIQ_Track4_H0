from sqlalchemy import create_engine

import os

engine = create_engine(
    os.environ["DATABASE_URL"]
)